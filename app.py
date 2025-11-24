import os
from flask_cors import CORS
from flask import Flask, jsonify, request, render_template
from flask_mysqldb import MySQL
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv

# Google 토큰 검증 라이브러리
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

# .env 파일 로드
load_dotenv()

# --- 1. 초기화 ---
app = Flask(__name__)
jwt = JWTManager(app)

# 모든 경로(r"/*")에 대해 모든 출처("origins": "*")를 허용
CORS(app, resources={r"/*": {"origins": "*"}})

# --- 2. 설정 ---
# DB 설정
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['MYSQL_CHARSET'] = 'utf8mb4'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'  # 결과를 딕셔너리로 받음

# JWT 설정
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

# Google Client ID 설정
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')

# 확장 프로그램 초기화
mysql = MySQL(app)


# --- 3. API 엔드포인트 ---

@app.route('/')
def home():
    return render_template("index.html")
    #return jsonify({"msg": "Google 로그인 API 서버입니다."})


# [POST] /login/google : 구글 로그인 (회원가입/로그인 통합)
@app.route('/login/google', methods=['POST'])
def login_google():
    """
    프론트엔드에서 받은 Google ID 토큰을 검증하고,
    사용자가 없으면 자동 회원가입, 있으면 로그인 처리 후
    우리 앱의 자체 JWT 토큰을 발급합니다.
    """

    # 1. 프론트엔드에서 보낸 Google ID 토큰 받기
    data = request.get_json()
    google_token = data.get('google_token')

    if not google_token:
        return jsonify(state="error", error="Google 토큰이 없습니다."), 400

    if not GOOGLE_CLIENT_ID:
        return jsonify(state="error", error="서버에 Google Client ID가 설정되지 않았습니다."), 500

    try:
        # 2. Google 토큰 검증
        id_info = id_token.verify_oauth2_token(
            google_token,
            google_requests.Request(),
            GOOGLE_CLIENT_ID
        )

        # 3. 토큰에서 사용자 정보 추출
        google_id = id_info['sub']  # 구글 고유 ID
        email = id_info['email']
        full_name = id_info.get('name')

        # 4. DB에서 사용자 조회
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE google_id = %s", [google_id])
        user = cur.fetchone()

        if not user:
            # 5-A. 신규 사용자 -> 자동 회원가입
            print(f"새 사용자 가입: {email}")
            cur.execute(
                "INSERT INTO users (google_id, email, full_name) VALUES (%s, %s, %s)",
                (google_id, email, full_name)
            )
            mysql.connection.commit()
            user_identity = email

        else:
            # 5-B. 기존 사용자 -> 로그인
            print(f"기존 사용자 로그인: {user['email']}")
            user_identity = user['email']

        cur.close()

        # 6. 인증 성공 -> 우리 앱의 JWT 토큰 발급
        #    (identity는 우리 DB의 email 사용)
        access_token = create_access_token(identity=user_identity)

        return jsonify(state="success", access_token=access_token, user_email=user_identity), 200

    except ValueError as e:
        # 토큰 유효하지 않거나 만료된 경우
        return jsonify(state="error", error="Google 토큰이 유효하지 않습니다.", details=str(e)), 401
    except Exception as e:
        return jsonify(state="error", error="서버 내부 오류가 발생했습니다.", details=str(e)), 500


# [GET] /protected : *우리 앱의* JWT로 보호되는 엔드포인트
@app.route('/protected', methods=['GET'])
@jwt_required()  # 헤더의 "Bearer [우리 JWT]"를 검사
def protected():
    # 토큰이 유효하면, identity (email)를 가져옴
    current_user_email = get_jwt_identity()
    return jsonify(
        state="success",
        logged_in_as=current_user_email,
        message="성공! 이 API는 Google이 아닌 우리 서버의 JWT로 보호됩니다."
    ), 200


# [POST] /emotions : 감정 기록 추가 또는 업데이트
@app.route('/emotions', methods=['POST'])
@jwt_required()
def add_or_update_emotion():
    """
    로그인된 사용자의 특정 날짜 감정 기록을 DB에 추가하거나,
    기록이 이미 존재하면 업데이트합니다.
    """
    # 1. 사용자 식별
    current_user_email = get_jwt_identity()

    # 2. 요청 본문에서 데이터 추출 (DB 스키마에 맞게)
    data = request.get_json()
    record_date = data.get('date') # apiTest.py 와 맞춤
    emotion_type = data.get('emotion') # apiTest.py 와 맞춤
    emotion_level = data.get('intensity') # apiTest.py 와 맞춤

    # 3. 필수 데이터 검증
    if not all([record_date, emotion_type, emotion_level]):
        return jsonify(state="error", error="date, emotion, intensity는 필수 항목입니다."), 400

    try:
        # 4. 데이터베이스에 삽입 또는 업데이트 (ON DUPLICATE KEY UPDATE 사용)
        cur = mysql.connection.cursor()
        sql = """
            INSERT INTO user_emotions (user_email, record_date, emotion_type, emotion_level)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                emotion_type = VALUES(emotion_type),
                emotion_level = VALUES(emotion_level)
        """
        cur.execute(sql, (current_user_email, record_date, emotion_type, emotion_level))
        mysql.connection.commit()

        # 5. 결과에 따라 다른 응답 반환
        # cursor.rowcount:
        # - 1: 새 행이 삽입됨 (INSERT)
        # - 2: 기존 행이 업데이트됨 (UPDATE)
        # - 0: 기존 행이 동일한 값으로 업데이트 시도됨 (변화 없음)
        if cur.rowcount == 1:
            status_code = 201  # Created
            action = "created"
            message = "감정 기록이 성공적으로 추가되었습니다."
        elif cur.rowcount == 2:
            status_code = 200  # OK
            action = "updated"
            message = "감정 기록이 성공적으로 업데이트되었습니다."
        else: # cur.rowcount == 0
            status_code = 200  # OK
            action = "no_change"
            message = "요청은 처리되었으나, 데이터에 변경 사항이 없습니다."

        cur.close()
        return jsonify(state="success", action=action, msg=message), status_code

    except Exception as e:
        # 그 외 다른 데이터베이스 오류나 서버 내부 오류
        return jsonify(state="error", error="서버 내부 오류가 발생했습니다.", details=str(e)), 500


# [GET] /emotions?start_date=YYYY-MM-DD[&end_date=YYYY-MM-DD] : 특정 기간의 감정 기록 조회
@app.route('/emotions', methods=['GET'])
@jwt_required()
def get_emotions():
    """
    로그인된 사용자의 특정 기간 감정 기록을 DB에서 조회합니다.
    end_date가 생략되면 start_date 하루의 기록만 조회합니다.
    """
    # 1. 사용자 식별
    current_user_email = get_jwt_identity()

    # 2. 쿼리 파라미터에서 날짜 추출
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date', start_date) # end_date가 없으면 start_date로 기본값 설정

    # 3. 날짜 파라미터 검증
    if not start_date:
        return jsonify(state="error", error="조회할 시작 날짜를 'start_date' 쿼리 파라미터로 지정해야 합니다."), 400

    try:
        # 4. 데이터베이스에서 해당 기간의 모든 감정 기록 조회
        cur = mysql.connection.cursor()
        sql = """
            SELECT id, record_date, emotion_type, emotion_level
            FROM user_emotions
            WHERE user_email = %s AND record_date BETWEEN %s AND %s
            ORDER BY record_date ASC
        """
        cur.execute(sql, (current_user_email, start_date, end_date))
        emotion_records = cur.fetchall()
        cur.close()

        # 5. 조회 결과 가공
        formatted_records = []
        for record in emotion_records:
            formatted_records.append({
                "id": record['id'],
                "date": record['record_date'].strftime('%Y-%m-%d'),
                "emotion": record['emotion_type'],
                "emotionLevel": record['emotion_level']
            })

        return jsonify(state="success", data=formatted_records), 200

    except Exception as e:
        return jsonify(state="error", error="서버 내부 오류가 발생했습니다.", details=str(e)), 500


# --- 4. 앱 실행 ---
if __name__ == '__main__':
    app.run(debug=True, port=5000)
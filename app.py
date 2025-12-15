import os
import base64
from flask_cors import CORS
from flask import Flask, jsonify, request, render_template
from flask_mysqldb import MySQL
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv
from datetime import timedelta

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
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=3)

# 업로드 폴더 설정
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')

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


# werkzeug 유틸리티 추가
from werkzeug.utils import secure_filename
import uuid # 고유한 파일명 생성을 위해 추가

# ... (기존 코드 생략) ...

# [POST] /emotions : 감정 기록 추가 또는 업데이트 (이미지 포함)
@app.route('/emotions', methods=['POST'])
@jwt_required()
def add_or_update_emotion():
    """
    로그인된 사용자의 특정 날짜 감정 기록을 DB에 추가하거나,
    기록이 이미 존재하면 업데이트합니다. 이미지 파일 업로드도 처리합니다.
    해금 로직이 포함되어 있어, 하루에 하나의 감정만 해금되도록 관리합니다.
    """
    # 1. 사용자 식별
    current_user_email = get_jwt_identity()

    # 2. 요청 데이터에서 텍스트와 파일 추출
    record_date = request.form.get('date')
    emotion_type = request.form.get('emotion')
    emotion_level = request.form.get('intensity')
    image_file = request.files.get('image')

    # 3. 필수 데이터 검증
    if not all([record_date, emotion_type, emotion_level]):
        return jsonify(state="error", error="date, emotion, intensity는 필수 항목입니다."), 400

    if not emotion_level.isdigit() or int(emotion_level) not in [1, 2, 3]:
        return jsonify(state="error", error="intensity는 1, 2, 3 중 하나의 정수여야 합니다."), 400

    db_image_filename = None
    save_path = None # 오류 시 파일 삭제를 위해 경로 저장

    # 4. 이미지 파일 처리 (DB 트랜잭션 전에 수행)
    if image_file:
        upload_folder = app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        
        filename = secure_filename(image_file.filename)
        extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        unique_filename = f"{uuid.uuid4()}.{extension}"
        db_image_filename = unique_filename
        
        save_path = os.path.join(upload_folder, unique_filename)
        image_file.save(save_path)
        print(f"이미지 저장 완료: {save_path}")

    cur = None # finally 블록에서 사용하기 위해 선언
    try:
        # 5. 데이터베이스 로직 (단일 트랜잭션으로 처리)
        cur = mysql.connection.cursor()

        # 5-1. 업데이트 전, 이전 감정 기록 조회
        cur.execute(
            "SELECT emotion_type, emotion_level FROM user_emotions WHERE user_email = %s AND record_date = %s",
            (current_user_email, record_date)
        )
        old_emotion_record = cur.fetchone()

        # 5-2. 감정 기록 삽입 또는 업데이트
        if db_image_filename:
            sql = """
                INSERT INTO user_emotions (user_email, record_date, emotion_type, emotion_level, image_url)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    emotion_type = VALUES(emotion_type),
                    emotion_level = VALUES(emotion_level),
                    image_url = VALUES(image_url)
            """
            params = (current_user_email, record_date, emotion_type, int(emotion_level), db_image_filename)
        else:
            # 이미지가 없는 경우, 기존 image_url 필드는 건드리지 않음
            sql = """
                INSERT INTO user_emotions (user_email, record_date, emotion_type, emotion_level)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    emotion_type = VALUES(emotion_type),
                    emotion_level = VALUES(emotion_level)
            """
            params = (current_user_email, record_date, emotion_type, int(emotion_level))

        cur.execute(sql, params)
        row_count = cur.rowcount # INSERT/UPDATE 결과를 미리 저장

        # 5-3. 해금된 감정 목록(도감) 관리
        new_emotion_level_int = int(emotion_level)
        
        emotion_has_changed = (
            old_emotion_record and
            (old_emotion_record['emotion_type'] != emotion_type or
             old_emotion_record['emotion_level'] != new_emotion_level_int)
        )

        if emotion_has_changed:
            old_emotion_type = old_emotion_record['emotion_type']
            old_emotion_level = old_emotion_record['emotion_level']

            # 이전 감정이 이 기록 외에 다른 날짜에도 사용되는지 확인
            cur.execute(
                "SELECT 1 FROM user_emotions WHERE user_email = %s AND emotion_type = %s AND emotion_level = %s LIMIT 1",
                (current_user_email, old_emotion_type, old_emotion_level)
            )
            is_old_emotion_still_in_use = cur.fetchone()

            # 다른 곳에서 사용되지 않는다면 '해금 목록'에서 제거
            if not is_old_emotion_still_in_use:
                cur.execute(
                    "DELETE FROM user_unlocked_emotions WHERE user_email = %s AND emotion_type = %s AND emotion_level = %s",
                    (current_user_email, old_emotion_type, old_emotion_level)
                )

        # 5-4. 새로운 감정을 '해금 목록'에 추가 (이미 있으면 무시)
        cur.execute(
            "INSERT IGNORE INTO user_unlocked_emotions (user_email, emotion_type, emotion_level) VALUES (%s, %s, %s)",
            (current_user_email, emotion_type, new_emotion_level_int)
        )

        # 6. 모든 변경사항을 한번에 커밋
        mysql.connection.commit()

        # 7. 결과에 따라 응답 반환
        if row_count == 1:
            status_code, action, message = 201, "created", "감정 기록이 성공적으로 추가되었습니다."
        elif row_count == 2:
            status_code, action, message = 200, "updated", "감정 기록이 성공적으로 업데이트되었습니다."
        else: # row_count == 0
            status_code, action, message = 200, "no_change", "요청은 처리되었으나, 데이터에 변경 사항이 없습니다."
        
        return jsonify({"state": "success", "action": action, "msg": message}), status_code

    except Exception as e:
        # DB 오류 발생 시 롤백
        if mysql.connection:
            mysql.connection.rollback()
        
        # 오류 발생 시 업로드된 파일이 있다면 삭제
        if save_path and os.path.exists(save_path):
            os.remove(save_path)
            print(f"오류로 인해 업로드된 파일 삭제: {save_path}")
            
        return jsonify(state="error", error="서버 내부 오류가 발생했습니다.", details=str(e)), 500
    finally:
        # 커서가 열려있으면 닫기
        if cur:
            cur.close()



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
            SELECT id, record_date, emotion_type, emotion_level, image_url
            FROM user_emotions
            WHERE user_email = %s AND record_date BETWEEN %s AND %s
            ORDER BY record_date ASC
        """
        cur.execute(sql, (current_user_email, start_date, end_date))
        emotion_records = cur.fetchall()
        cur.close()

        # 5. 조회 결과 가공 (Base64 인코딩 포함)
        formatted_records = []
        for record in emotion_records:
            image_data = None
            if record['image_url']:
                try:
                    # DB에 저장된 파일명으로 절대 경로 구성
                    image_path = os.path.join(app.config['UPLOAD_FOLDER'], record['image_url'])
                    with open(image_path, 'rb') as image_file:
                        # 파일을 읽고 Base64로 인코딩
                        encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
                        
                        # 파일 확장자에 따른 Data URI 스킴 생성
                        extension = record['image_url'].rsplit('.', 1)[1].lower()
                        image_data = f"data:image/{extension};base64,{encoded_string}"

                except FileNotFoundError:
                    print(f"경고: 파일을 찾을 수 없습니다 - {record['image_url']}")
                except Exception as e:
                    print(f"경고: 이미지 처리 중 오류 발생 - {e}")

            formatted_records.append({
                "id": record['id'],
                "date": record['record_date'].strftime('%Y-%m-%d'),
                "emotion": record['emotion_type'],
                "emotionLevel": record['emotion_level'],
                "imageData": image_data # URL 대신 Base64 인코딩된 데이터
            })

        return jsonify(state="success", data=formatted_records), 200

    except Exception as e:
        return jsonify(state="error", error="서버 내부 오류가 발생했습니다.", details=str(e)), 500


# [GET] /unlocked-emotions : 해금된 감정 목록 조회
@app.route('/unlocked-emotions', methods=['GET'])
@jwt_required()
def get_unlocked_emotions():
    """
    로그인된 사용자가 현재까지 해금한 감정의 목록과 총 개수를 반환합니다.
    """
    current_user_email = get_jwt_identity()

    try:
        cur = mysql.connection.cursor()
        sql = """
            SELECT emotion_type, emotion_level
            FROM user_unlocked_emotions
            WHERE user_email = %s
            ORDER BY emotion_type ASC, emotion_level ASC
        """
        cur.execute(sql, [current_user_email])
        unlocked_records = cur.fetchall()
        cur.close()

        # 보기 좋은 형태로 가공
        formatted_records = [
            {"emotion": record['emotion_type'], "level": record['emotion_level']}
            for record in unlocked_records
        ]
        
        # 총 해금 개수와 목록을 함께 반환
        response_data = {
            "state": "success",
            "count": len(formatted_records),
            "unlocked_emotions": formatted_records
        }

        return jsonify(response_data), 200

    except Exception as e:
        return jsonify(state="error", error="서버 내부 오류가 발생했습니다.", details=str(e)), 500


# [POST] /user/representative-emotion : 대표 감정 설정
@app.route('/user/representative-emotion', methods=['POST'])
@jwt_required()
def set_representative_emotion():
    """
    로그인된 사용자의 대표 감정을 설정합니다.
    """
    current_user_email = get_jwt_identity()
    data = request.get_json()
    emotion_type = data.get('emotion_type')
    emotion_level = data.get('emotion_level')

    if not emotion_type or not emotion_level:
        return jsonify(state="error", error="emotion_type과 emotion_level은 필수입니다."), 400

    try:
        cur = mysql.connection.cursor()
        sql = """
            UPDATE users
            SET rep_emotion_type = %s, rep_emotion_level = %s
            WHERE email = %s
        """
        cur.execute(sql, (emotion_type, emotion_level, current_user_email))
        mysql.connection.commit()
        cur.close()

        return jsonify(state="success", msg="대표 감정이 성공적으로 설정되었습니다."), 200

    except Exception as e:
        return jsonify(state="error", error="서버 내부 오류가 발생했습니다.", details=str(e)), 500


# [GET] /user/representative-emotion : 대표 감정 조회
@app.route('/user/representative-emotion', methods=['GET'])
@jwt_required()
def get_representative_emotion():
    """
    로그인된 사용자의 대표 감정을 조회합니다.
    """
    current_user_email = get_jwt_identity()

    try:
        cur = mysql.connection.cursor()
        sql = """
            SELECT rep_emotion_type, rep_emotion_level
            FROM users
            WHERE email = %s
        """
        cur.execute(sql, [current_user_email])
        user = cur.fetchone()
        cur.close()

        if user and user['rep_emotion_type']:
            response_data = {
                "state": "success",
                "emotion_type": user['rep_emotion_type'],
                "emotion_level": user['rep_emotion_level']
            }
        else:
            response_data = {
                "state": "success",
                "emotion_type": None,
                "emotion_level": None,
                "msg": "대표 감정이 아직 설정되지 않았습니다."
            }

        return jsonify(response_data), 200

    except Exception as e:
        return jsonify(state="error", error="서버 내부 오류가 발생했습니다.", details=str(e)), 500




# [POST] /image : 특정 날짜의 이미지 업데이트
@app.route('/image', methods=['POST'])
@jwt_required()
def update_image():
    """
    로그인된 사용자의 특정 날짜에 해당하는 이미지를 업데이트합니다.
    해당 날짜에 감정 기록이 먼저 존재해야 합니다.
    """
    # 1. 사용자 식별 및 요청 데이터 파싱
    current_user_email = get_jwt_identity()
    record_date = request.form.get('date')
    image_file = request.files.get('image')

    # 2. 필수 데이터 검증
    if not all([record_date, image_file]):
        return jsonify(state="error", error="date와 image 파일은 필수 항목입니다."), 400

    # 3. 이미지 파일 저장
    upload_folder = app.config['UPLOAD_FOLDER']
    os.makedirs(upload_folder, exist_ok=True)
    
    filename = secure_filename(image_file.filename)
    extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    unique_filename = f"{uuid.uuid4()}.{extension}"
    
    save_path = os.path.join(upload_folder, unique_filename)
    image_file.save(save_path)
    print(f"이미지 저장 완료: {save_path}")

    try:
        # 4. 데이터베이스 업데이트
        cur = mysql.connection.cursor()
        sql = """
            UPDATE user_emotions
            SET image_url = %s
            WHERE user_email = %s AND record_date = %s
        """
        cur.execute(sql, (unique_filename, current_user_email, record_date))
        mysql.connection.commit()

        # 5. 업데이트 결과 확인
        if cur.rowcount == 0:
            # 업데이트된 행이 0개이면, 해당 날짜에 레코드가 없다는 의미
            cur.close()
            # 방금 저장한 불필요한 파일 삭제
            os.remove(save_path)
            print(f"레코드 없어 파일 삭제: {save_path}")
            return jsonify(state="error", error=f"{record_date}에 해당하는 감정 기록이 없습니다. 먼저 감정 기록을 생성해주세요."), 404

        cur.close()
        return jsonify(state="success", msg="이미지가 성공적으로 업데이트되었습니다."), 200

    except Exception as e:
        # 오류 발생 시 저장했던 파일 삭제
        if os.path.exists(save_path):
            os.remove(save_path)
        return jsonify(state="error", error="서버 내부 오류가 발생했습니다.", details=str(e)), 500


# --- 4. 앱 실행 ---
if __name__ == '__main__':
    app.run(debug=True, port=5000)
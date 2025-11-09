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
        return jsonify({"error": "Google 토큰이 없습니다."}), 400

    if not GOOGLE_CLIENT_ID:
        return jsonify({"error": "서버에 Google Client ID가 설정되지 않았습니다."}), 500

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

        return jsonify(access_token=access_token, user_email=user_identity), 200

    except ValueError as e:
        # 토큰 유효하지 않거나 만료된 경우
        return jsonify({"error": "Google 토큰이 유효하지 않습니다.", "details": str(e)}), 401
    except Exception as e:
        return jsonify({"error": "서버 내부 오류가 발생했습니다.", "details": str(e)}), 500


# [GET] /protected : *우리 앱의* JWT로 보호되는 엔드포인트
@app.route('/protected', methods=['GET'])
@jwt_required()  # 헤더의 "Bearer [우리 JWT]"를 검사
def protected():
    # 토큰이 유효하면, identity (email)를 가져옴
    current_user_email = get_jwt_identity()
    return jsonify(
        logged_in_as=current_user_email,
        message="성공! 이 API는 Google이 아닌 우리 서버의 JWT로 보호됩니다."
    ), 200


# --- 4. 앱 실행 ---
if __name__ == '__main__':
    app.run(debug=True, port=5000)
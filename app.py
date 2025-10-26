import os
from flask import Flask, jsonify, request
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

# 초기화
app = Flask(__name__)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# db 설정
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

app.config['MYSQL_CURSORCLASS'] = 'DictCursor' # 결과를 딕셔너리 형태로 받음




mysql = MySQL(app)

@app.route('/')
def home():
    return jsonify({"msg": "API 서버가 정상 동작 중입니다."})

# [POST] /register : 회원가입
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "사용자 이름과 비밀번호를 모두 입력해야 합니다."}), 400

    # 비밀번호 해싱
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        # DB에 사용자 저장
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(username, password) VALUES (%s, %s)", (username, hashed_password))
        mysql.connection.commit()
        cur.close()

    except Exception as e:
        # 중복된 사용자 이름 처리
        if '1062' in str(e):
             return jsonify({"error": "이미 존재하는 사용자 이름입니다."}), 409
        return jsonify({"error": "데이터베이스 오류: " + str(e)}), 500

    return jsonify({"msg": f"'{username}' 사용자 가입 성공!"}), 201

# [POST] /login : 로그인 및 토큰 발급
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "사용자 이름과 비밀번호를 모두 입력해야 합니다."}), 400

    # DB에서 사용자 정보 조회
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", [username])
    user = cur.fetchone()
    cur.close()

    #사용자 확인 및 비밀번호 검증
    if user and bcrypt.check_password_hash(user['password'], password):
        # 비밀번호 일치 시 토큰 생성
        # 'identity'는 토큰의 주인을 식별할 수 있는 값 (여기서는 username 사용)
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"error": "잘못된 사용자 이름 또는 비밀번호입니다."}), 401

# [GET] /protected : 인증이 필요한 보호된 라우트
@app.route('/protected', methods=['GET'])
@jwt_required()  # 이 데코레이터가 헤더에 유효한 JWT 토큰이 있는지 검사합니다.
def protected():
    # 토큰이 유효하면, 토큰에 저장된 identity(여기서는 username)를 가져올 수 있습니다.
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == '__main__':
    app.run(debug=True)
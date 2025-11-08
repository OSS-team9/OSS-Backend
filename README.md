## 🔑 API 엔드포인트

### 1. `GET /`

* **설명:** 테스트용 'Google ID 토큰 발급' HTML 페이지 (`index.html`)를 반환합니다.

* **참고:** (PythonAnywhere 등 호스팅 환경의 'Static Files' 설정을 통해 `/` 경로에 매핑됩니다.)

* **응답 (200 OK):**

    ```html
    <!-- (Google ID 토큰 발급을 위한 HTML 페이지) -->
    <!DOCTYPE html>
    <html>
    ...
    </html>
    ```

### 2. `POST /login/google`

* **설명:** Google 로그인을 처리하고 **(필요시 자동 회원가입)**, 서버 전용 JWT를 발급합니다.

* **요청 본문 (Request Body):**

    ```json
    {
      "google_token": "eyJhbGciOiJSUzI1NiIsI... (프론트에서 받은 Google ID 토큰)"
    }
    ```

* **성공 응답 (200 OK):**

    ```json
    {
      "access_token": "eyJ0eXAiOiJKV1QiLCJh... (우리 API 서버가 발급한 JWT)"
    }
    ```

* **주요 실패 응답:**
    * `400 Bad Request`: `{"error": "Google 토큰이 없습니다."}`
    * `401 Unauthorized`: `{"error": "유효하지 않은 토큰입니다."}` (토큰 검증 실패)
    * `500 Internal Server Error`: `{"error": "서버에 Google Client ID가 설정되지 않았습니다."}` (서버 환경 변수 누락)

### 3. `GET /protected`

* **설명:** 인증된 사용자만 접근할 수 있는 보호된 테스트 엔드포인트입니다.

* **필수 헤더 (Request Header):**

    ```
    Authorization: Bearer <2번에서 발급받은 access_token>
    ```

* **성공 응답 (200 OK):**

    ```json
    {
      "logged_in_as": "your_email@gmail.com"
    }
    ```

* **주요 실패 응답:**
    * `401 Unauthorized`: `{"msg": "Missing Authorization Header"}` (헤더가 없는 경우)
    * `401 Unauthorized`: `{"msg": "Token has expired"}` (토큰이 만료된 경우)
    * `422 Unprocessable Entity`: `{"msg": "Invalid header format. Use 'Bearer <token>'"}` (형식이 잘못된 경우)

import os
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from fastapi import HTTPException, status

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

def exchange_code_for_tokens(code: str, redirect_uri: str):
    """使用授權碼向 Google 換取存取權杖和 ID 權杖"""
    import requests

    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    response = requests.post(GOOGLE_TOKEN_URL, data=data)
    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="無法從 Google 換取 Token"
        )
    return response.json()

def verify_google_id_token(token: str):
    """驗證從前端或 Postman 傳來的 Google ID Token"""
    try:
        # 這裡會去向 Google 的伺服器驗證 token 是否合法、過期
        idinfo = id_token.verify_oauth2_token(
            token, google_requests.Request(), GOOGLE_CLIENT_ID
        )
        # 返回 Google 使用者資訊 (email, name, sub...)
        return idinfo
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="無效的 Google Token"
        )
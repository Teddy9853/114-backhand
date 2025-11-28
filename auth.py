from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI()
fake_users_db = {
    "Alice": {"username": "Alice", "password": "secret123"},
}

SECCRET_KEY = "super secret key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECCRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    
#    credentials_exception = HTTPException(
#        status_code=status.HTTP_401_UNAUTHORIZED,
#        detail="Could not validate credentials",
#        headers={"WWW-Authenticate": "Bearer"},
#    )
    try:
        payload = jwt.decode(token, SECCRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), Response=None):
    user = fake_users_db.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    #access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    #access_token = create_access_token(
    #    data={"sub": user["username"]}, expires_delta=access_token_expires)
    access_token = create_access_token(data={"sub": user["username"]})
    Response.set_cookie(key = "jwt", value = access_token, httponly = True, samesite = "lax")

    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me")
async def me(token: Optional[str] = Depends(oauth2_scheme), jwt_cookie: Optional[str] = Cookie(None)):
    if token:
        username = verify_token(token)
    elif jwt_cookie:
        username = verify_token(jwt_cookie)
    else:
        raise HTTPException(status_code=401, detail="Missing token or cookie")
    
    return {"message": "Hello, {username}! You are authenticated."}
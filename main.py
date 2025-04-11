from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional

app = FastAPI()
security = HTTPBearer()

# Конфигурация JWT
SECRET_KEY = "your-secret-key-here"  # В продакшене используйте надёжный ключ!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Фиксированные тестовые пользователи (для стабильного тестирования)
TEST_USERS = {
    "john_doe": "securepassword123",
    "alice": "wonderland"
}

class LoginRequest(BaseModel):
    username: str
    password: str

def authenticate_user(username: str, password: str) -> bool:
    # Теперь проверяем реальные учётные данные
    return TEST_USERS.get(username) == password

def create_access_token(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {
        "sub": username,
        "exp": expire
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"}
            )
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"}
        )

@app.post("/login")
async def login(login_data: LoginRequest):
    if not authenticate_user(login_data.username, login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    access_token = create_access_token(login_data.username)
    return {"access_token": access_token}

@app.get("/protected_resource")
async def protected_route(username: str = Depends(verify_token)):
    return {
        "message": f"Доступ разрешён для пользователя {username}!",
        "status": "success"
    }
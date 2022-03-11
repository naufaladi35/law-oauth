from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status, Form, Request, Response
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from uuid import uuid4

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 5

fake_db = {
    "naufaladi": {
        "username": "naufaladi",
        "password": "secretpassword",
        "full_name": "Naufal Wijanarko",
        "npm": "1906305871",
        "grant_type": "password",
        "client_id": "190630",
        "client_secret": "5871",
    },
}

session_storage = []

app = FastAPI()


class User(BaseModel):
    username: str = Field(..., max_length=50)
    password: str = Field(..., max_length=50)
    grant_type: str = Field(..., max_length=50)
    client_id: str = Field(..., max_length=50)
    client_secret: str = Field(..., max_length=50)


class Token(BaseModel):
    username: str
    access_token: str
    refresh_token: str
    timestamp: datetime
    expires_in: int


app = FastAPI()


def generate_token():
    token = "1984" + uuid4().hex + "1984"
    return token


def store_token(new_token: Token, storage: list):
    for token in storage:
        if token.username == new_token.username:
            storage.remove(token)
    storage.append(new_token)


def get_token_object(token_string, storage):
    token_object: Token = None
    if token_string is None:
        return False
    for token in storage:
        if token.access_token == token_string:
            token_object = token
    if token_object == None:
        return False
    token_age = (datetime.now() - token_object.timestamp).total_seconds()
    if token_age > 300:
        return False
    else:
        return token


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return User(**user_dict)


def authenticate_user(fake_db: dict, form_user: User):
    user = get_user(fake_db, form_user.username)
    if not user:
        return False
    if not (user.password == form_user.password and user.client_id == form_user.client_id and user.client_secret == form_user.client_secret):
        return False
    return user


@app.post("/oauth/token")
async def login_for_access_token(
    username: str = Form(...),
    password: str = Form(...),
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
):
    form_data = User(
        username=username,
        password=password,
        grant_type=grant_type,
        client_id=client_id,
        client_secret=client_secret
    )
    user = authenticate_user(
        fake_db, form_data)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    timestamp = datetime.now()
    access_token_expires = timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES).total_seconds()
    access_token = generate_token()
    refresh_token = generate_token()
    new_Token = Token(
        username=user.username,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=access_token_expires,
        timestamp=timestamp
    )
    store_token(new_Token, session_storage)

    respone = {
        "access_token": access_token,
        "expires_in": access_token_expires,
        "token_type": "Bearer",
        "scope": None,
        "refresh_token": refresh_token
    }

    return respone


@app.get("/session-storage")
async def get_session_storage():
    return session_storage


@app.post("/oauth/resource/")
async def resource(request: Request, response: Response):
    auth_header = request.headers.get("Authorization")
    if auth_header is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    auth_header = auth_header.split(" ")
    if auth_header[0] is None or auth_header[0].lower() != "bearer" or len(auth_header) != 2:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = get_token_object(auth_header[1], session_storage)
    if token:
        user = fake_db[token.username]
        if user:
            response = {
                "access_token": token.access_token,
                "client_id": user['client_id'],
                "user_id": user['username'],
                "full_name": user['full_name'],
                "npm": user['npm'],
                "expires": timedelta(minutes=5).total_seconds() - (datetime.now() - token.timestamp).total_seconds(),
                "refresh_token": token.refresh_token
            }
            return response
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Bearer token expired",
        headers={"WWW-Authenticate": "Bearer"},
    )

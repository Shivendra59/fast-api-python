from datetime import timedelta
from typing import List
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from passlib.context import CryptContext
from pydantic import BaseSettings
from sqlalchemy.orm import Session

import models
from database import SessionLocal, engine
from schemas import CreateToken, User, UserCreate, UserUpdate

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()
models.Base.metadata.create_all(bind=engine)



def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class Settings(BaseSettings):
    authjwt_secret_key: str = "ca370c3bdb0b8690c5228fc4d84ae3dd6cfcb1e4"


@AuthJWT.load_config
def get_config():
    return Settings()


@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    status_code = 401
    detail = "Authentication error"
    if "Missing" in str(exc):
        detail = "Missing JWT token"
    elif "Expired" in str(exc):
        detail = "JWT token has expired"
    elif "Invalid" in str(exc):
        detail = "Invalid JWT token"
    return JSONResponse(status_code=status_code, content={"detail": detail})


def get_current_user_role(db: Session = Depends(get_db), Authorize: AuthJWT = Depends()) -> str:
    try:
        Authorize.jwt_required()
        current_user_email = Authorize.get_jwt_subject()
        if current_user_email is None:
            raise HTTPException(status_code=401, detail="token is missing")
        user = (db.query(models.Users).filter(models.Users.email == current_user_email).first())
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        role = getattr(user, "role")
        return role
    except AuthJWTException as e:
        print("error")
        raise HTTPException(status_code=401, detail=str(e))
    
class RoleChecker:
    def __init__(self, allowed_roles: List):
        self.allowed_roles = allowed_roles

    def __call__(self, role: str = Depends(get_current_user_role)):
        if role not in self.allowed_roles:
            print(f"User with role {role} not in {self.allowed_roles}")
            raise HTTPException(status_code=403, detail="Operation not permitted")
        

@app.post("/users/", response_model=User)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = models.Users(
        email=user.email,
        username=user.username,
        password=user.password,
        role=user.role.value,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.post("/login")
def login(user: CreateToken, Authorize: AuthJWT = Depends(), db: Session = Depends(get_db)):
    user_data = db.query(models.Users).filter(models.Users.email == user.email).first()
    if user_data is None or not pwd_context.verify(user.password, str(user_data.password)):
        raise HTTPException(status_code=401, detail="Bad username or password")
    access_token = Authorize.create_access_token(subject=user.email, expires_time=timedelta(minutes=30))
    refresh_token = Authorize.create_refresh_token(
        subject=user.email, expires_time=timedelta(days=1)
    )
    return {"access_token": access_token, "refresh_token": {refresh_token}}


@app.post("/refresh")
def refresh(Authorize: AuthJWT = Depends(), db: Session = Depends(get_db)):
    Authorize.jwt_refresh_token_required()
    current_user_email = Authorize.get_jwt_subject()
    if current_user_email is not None:
        user = (db.query(models.Users).filter(models.Users.email == current_user_email).first())
        if user:
            new_access_token = Authorize.create_access_token(subject=current_user_email, expires_time=timedelta(minutes=5))
            return {"access_token": new_access_token}
        else:
            raise HTTPException(status_code=401, detail="User not found")
    else:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.delete("/user/{user_id}", dependencies=[Depends(RoleChecker([models.Role.ADMIN.value]))])
def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(models.Users).filter(models.Users.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}


@app.put("/user/{user_id}", dependencies=[Depends(RoleChecker([models.Role.MANAGER.value]))])
def update_user(user_id: int, user_update: UserUpdate, db: Session = Depends(get_db)):
    user = db.query(models.Users).filter(models.Users.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    setattr(user, 'username', user_update.username)
    db.commit()
    return {"message": "User updated successfully"}


@app.get("/user/{user_id}", dependencies=[Depends(RoleChecker([models.Role.HR.value]))])
def get_user_details(user_id : int, db: Session = Depends(get_db)):
    user = db.query(models.Users).filter(models.Users.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return {"username": user.username, "role": user.role}
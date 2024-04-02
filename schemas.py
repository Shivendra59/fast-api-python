from pydantic import BaseModel, EmailStr
from models import Role

class UserCreate(BaseModel):
    email : EmailStr
    username: str
    password: str
    role: Role

class User(BaseModel):
    id: int
    class Config:
        orm_mode = True

class CreateToken(BaseModel):
    email : str
    password : str

class UserUpdate(BaseModel):
    username: str    
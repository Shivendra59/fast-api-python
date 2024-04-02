from enum import Enum
from sqlalchemy import Boolean, Column, Integer, String
from database import Base
from sqlalchemy.orm import validates
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Role(Enum):
    ADMIN = "Admin"
    MANAGER = "Manager"
    HR = "Human Resource"

class Users(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True)
    username = Column(String)
    password = Column(String)
    role = Column(String)

    @validates('password')
    def validate_password(self, key, password):
        return pwd_context.hash(password)
    
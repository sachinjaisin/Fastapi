from sqlalchemy import Column, Integer, String, TIMESTAMP,text,Boolean,JSON, ForeignKey, Table,Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from database import Base
import uuid
from sqlalchemy.dialects.mysql import CHAR
# Many-to-Many Table for Security Questions
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

user_security_questions = Table(
    "user_security_questions",
    Base.metadata,
    Column("user_id", String, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("question_id", String, ForeignKey("security_questions.id", ondelete="CASCADE"), primary_key=True),
    Column("answer", String, nullable=False),  # Encrypted answer
    schema="risk"
)

class SecurityQuestion(Base):
    __tablename__ = "security_questions"

    id = Column(CHAR(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    question = Column(String, nullable=False, unique=True)
    created_at = Column(TIMESTAMP(timezone=True), server_default=text('now()'))

class User(Base):
    __tablename__ = "users"

    id = Column(CHAR(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    phone_number = Column(String,nullable=True)  
    otp = Column(String,nullable=True)  
    otp_verified = Column(Boolean,default=False)  
    answer_verified = Column(Boolean,default=False)
    pan_number = Column(String, nullable=True)  
    dob = Column(TIMESTAMP(timezone=True), nullable=True)  
    nationality = Column(String, nullable=True)  
    token=Column(Text,nullable=True)
    profile_image = Column(String, nullable=True)  
    created_at = Column(TIMESTAMP(timezone=True), server_default=text('now()'))
    updated_at = Column(TIMESTAMP(timezone=True), server_default=text('now()')) 

    # Many-to-Many Relationship with Security Questions
    security_questions = relationship("SecurityQuestion", secondary=user_security_questions, backref="users")

from pydantic import BaseModel, EmailStr,field_serializer,Field,validator
from datetime import datetime
from typing import Optional, List
from fastapi import UploadFile

class UserBase(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone_number: str
    pan_number: str
    dob: Optional[datetime] = None
    nationality: Optional[str] = None
    profile_image: Optional[str] = None

class UserSignup(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    confirm_password: str

    
class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str  # UUID stored as CHAR(36)
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: EmailStr
    phone_number: Optional[str] = None
    pan_number: Optional[str] = None
    dob: Optional[datetime] = None
    nationality: Optional[str] = None
    profile_image: Optional[str] = None
    token: Optional[str] = None  
    created_at: datetime
    updated_at: datetime
    
    @field_serializer("created_at", "updated_at", "dob", mode="plain")
    def serialize_datetime(value: Optional[datetime]) -> Optional[str]:
        return value.isoformat() if value else None
    class Config:
        from_attributes = True 

class SecurityQuestionCreate(BaseModel):
    question: str

# Response Schema for returning security questions
class SecurityQuestionResponse(BaseModel):
    id: str
    question: str
    created_at:datetime
    
    @field_serializer("created_at")
    def serialize_datetime(value: Optional[datetime]) -> Optional[str]:
        return value.isoformat() if value else None
    class Config:
        from_attributes = True  # Allows ORM conversion

# Request Schema for submitting security question answers
class UserSecurityQuestionAnswer(BaseModel):
    question_id: str
    answer: str  # Will be encrypted before saving

# Request Schema for bulk submission of answers
class UserSecurityQuestionsSubmit(BaseModel):
    email: EmailStr
    answers: List[UserSecurityQuestionAnswer]


class ChangePasswordRequest(BaseModel):
    old_password: str 
    new_password: str 
    confirm_password: str 
    

class ResetPasswordRequest(BaseModel):
    email: str
    new_password: str
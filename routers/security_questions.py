from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from models import SecurityQuestion, User, user_security_questions
from database import get_db
from typing import List
import uuid
from auth import *
from schemas import *
from routers.users import format_response
from sqlalchemy.sql import text

router = APIRouter()


@router.get("/", response_model=List[SecurityQuestionResponse])
def get_security_questions(db: Session = Depends(get_db)):
    questions = db.query(SecurityQuestion).all()
    return format_response(
        status="success",
        message="Security questions fetched successfully",
        results=[SecurityQuestionResponse.from_orm(q) for q in questions]
    )


@router.post("/", response_model=SecurityQuestionResponse)
def create_security_question(question_data: SecurityQuestionCreate, db: Session = Depends(get_db)):
    existing_question = db.query(SecurityQuestion).filter(SecurityQuestion.question == question_data.question).first()
    if existing_question:
        return format_response(
            status="error",
            message="Question already exists",
            status_code=400
        )

    new_question = SecurityQuestion(question=question_data.question)
    db.add(new_question)
    db.commit()
    db.refresh(new_question)
    return format_response(
        status="success",
        message="Security question added successfully",
        results=SecurityQuestionResponse.from_orm(new_question)
    )

@router.post("/verify_answers")
def verify_security_answers(
    verify_data: UserSecurityQuestionsSubmit,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == verify_data.email).first()
    if not user:
        return format_response(
            status="error",
            message="User not found",
            status_code=400
        )

    for answer_data in verify_data.answers:
        encrypted_answer = hashlib.sha256(answer_data.answer.encode()).hexdigest()

        query = db.execute(
            text(
                """
                SELECT * FROM risk.user_security_questions
                WHERE user_id = :user_id AND question_id = :question_id AND answer = :encrypted_answer
                """
            ),
            {"user_id": user.id, "question_id": answer_data.question_id, "encrypted_answer": encrypted_answer}
        ).fetchone()

        if query:
            user.answer_verified = True
            db.commit()

            return format_response(
                status="success",
                message="Security answers verified successfully.",
            )
    return format_response(
            status="error",
            message="All answers are incorrect.",
            status_code=400
        )
  

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv
import os

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")  # From .env file

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class CustomBase(declarative_base()):
    __abstract__ = True
    __table_args__ = {"schema": "risk"}

Base = CustomBase  

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

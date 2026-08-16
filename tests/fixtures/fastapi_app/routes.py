from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

router = APIRouter(prefix="/books")


class BookCreate(BaseModel):
    title: str = Field(..., min_length=2, max_length=120)
    author_id: int = Field(..., ge=1)
    access_token: str | None = None


def get_current_user():
    raise NotImplementedError


@router.post("/")
def create_book(payload: BookCreate, user=Depends(get_current_user)):
    return payload


@router.get("/{book_id}")
def read_book(book_id: int):
    return {"id": book_id}

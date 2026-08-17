from enum import Enum
from typing import Annotated, Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Path, Query, status
from pydantic import BaseModel, EmailStr, Field

router = APIRouter(prefix="/books")


class Genre(str, Enum):
    FICTION = "fiction"
    REFERENCE = "reference"


class AuthorRef(BaseModel):
    author_id: int = Field(..., ge=1)


class BookBase(BaseModel):
    title: str = Field(..., min_length=2, max_length=120)


class BookCreate(BookBase):
    author_id: int = Field(..., ge=1)
    access_token: str | None = None
    contact_email: EmailStr
    tags: list[str]
    genre: Genre
    format: Literal["hardcover", "paperback"]
    nested: AuthorRef
    notes: Annotated[str, Field(min_length=1, max_length=40)]


class BookOut(BaseModel):
    id: UUID
    title: str


def get_current_user():
    raise NotImplementedError


@router.post("/", response_model=BookOut, status_code=status.HTTP_201_CREATED)
def create_book(payload: BookCreate, user=Depends(get_current_user)):
    return payload


@router.get("/{book_id}")
def read_book(
    book_id: int = Path(..., ge=1),
    q: Optional[str] = Query(None),
    x_request_id: str = Header(None),
):
    return {"id": book_id}

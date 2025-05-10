from pydantic import BaseModel, EmailStr, Field, validator
from datetime import datetime
import re
import bleach

class UserBusiness(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Company name")
    email: EmailStr = Field(..., description="Valid email address")
    phone: str = Field(..., min_length=7, max_length=20, description="Phone number")
    hq: str = Field(..., min_length=1, max_length=50, description="Headquarters location")
    operations: str = Field(..., min_length=1, max_length=225, description="Business operations")
    website: str = Field(..., min_length=1, max_length=50, description="Company website")
    details: str = Field(..., min_length=1, max_length=225, description="Business details")

    @validator("phone")
    def validate_phone(cls, v):
        # Basic phone number regex (allows + and digits, optional spaces/hyphens)
        if not re.match(r"^\+?[\d\s-]{7,20}$", v):
            raise ValueError("Invalid phone number format")
        return v

    @validator("website")
    def validate_website(cls, v):
        # Basic URL regex
        if not re.match(r"^(https?://)?[\w.-]+\.[a-zA-Z]{2,}(/.*)?$", v):
            raise ValueError("Invalid website URL")
        return v
    
    @validator("details", "operations")
    def sanitize_text(cls, v):
        return bleach.clean(v)

class Business(BaseModel):
    id: int
    company_name: str
    email: EmailStr

class OTPGenerateRequest(BaseModel):
    email: EmailStr = Field(..., description="Valid email address")

class OTPGenerateResponse(BaseModel):
    email: EmailStr
    otp: str
    expires_at: datetime

class OTPVerifyRequest(BaseModel):
    email: EmailStr = Field(..., description="Valid email address")
    otp: str = Field(..., min_length=6, max_length=6, description="6-digit OTP")

class OTPVerifyResponse(BaseModel):
    email: EmailStr
    valid: bool
    message: str

class UserCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="User name")
    email: EmailStr = Field(..., description="Valid email address")
    phone: str = Field(..., min_length=7, max_length=20, description="Phone number")
    password: str = Field(..., min_length=8, max_length=128, description="Password")
    company_id: int = Field(..., gt=0, description="Valid company ID")
    role: str = Field(..., min_length=1, max_length=50, description="User role")

    @validator("phone")
    def validate_phone(cls, v):
        if not re.match(r"^\+?[\d\s-]{7,20}$", v):
            raise ValueError("Invalid phone number format")
        return v

    @validator("password")
    def validate_password(cls, v):
        # Ensure password has at least one letter and one number
        if not re.search(r"[A-Za-z]", v) or not re.search(r"\d", v):
            raise ValueError("Password must contain at least one letter and one number")
        return v

class User(BaseModel):
    id: int
    name: str
    email: EmailStr
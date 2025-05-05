from pydantic import BaseModel, EmailStr
from datetime import datetime

#Business profile input
class UserBusiness(BaseModel):
    name: str #need to be company name
    email: EmailStr
    phone: str
    hq: str
    operations: str
    website: str
    details: str


# output after busines profile creation
class Business(BaseModel):
    id: int
    company_name: str
    email: EmailStr

#Generate OTP Request
class OTPGenerateRequest(BaseModel):
    email: EmailStr

#Generate OTP Response
class OTPGenerateResponse(BaseModel):
    email: EmailStr
    otp: str
    expires_at: datetime

#Verify OTP Request
class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp: str

#Verify OTP Response
class OTPVerifyResponse(BaseModel):
    email: EmailStr
    valid: bool
    message: str

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    phone: str
    password: str
    company_id: int
    role: str

class User(BaseModel):
    id: int
    name: str
    email: str
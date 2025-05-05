from fastapi import FastAPI, HTTPException
from schemas import UserBusiness,Business, OTPGenerateRequest, OTPGenerateResponse, OTPVerifyRequest, OTPVerifyResponse, User, UserCreate
from database import get_db_connection
import psycopg2
import random
import string
from datetime import datetime, timedelta
from passlib.context import CryptContext

app = FastAPI()

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Generate a 6-digit OTP
def generate_otp_code(length=6):
    return ''.join(random.choices(string.digits, k=length))



#create Business profile
@app.post("/Business/", response_model=Business)
def create_business_profile(business: UserBusiness):
    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO Business (company_name, Email, Phone, HQ, Operations, Website, Details) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id, company_name, email",
                    (business.name, business.email, business.phone, business.hq, business.operations, business.website, business.details)
                )
                new_user = cur.fetchone()
                if not new_user:
                    raise HTTPException(status_code=400, detail="Business creation failed")
                return new_user
    except psycopg2.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already exists")
    finally:
        conn.close() 

@app.post("/generate-otp/", response_model=OTPGenerateResponse)
def generate_otp(request: OTPGenerateRequest):
    otp = generate_otp_code()
    expires_at = datetime.utcnow() + timedelta(minutes=5)
    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor() as cur:
                # Delete any existing OTP for this email
                cur.execute("DELETE FROM otps WHERE email = %s", (request.email,))
                # Insert new OTP
                cur.execute(
                    "INSERT INTO otps (email, otp, expires_at) VALUES (%s, %s, %s) RETURNING email, otp, expires_at",
                    (request.email, otp, expires_at)
                )
                result = cur.fetchone()
                if not result:
                    raise HTTPException(status_code=500, detail="Failed to generate OTP")
                return result
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        conn.close()

# Verify OTP endpoint
@app.post("/verify-otp/", response_model=OTPVerifyResponse)  
def verify_otp(request: OTPVerifyRequest):
    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT otp, expires_at FROM otps WHERE email = %s",
                    (request.email,)
                )
                result = cur.fetchone()
                if not result:
                    return OTPVerifyResponse(
                        email=request.email,
                        valid=False,
                        message="No OTP found for this email"
                    )
                
                stored_otp = result['otp']
                expires_at = result['expires_at']
                
                # Check if OTP has expired
                if datetime.utcnow() > expires_at:
                    return OTPVerifyResponse(
                        email=request.email,
                        valid=False,
                        message="OTP has expired"
                    )
                
                # Verify OTP
                if request.otp == stored_otp:
                    # Delete OTP after successful verification
                    cur.execute("DELETE FROM otps WHERE email = %s", (request.email,))
                    return OTPVerifyResponse(
                        email=request.email,
                        valid=True,
                        message="OTP verified successfully"
                    )
                else:
                    return OTPVerifyResponse(
                        email=request.email,
                        valid=False,
                        message="Invalid OTP"
                    )
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        conn.close() 

# Create User API
@app.post("/users/", response_model=User) # need to hash the password.
def create_user(user: UserCreate):
    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor() as cur:
                hashed_password = pwd_context.hash(user.password)
                cur.execute(
                    "INSERT INTO users (name, Email, Phone, Password, Role, Company_id) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id, name, Email",
                    (user.name, user.email, user.phone, hashed_password, user.role, user.company_id)
                )
                new_user = cur.fetchone()
                if not new_user:
                    raise HTTPException(status_code=400, detail="User creation failed")
                return new_user
    except psycopg2.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already exists")
    finally:
        conn.close()


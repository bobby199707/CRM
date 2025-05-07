from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.responses import JSONResponse
from app.schemas import UserBusiness,Business, OTPGenerateRequest, OTPGenerateResponse, OTPVerifyRequest, OTPVerifyResponse, User, UserCreate
from app.database import get_db_connection
import psycopg2
from psycopg2.extras import RealDictCursor
import random
import string
from datetime import datetime, timedelta
from passlib.context import CryptContext
import redis.asyncio as redis
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
import asyncio
import logging
from pydantic import ValidationError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Custom exception handlers
@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    logger.error(f"Validation error: {exc.errors()}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors()}
    )

@app.exception_handler(redis.ConnectionError)
async def redis_connection_exception_handler(request: Request, exc: redis.ConnectionError):
    logger.error(f"Redis connection error: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": "Failed to connect to Redis. Please try again later."}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unexpected error: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected error occurred. Please try again later."}
    )

def get_db():
    conn = get_db_connection()
    try:
        yield conn
    finally:
        conn.close()

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Generate a 6-digit OTP
def generate_otp_code(length=6):
    return ''.join(random.choices(string.digits, k=length))

# Initialize FastAPI-Limiter on app startup
@app.on_event("startup")
async def startup():
    max_retries = 5
    retry_delay = 2  # seconds
    for attempt in range(max_retries):
        try:
            redis_connection = redis.from_url("redis://:Alpha_1997@redis:6379", encoding="utf-8", decode_responses=True)
            await redis_connection.ping()  # Test connection
            await FastAPILimiter.init(redis_connection)
            print("Successfully connected to Redis")
            return
        except redis.ConnectionError as e:
            print(f"Redis connection attempt {attempt + 1} failed: {str(e)}")
            if attempt == max_retries - 1:
                raise HTTPException(status_code=500, detail="Failed to connect to Redis after multiple attempts")
            await asyncio.sleep(retry_delay)



#create Business profile
@app.post("/Business/", response_model=Business)
def create_business_profile(business: UserBusiness, conn=Depends(get_db)):
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "INSERT INTO Business (company_name, email, phone, hq, operations, website, details) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id, company_name, email",
                (business.name, business.email, business.phone, business.hq, business.operations, business.website, business.details)
            )
            new_business = cur.fetchone()
            if not new_business:
                logger.error("Business creation failed: No record returned")
                raise HTTPException(status_code=400, detail="Business creation failed")
            conn.commit()
            logger.info(f"Created business: {new_business['email']}")
            return new_business
    except psycopg2.IntegrityError as e:
        conn.rollback()
        logger.warning(f"Duplicate email: {business.email}")
        raise HTTPException(status_code=400, detail="Email already exists")
    except psycopg2.Error as e:
        conn.rollback()
        logger.error(f"Database error in create_business_profile: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

#Generate OTP
@app.post("/generate-otp/", response_model=OTPGenerateResponse, dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def generate_otp(request: OTPGenerateRequest, conn=Depends(get_db)):
    try:
        # Check if email exists in Business table
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id FROM Business WHERE email = %s", (request.email,))
            if not cur.fetchone():
                logger.warning(f"Email not found for OTP generation: {request.email}")
                raise HTTPException(status_code=404, detail="Email not associated with a business")

            otp = generate_otp_code()
            expires_at = datetime.utcnow() + timedelta(minutes=5)

            # Delete any existing OTP for this email
            cur.execute("DELETE FROM otps WHERE email = %s", (request.email,))
            # Insert new OTP
            cur.execute(
                "INSERT INTO otps (email, otp, expires_at) VALUES (%s, %s, %s) RETURNING email, otp, expires_at",
                (request.email, otp, expires_at)
            )
            result = cur.fetchone()
            if not result:
                logger.error("OTP generation failed: No record returned")
                raise HTTPException(status_code=500, detail="Failed to generate OTP")
            conn.commit()
            logger.info(f"Generated OTP for: {request.email}")
            return result
    except psycopg2.Error as e:
        conn.rollback()
        logger.error(f"Database error in generate_otp: {str(e)}")
        raise HTTPException(status_code=500, detail="Database error occurred")

# Verify OTP endpoint
@app.post("/verify-otp/", response_model=OTPVerifyResponse, dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def verify_otp(request: OTPVerifyRequest, conn=Depends(get_db)):
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Check if OTP exists and is valid
            cur.execute(
                "SELECT otp, expires_at FROM otps WHERE email = %s",
                (request.email,)
            )
            result = cur.fetchone()
            if not result:
                logger.warning(f"No OTP found for: {request.email}")
                return OTPVerifyResponse(
                    email=request.email,
                    valid=False,
                    message="No OTP found for this email"
                )

            stored_otp = result['otp']
            expires_at = result['expires_at']

            # Check if OTP has expired
            if datetime.utcnow() > expires_at:
                logger.warning(f"Expired OTP for: {request.email}")
                return OTPVerifyResponse(
                    email=request.email,
                    valid=False,
                    message="OTP has expired"
                )

            # Verify OTP
            if request.otp == stored_otp:
                # Delete OTP after successful verification
                cur.execute("DELETE FROM otps WHERE email = %s", (request.email,))
                # Mark business as verified
                cur.execute(
                    "UPDATE Business SET verified = TRUE WHERE email = %s RETURNING id",
                    (request.email,)
                )
                updated = cur.fetchone()
                if not updated:
                    logger.warning(f"No business found for: {request.email}")
                    return OTPVerifyResponse(
                        email=request.email,
                        valid=False,
                        message="No business found with this email"
                    )
                conn.commit()
                logger.info(f"OTP verified for: {request.email}")
                return OTPVerifyResponse(
                    email=request.email,
                    valid=True,
                    message="OTP verified successfully"
                )
            else:
                logger.warning(f"Invalid OTP for: {request.email}")
                return OTPVerifyResponse(
                    email=request.email,
                    valid=False,
                    message="Invalid OTP"
                )
    except psycopg2.Error as e:
        conn.rollback()
        logger.error(f"Database error in verify_otp: {str(e)}")
        raise HTTPException(status_code=500, detail="Database error occurred")

# Create User API
@app.post("/users/", response_model=User)
def create_user(user: UserCreate, conn=Depends(get_db)):
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Verify company_id exists
            cur.execute("SELECT id FROM Business WHERE id = %s", (user.company_id,))
            if not cur.fetchone():
                logger.warning(f"Invalid company_id: {user.company_id}")
                raise HTTPException(status_code=400, detail="Invalid company ID")

            hashed_password = pwd_context.hash(user.password)
            cur.execute(
                "INSERT INTO users (name, email, phone, password, role, company_id) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id, name, email",
                (user.name, user.email, user.phone, hashed_password, user.role, user.company_id)
            )
            new_user = cur.fetchone()
            if not new_user:
                logger.error("User creation failed: No record returned")
                raise HTTPException(status_code=400, detail="User creation failed")
            conn.commit()
            logger.info(f"Created user: {new_user['email']}")
            return new_user
    except psycopg2.IntegrityError as e:
        conn.rollback()
        logger.warning(f"Duplicate email: {user.email}")
        raise HTTPException(status_code=400, detail="Email already exists")
    except psycopg2.Error as e:
        conn.rollback()
        logger.error(f"Database error in create_user: {str(e)}")
        raise HTTPException(status_code=500, detail="Database error occurred")
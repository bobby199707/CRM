from fastapi import FastAPI, HTTPException, Depends, Request, status, Response
from fastapi.responses import JSONResponse
from app.schemas import UserBusiness,Business, OTPGenerateRequest, OTPGenerateResponse, OTPVerifyRequest, OTPVerifyResponse, User, UserCreate
from app.database import get_db, init_db_pool, close_db_pool
import asyncpg
import random
import string
import uuid
from datetime import datetime, timedelta
from passlib.context import CryptContext
import redis.asyncio as redis
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
import asyncio
import logging
from pydantic import ValidationError
from fastapi.security import OAuth2PasswordRequestForm

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()
# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Redis client for session storage
redis_client = redis.from_url("redis://:Alpha_1997@redis:6379", encoding="utf-8", decode_responses=True)

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

@app.exception_handler(asyncpg.PostgresError)
async def postgres_exception_handler(request: Request, exc: asyncpg.PostgresError):
    logger.error(f"Database error: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Database error occurred"}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unexpected error: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected error occurred. Please try again later."}
    )

# Dependency for database connection
async def get_db_conn():
    async for conn in get_db():
        yield conn

# Dependency for authenticated user
async def get_current_user(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_data = await redis_client.get(f"session:{session_id}")
    if not user_data:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    # In a real app, parse user_data (e.g., JSON) and return user object
    return {"email": user_data}

# Generate a 6-digit OTP
def generate_otp_code(length=6):
    return ''.join(random.choices(string.digits, k=length))

# Initialize FastAPI-Limiter and database pool on app startup
@app.on_event("startup")
async def startup():
    await init_db_pool()
    max_retries = 5
    retry_delay = 2
    for attempt in range(max_retries):
        try:
            await redis_client.ping()
            await FastAPILimiter.init(redis_client)
            logger.info("Successfully connected to Redis")
            return
        except redis.ConnectionError as e:
            logger.warning(f"Redis connection attempt {attempt + 1} failed: {str(e)}")
            if attempt == max_retries - 1:
                raise HTTPException(status_code=500, detail="Failed to connect to Redis after multiple attempts")
            await asyncio.sleep(retry_delay)

@app.on_event("shutdown")
async def shutdown():
    await close_db_pool()

# Create Business profile
@app.post("/Business/", response_model=Business)
async def create_business_profile(business: UserBusiness, conn=Depends(get_db_conn)):
    try:
        # Insert business
        result = await conn.fetch(
            "INSERT INTO Business (company_name, email, phone, hq, operations, website, details) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, company_name, email",
            business.name, business.email, business.phone, business.hq, business.operations, business.website, business.details
        )
        if not result:
            logger.error("Business creation failed: No record returned")
            raise HTTPException(status_code=400, detail="Business creation failed")
        new_business = dict(result[0])
        logger.info(f"Created business: {new_business['email']}")
        return new_business
    except asyncpg.UniqueViolationError as e:
        logger.warning(f"Duplicate email: {business.email}")
        raise HTTPException(status_code=400, detail="Email already exists")
    except asyncpg.PostgresError as e:
        logger.error(f"Database error in create_business_profile: {str(e)}")
        raise HTTPException(status_code=500, detail="Database error occurred")

# Generate OTP with rate-limiting (5 requests per minute per client IP)
@app.post("/generate-otp/", response_model=OTPGenerateResponse, dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def generate_otp(request: OTPGenerateRequest, conn=Depends(get_db_conn)):
    try:
        # Check if email exists in Business table
        result = await conn.fetch("SELECT id FROM Business WHERE email = $1", request.email)
        if not result:
            logger.warning(f"Email not found for OTP generation: {request.email}")
            raise HTTPException(status_code=404, detail="Email not associated with a business")

        otp = generate_otp_code()
        hashed_otp = pwd_context.hash(otp)
        expires_at = datetime.utcnow() + timedelta(minutes=5)

        # Delete any existing OTP for this email
        await conn.execute("DELETE FROM otps WHERE email = $1", request.email)
        # Insert new OTP
        result = await conn.fetch(
            "INSERT INTO otps (email, otp, expires_at) VALUES ($1, $2, $3) RETURNING email, expires_at",
            request.email, hashed_otp, expires_at
        )
        if not result:
            logger.error("OTP generation failed: No record returned")
            raise HTTPException(status_code=500, detail="Failed to generate OTP")
        result_dict = dict(result[0])
        logger.info(f"Generated OTP for: {request.email}")
        # Return plain OTP in response (not hashed)
        return OTPGenerateResponse(email=result_dict["email"], otp=otp, expires_at=result_dict["expires_at"])
    except asyncpg.PostgresError as e:
        logger.error(f"Database error in generate_otp: {str(e)}")
        raise HTTPException(status_code=500, detail="Database error occurred")

# Verify OTP with rate-limiting (10 requests per minute per client IP)
@app.post("/verify-otp/", response_model=OTPVerifyResponse, dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def verify_otp(request: OTPVerifyRequest, conn=Depends(get_db_conn), response: Response = None):
    try:
        result = await conn.fetch("SELECT otp, expires_at FROM otps WHERE email = $1", request.email)
        if not result:
            logger.warning(f"No OTP found for: {request.email}")
            return OTPVerifyResponse(
                email=request.email,
                valid=False,
                message="No OTP found for this email"
            )

        stored_otp = result[0]["otp"]
        expires_at = result[0]["expires_at"]

        if datetime.utcnow() > expires_at:
            logger.warning(f"Expired OTP for: {request.email}")
            return OTPVerifyResponse(
                email=request.email,
                valid=False,
                message="OTP has expired"
            )

        if pwd_context.verify(request.otp, stored_otp):
            await conn.execute("DELETE FROM otps WHERE email = $1", request.email)
            result = await conn.fetch("UPDATE Business SET verified = TRUE WHERE email = $1 RETURNING id", request.email)
            if not result:
                logger.warning(f"No business found for: {request.email}")
                return OTPVerifyResponse(
                    email=request.email,
                    valid=False,
                    message="No business found with this email"
                )

            # Create session
            session_id = str(uuid.uuid4())
            await redis_client.setex(f"session:{session_id}", 1800, request.email)  # 30 minutes TTL
            response.set_cookie(
                key="session_id",
                value=session_id,
                httponly=True,
                secure=True,  # Requires HTTPS in production
                samesite="lax",
                max_age=1800
            )
            logger.info(f"OTP verified and session created for: {request.email}")
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
    except asyncpg.PostgresError as e:
        logger.error(f"Database error in verify_otp: {str(e)}")
        raise HTTPException(status_code=500, detail="Database error occurred")

# Login endpoint
@app.post("/login/")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), conn=Depends(get_db_conn), response: Response = None):
    try:
        result = await conn.fetch("SELECT email, password FROM users WHERE email = $1", form_data.username)
        if not result or not pwd_context.verify(form_data.password, result[0]["password"]):
            logger.warning(f"Invalid login attempt for: {form_data.username}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Create session
        session_id = str(uuid.uuid4())
        await redis_client.setex(f"session:{session_id}", 1800, form_data.username)
        response.set_cookie(
            key="session_id",
            value=session_id,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=1800
        )
        logger.info(f"User logged in: {form_data.username}")
        return {"message": "Login successful"}
    except asyncpg.PostgresError as e:
        logger.error(f"Database error in login: {str(e)}")
        raise HTTPException(status_code=500, detail="Database error occurred")

# Create User
@app.post("/users/", response_model=User)
async def create_user(user: UserCreate, conn=Depends(get_db_conn)):
    try:
        # Verify company_id exists
        result = await conn.fetch("SELECT id FROM Business WHERE id = $1", user.company_id)
        if not result:
            logger.warning(f"Invalid company_id: {user.company_id}")
            raise HTTPException(status_code=400, detail="Invalid company ID")

        hashed_password = pwd_context.hash(user.password)
        result = await conn.fetch(
            "INSERT INTO users (name, email, phone, password, role, company_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, email",
            user.name, user.email, user.phone, hashed_password, user.role, user.company_id
        )
        if not result:
            logger.error("User creation failed: No record returned")
            raise HTTPException(status_code=400, detail="User creation failed")
        new_user = dict(result[0])
        logger.info(f"Created user: {new_user['email']}")
        return new_user
    except asyncpg.UniqueViolationError as e:
        logger.warning(f"Duplicate email: {user.email}")
        raise HTTPException(status_code=400, detail="Email already exists")
    except asyncpg.PostgresError as e:
        logger.error(f"Database error in create_user: {str(e)}")
        raise HTTPException(status_code=500, detail="Database error occurred")
    
# Protected profile endpoint
@app.get("/profile/")
async def get_profile(current_user=Depends(get_current_user)):
    return {"email": current_user["email"], "message": "Authenticated user profile"}
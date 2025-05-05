from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
password = "testpassword"
hashed = pwd_context.hash(password)
print(hashed)
print(pwd_context.verify("testpassword", hashed))
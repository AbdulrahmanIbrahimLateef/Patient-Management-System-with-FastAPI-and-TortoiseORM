# Import necessary libraries
from fastapi import FastAPI, Depends, HTTPException, WebSocket
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from tortoise.contrib.fastapi import register_tortoise
from tortoise import fields
from tortoise.models import Model
from pydantic import BaseModel
from typing import List, Optional
from jose import JWTError, jwt
from datetime import datetime, timedelta

# Initialize FastAPI app
app = FastAPI()

# Secret key for JWT token
SECRET_KEY = "4900f70bded2c9248f204f79726a28a6d88056e39b72c9ee88f359b6e48b20be"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Define OAuth2 scheme for token-based authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Define models for Tortoise ORM
class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(max_length=50, unique=True)
    password_hash = fields.CharField(max_length=255)
    role = fields.CharField(max_length=20)

class Patient(Model):
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=100)
    details = fields.TextField()
    doctor_id = fields.ForeignKeyField('models.User')

# Initialize Tortoise ORM
register_tortoise(
    app,
    db_url='sqlite://db.sqlite3',
    modules={'models': ['__main__']},
    generate_schemas=True,
)

# Helper functions for token authentication
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = await User.get_or_none(username=username)
    if user is None:
        raise credentials_exception
    return user

# Define endpoints
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await User.get_or_none(username=form_data.username)
    if user is None or not user.password_hash == form_data.password:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/register")
async def register(username: str, password: str, role: str):
    user = await User.create(username=username, password_hash=password, role=role)
    return {"username": user.username, "role": user.role}

@app.get("/patients", response_model=None)
async def get_patients(current_user: User = Depends(get_current_user)):
    if current_user.role != "Doctor":
        raise HTTPException(status_code=403, detail="Permission denied")
    patients = await Patient.filter(doctor_id=current_user.id)
    return patients

class PatientBase(BaseModel):
    name: str
    details: str

class PatientCreate(PatientBase):
    pass

@app.post("/patients")
async def create_patient(patient: PatientCreate, current_user: User = Depends(get_current_user)):
    if current_user.role != "Doctor":
        raise HTTPException(status_code=403, detail="Permission denied")
    patient_obj = await Patient.create(**patient.dict(), doctor_id=current_user.id)
    return patient_obj

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    while True:
        data = await websocket.receive_text()
        # Implement secure handling of WebSocket messages using JWT tokens
        await websocket.send_text(f"Message text was: {data}")

# Define models for Pydantic
class UserBase(BaseModel):
    username: str
    role: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int

    class Config:
        from_attributes = True

class Patient(PatientBase):
    id: int
    doctor_id: int

    class Config:
        from_attributes = True


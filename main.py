import os
import time
import random
import hashlib
import shutil
from datetime import datetime, timedelta, timezone
from typing import Optional, Generator

import jwt
import resend
import redis
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import (
    create_engine,
    Column,
    String,
    Integer,
    DateTime,
    Text,
    ForeignKey,
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship

load_dotenv()

app = FastAPI(title="Xavier Carpooling API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# Uploads
# =========================
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
PROFILE_IMAGE_DIR = os.path.join(UPLOAD_DIR, "profile_images")
os.makedirs(PROFILE_IMAGE_DIR, exist_ok=True)

app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# =========================
# Domains
# =========================
STUDENT_DOMAIN = "student.xavier.ac.in"
STAFF_DOMAIN = "xavier.ac.in"

# =========================
# ENV
# =========================
OTP_TTL_MIN = int(os.getenv("OTP_TTL_MIN", "10"))
OTP_RESEND_COOLDOWN_SEC = int(os.getenv("OTP_RESEND_COOLDOWN_SEC", "60"))
OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", "5"))

JWT_SECRET = os.getenv("JWT_SECRET", "change-me-now")
JWT_ACCESS_TTL_MIN = int(os.getenv("JWT_ACCESS_TTL_MIN", "30"))

RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
FROM_EMAIL = os.getenv("FROM_EMAIL", "no-reply@xaviercarpool.com")

OTP_PEPPER = os.getenv("OTP_PEPPER", "change-this-secret")

DEV_TEST_EMAILS = [
    e.strip().lower()
    for e in os.getenv("DEV_TEST_EMAILS", "").split(",")
    if e.strip()
]
DEV_EMAIL_REDIRECT = os.getenv("DEV_EMAIL_REDIRECT", "false").lower() in (
    "1",
    "true",
    "yes",
    "y",
    "on",
)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://carpool:carpoolpass@localhost:5432/carpooldb",
)

# =========================
# Redis
# =========================
REDIS_URL = os.getenv("REDIS_URL", "").strip()

redis_enabled = False
rdb = None

try:
    if REDIS_URL:
        rdb = redis.Redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
        )
        rdb.ping()
        redis_enabled = True
        print(f"✅ Redis connected: {REDIS_URL}")
    else:
        print("⚠️ REDIS_URL not set. Using in-memory OTP store.")
except Exception as e:
    redis_enabled = False
    rdb = None
    print(
        f"⚠️ Redis not available, using in-memory OTP store. "
        f"REDIS_URL={REDIS_URL} | Error: {repr(e)}"
    )

OTP_STORE = {}

# =========================
# Database
# =========================
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    email = Column(String, primary_key=True, index=True)
    role = Column(String, nullable=False)
    full_name = Column(String, nullable=False, default="")
    phone_number = Column(String, nullable=False, default="")
    department = Column(String, nullable=False, default="")
    address = Column(Text, nullable=False, default="")
    emergency_contact_name = Column(String, nullable=False, default="")
    emergency_contact_phone = Column(String, nullable=False, default="")
    profile_image_url = Column(Text, nullable=False, default="")
    last_ride_id = Column(String, nullable=False, default="")
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    rides = relationship("Ride", back_populates="driver", cascade="all, delete-orphan")


class Ride(Base):
    __tablename__ = "rides"

    ride_id = Column(String, primary_key=True, index=True)
    driver_email = Column(String, ForeignKey("users.email"), nullable=False)
    driver_role = Column(String, nullable=False)
    from_location = Column(String, nullable=False)
    to_location = Column(String, nullable=False)
    departure_time = Column(DateTime(timezone=True), nullable=False)
    seats_total = Column(Integer, nullable=False)
    notes = Column(Text, nullable=False, default="")
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    seat_taken = Column(Integer, nullable=False, default=0)
    seat_left = Column(Integer, nullable=False, default=0)

    driver = relationship("User", back_populates="rides")
    passengers = relationship(
        "RidePassenger",
        back_populates="ride",
        cascade="all, delete-orphan",
    )


class RidePassenger(Base):
    __tablename__ = "ride_passengers"

    ride_id = Column(String, ForeignKey("rides.ride_id"), primary_key=True)
    passenger_email = Column(String, primary_key=True)
    joined_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    ride = relationship("Ride", back_populates="passengers")


Base.metadata.create_all(bind=engine)
print("✅ Postgres tables ready.")


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =========================
# Helpers
# =========================
def is_college_email(email: str) -> bool:
    return email.endswith(f"@{STUDENT_DOMAIN}") or email.endswith(f"@{STAFF_DOMAIN}")


def detect_role(email: str) -> str:
    return "student" if email.endswith(f"@{STUDENT_DOMAIN}") else "staff"


def hash_otp(email: str, otp: str) -> str:
    raw = f"{email}:{otp}:{OTP_PEPPER}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def make_access_token(email: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": email,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_ACCESS_TTL_MIN)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def resend_send_email(to_email: str, subject: str, html: str):
    if not RESEND_API_KEY:
        raise RuntimeError("RESEND_API_KEY missing in environment variables")
    resend.api_key = RESEND_API_KEY

    payload = {
        "from": FROM_EMAIL,
        "to": [to_email],
        "subject": subject,
        "html": html,
    }
    return resend.Emails.send(payload)


def send_otp_email(requested_email: str, otp: str, ttl_min: int):
    subject = "Xavier Carpool - OTP Verification"
    html = f"""
    <div style="font-family:Arial,sans-serif;line-height:1.5;">
      <h2>Xavier Carpool OTP</h2>
      <p>Your OTP is:</p>
      <div style="font-size:28px;font-weight:bold;letter-spacing:4px;margin:12px 0;">
        {otp}
      </div>
      <p>Expires in <b>{ttl_min} minutes</b>.</p>
      <p>If you did not request this, ignore this email.</p>
    </div>
    """

    if DEV_EMAIL_REDIRECT:
        if not DEV_TEST_EMAILS:
            raise RuntimeError("DEV_EMAIL_REDIRECT=true but DEV_TEST_EMAILS is empty")
        results = []
        for dev_to in DEV_TEST_EMAILS:
            results.append(resend_send_email(dev_to, subject, html))
        return {"mode": "dev_redirect", "sent_to": DEV_TEST_EMAILS, "results": results}

    result = resend_send_email(requested_email, subject, html)
    return {"mode": "normal", "sent_to": requested_email, "result": result}


def otp_key(email: str) -> str:
    return f"otp:{email}"


def cooldown_key(email: str) -> str:
    return f"otp_cd:{email}"


def serialize_ride(ride: Ride, current_user_email: str, db: Session):
    driver_profile = db.query(User).filter(User.email == ride.driver_email).first()

    passenger_details = []
    passenger_emails = []

    for p in ride.passengers:
        passenger_emails.append(p.passenger_email)
        passenger_profile = db.query(User).filter(User.email == p.passenger_email).first()

        passenger_details.append({
            "email": p.passenger_email,
            "phone_number": passenger_profile.phone_number if passenger_profile else "",
            "full_name": passenger_profile.full_name if passenger_profile else "",
        })

    return {
        "ride_id": ride.ride_id,
        "id": ride.ride_id,
        "driver_email": ride.driver_email,
        "driver_role": ride.driver_role,
        "driver_phone_number": driver_profile.phone_number if driver_profile else "",
        "driver_phone": driver_profile.phone_number if driver_profile else "",
        "driver_full_name": driver_profile.full_name if driver_profile else "",
        "driver_name": driver_profile.full_name if driver_profile else "",
        "from_location": ride.from_location,
        "to_location": ride.to_location,
        "departure_time": ride.departure_time.isoformat(),
        "seats_total": ride.seats_total,
        "seat_taken": ride.seat_taken,
        "seat_left": ride.seat_left,
        "seats_left": ride.seat_left,
        "available_seats": ride.seat_left,
        "notes": ride.notes,
        "created_at": ride.created_at.isoformat(),
        "is_driver": ride.driver_email == current_user_email,
        "is_joined": current_user_email in passenger_emails,
        "passengers": passenger_details,
    }


# =========================
# Auth
# =========================
bearer = HTTPBearer(auto_error=True)


def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
):
    token = creds.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return {
            "email": payload["sub"],
            "role": payload.get("role", "unknown"),
        }
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# =========================
# Schemas
# =========================
class RequestOtpBody(BaseModel):
    email: EmailStr


class VerifyOtpBody(BaseModel):
    email: EmailStr
    otp: str


class RideCreateBody(BaseModel):
    from_location: str = Field(..., min_length=2)
    to_location: str = Field(..., min_length=2)
    departure_time: datetime
    seats_total: int = Field(..., ge=1, le=8)
    notes: Optional[str] = Field(default="", max_length=500)


class ProfileUpdateBody(BaseModel):
    full_name: str = Field(default="", max_length=100)
    phone_number: str = Field(default="", max_length=20)
    department: str = Field(default="", max_length=50)
    address: str = Field(default="", max_length=300)
    emergency_contact_name: str = Field(default="", max_length=100)
    emergency_contact_phone: str = Field(default="", max_length=20)
    profile_image_url: str = Field(default="", max_length=500)


# =========================
# Routes
# =========================
@app.get("/")
def root():
    return {"status": "API running"}


@app.get("/me")
def me(user=Depends(get_current_user)):
    return {"email": user["email"], "role": user["role"]}


@app.post("/auth/request-otp")
def request_otp(body: RequestOtpBody):
    email = body.email.lower().strip()

    if not is_college_email(email):
        raise HTTPException(
            status_code=403,
            detail="Only Xavier college email IDs are allowed.",
        )

    otp = f"{random.randint(0, 999999):06d}"

    if redis_enabled and rdb is not None:
        if rdb.exists(cooldown_key(email)):
            ttl = rdb.ttl(cooldown_key(email))
            raise HTTPException(
                status_code=429,
                detail=f"Please wait {max(ttl, 1)}s before requesting another OTP.",
            )

        rdb.hset(
            otp_key(email),
            mapping={
                "otp_hash": hash_otp(email, otp),
                "attempts": 0,
            },
        )
        rdb.expire(otp_key(email), OTP_TTL_MIN * 60)
        rdb.setex(cooldown_key(email), OTP_RESEND_COOLDOWN_SEC, "1")
    else:
        now = time.time()
        existing = OTP_STORE.get(email)
        if existing and (now - existing["last_sent_ts"] < OTP_RESEND_COOLDOWN_SEC):
            wait = int(OTP_RESEND_COOLDOWN_SEC - (now - existing["last_sent_ts"]))
            raise HTTPException(
                status_code=429,
                detail=f"Please wait {wait}s before requesting another OTP.",
            )

        OTP_STORE[email] = {
            "otp_hash": hash_otp(email, otp),
            "expires_at": now + OTP_TTL_MIN * 60,
            "attempts": 0,
            "last_sent_ts": now,
        }

    print(f"➡️ REQUEST OTP for: {email} | redis={redis_enabled} | redirect={DEV_EMAIL_REDIRECT}")

    try:
        resp = send_otp_email(email, otp, OTP_TTL_MIN)
        print("✅ Resend response:", resp)
    except Exception as e:
        if redis_enabled and rdb is not None:
            rdb.delete(otp_key(email))
            rdb.delete(cooldown_key(email))
        else:
            OTP_STORE.pop(email, None)
        raise HTTPException(status_code=500, detail=f"Failed to send OTP email: {repr(e)}")

    return {"status": "otp_sent"}


@app.post("/auth/verify-otp")
def verify_otp(body: VerifyOtpBody, db: Session = Depends(get_db)):
    email = body.email.lower().strip()
    otp = body.otp.strip()

    if redis_enabled and rdb is not None:
        record = rdb.hgetall(otp_key(email))
        if not record:
            raise HTTPException(status_code=400, detail="OTP not found. Request OTP again.")

        attempts = int(record.get("attempts", 0))
        if attempts >= OTP_MAX_ATTEMPTS:
            rdb.delete(otp_key(email))
            raise HTTPException(status_code=429, detail="Too many attempts. Request OTP again.")

        if len(otp) != 6 or not otp.isdigit():
            raise HTTPException(status_code=400, detail="OTP must be a 6-digit number.")

        rdb.hincrby(otp_key(email), "attempts", 1)

        if hash_otp(email, otp) != record.get("otp_hash"):
            raise HTTPException(status_code=400, detail="Invalid OTP.")

        rdb.delete(otp_key(email))
    else:
        record = OTP_STORE.get(email)
        if not record:
            raise HTTPException(status_code=400, detail="OTP not found. Request OTP again.")

        if time.time() > record["expires_at"]:
            OTP_STORE.pop(email, None)
            raise HTTPException(status_code=400, detail="OTP expired. Request OTP again.")

        if record["attempts"] >= OTP_MAX_ATTEMPTS:
            OTP_STORE.pop(email, None)
            raise HTTPException(status_code=429, detail="Too many attempts. Request OTP again.")

        record["attempts"] += 1

        if len(otp) != 6 or not otp.isdigit():
            raise HTTPException(status_code=400, detail="OTP must be a 6-digit number.")

        if hash_otp(email, otp) != record["otp_hash"]:
            raise HTTPException(status_code=400, detail="Invalid OTP.")

        OTP_STORE.pop(email, None)

    role = detect_role(email)

    existing_user = db.query(User).filter(User.email == email).first()
    if not existing_user:
        new_user = User(
            email=email,
            role=role,
        )
        db.add(new_user)
        db.commit()

    token = make_access_token(email, role)
    return {"access_token": token, "token_type": "bearer", "role": role}


@app.get("/profile/me")
def get_profile(user=Depends(get_current_user), db: Session = Depends(get_db)):
    profile = db.query(User).filter(User.email == user["email"]).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    return {
        "email": profile.email,
        "role": profile.role,
        "full_name": profile.full_name,
        "phone_number": profile.phone_number,
        "department": profile.department,
        "address": profile.address,
        "emergency_contact_name": profile.emergency_contact_name,
        "emergency_contact_phone": profile.emergency_contact_phone,
        "profile_image_url": profile.profile_image_url,
        "last_ride_id": profile.last_ride_id,
        "created_at": profile.created_at.isoformat(),
        "updated_at": profile.updated_at.isoformat(),
    }


@app.put("/profile/me")
def update_profile(
    body: ProfileUpdateBody,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    profile = db.query(User).filter(User.email == user["email"]).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    profile.full_name = body.full_name
    profile.phone_number = body.phone_number
    profile.department = body.department
    profile.address = body.address
    profile.emergency_contact_name = body.emergency_contact_name
    profile.emergency_contact_phone = body.emergency_contact_phone
    profile.profile_image_url = body.profile_image_url
    profile.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(profile)

    return {
        "status": "profile_updated",
        "profile": {
            "email": profile.email,
            "role": profile.role,
            "full_name": profile.full_name,
            "phone_number": profile.phone_number,
            "department": profile.department,
            "address": profile.address,
            "emergency_contact_name": profile.emergency_contact_name,
            "emergency_contact_phone": profile.emergency_contact_phone,
            "profile_image_url": profile.profile_image_url,
            "last_ride_id": profile.last_ride_id,
            "created_at": profile.created_at.isoformat(),
            "updated_at": profile.updated_at.isoformat(),
        },
    }


@app.post("/profile/upload-image")
def upload_profile_image(
    file: UploadFile = File(...),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    original_name = (file.filename or "").strip()
    ext = os.path.splitext(original_name)[1].lower()

    allowed_exts = {".jpg", ".jpeg", ".png"}
    if ext not in allowed_exts:
        raise HTTPException(
            status_code=400,
            detail=f"Only JPG, JPEG, PNG files are allowed. Got: {original_name}",
        )

    safe_email = user["email"].replace("@", "_at_").replace(".", "_")
    filename = f"{safe_email}{ext}"
    file_path = os.path.join(PROFILE_IMAGE_DIR, filename)

    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save image: {repr(e)}")
    finally:
        file.file.close()

    profile = db.query(User).filter(User.email == user["email"]).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    image_url = f"/uploads/profile_images/{filename}"
    profile.profile_image_url = image_url
    profile.updated_at = datetime.now(timezone.utc)
    db.commit()

    return {
        "status": "image_uploaded",
        "profile_image_url": image_url,
        "filename": filename,
    }


@app.post("/rides/create")
def create_ride(
    body: RideCreateBody,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ride_id = f"ride_{int(time.time())}_{random.randint(1000, 9999)}"
    seats_total = body.seats_total

    if seats_total < 1:
        raise HTTPException(status_code=400, detail="seats_total must be at least 1")

    ride = Ride(
        ride_id=ride_id,
        driver_email=user["email"],
        driver_role=user["role"],
        from_location=body.from_location.strip(),
        to_location=body.to_location.strip(),
        departure_time=body.departure_time.astimezone(timezone.utc),
        seats_total=seats_total,
        notes=(body.notes or "").strip(),
        seat_taken=0,
        seat_left=seats_total,
    )

    db.add(ride)

    profile = db.query(User).filter(User.email == user["email"]).first()
    if profile:
        profile.last_ride_id = ride_id
        profile.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(ride)

    return {
        "status": "ride_created",
        "ride": serialize_ride(ride, user["email"], db),
    }


@app.get("/rides/search")
def search_rides(
    from_location: Optional[str] = None,
    to_location: Optional[str] = None,
    after: Optional[datetime] = None,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(Ride)

    if from_location and from_location.strip():
        query = query.filter(Ride.from_location.ilike(f"%{from_location.strip()}%"))

    if to_location and to_location.strip():
        query = query.filter(Ride.to_location.ilike(f"%{to_location.strip()}%"))

    if after:
        query = query.filter(Ride.departure_time >= after.astimezone(timezone.utc))

    ride_list = query.order_by(Ride.created_at.desc()).all()

    results = [serialize_ride(ride, user["email"], db) for ride in ride_list]

    return {
        "count": len(results),
        "rides": results,
    }


@app.post("/rides/{ride_id}/join")
def join_ride(
    ride_id: str,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ride = db.query(Ride).filter(Ride.ride_id == ride_id).first()
    if not ride:
        raise HTTPException(status_code=404, detail="Ride not found")

    if ride.driver_email == user["email"]:
        raise HTTPException(status_code=400, detail="Driver cannot join their own ride")

    existing = (
        db.query(RidePassenger)
        .filter(
            RidePassenger.ride_id == ride_id,
            RidePassenger.passenger_email == user["email"],
        )
        .first()
    )
    if existing:
        raise HTTPException(status_code=400, detail="Already joined this ride")

    if ride.seat_left <= 0:
        raise HTTPException(status_code=400, detail="No seats left")

    passenger = RidePassenger(
        ride_id=ride_id,
        passenger_email=user["email"],
    )
    db.add(passenger)

    ride.seat_taken += 1
    ride.seat_left = max(0, ride.seats_total - ride.seat_taken)

    profile = db.query(User).filter(User.email == user["email"]).first()
    if profile:
        profile.last_ride_id = ride_id
        profile.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(ride)

    return {
        "status": "joined",
        "ride": serialize_ride(ride, user["email"], db),
    }


@app.post("/rides/{ride_id}/leave")
def leave_ride(
    ride_id: str,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ride = db.query(Ride).filter(Ride.ride_id == ride_id).first()
    if not ride:
        raise HTTPException(status_code=404, detail="Ride not found")

    passenger = (
        db.query(RidePassenger)
        .filter(
            RidePassenger.ride_id == ride_id,
            RidePassenger.passenger_email == user["email"],
        )
        .first()
    )
    if not passenger:
        raise HTTPException(status_code=400, detail="You have not joined this ride")

    db.delete(passenger)
    ride.seat_taken = max(0, ride.seat_taken - 1)
    ride.seat_left = max(0, ride.seats_total - ride.seat_taken)

    db.commit()
    db.refresh(ride)

    return {
        "status": "left",
        "ride": serialize_ride(ride, user["email"], db),
    }
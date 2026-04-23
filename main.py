import os
import time
import random
import hashlib
import shutil
from datetime import datetime, timedelta, timezone
from typing import Optional, Generator

import jwt
import resend
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Query
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
    Boolean,
    Float,
    text,
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session

load_dotenv()

app = FastAPI(title="LiftLink API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
PROFILE_IMAGE_DIR = os.path.join(UPLOAD_DIR, "profile_images")
os.makedirs(PROFILE_IMAGE_DIR, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

STUDENT_DOMAIN = "student.xavier.ac.in"
FACULTY_DOMAIN = "xavier.ac.in"

OTP_TTL_MIN = int(os.getenv("OTP_TTL_MIN", "10"))
OTP_RESEND_COOLDOWN_SEC = int(os.getenv("OTP_RESEND_COOLDOWN_SEC", "60"))
OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", "5"))

JWT_SECRET = os.getenv("JWT_SECRET", "change-me-now")
JWT_ACCESS_TTL_MIN = int(os.getenv("JWT_ACCESS_TTL_MIN", "30"))

RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
FROM_EMAIL = os.getenv("FROM_EMAIL", "onboarding@resend.dev")
OTP_PEPPER = os.getenv("OTP_PEPPER", "change-this-secret")

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://carpool:carpoolpass@localhost:5432/carpooldb",
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    email = Column(String, primary_key=True, index=True)
    role = Column(String, nullable=False, default="student")
    full_name = Column(String, nullable=False, default="")
    phone_number = Column(String, nullable=False, default="")
    department = Column(String, nullable=False, default="")
    address = Column(Text, nullable=False, default="")
    emergency_contact_name = Column(String, nullable=False, default="")
    emergency_contact_phone = Column(String, nullable=False, default="")
    profile_image_url = Column(Text, nullable=False, default="")
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


class Ride(Base):
    __tablename__ = "rides"

    ride_id = Column(String, primary_key=True, index=True)
    driver_email = Column(String, ForeignKey("users.email"), nullable=False)
    driver_role = Column(String, nullable=False, default="student")
    from_location = Column(String, nullable=False)
    to_location = Column(String, nullable=False)
    departure_time = Column(DateTime(timezone=True), nullable=False)
    seats_total = Column(Integer, nullable=False)
    seat_taken = Column(Integer, nullable=False, default=0)
    seat_left = Column(Integer, nullable=False, default=0)
    notes = Column(Text, nullable=False, default="")
    total_cost = Column(Float, nullable=False, default=0.0)
    allowed_role = Column(String, nullable=False, default="all")
    status = Column(String, nullable=False, default="scheduled")
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
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


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_email = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    type = Column(String, nullable=False, default="general")
    is_read = Column(Boolean, nullable=False, default=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class RecentRide(Base):
    __tablename__ = "recent_rides"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_email = Column(String, nullable=False, index=True)
    from_location = Column(String, nullable=False)
    to_location = Column(String, nullable=False)
    used_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class OtpCode(Base):
    __tablename__ = "otp_codes"

    email = Column(String, primary_key=True, index=True)
    otp_hash = Column(String, nullable=False)
    role = Column(String, nullable=False)
    attempts = Column(Integer, nullable=False, default=0)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    last_sent_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


def migrate_schema():
    with engine.begin() as conn:
        conn.execute(text("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS role VARCHAR NOT NULL DEFAULT 'student'
        """))
        conn.execute(text("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS full_name VARCHAR NOT NULL DEFAULT ''
        """))
        conn.execute(text("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS phone_number VARCHAR NOT NULL DEFAULT ''
        """))
        conn.execute(text("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS department VARCHAR NOT NULL DEFAULT ''
        """))
        conn.execute(text("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS address TEXT NOT NULL DEFAULT ''
        """))
        conn.execute(text("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS emergency_contact_name VARCHAR NOT NULL DEFAULT ''
        """))
        conn.execute(text("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS emergency_contact_phone VARCHAR NOT NULL DEFAULT ''
        """))
        conn.execute(text("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS profile_image_url TEXT NOT NULL DEFAULT ''
        """))

        conn.execute(text("""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_name = 'users'
                    AND column_name = 'last_ride_id'
                ) THEN
                    BEGIN
                        ALTER TABLE users ALTER COLUMN last_ride_id DROP NOT NULL;
                    EXCEPTION WHEN others THEN
                        NULL;
                    END;

                    ALTER TABLE users DROP COLUMN last_ride_id CASCADE;
                END IF;
            END $$;
        """))

        conn.execute(text("""
            ALTER TABLE rides
            ADD COLUMN IF NOT EXISTS driver_role VARCHAR NOT NULL DEFAULT 'student'
        """))
        conn.execute(text("""
            ALTER TABLE rides
            ADD COLUMN IF NOT EXISTS total_cost DOUBLE PRECISION NOT NULL DEFAULT 0.0
        """))
        conn.execute(text("""
            ALTER TABLE rides
            ADD COLUMN IF NOT EXISTS allowed_role VARCHAR NOT NULL DEFAULT 'all'
        """))
        conn.execute(text("""
            ALTER TABLE rides
            ADD COLUMN IF NOT EXISTS status VARCHAR NOT NULL DEFAULT 'scheduled'
        """))

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS recent_rides (
                id SERIAL PRIMARY KEY,
                user_email VARCHAR NOT NULL,
                from_location VARCHAR NOT NULL,
                to_location VARCHAR NOT NULL,
                used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS otp_codes (
                email VARCHAR PRIMARY KEY,
                otp_hash VARCHAR NOT NULL,
                role VARCHAR NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                expires_at TIMESTAMPTZ NOT NULL,
                last_sent_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS notifications (
                id SERIAL PRIMARY KEY,
                user_email VARCHAR NOT NULL,
                title VARCHAR NOT NULL,
                message TEXT NOT NULL,
                type VARCHAR NOT NULL DEFAULT 'general',
                is_read BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))

        conn.execute(text("""
            ALTER TABLE notifications
            ADD COLUMN IF NOT EXISTS id BIGSERIAL
        """))
        conn.execute(text("""
            ALTER TABLE notifications
            ADD COLUMN IF NOT EXISTS user_email VARCHAR NOT NULL DEFAULT ''
        """))
        conn.execute(text("""
            ALTER TABLE notifications
            ADD COLUMN IF NOT EXISTS title VARCHAR NOT NULL DEFAULT ''
        """))
        conn.execute(text("""
            ALTER TABLE notifications
            ADD COLUMN IF NOT EXISTS message TEXT NOT NULL DEFAULT ''
        """))
        conn.execute(text("""
            ALTER TABLE notifications
            ADD COLUMN IF NOT EXISTS type VARCHAR NOT NULL DEFAULT 'general'
        """))
        conn.execute(text("""
            ALTER TABLE notifications
            ADD COLUMN IF NOT EXISTS is_read BOOLEAN NOT NULL DEFAULT FALSE
        """))
        conn.execute(text("""
            ALTER TABLE notifications
            ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        """))

        conn.execute(text("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_constraint
                    WHERE conname = 'notifications_pkey'
                ) THEN
                    ALTER TABLE notifications
                    ADD CONSTRAINT notifications_pkey PRIMARY KEY (id);
                END IF;
            EXCEPTION
                WHEN duplicate_table THEN NULL;
                WHEN duplicate_object THEN NULL;
            END $$;
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_notifications_user_email
            ON notifications (user_email)
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_recent_rides_user_email
            ON recent_rides (user_email)
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_otp_codes_email
            ON otp_codes (email)
        """))


Base.metadata.create_all(bind=engine)
migrate_schema()
print("✅ Postgres tables ready.")


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def detect_role_from_email(email: str) -> str:
    if email.endswith(f"@{STUDENT_DOMAIN}"):
        return "student"
    if email.endswith(f"@{FACULTY_DOMAIN}") and not email.endswith(f"@{STUDENT_DOMAIN}"):
        return "faculty"
    return "unknown"


def is_allowed_email(email: str) -> bool:
    return detect_role_from_email(email) in ["student", "faculty"]


def validate_role_with_email(email: str, selected_role: str) -> bool:
    return detect_role_from_email(email) == selected_role


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


def send_otp_email(email: str, otp: str):
    if not RESEND_API_KEY:
        raise RuntimeError("RESEND_API_KEY missing")
    resend.api_key = RESEND_API_KEY
    return resend.Emails.send(
        {
            "from": FROM_EMAIL,
            "to": [email],
            "subject": "LiftLink OTP Verification",
            "html": f"""
                <div style="font-family:Arial,sans-serif">
                  <h2>LiftLink OTP</h2>
                  <p>Your OTP is:</p>
                  <h1>{otp}</h1>
                  <p>Expires in {OTP_TTL_MIN} minutes.</p>
                </div>
            """,
        }
    )


def create_notification(
    db: Session,
    user_email: str,
    title: str,
    message: str,
    type_: str = "general",
):
    n = Notification(
        user_email=user_email,
        title=title,
        message=message,
        type=type_,
    )
    db.add(n)
    db.commit()


def add_recent_ride(db: Session, user_email: str, from_location: str, to_location: str):
    rec = RecentRide(
        user_email=user_email,
        from_location=from_location,
        to_location=to_location,
    )
    db.add(rec)
    db.commit()

    rows = (
        db.query(RecentRide)
        .filter(RecentRide.user_email == user_email)
        .order_by(RecentRide.used_at.desc())
        .all()
    )
    if len(rows) > 5:
        for old in rows[5:]:
            db.delete(old)
        db.commit()


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


class RequestOtpBody(BaseModel):
    email: EmailStr
    role: str = Field(..., pattern="^(student|faculty)$")


class VerifyOtpBody(BaseModel):
    email: EmailStr
    otp: str


class ProfileUpdateBody(BaseModel):
    full_name: str = ""
    phone_number: str = ""
    department: str = ""
    address: str = ""
    emergency_contact_name: str = ""
    emergency_contact_phone: str = ""
    profile_image_url: str = ""


class RideCreateBody(BaseModel):
    from_location: str
    to_location: str
    departure_time: datetime
    seats_total: int = Field(..., ge=1, le=8)
    notes: str = ""
    total_cost: float = Field(default=0.0, ge=0.0)
    allowed_role: str = Field(default="all", pattern="^(all|student|faculty)$")


class RideStatusBody(BaseModel):
    status: str = Field(..., pattern="^(on_the_way|arrived|completed)$")


@app.get("/")
def root():
    return {"status": "LiftLink API running"}


@app.post("/auth/request-otp")
def request_otp(body: RequestOtpBody, db: Session = Depends(get_db)):
    email = body.email.lower().strip()
    role = body.role.lower().strip()

    if not is_allowed_email(email):
        raise HTTPException(status_code=403, detail="Only institutional email allowed.")

    if not validate_role_with_email(email, role):
        raise HTTPException(
            status_code=400,
            detail="Selected role does not match institutional email.",
        )

    existing = db.query(OtpCode).filter(OtpCode.email == email).first()
    now = datetime.now(timezone.utc)

    if existing:
        seconds_since_last = (now - existing.last_sent_at).total_seconds()
        if seconds_since_last < OTP_RESEND_COOLDOWN_SEC:
            wait = int(OTP_RESEND_COOLDOWN_SEC - seconds_since_last)
            raise HTTPException(status_code=429, detail=f"Wait {max(wait, 1)} seconds.")

    otp = f"{random.randint(0, 999999):06d}"
    otp_hash = hash_otp(email, otp)

    if existing:
        existing.otp_hash = otp_hash
        existing.role = role
        existing.attempts = 0
        existing.expires_at = now + timedelta(minutes=OTP_TTL_MIN)
        existing.last_sent_at = now
    else:
        db.add(
            OtpCode(
                email=email,
                otp_hash=otp_hash,
                role=role,
                attempts=0,
                expires_at=now + timedelta(minutes=OTP_TTL_MIN),
                last_sent_at=now,
            )
        )

    db.commit()

    try:
        send_otp_email(email, otp)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send OTP: {repr(e)}")

    return {"status": "otp_sent"}


@app.post("/auth/verify-otp")
def verify_otp(body: VerifyOtpBody, db: Session = Depends(get_db)):
    email = body.email.lower().strip()
    otp = body.otp.strip()

    record = db.query(OtpCode).filter(OtpCode.email == email).first()
    if not record:
        raise HTTPException(status_code=400, detail="OTP not found.")

    now = datetime.now(timezone.utc)

    if now > record.expires_at:
        db.delete(record)
        db.commit()
        raise HTTPException(status_code=400, detail="OTP expired.")

    if record.attempts >= OTP_MAX_ATTEMPTS:
        db.delete(record)
        db.commit()
        raise HTTPException(status_code=429, detail="Too many attempts.")

    expected_hash = hash_otp(email, otp)
    if expected_hash != record.otp_hash:
        record.attempts += 1
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid OTP.")

    role = detect_role_from_email(email)
    if role == "unknown":
        db.delete(record)
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid user role.")

    db.delete(record)
    db.commit()

    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(email=email, role=role)
        db.add(user)
    else:
        user.role = role
        user.updated_at = now
    db.commit()

    token = make_access_token(email, role)
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": role,
    }


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
    return {"status": "profile_updated"}


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
        raise HTTPException(status_code=400, detail="Only JPG, JPEG, PNG allowed.")

    safe_email = user["email"].replace("@", "_at_").replace(".", "_")
    filename = f"{safe_email}{ext}"
    file_path = os.path.join(PROFILE_IMAGE_DIR, filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

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
    }


@app.post("/rides/create")
def create_ride(
    body: RideCreateBody,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ride_id = f"ride_{int(time.time())}_{random.randint(1000, 9999)}"

    ride = Ride(
        ride_id=ride_id,
        driver_email=user["email"],
        driver_role=user["role"],
        from_location=body.from_location,
        to_location=body.to_location,
        departure_time=body.departure_time.astimezone(timezone.utc),
        seats_total=body.seats_total,
        seat_taken=0,
        seat_left=body.seats_total,
        notes=body.notes,
        total_cost=body.total_cost,
        allowed_role=body.allowed_role,
        status="scheduled",
    )
    db.add(ride)
    db.commit()

    add_recent_ride(db, user["email"], body.from_location, body.to_location)

    return {"ride_id": ride_id, "status": "created"}


@app.get("/rides/recent")
def recent_rides(user=Depends(get_current_user), db: Session = Depends(get_db)):
    rows = (
        db.query(RecentRide)
        .filter(RecentRide.user_email == user["email"])
        .order_by(RecentRide.used_at.desc())
        .limit(5)
        .all()
    )
    return {
        "recent_rides": [
            {
                "id": r.id,
                "from_location": r.from_location,
                "to_location": r.to_location,
                "used_at": r.used_at.isoformat(),
            }
            for r in rows
        ]
    }


@app.get("/rides/search")
def search_rides(
    from_location: Optional[str] = Query(default=None),
    to_location: Optional[str] = Query(default=None),
    role_scope: Optional[str] = Query(default="all"),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(Ride).filter(Ride.status != "completed")

    if from_location:
        query = query.filter(Ride.from_location.ilike(f"%{from_location}%"))
    if to_location:
        query = query.filter(Ride.to_location.ilike(f"%{to_location}%"))

    if role_scope in ["student", "faculty"]:
        query = query.filter(Ride.driver_role == role_scope)

    rides = query.order_by(Ride.created_at.desc()).all()

    results = []
    for ride in rides:
        if ride.status == "cancelled":
            continue

        if (
            ride.allowed_role != "all"
            and ride.allowed_role != user["role"]
            and ride.driver_email != user["email"]
        ):
            continue

        driver_profile = db.query(User).filter(User.email == ride.driver_email).first()
        passenger_rows = (
            db.query(RidePassenger)
            .filter(RidePassenger.ride_id == ride.ride_id)
            .all()
        )

        passenger_emails = [p.passenger_email for p in passenger_rows]
        passengers = []
        for p in passenger_rows:
            pp = db.query(User).filter(User.email == p.passenger_email).first()
            passengers.append(
                {
                    "email": p.passenger_email,
                    "full_name": pp.full_name if pp else "",
                    "phone_number": pp.phone_number if pp else "",
                }
            )

        occupants = ride.seat_taken + 1
        share_amount = round((ride.total_cost / occupants), 2) if ride.total_cost > 0 else 0.0

        results.append(
            {
                "ride_id": ride.ride_id,
                "driver_email": ride.driver_email,
                "driver_role": ride.driver_role,
                "driver_full_name": driver_profile.full_name if driver_profile else "",
                "driver_phone_number": driver_profile.phone_number if driver_profile else "",
                "from_location": ride.from_location,
                "to_location": ride.to_location,
                "departure_time": ride.departure_time.isoformat(),
                "seats_total": ride.seats_total,
                "seat_taken": ride.seat_taken,
                "seat_left": ride.seat_left,
                "notes": ride.notes,
                "total_cost": ride.total_cost,
                "share_amount": share_amount,
                "allowed_role": ride.allowed_role,
                "status": ride.status,
                "is_driver": ride.driver_email == user["email"],
                "is_joined": user["email"] in passenger_emails,
                "passengers": passengers,
            }
        )

    return {"rides": results}


@app.post("/rides/{ride_id}/join")
def join_ride(ride_id: str, user=Depends(get_current_user), db: Session = Depends(get_db)):
    ride = db.query(Ride).filter(Ride.ride_id == ride_id).first()
    if not ride:
        raise HTTPException(status_code=404, detail="Ride not found")
    if ride.status == "cancelled":
        raise HTTPException(status_code=400, detail="Ride cancelled")
    if ride.driver_email == user["email"]:
        raise HTTPException(status_code=400, detail="Driver cannot join own ride")
    if ride.allowed_role != "all" and ride.allowed_role != user["role"]:
        raise HTTPException(status_code=403, detail="Ride not allowed for your role")
    if ride.seat_left <= 0:
        raise HTTPException(status_code=400, detail="No seats left")

    existing = (
        db.query(RidePassenger)
        .filter(
            RidePassenger.ride_id == ride_id,
            RidePassenger.passenger_email == user["email"],
        )
        .first()
    )
    if existing:
        raise HTTPException(status_code=400, detail="Already joined")

    passenger = RidePassenger(ride_id=ride_id, passenger_email=user["email"])
    db.add(passenger)
    ride.seat_taken += 1
    ride.seat_left = max(0, ride.seats_total - ride.seat_taken)
    db.commit()

    add_recent_ride(db, user["email"], ride.from_location, ride.to_location)

    passenger_user = db.query(User).filter(User.email == user["email"]).first()
    passenger_name = (
        passenger_user.full_name
        if passenger_user and passenger_user.full_name
        else user["email"]
    )

    create_notification(
        db,
        ride.driver_email,
        "Passenger joined your ride",
        f"{passenger_name} joined ride {ride.from_location} → {ride.to_location}",
        "ride_join",
    )

    return {"status": "joined"}


@app.post("/rides/{ride_id}/leave")
def leave_ride(ride_id: str, user=Depends(get_current_user), db: Session = Depends(get_db)):
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

    passenger_user = db.query(User).filter(User.email == user["email"]).first()
    passenger_name = (
        passenger_user.full_name
        if passenger_user and passenger_user.full_name
        else user["email"]
    )

    create_notification(
        db,
        ride.driver_email,
        "Passenger left your ride",
        f"{passenger_name} left ride {ride.from_location} → {ride.to_location}",
        "ride_leave",
    )

    return {"status": "left"}


@app.post("/rides/{ride_id}/cancel")
def cancel_ride(ride_id: str, user=Depends(get_current_user), db: Session = Depends(get_db)):
    ride = db.query(Ride).filter(Ride.ride_id == ride_id).first()
    if not ride:
        raise HTTPException(status_code=404, detail="Ride not found")
    if ride.driver_email != user["email"]:
        raise HTTPException(status_code=403, detail="Only driver can cancel")
    if ride.status == "cancelled":
        raise HTTPException(status_code=400, detail="Already cancelled")

    ride.status = "cancelled"
    db.commit()

    passengers = db.query(RidePassenger).filter(RidePassenger.ride_id == ride_id).all()
    for p in passengers:
        create_notification(
            db,
            p.passenger_email,
            "Ride cancelled",
            f"Your ride {ride.from_location} → {ride.to_location} was cancelled by the driver.",
            "ride_cancelled",
        )

    return {"status": "cancelled"}


@app.post("/rides/{ride_id}/status")
def update_ride_status(
    ride_id: str,
    body: RideStatusBody,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ride = db.query(Ride).filter(Ride.ride_id == ride_id).first()
    if not ride:
        raise HTTPException(status_code=404, detail="Ride not found")
    if ride.driver_email != user["email"]:
        raise HTTPException(status_code=403, detail="Only driver can update status")
    if ride.status == "cancelled":
        raise HTTPException(status_code=400, detail="Ride is cancelled")

    ride.status = body.status
    db.commit()

    passengers = db.query(RidePassenger).filter(RidePassenger.ride_id == ride_id).all()

    title_map = {
        "on_the_way": "Ride on the way",
        "arrived": "Ride arrived",
        "completed": "Ride completed",
    }
    msg_map = {
        "on_the_way": f"Driver has started ride {ride.from_location} → {ride.to_location}",
        "arrived": f"Driver has arrived for ride {ride.from_location} → {ride.to_location}",
        "completed": f"Ride {ride.from_location} → {ride.to_location} is completed",
    }

    for p in passengers:
        create_notification(
            db,
            p.passenger_email,
            title_map[body.status],
            msg_map[body.status],
            "ride_status",
        )

    return {"status": body.status}


@app.get("/notifications")
def get_notifications(user=Depends(get_current_user), db: Session = Depends(get_db)):
    rows = (
        db.query(Notification)
        .filter(Notification.user_email == user["email"])
        .order_by(Notification.created_at.desc())
        .limit(50)
        .all()
    )
    return {
        "notifications": [
            {
                "id": n.id,
                "title": n.title,
                "message": n.message,
                "type": n.type,
                "is_read": n.is_read,
                "created_at": n.created_at.isoformat(),
            }
            for n in rows
        ]
    }


@app.post("/notifications/{notification_id}/read")
def mark_notification_read(
    notification_id: int,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    n = (
        db.query(Notification)
        .filter(
            Notification.id == notification_id,
            Notification.user_email == user["email"],
        )
        .first()
    )
    if not n:
        raise HTTPException(status_code=404, detail="Notification not found")
    n.is_read = True
    db.commit()
    return {"status": "read"}
from fastapi import APIRouter, HTTPException, status
from app.schemas import (
    OTPRequest,
    OTPVerifyRequest,
    MessageResponse,
    UserVerificationStatus,
)
from app.database import db
from app.otp import OTPService
from datetime import datetime

router = APIRouter(prefix="/api/v1/otp", tags=["OTP Management"])


@router.post("/generate", response_model=MessageResponse)
async def generate_otp(request: OTPRequest):
    try:
        if request.purpose == 'registration':
            query = "SELECT id, is_verified FROM users WHERE LOWER(email) = :1"
            result = db.fetch_one(query, (request.email,))
            if result:
                user_id, is_verified = result
                if is_verified == 'Y':
                    raise HTTPException(status_code=400, detail="Email already verified. Please login instead.")
                OTPService.invalidate_old_otps(request.email, 'registration')

            otp_code = OTPService.generate_otp()
            OTPService.store_otp(request.email, otp_code, 'registration')
            email_sent = OTPService.send_email(request.email, otp_code, 'registration')
            if not email_sent:
                raise HTTPException(status_code=500, detail="Failed to send OTP email")
            return {"message": f"OTP sent successfully to {request.email} for registration",
                    "success": True, "data": {"email": request.email}}

        elif request.purpose == 'login':
            query = "SELECT id, is_verified FROM users WHERE LOWER(email) = :1"
            result = db.fetch_one(query, (request.email,))
            if not result:
                raise HTTPException(status_code=404, detail="User not found. Please register first.")
            user_id, is_verified = result
            if is_verified == 'N':
                raise HTTPException(status_code=403, detail="Email not verified. Please verify your email first.")
            OTPService.invalidate_old_otps(request.email, 'login')
            otp_code = OTPService.generate_otp()
            OTPService.store_otp(request.email, otp_code, 'login')
            email_sent = OTPService.send_email(request.email, otp_code, 'login')
            if not email_sent:
                raise HTTPException(status_code=500, detail="Failed to send OTP email")
            return {"message": f"OTP sent successfully to {request.email} for login",
                    "success": True, "data": {"email": request.email}}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate OTP: {str(e)}")


@router.post("/verify", response_model=MessageResponse)
async def verify_otp(request: OTPVerifyRequest):
    try:
        is_valid, message = OTPService.verify_otp(request.email, request.otp_code, request.purpose)
        if not is_valid:
            raise HTTPException(status_code=400, detail=message)

        if request.purpose == 'registration':
            query = "SELECT id, is_verified FROM users WHERE LOWER(email) = :1"
            result = db.fetch_one(query, (request.email,))
            if not result:
                raise HTTPException(status_code=404, detail="User not found. Please register first.")
            user_id, is_verified = result
            if is_verified == 'Y':
                return {"message": "Email already verified. Please login.",
                        "success": True, "data": {"email": request.email}}
            db.execute_query("UPDATE users SET is_verified = 'Y' WHERE LOWER(email) = :1", (request.email,))
            return {"message": "Email verified successfully! You can now login.",
                    "success": True, "data": {"email": request.email}}

        elif request.purpose == 'login':
            return {"message": "OTP verified successfully! Login complete.",
                    "success": True, "data": {"email": request.email}}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OTP verification failed: {str(e)}")


@router.post("/resend", response_model=MessageResponse)
async def resend_otp(request: OTPRequest):
    try:
        if request.purpose == 'registration':
            query = "SELECT id, is_verified FROM users WHERE LOWER(email) = :1"
            result = db.fetch_one(query, (request.email,))
            if not result:
                raise HTTPException(status_code=404, detail="User not found. Please register first.")
            user_id, is_verified = result
            if is_verified == 'Y':
                raise HTTPException(status_code=400, detail="Email already verified. Please login instead.")
            OTPService.invalidate_old_otps(request.email, 'registration')

        elif request.purpose == 'login':
            query = "SELECT id, is_verified FROM users WHERE LOWER(email) = :1"
            result = db.fetch_one(query, (request.email,))
            if not result:
                raise HTTPException(status_code=404, detail="User not found. Please register first.")
            user_id, is_verified = result
            if is_verified == 'N':
                raise HTTPException(status_code=403, detail="Email not verified. Please verify your email first.")
            OTPService.invalidate_old_otps(request.email, 'login')

        otp_code = OTPService.generate_otp()
        OTPService.store_otp(request.email, otp_code, request.purpose)
        email_sent = OTPService.send_email(request.email, otp_code, request.purpose)
        if not email_sent:
            raise HTTPException(status_code=500, detail="Failed to send OTP email")

        return {"message": f"New OTP sent successfully to {request.email} for {request.purpose}",
                "success": True, "data": {"email": request.email}}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to resend OTP: {str(e)}")


@router.post("/validate", response_model=MessageResponse)
async def validate_otp(request: OTPVerifyRequest):
    try:
        query = """
            SELECT id, expires_at, is_used
            FROM otp_codes
            WHERE email = :1 AND otp_code = :2 AND purpose = :3 AND is_used = 'N'
            ORDER BY created_at DESC
            FETCH FIRST 1 ROW ONLY
        """
        result = db.fetch_one(query, (request.email, request.otp_code, request.purpose))
        if not result:
            raise HTTPException(status_code=400, detail="Invalid OTP")
        otp_id, expires_at, is_used = result
        if datetime.now() > expires_at:
            raise HTTPException(status_code=400, detail="OTP has expired")
        return {"message": "OTP is valid", "success": True,
                "data": {"email": request.email, "purpose": request.purpose}}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OTP validation failed: {str(e)}")


@router.get("/check-verification/{email}", response_model=UserVerificationStatus)
async def check_verification_status(email: str):
    try:
        query = "SELECT is_verified FROM users WHERE LOWER(email) = :1"
        result = db.fetch_one(query, (email,))
        if not result:
            raise HTTPException(status_code=404, detail="User not found")
        is_verified = result[0]
        is_verified_bool = is_verified == 'Y'
        return UserVerificationStatus(
            email=email,
            is_verified=is_verified_bool,
            status="verified" if is_verified_bool else "unverified",
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to check verification status: {str(e)}")


# NOTE: The /invalidate/{email} endpoint has been REMOVED for security reasons.
# It allowed any unauthenticated caller to invalidate another user's OTPs.
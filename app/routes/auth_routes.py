from fastapi import APIRouter, HTTPException, status, Depends, Request,Response
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials
from app.schemas import (
    RegistrationRequest,
    LoginRequest,
    OTPVerifyRequest,
    TokenResponse,
    MessageResponse,
    RefreshTokenRequest,
    UserProfileResponse,
    UpdateProfileRequest,
    CustomerNumberRequest,
    AccountNumberRequest,
    CustomerNumberResponse,
    CheckCustomerNumberRequest,
    CheckCustomerNumberResponse,
    AssociateProfileRequest,
    AssociationRecord,
    AssociationListResponse,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    AuditLogRequest,
    # Loan APIs
    LoanListRequest,
    LoanListItem,
    LoanListResponse,
    LoanDetailRequest,
    LoanSummaryRecord,
    LoanSummaryResponse,
    LoanHistoryRecord,
    LoanHistoryResponse,
    LoanRepaymentRecord,
    LoanRepaymentResponse,
    # statement
    StatementRequest, 
    StatementDownloadRequest,
)
from app.database import db
from app.auth import AuthService
from app.otp import OTPService
from app.customer_service import CustomerService
from app.admin_auth import bearer_scheme
from app.config import Config
from app.rate_limiter import login_limiter
from app import auth_logger
import oracledb
import secrets
from datetime import datetime, timedelta
from typing import Optional
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Authorization header required",
                            headers={"WWW-Authenticate": "Bearer"})
    try:
        token = credentials.credentials
        payload = AuthService.decode_token(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid or expired access token")
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        if AuthService.is_token_blacklisted(token, "access"):
            raise HTTPException(status_code=401, detail="Token has been revoked")
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        result = db.fetch_one("SELECT is_locked FROM users WHERE LOWER(email) = :1", (email,))
        if result and result[0] == 'Y':
            raise HTTPException(status_code=403, detail="Your account has been locked. Please contact support.")
        return email
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")


# ============================================================
# REGISTER
# ============================================================
@router.post("/register", response_model=MessageResponse)
async def register(request: RegistrationRequest, http: Request):
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        existing = db.fetch_one("SELECT id, is_verified FROM users WHERE LOWER(email) = :1", (request.email,))

        if existing:
            user_id, is_verified = existing
            if is_verified == 'N':
                can_send, _ = OTPService.can_resend(request.email, 'registration', 60)
                if can_send:
                    OTPService.invalidate_old_otps(request.email, 'registration')
                    otp_code = OTPService.generate_otp()
                    OTPService.store_otp(request.email, otp_code, 'registration')
                    OTPService.send_email_async(request.email, otp_code, 'registration')

                auth_logger.log_event(
                    "auth.register.pending_verify",
                    email=request.email, ip=ip, user_agent=ua, request_id=rid,
                    http_method="POST", http_path="/api/v1/auth/register", http_status=400,
                    success=False,
                    details={"reason": "already_registered_unverified"},
                )
                raise HTTPException(
                    status_code=400,
                    detail=("This email is already registered but not yet verified. "
                            "A new OTP has been sent to your email. "
                            "Please check your inbox and verify your account. "
                            "Note: your original password is still valid.")
                )

            auth_logger.log_event(
                "auth.register.duplicate",
                email=request.email, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/auth/register", http_status=400,
                success=False,
                details={"reason": "already_registered_verified"},
            )
            raise HTTPException(status_code=400, detail="Email already registered")

        if request.phone_number:
            phone_exists = db.fetch_one(
                "SELECT email FROM users WHERE phone_number = :1", (request.phone_number,)
            )
            if phone_exists:
                auth_logger.log_event(
                    "auth.register.duplicate_phone",
                    email=request.email, ip=ip, user_agent=ua, request_id=rid,
                    http_method="POST", http_path="/api/v1/auth/register", http_status=400,
                    success=False,
                    details={"reason": "phone_in_use"},
                )
                raise HTTPException(status_code=400,
                                    detail="This phone number is already registered to another account.")

        hashed_password = AuthService.hash_password(request.password)
        cursor = db.connection.cursor()
        id_var = cursor.var(oracledb.NUMBER)
        cursor.execute("""
            INSERT INTO users (email, password_hash, full_name, phone_number, is_verified, is_locked)
            VALUES (:1, :2, :3, :4, 'N', 'N')
            RETURNING id INTO :5
        """, (request.email, hashed_password, request.full_name,
              request.phone_number, id_var))
        db.connection.commit()
        cursor.close()

        otp_code = OTPService.generate_otp()
        OTPService.store_otp(request.email, otp_code, 'registration')
        OTPService.send_email_async(request.email, otp_code, 'registration')

        auth_logger.log_event(
            "auth.register.success",
            email=request.email, user_name=request.full_name,
            ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/auth/register", http_status=200,
            success=True,
            details={"phone": request.phone_number},
        )

        return {
            "message": "Registration successful. Please verify your email with OTP to get access tokens.",
            "success": True,
            "data": {"email": request.email, "full_name": request.full_name},
        }
    except HTTPException:
        raise
    except oracledb.IntegrityError as e:
        error, = e.args
        auth_logger.log_event(
            "auth.register.error",
            email=request.email, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/auth/register", http_status=500,
            success=False, severity="error", error=error.message,
        )
        if "UK_USERS_PHONE" in (error.message or "").upper() or "phone" in (error.message or "").lower():
            raise HTTPException(status_code=400, detail="This phone number is already registered.")
        raise HTTPException(status_code=500, detail="Registration failed.")
    except Exception as e:
        auth_logger.log_event(
            "auth.register.error",
            email=request.email, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/auth/register", http_status=500,
            success=False, severity="error", error=str(e),
        )
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


# ============================================================
# VERIFY REGISTRATION OTP
# ============================================================
@router.post("/verify-otp", response_model=dict)
async def verify_otp(request: OTPVerifyRequest, http: Request):
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        is_valid, message = OTPService.verify_otp(request.email, request.otp_code, 'registration')
        if not is_valid:
            auth_logger.log_event(
                "auth.verify_otp.failed",
                email=request.email, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/auth/verify-otp", http_status=400,
                success=False,
                details={"reason": message},
            )
            if "expired" in message.lower():
                raise HTTPException(status_code=400, detail={
                    "message": message,
                    "action": "resend_available",
                    "resend_endpoint": "/api/v1/otp/resend",
                    "resend_payload": {"email": request.email, "purpose": "registration"},
                })
            raise HTTPException(status_code=400, detail=message)

        result = db.fetch_one("""
            SELECT id, is_verified, is_locked FROM users WHERE LOWER(email) = :1
        """, (request.email,))
        if not result:
            raise HTTPException(status_code=404, detail="User not found")

        user_id, is_verified, is_locked = result
        if is_locked == 'Y':
            raise HTTPException(status_code=403, detail="Your account has been locked. Please contact support.")

        if is_verified == 'N':
            db.execute_query("UPDATE users SET is_verified = 'Y' WHERE LOWER(email) = :1", (request.email,))

        access_token = AuthService.create_access_token({"sub": request.email})
        refresh_token = AuthService.create_refresh_token({"sub": request.email})

        auth_logger.log_event(
            "auth.verify_otp.success",
            email=request.email, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/auth/verify-otp", http_status=200,
            success=True,
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "email": request.email,
            "is_verified": True,
            "expires_in": Config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_expires_in": Config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            "message": "Email verified and tokens generated successfully",
        }
    except HTTPException:
        raise
    except Exception as e:
        auth_logger.log_event(
            "auth.verify_otp.error",
            email=request.email, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/auth/verify-otp", http_status=500,
            success=False, severity="error", error=str(e),
        )
        raise HTTPException(status_code=500, detail=f"OTP verification failed: {str(e)}")


# ============================================================
# LOGIN
# ============================================================
@router.post("/login", response_model=MessageResponse)
async def login(request: LoginRequest, http: Request):
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)
    rate_key = f"login:{request.email}:{ip}"

    locked, wait_seconds = login_limiter.is_locked(rate_key)
    if locked:
        auth_logger.log_event(
            "auth.login.blocked",
            email=request.email, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/auth/login", http_status=429,
            success=False, severity="warn",
            details={"reason": "rate_limit", "wait_seconds": wait_seconds},
        )
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Please try again in {wait_seconds} seconds.",
        )

    try:
        user = db.fetch_one("""
            SELECT id, email, password_hash, is_verified, is_locked, locked_reason
            FROM users WHERE LOWER(email) = :1
        """, (request.email,))

        if not user:
            login_limiter.record_attempt(
                rate_key,
                Config.LOGIN_WINDOW_MINUTES * 60,
                Config.LOGIN_MAX_ATTEMPTS,
                Config.LOGIN_LOCKOUT_MINUTES * 60,
            )
            auth_logger.log_event(
                "auth.login.failed",
                email=request.email, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/auth/login", http_status=401,
                success=False,
                details={"reason": "unknown_email"},
            )
            raise HTTPException(status_code=401, detail="Invalid credentials")

        user_id, email, password_hash, is_verified, is_locked, locked_reason = user

        if not AuthService.verify_password(request.password, password_hash):
            login_limiter.record_attempt(
                rate_key,
                Config.LOGIN_WINDOW_MINUTES * 60,
                Config.LOGIN_MAX_ATTEMPTS,
                Config.LOGIN_LOCKOUT_MINUTES * 60,
            )
            auth_logger.log_event(
                "auth.login.failed",
                email=request.email, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/auth/login", http_status=401,
                success=False,
                details={"reason": "invalid_password"},
            )
            raise HTTPException(status_code=401, detail="Invalid credentials")

        login_limiter.reset(rate_key)

        if is_locked == 'Y':
            auth_logger.log_event(
                "auth.login.blocked",
                email=email, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/auth/login", http_status=403,
                success=False, severity="warn",
                details={"reason": "account_locked"},
            )
            reason_msg = f" Reason: {locked_reason}" if locked_reason else ""
            raise HTTPException(status_code=403,
                                detail=f"Your account has been locked. Please contact support.{reason_msg}")

        if is_verified == 'N':
            can_send, wait2 = OTPService.can_resend(email, 'registration', 60)
            if can_send:
                OTPService.invalidate_old_otps(email, 'registration')
                otp_code = OTPService.generate_otp()
                OTPService.store_otp(email, otp_code, 'registration')
                OTPService.send_email_async(email, otp_code, 'registration')

                auth_logger.log_event(
                    "auth.login.unverified_otp_sent",
                    email=email, ip=ip, user_agent=ua, request_id=rid,
                    http_method="POST", http_path="/api/v1/auth/login", http_status=403,
                    success=False,
                    details={"reason": "not_verified_otp_sent"},
                )
                raise HTTPException(status_code=403,
                                    detail="Your email is not yet verified. A fresh OTP has been sent to your email. "
                                           "Please check your inbox, then verify your account.")
            else:
                auth_logger.log_event(
                    "auth.login.unverified_throttled",
                    email=email, ip=ip, user_agent=ua, request_id=rid,
                    http_method="POST", http_path="/api/v1/auth/login", http_status=403,
                    success=False,
                    details={"reason": "not_verified_throttled", "wait_seconds": wait2},
                )
                raise HTTPException(status_code=403,
                                    detail=f"Your email is not yet verified. Please wait {wait2}s to request another OTP.")

        otp_code = OTPService.generate_otp()
        OTPService.store_otp(email, otp_code, 'login')
        OTPService.send_email_async(email, otp_code, 'login')

        auth_logger.log_event(
            "auth.login.otp_sent",
            email=email, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/auth/login", http_status=200,
            success=True,
        )

        return {
            "message": "Login successful. OTP sent to your email. Verify to get access tokens.",
            "success": True,
            "data": {"email": email},
        }
    except HTTPException:
        raise
    except Exception as e:
        auth_logger.log_event(
            "auth.login.error",
            email=request.email, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/auth/login", http_status=500,
            success=False, severity="error", error=str(e),
        )
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")


# ============================================================
# VERIFY LOGIN OTP
# ============================================================
@router.post("/verify-login-otp", response_model=dict)
async def verify_login_otp(request: OTPVerifyRequest, http: Request):
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        is_valid, message = OTPService.verify_otp(request.email, request.otp_code, 'login')
        if not is_valid:
            auth_logger.log_event(
                "auth.verify_login_otp.failed",
                email=request.email, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/auth/verify-login-otp", http_status=400,
                success=False,
                details={"reason": message},
            )
            raise HTTPException(status_code=400, detail=message)

        result = db.fetch_one("SELECT is_verified, is_locked FROM users WHERE LOWER(email) = :1", (request.email,))
        if not result:
            raise HTTPException(status_code=404, detail="User not found")

        is_verified, is_locked = result
        if is_locked == 'Y':
            raise HTTPException(status_code=403, detail="Your account has been locked. Please contact support.")

        access_token = AuthService.create_access_token({"sub": request.email})
        refresh_token = AuthService.create_refresh_token({"sub": request.email})

        auth_logger.log_event(
            "auth.login.success",
            email=request.email, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/auth/verify-login-otp", http_status=200,
            success=True,
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "email": request.email,
            "is_verified": is_verified == 'Y',
            "expires_in": Config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_expires_in": Config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            "message": "Login verified and tokens generated successfully",
        }
    except HTTPException:
        raise
    except Exception as e:
        auth_logger.log_event(
            "auth.verify_login_otp.error",
            email=request.email, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/auth/verify-login-otp", http_status=500,
            success=False, severity="error", error=str(e),
        )
        raise HTTPException(status_code=500, detail=f"Login OTP verification failed: {str(e)}")


# ============================================================
# REFRESH TOKEN
# ============================================================
@router.post("/refresh", response_model=dict)
async def refresh_token(request: RefreshTokenRequest, http: Request):
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        result = AuthService.refresh_access_token(request.refresh_token)
        if not result:
            auth_logger.log_event(
                "auth.refresh.failed",
                ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/auth/refresh", http_status=401,
                success=False,
                details={"reason": "invalid_or_expired_refresh_token"},
            )
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

        email = result["email"]
        check = db.fetch_one("SELECT is_locked FROM users WHERE LOWER(email) = :1", (email,))
        if check and check[0] == 'Y':
            raise HTTPException(status_code=403, detail="Your account has been locked. Please contact support.")

        return {
            "access_token": result["access_token"],
            "token_type": result["token_type"],
            "email": result["email"],
            "expires_in": result["expires_in"],
            "message": "Access token refreshed successfully",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token refresh failed: {str(e)}")


# ============================================================
# FORGOT PASSWORD
# ============================================================
@router.post("/forgot-password", response_model=MessageResponse)
async def customer_forgot_password(request: ForgotPasswordRequest, http: Request):
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        user = db.fetch_one("SELECT id, full_name FROM users WHERE LOWER(email) = :1", (request.email,))

        generic_response = {
            "message": "If your email is registered, a password reset link has been sent.",
            "success": True,
        }

        if not user:
            auth_logger.log_event(
                "auth.password_reset.requested",
                email=request.email, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/auth/forgot-password", http_status=200,
                success=True,
                details={"note": "email_not_found"},
            )
            return generic_response

        user_id, full_name = user
        token = secrets.token_urlsafe(48)
        expires_at = datetime.now() + timedelta(hours=24)

        db.execute_query("""
            UPDATE users
            SET reset_token = :1, reset_token_expires_at = :2, updated_at = CURRENT_TIMESTAMP
            WHERE LOWER(email) = :3
        """, (token, expires_at, request.email))

        reset_link = f"{Config.FRONTEND_BASE_URL}{Config.CUSTOMER_RESET_PATH}?token={token}"
        OTPService.send_password_reset_email_async(
            request.email, reset_link, "customer_password_reset", recipient_name=full_name
        )

        auth_logger.log_event(
            "auth.password_reset.requested",
            email=request.email, user_name=full_name,
            ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/auth/forgot-password", http_status=200,
            success=True,
        )

        return generic_response
    except Exception as e:
        logger.error(f"Forgot password failed: {e}")
        return {
            "message": "If your email is registered, a password reset link has been sent.",
            "success": True,
        }


# ============================================================
# RESET PASSWORD
# ============================================================
@router.post("/reset-password", response_model=MessageResponse)
async def customer_reset_password(request: ResetPasswordRequest, http: Request):
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        result = db.fetch_one("""
            SELECT email, reset_token_expires_at FROM users WHERE reset_token = :1
        """, (request.token,))

        if not result:
            auth_logger.log_event(
                "auth.password_reset.failed",
                ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/auth/reset-password", http_status=400,
                success=False,
                details={"reason": "invalid_token"},
            )
            raise HTTPException(status_code=400, detail="Invalid or expired reset token")

        email, expires_at = result
        if datetime.now() > expires_at:
            auth_logger.log_event(
                "auth.password_reset.failed",
                email=email, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/auth/reset-password", http_status=400,
                success=False,
                details={"reason": "token_expired"},
            )
            raise HTTPException(status_code=400, detail="Reset token has expired. Please request a new one.")

        hashed = AuthService.hash_password(request.new_password)
        db.execute_query("""
            UPDATE users
            SET password_hash = :1, reset_token = NULL, reset_token_expires_at = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE LOWER(email) = :2
        """, (hashed, email))

        auth_logger.log_event(
            "auth.password_reset.completed",
            email=email, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/auth/reset-password", http_status=200,
            success=True,
        )

        return {
            "message": "Password reset successfully. You can now login with your new password.",
            "success": True,
            "data": {"email": email},
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Password reset failed: {str(e)}")


# ============================================================
# LOGOUT
# ============================================================
@router.post("/logout", response_model=MessageResponse)
async def logout(
    http: Request,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    refresh_token: Optional[str] = None,
):
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)
    email = None

    try:
        if credentials:
            token = credentials.credentials
            payload = AuthService.decode_token(token)
            if payload:
                email = payload.get("sub")
                expires_at = datetime.fromtimestamp(payload.get("exp"))
                db.execute_query("""
                    INSERT INTO access_token_blacklist (token, email, expires_at)
                    VALUES (:1, :2, :3)
                """, (token, email, expires_at))

        if refresh_token:
            payload = AuthService.decode_token(refresh_token)
            if payload:
                email = payload.get("sub") or email
                expires_at = datetime.fromtimestamp(payload.get("exp"))
                db.execute_query("""
                    INSERT INTO refresh_token_blacklist (token, email, expires_at)
                    VALUES (:1, :2, :3)
                """, (refresh_token, email, expires_at))

        auth_logger.log_event(
            "auth.logout.success",
            email=email, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/auth/logout", http_status=200,
            success=True,
        )

        return {"message": "Logged out successfully", "success": True,
                "data": {"email": email or "unknown"}}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Logout failed: {str(e)}")


# ============================================================
# GET PROFILE
# ============================================================
@router.get("/profile", response_model=UserProfileResponse)
async def get_profile(current_user: str = Depends(get_current_user)):
    try:
        user = db.fetch_one("""
            SELECT id, email, full_name, phone_number, profile, customer_no,
                   is_verified, is_locked, created_at
            FROM users WHERE LOWER(email) = :1
        """, (current_user,))
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user_id, email, full_name, phone_number, profile, customer_no, is_verified, is_locked, created_at = user

        return UserProfileResponse(
            id=user_id, email=email, full_name=full_name, phone_number=phone_number,
            profile=profile, customer_no=customer_no, is_verified=is_verified == 'Y',
            is_locked=is_locked or 'N', created_at=created_at,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get profile: {str(e)}")


# ============================================================
# UPDATE PROFILE
# ============================================================
@router.put("/profile", response_model=MessageResponse)
async def update_profile(request: UpdateProfileRequest, current_user: str = Depends(get_current_user)):
    try:
        update_fields = []
        params = []

        if request.full_name is not None:
            update_fields.append("full_name = :1")
            params.append(request.full_name)

        if request.phone_number is not None:
            phone_exists = db.fetch_one("""
                SELECT email FROM users WHERE phone_number = :1 AND LOWER(email) != :2
            """, (request.phone_number, current_user))
            if phone_exists:
                raise HTTPException(status_code=400,
                                    detail="This phone number is already registered to another account.")
            update_fields.append("phone_number = :2")
            params.append(request.phone_number)

        if not update_fields:
            raise HTTPException(status_code=400, detail="No fields to update")

        params.append(current_user)
        update_query = f"""
            UPDATE users
            SET {', '.join(update_fields)}, updated_at = CURRENT_TIMESTAMP
            WHERE LOWER(email) = :{len(params)}
        """
        db.execute_query(update_query, tuple(params))

        return {
            "message": "Profile updated successfully",
            "success": True,
            "data": {"email": current_user,
                     "updated_fields": [f.split('=')[0].strip() for f in update_fields]},
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update profile: {str(e)}")


# ============================================================
# GET CUSTOMER INFO (AUTH-GATED)
# ============================================================
@router.post("/get-customer-info", response_model=CustomerNumberResponse)
async def get_customer_info_by_email(
    request: CustomerNumberRequest,
    current_user: str = Depends(get_current_user),
):
    try:
        user = CustomerService.get_user_by_email(request.email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return CustomerNumberResponse(
            email=user['email'], customer_no=user['customer_no'], profile=user['profile'],
            account_name=None, account_number=None,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get customer info: {str(e)}")


# ============================================================
# CHECK CUSTOMER NUMBER (AUTH-GATED)
# ============================================================
@router.post("/check-customer-number", response_model=CheckCustomerNumberResponse)
async def check_customer_number(
    request: CheckCustomerNumberRequest,
    current_user: str = Depends(get_current_user),
):
    try:
        result = db.fetch_one("""
            SELECT email, customer_name FROM associate_profile
            WHERE customer_no = :1 AND status = 'PROFILED'
            FETCH FIRST 1 ROW ONLY
        """, (request.customer_number,))

        if result:
            return CheckCustomerNumberResponse(
                customer_number=request.customer_number,
                is_linked=True,
                linked_email=result[0],
                linked_name=result[1],
                message=f"This customer number is already linked to {result[0]}",
            )
        return CheckCustomerNumberResponse(
            customer_number=request.customer_number,
            is_linked=False,
            message="This customer number is available",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to check customer number: {str(e)}")


# ============================================================
# GET USER BY CUSTOMER NUMBER (AUTH-GATED)
# ============================================================
@router.get("/user-by-customer/{customer_number}", response_model=dict)
async def get_user_by_customer_number(
    customer_number: str,
    current_user: str = Depends(get_current_user),
):
    try:
        user = CustomerService.get_user_by_customer_number(customer_number)
        if not user:
            raise HTTPException(status_code=404, detail="No user found with this customer number")
        return {
            "email": user['email'], "full_name": user['full_name'],
            "phone_number": user['phone_number'], "profile": user['profile'],
            "customer_no": user['customer_no'], "is_verified": user['is_verified'],
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get user: {str(e)}")


# ============================================================
# ASSOCIATE PROFILE
# ============================================================
@router.post("/associate-profile", response_model=MessageResponse)
async def associate_profile(
    request: AssociateProfileRequest,
    http: Request,
    current_user: str = Depends(get_current_user),
):
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        result = CustomerService.submit_profile_association(
            email=current_user,
            account_number=request.account_number,
            submitted_by=current_user,
            corebank_email_lookup=request.email,
        )
        if not result['success']:
            auth_logger.log_event(
                "customer.association.submit_failed",
                email=current_user, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/auth/associate-profile", http_status=400,
                success=False,
                details={"reason": result['message'], "account_number": request.account_number},
            )
            raise HTTPException(status_code=400, detail=result['message'])

        record = result.get('record') or {}

        auth_logger.log_event(
            "customer.association.submitted",
            email=current_user, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/auth/associate-profile", http_status=200,
            success=True,
            target=f"association:{record.get('id')}",
            details={"account_number": request.account_number, "customer_no": record.get('customer_no')},
        )

        return {
            "message": result['message'],
            "success": True,
            "data": {
                "id": record.get('id'),
                "email": record.get('email'),
                "account_number": record.get('account_number'),
                "customer_no": record.get('customer_no'),
                "customer_name": record.get('customer_name'),
                "disbursement_limit": record.get('disbursement_limit'),
                "corebank_email": record.get('corebank_email'),
                "corebank_category": record.get('corebank_category'),
                "corebank_branch": record.get('corebank_branch'),
                "corebank_cust_id": record.get('corebank_cust_id'),
                "status": record.get('status'),
                "submitted_by": record.get('submitted_by'),
                "reviewed_by": record.get('reviewed_by'),
                "reviewed_at": record.get('reviewed_at'),
                "review_notes": record.get('review_notes'),
                "is_verified": record.get('is_verified'),
                "profile": record.get('profile'),
                "created_at": record.get('created_at'),
                "updated_at": record.get('updated_at'),
            },
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to submit association: {str(e)}")


# ============================================================
# MY ASSOCIATIONS
# ============================================================
@router.get("/my-associations", response_model=AssociationListResponse)
async def my_associations(
    status: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
    current_user: str = Depends(get_current_user),
):
    try:
        result = CustomerService.list_associations(
            status=status, email=current_user, page=page, page_size=page_size
        )
        records = []
        for r in result['records']:
            records.append(AssociationRecord(
                id=r['id'], email=r['email'], account_number=r['account_number'],
                customer_no=r['customer_no'], customer_name=r.get('customer_name'),
                corebank_email=r.get('corebank_email'),
                corebank_category=r.get('corebank_category'),
                corebank_branch=r.get('corebank_branch'),
                corebank_cust_id=r.get('corebank_cust_id'),
                addr_line_1=r.get('addr_line_1'), city=r.get('city'),
                state=r.get('state'), country=r.get('country'),
                primary_officer_name=r.get('primary_officer_name'),
                registration_no=r.get('registration_no'),
                registration_dt=r.get('registration_dt'),
                bu_nm=r.get('bu_nm'), industry_desc=r.get('industry_desc'),
                cust_seg_desc=r.get('cust_seg_desc'),
                disbursement_limit=r.get('disbursement_limit'),
                term_cd=r.get('term_cd'), term_value=r.get('term_value'),
                ref_desc=r.get('ref_desc'), rec_st=r.get('rec_st'),
                status=r['status'], submitted_by=r.get('submitted_by'),
                reviewed_by=r.get('reviewed_by'), reviewed_at=r.get('reviewed_at'),
                review_notes=r.get('review_notes'),
                is_verified=r.get('is_verified'), profile=r.get('profile'),
                created_at=r.get('created_at'), updated_at=r.get('updated_at'),
            ))
        return AssociationListResponse(total=result['total'], records=records)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch associations: {str(e)}")


# ============================================================
# AUDIT LOG
# ============================================================
@router.post("/audit-log", response_model=MessageResponse)
async def create_audit_log(
    request_body: AuditLogRequest,
    request: Request,
    current_user: str = Depends(get_current_user),
):
    try:
        ip_address = auth_logger.get_client_ip(request)

        result = CustomerService.create_audit_log(
            email=current_user,
            action=request_body.action,
            page=request_body.page,
            when_logged=request_body.when,
            ip_address=ip_address,
        )
        if not result['success']:
            raise HTTPException(status_code=500, detail=result['message'])

        return {
            "message": "Audit log recorded.",
            "success": True,
            "data": {
                "id": result.get('id'),
                "email": result.get('email'),
                "user_name": result.get('user_name'),
            },
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create audit log: {str(e)}")


# ============================================================
# LOAN LIST
# ============================================================
@router.post("/loan-list", response_model=LoanListResponse)
async def loan_list(
    request: LoanListRequest,
    http: Request,
    current_user: str = Depends(get_current_user),
):
    """
    Return the customer's list of loans.
    The customer number must match the logged-in user's own customer_no.
    """
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        # Ownership check
        if not CustomerService.customer_owns_customer_no(current_user, request.cust_num):
            auth_logger.log_event(
                "customer.loan.list.denied",
                email=current_user, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/auth/loan-list", http_status=403,
                success=False,
                details={"reason": "not_owner", "cust_num": request.cust_num},
            )
            raise HTTPException(
                status_code=403,
                detail="You do not have access to this customer number.",
            )

        loans = CustomerService.fetch_loan_list(request.cust_num)

        if not loans:
            auth_logger.log_event(
                "customer.loan.list.success",
                email=current_user, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/auth/loan-list", http_status=200,
                success=True,
                details={"cust_num": request.cust_num, "count": 0},
            )
            return LoanListResponse(total=0, loans=[])

        items = [LoanListItem(
            account_number=l['account_number'],
            rec_st=l['rec_st'],
            status=l['status'],
            product_description=l['product_description'],
        ) for l in loans]

        auth_logger.log_event(
            "customer.loan.list.success",
            email=current_user, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/auth/loan-list", http_status=200,
            success=True,
            details={"cust_num": request.cust_num, "count": len(items)},
        )

        return LoanListResponse(total=len(items), loans=items)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch loan list: {str(e)}")


# ============================================================
# LOAN SUMMARY  (token-only, no ownership check)
# ============================================================
@router.post("/loan-summary", response_model=LoanSummaryResponse)
async def loan_summary(
    request: LoanDetailRequest,
    http: Request,
    current_user: str = Depends(get_current_user),
):
    """
    Return the loan summary for the given loan account.
    Customer must hold a valid token. No ownership re-check   a verified
    customer may have multiple loan accounts beyond the one on file.
    """
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        summary = CustomerService.fetch_loan_summary(request.loan_account)

        if not summary:
            auth_logger.log_event(
                "customer.loan.summary.empty",
                email=current_user, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/auth/loan-summary", http_status=200,
                success=True,
                details={"loan_account": request.loan_account, "found": False},
            )
            return LoanSummaryResponse(loan_account=request.loan_account, summary=None)

        auth_logger.log_event(
            "customer.loan.summary.success",
            email=current_user, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/auth/loan-summary", http_status=200,
            success=True,
            details={"loan_account": request.loan_account},
        )

        return LoanSummaryResponse(
            loan_account=request.loan_account,
            summary=LoanSummaryRecord(**summary),
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch loan summary: {str(e)}")


# ============================================================
# LOAN HISTORY  (token-only, no ownership check)
# ============================================================
@router.post("/loan-history", response_model=LoanHistoryResponse)
async def loan_history(
    request: LoanDetailRequest,
    http: Request,
    current_user: str = Depends(get_current_user),
):
    """
    Return loan history for the given loan account.
    Customer must hold a valid token. No ownership re-check.
    """
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        records = CustomerService.fetch_loan_history(request.loan_account)

        if not records:
            auth_logger.log_event(
                "customer.loan.history.empty",
                email=current_user, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/auth/loan-history", http_status=200,
                success=True,
                details={"loan_account": request.loan_account, "count": 0},
            )
            return LoanHistoryResponse(loan_account=request.loan_account, total=0, records=[])

        items = [LoanHistoryRecord(**r) for r in records]

        auth_logger.log_event(
            "customer.loan.history.success",
            email=current_user, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/auth/loan-history", http_status=200,
            success=True,
            details={"loan_account": request.loan_account, "count": len(items)},
        )

        return LoanHistoryResponse(
            loan_account=request.loan_account,
            total=len(items),
            records=items,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch loan history: {str(e)}")


# ============================================================
# LOAN REPAYMENT SCHEDULE  (token-only, no ownership check)
# ============================================================
@router.post("/loan-repayment", response_model=LoanRepaymentResponse)
async def loan_repayment(
    request: LoanDetailRequest,
    http: Request,
    current_user: str = Depends(get_current_user),
):
    """
    Return loan repayment schedule for the given loan account.
    Customer must hold a valid token. No ownership re-check.
    """
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        records = CustomerService.fetch_loan_repayment(request.loan_account)

        if not records:
            auth_logger.log_event(
                "customer.loan.repayment.empty",
                email=current_user, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/auth/loan-repayment", http_status=200,
                success=True,
                details={"loan_account": request.loan_account, "count": 0},
            )
            return LoanRepaymentResponse(loan_account=request.loan_account, total=0, records=[])

        items = [LoanRepaymentRecord(**r) for r in records]

        auth_logger.log_event(
            "customer.loan.repayment.success",
            email=current_user, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/auth/loan-repayment", http_status=200,
            success=True,
            details={"loan_account": request.loan_account, "count": len(items)},
        )

        return LoanRepaymentResponse(
            loan_account=request.loan_account,
            total=len(items),
            records=items,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch loan repayment schedule: {str(e)}")



# ============================================================
# CUSTOMER - STATEMENT LIST
# ============================================================
@router.post("/statement-list")
async def customer_statement_list(
    request: StatementRequest,
    current_user: str = Depends(get_current_user),
):
    try:
        result = CustomerService.fetch_statements(request.acc_no)
        if result is None:
            raise HTTPException(status_code=404, detail="No statements found or API error.")
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch statements: {str(e)}")


# ============================================================
# CUSTOMER - STATEMENT VIEW (STREAM)
# ============================================================
@router.post("/statement-view")
async def customer_statement_view(
    request: StatementDownloadRequest,
    current_user: str = Depends(get_current_user),
):
    try:
        pdf_bytes = CustomerService.download_statement_pdf(request.date, request.filename)
        if not pdf_bytes:
            raise HTTPException(status_code=404, detail="Could not fetch the statement file.")

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'inline; filename="{request.filename}"'}
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"View failed: {str(e)}")
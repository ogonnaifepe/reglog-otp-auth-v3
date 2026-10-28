from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials
from datetime import datetime, timedelta
from app.schemas import (
    AdminRegisterRequest,
    AdminLoginRequest,
    AdminOTPVerifyRequest,
    AdminOTPResendRequest,
    AdminForgotPasswordRequest,
    AdminResetPasswordRequest,
    AdminResponse,
    AdminListResponse,
    MessageResponse,
    RefreshTokenRequest,
    AuditLogListResponse,
    AuditLogRecord,
)
from app.admin_auth import AdminAuthService, bearer_scheme
from app.customer_service import CustomerService
from app.database import db
from app.config import Config
from app.otp import OTPService
from app import auth_logger
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/admin", tags=["Admin Authentication"])


def get_current_admin(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Authorization header required",
                            headers={"WWW-Authenticate": "Bearer"})
    try:
        token = credentials.credentials
        payload = AdminAuthService.decode_token(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        if payload.get("user_type") != "admin":
            raise HTTPException(status_code=401, detail="Not an admin token")
        if AdminAuthService.is_admin_token_blacklisted(token):
            raise HTTPException(status_code=401, detail="Token has been revoked")
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return email
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")


def require_super_admin(current_admin: str = Depends(get_current_admin)):
    admin = AdminAuthService.get_admin_by_email(current_admin)
    if not admin or admin['role'] != 'super_admin':
        raise HTTPException(status_code=403, detail="Super admin access required")
    return current_admin


# ============================================================
# ADMIN REGISTER (super admin only)
# ============================================================
@router.post("/register", response_model=MessageResponse)
async def admin_register(
    request: AdminRegisterRequest,
    http: Request,
    current_admin: str = Depends(require_super_admin),
):
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        existing = AdminAuthService.get_admin_by_email(request.email)
        if existing:
            auth_logger.log_event(
                "admin.create.duplicate",
                email=current_admin, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/admin/register", http_status=400,
                success=False,
                details={"new_admin_email": request.email},
            )
            raise HTTPException(status_code=400, detail="Admin email already registered")

        result = AdminAuthService.create_admin(
            full_name=request.full_name,
            email=request.email,
            password=request.password,
            role=request.role,
        )
        if not result['success']:
            raise HTTPException(status_code=500, detail=result['message'])

        auth_logger.log_event(
            "admin.create.success",
            email=current_admin, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/admin/register", http_status=200,
            success=True,
            target=f"admin:{request.email}",
            details={"new_admin_email": request.email, "role": request.role},
        )

        return {
            "message": "Admin registered. Check your email for the OTP to verify your account.",
            "success": True,
            "data": {"email": request.email, "role": request.role, "next_step": "verify-otp"},
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Admin registration failed: {str(e)}")


# ============================================================
# ADMIN VERIFY REGISTRATION OTP
# ============================================================
@router.post("/verify-otp", response_model=dict)
async def admin_verify_otp(request: AdminOTPVerifyRequest, http: Request):
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        if request.purpose != 'registration':
            raise HTTPException(status_code=400, detail="Use purpose='registration' on this endpoint")

        is_valid, message = OTPService.verify_otp(request.email, request.otp_code, 'registration')
        if not is_valid:
            auth_logger.log_event(
                "admin.verify_otp.failed",
                email=request.email, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/admin/verify-otp", http_status=400,
                success=False,
                details={"reason": message},
            )
            if "expired" in message.lower():
                raise HTTPException(status_code=400, detail={
                    "message": message,
                    "action": "resend_available",
                    "resend_endpoint": "/api/v1/admin/resend-otp",
                    "resend_payload": {"email": request.email, "purpose": "registration"},
                })
            raise HTTPException(status_code=400, detail=message)

        admin = AdminAuthService.get_admin_by_email(request.email)
        if not admin:
            raise HTTPException(status_code=404, detail="Admin not found")
        if admin['is_active'] != 'Y':
            raise HTTPException(status_code=403, detail="Admin account is deactivated")

        if admin['is_verified'] != 'Y':
            AdminAuthService.mark_admin_verified(request.email)

        access_token = AdminAuthService.create_access_token({
            "sub": request.email, "user_type": "admin", "role": admin['role'],
        })
        refresh_token = AdminAuthService.create_refresh_token({
            "sub": request.email, "user_type": "admin", "role": admin['role'],
        })

        auth_logger.log_event(
            "admin.verify_otp.success",
            email=request.email, user_name=admin['full_name'],
            ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/admin/verify-otp", http_status=200,
            success=True,
            details={"role": admin['role']},
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "email": request.email,
            "role": admin['role'],
            "full_name": admin['full_name'],
            "is_verified": True,
            "expires_in": Config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_expires_in": Config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            "message": "Admin verified and tokens generated successfully",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Admin OTP verification failed: {str(e)}")


# ============================================================
# ADMIN LOGIN (step 1)
# ============================================================
@router.post("/login", response_model=MessageResponse)
async def admin_login(request: AdminLoginRequest, http: Request):
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        admin = AdminAuthService.get_admin_by_email(request.email)
        if not admin:
            auth_logger.log_event(
                "admin.login.failed",
                email=request.email, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/admin/login", http_status=401,
                success=False,
                details={"reason": "unknown_email"},
            )
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if admin['is_active'] != 'Y':
            auth_logger.log_event(
                "admin.login.blocked",
                email=request.email, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/admin/login", http_status=403,
                success=False, severity="warn",
                details={"reason": "deactivated"},
            )
            raise HTTPException(status_code=403, detail="Admin account is deactivated")
        if not AdminAuthService.verify_password(request.password, admin['password_hash']):
            auth_logger.log_event(
                "admin.login.failed",
                email=request.email, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/admin/login", http_status=401,
                success=False,
                details={"reason": "invalid_password"},
            )
            raise HTTPException(status_code=401, detail="Invalid credentials")

        if admin['is_verified'] != 'Y':
            can_send, _ = OTPService.can_resend(request.email, 'registration', 60)
            if can_send:
                OTPService.invalidate_old_otps(request.email, 'registration')
                otp_code = OTPService.generate_otp()
                OTPService.store_otp(request.email, otp_code, 'registration')
                OTPService.send_email_async(request.email, otp_code, 'registration', user_type='admin')

            auth_logger.log_event(
                "admin.login.unverified",
                email=request.email, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/admin/login", http_status=403,
                success=False,
                details={"reason": "not_verified"},
            )
            raise HTTPException(status_code=403,
                                detail="This admin account is not yet verified. A new registration OTP "
                                       "has been sent to your email. Please verify first.")

        otp_code = OTPService.generate_otp()
        OTPService.store_otp(request.email, otp_code, 'login')
        OTPService.send_email_async(request.email, otp_code, 'login', user_type='admin')

        auth_logger.log_event(
            "admin.login.otp_sent",
            email=request.email, user_name=admin['full_name'],
            ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/admin/login", http_status=200,
            success=True,
        )

        return {
            "message": "Credentials verified. OTP sent to your email. Complete login via /api/v1/admin/verify-login-otp.",
            "success": True,
            "data": {"email": request.email, "next_step": "verify-login-otp"},
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Admin login failed: {str(e)}")


# ============================================================
# ADMIN VERIFY LOGIN OTP (step 2)
# ============================================================
@router.post("/verify-login-otp", response_model=dict)
async def admin_verify_login_otp(request: AdminOTPVerifyRequest, http: Request):
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        if request.purpose != 'login':
            raise HTTPException(status_code=400, detail="Use purpose='login' on this endpoint")

        is_valid, message = OTPService.verify_otp(request.email, request.otp_code, 'login')
        if not is_valid:
            auth_logger.log_event(
                "admin.verify_login_otp.failed",
                email=request.email, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/admin/verify-login-otp", http_status=400,
                success=False,
                details={"reason": message},
            )
            if "expired" in message.lower():
                raise HTTPException(status_code=400, detail={
                    "message": message,
                    "action": "resend_available",
                    "resend_endpoint": "/api/v1/admin/resend-otp",
                    "resend_payload": {"email": request.email, "purpose": "login"},
                })
            raise HTTPException(status_code=400, detail=message)

        admin = AdminAuthService.get_admin_by_email(request.email)
        if not admin:
            raise HTTPException(status_code=404, detail="Admin not found")
        if admin['is_active'] != 'Y':
            raise HTTPException(status_code=403, detail="Admin account is deactivated")

        AdminAuthService.update_admin_last_login(request.email)

        access_token = AdminAuthService.create_access_token({
            "sub": request.email, "user_type": "admin", "role": admin['role'],
        })
        refresh_token = AdminAuthService.create_refresh_token({
            "sub": request.email, "user_type": "admin", "role": admin['role'],
        })

        auth_logger.log_event(
            "admin.login.success",
            email=request.email, user_name=admin['full_name'],
            ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/admin/verify-login-otp", http_status=200,
            success=True,
            details={"role": admin['role']},
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "email": request.email,
            "role": admin['role'],
            "full_name": admin['full_name'],
            "is_verified": admin['is_verified'] == 'Y',
            "expires_in": Config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_expires_in": Config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            "message": "Admin login verified and tokens generated successfully",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Admin login OTP verification failed: {str(e)}")


# ============================================================
# ADMIN RESEND OTP
# ============================================================
@router.post("/resend-otp", response_model=MessageResponse)
async def admin_resend_otp(request: AdminOTPResendRequest, http: Request):
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        admin = AdminAuthService.get_admin_by_email(request.email)
        if not admin:
            raise HTTPException(status_code=404, detail="Admin not found")
        if admin['is_active'] != 'Y':
            raise HTTPException(status_code=403, detail="Admin account is deactivated")

        if request.purpose == 'registration':
            if admin['is_verified'] == 'Y':
                raise HTTPException(status_code=400, detail="Admin is already verified. Please login.")
        elif request.purpose == 'login':
            if admin['is_verified'] != 'Y':
                raise HTTPException(status_code=400, detail="Admin is not yet verified. Please verify first.")

        can_send, wait_seconds = OTPService.can_resend(request.email, request.purpose, 60)
        if not can_send:
            raise HTTPException(status_code=429,
                                detail=f"Please wait {wait_seconds} seconds before requesting another OTP.")

        OTPService.invalidate_old_otps(request.email, request.purpose)
        otp_code = OTPService.generate_otp()
        OTPService.store_otp(request.email, otp_code, request.purpose)
        OTPService.send_email_async(request.email, otp_code, request.purpose, user_type='admin')

        auth_logger.log_event(
            "admin.otp.resent",
            email=request.email, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/admin/resend-otp", http_status=200,
            success=True,
            details={"purpose": request.purpose},
        )

        return {
            "message": f"A new OTP has been sent to {request.email}.",
            "success": True,
            "data": {"email": request.email, "purpose": request.purpose},
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to resend OTP: {str(e)}")


# ============================================================
# ADMIN FORGOT PASSWORD
# ============================================================
@router.post("/forgot-password", response_model=MessageResponse)
async def admin_forgot_password(request: AdminForgotPasswordRequest, http: Request):
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        admin = AdminAuthService.get_admin_by_email(request.email)
        if not admin:
            auth_logger.log_event(
                "admin.password_reset.requested",
                email=request.email, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/admin/forgot-password", http_status=200,
                success=True,
                details={"note": "email_not_found"},
            )
            return {"message": "If the email exists, a reset link has been sent", "success": True}

        token = AdminAuthService.generate_reset_token()
        expires_at = datetime.now() + timedelta(hours=24)
        AdminAuthService.store_admin_reset_token(request.email, token, expires_at)

        reset_link = f"{Config.FRONTEND_BASE_URL}{Config.ADMIN_RESET_PATH}?token={token}"
        OTPService.send_password_reset_email_async(
            request.email, reset_link, "admin_password_reset", recipient_name=admin['full_name']
        )

        auth_logger.log_event(
            "admin.password_reset.requested",
            email=request.email, user_name=admin['full_name'],
            ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/admin/forgot-password", http_status=200,
            success=True,
        )

        return {
            "message": "If the email exists, a reset link has been sent",
            "success": True,
            "data": {"reset_link": reset_link},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process request: {str(e)}")


# ============================================================
# ADMIN RESET PASSWORD
# ============================================================
@router.post("/reset-password", response_model=MessageResponse)
async def admin_reset_password(request: AdminResetPasswordRequest, http: Request):
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        email = AdminAuthService.verify_admin_reset_token(request.token)
        if not email:
            auth_logger.log_event(
                "admin.password_reset.failed",
                ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/admin/reset-password", http_status=400,
                success=False,
                details={"reason": "invalid_token"},
            )
            raise HTTPException(status_code=400, detail="Invalid or expired reset token")

        result = AdminAuthService.update_admin_password(email, request.new_password)
        if not result:
            raise HTTPException(status_code=500, detail="Failed to reset password")

        auth_logger.log_event(
            "admin.password_reset.completed",
            email=email, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/admin/reset-password", http_status=200,
            success=True,
        )

        return {"message": "Password reset successfully. You can now login.",
                "success": True, "data": {"email": email}}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Password reset failed: {str(e)}")


# ============================================================
# LIST ADMINS
# ============================================================
@router.get("/list", response_model=AdminListResponse)
async def list_admins(current_admin: str = Depends(require_super_admin)):
    try:
        results = AdminAuthService.list_admins()
        admins = []
        for r in results:
            admins.append(AdminResponse(
                id=r[0], email=r[1], full_name=r[2], role=r[3], is_active=r[4],
                is_verified=r[5] or 'N', last_login=r[6], created_at=r[7],
            ))
        return AdminListResponse(total=len(admins), admins=admins)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list admins: {str(e)}")


# ============================================================
# ADMIN PROFILE
# ============================================================
@router.get("/profile", response_model=AdminResponse)
async def get_admin_profile(current_admin: str = Depends(get_current_admin)):
    try:
        admin = AdminAuthService.get_admin_by_email(current_admin)
        if not admin:
            raise HTTPException(status_code=404, detail="Admin not found")

        cursor = db.connection.cursor()
        cursor.execute("SELECT created_at FROM admins WHERE LOWER(email) = :1", (current_admin,))
        row = cursor.fetchone()
        cursor.close()

        return AdminResponse(
            id=admin['id'], email=admin['email'], full_name=admin['full_name'],
            role=admin['role'], is_active=admin['is_active'],
            is_verified=admin['is_verified'], last_login=admin['last_login'],
            created_at=row[0] if row else datetime.now(),
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get profile: {str(e)}")


# ============================================================
# LOGOUT
# ============================================================
@router.post("/logout", response_model=MessageResponse)
async def admin_logout(
    http: Request,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        if not credentials:
            raise HTTPException(status_code=401, detail="Authorization header required")
        token = credentials.credentials
        payload = AdminAuthService.decode_token(token)
        if payload:
            email = payload.get("sub")
            expires_at = datetime.fromtimestamp(payload.get("exp"))
            AdminAuthService.blacklist_admin_token(token, email, expires_at)

            auth_logger.log_event(
                "admin.logout.success",
                email=email, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/admin/logout", http_status=200,
                success=True,
            )

        return {"message": "Logged out successfully", "success": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Logout failed: {str(e)}")


# ============================================================
# REFRESH
# ============================================================
@router.post("/refresh", response_model=dict)
async def admin_refresh_token(request: RefreshTokenRequest):
    try:
        from app.auth import AuthService
        result = AuthService.refresh_access_token(request.refresh_token)
        if not result:
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

        admin = AdminAuthService.get_admin_by_email(result["email"])
        role = admin['role'] if admin else None

        return {
            "access_token": result["access_token"],
            "token_type": result["token_type"],
            "email": result["email"],
            "role": role,
            "expires_in": result["expires_in"],
            "message": "Token refreshed successfully",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token refresh failed: {str(e)}")


# ============================================================
# ADMIN - LIST AUDIT LOGS
# ============================================================
@router.get("/audit-logs", response_model=AuditLogListResponse)
async def list_audit_logs(
    email: str = None,
    action: str = None,
    page: str = None,
    date_from: datetime = None,
    date_to: datetime = None,
    ip_address: str = None,
    page_num: int = 1,
    page_size: int = 20,
    current_admin: str = Depends(get_current_admin),
):
    try:
        if page_num < 1:
            page_num = 1
        if page_size < 1:
            page_size = 20
        if page_size > 100:
            page_size = 100

        result = CustomerService.list_audit_logs(
            email=email, action=action, page=page,
            date_from=date_from, date_to=date_to,
            ip_address=ip_address,
            page_num=page_num, page_size=page_size,
        )

        records = []
        for r in result['records']:
            records.append(AuditLogRecord(
                id=r['id'], email=r['email'], user_name=r.get('user_name'),
                action=r['action'], page=r.get('page'),
                when_logged=r.get('when_logged'), created_at=r.get('created_at'),
                ip_address=r.get('ip_address'),
            ))

        return AuditLogListResponse(
            total=result['total'], page=page_num, page_size=page_size, records=records,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list audit logs: {str(e)}")
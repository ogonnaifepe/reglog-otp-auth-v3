from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.config import Config
from app.database import db
from app.otp import OTPService
import logging
import secrets

logger = logging.getLogger(__name__)

bearer_scheme = HTTPBearer(auto_error=False)


class AdminAuthService:
    # ============================================================
    # JWT / PASSWORD (delegates to AuthService)
    # ============================================================
    @staticmethod
    def create_access_token(data: dict) -> str:
        from app.auth import AuthService
        return AuthService.create_access_token(data)

    @staticmethod
    def create_refresh_token(data: dict) -> str:
        from app.auth import AuthService
        return AuthService.create_refresh_token(data)

    @staticmethod
    def decode_token(token: str) -> dict:
        from app.auth import AuthService
        return AuthService.decode_token(token)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        from app.auth import AuthService
        return AuthService.verify_password(plain_password, hashed_password)

    @staticmethod
    def hash_password(password: str) -> str:
        from app.auth import AuthService
        return AuthService.hash_password(password)

    # ============================================================
    # BLACKLIST
    # ============================================================
    @staticmethod
    def is_admin_token_blacklisted(token: str) -> bool:
        try:
            result = db.fetch_one("SELECT id FROM admin_token_blacklist WHERE token = :1", (token,))
            return result is not None
        except Exception as e:
            logger.error(f"Failed to check admin token blacklist: {e}")
            return False

    @staticmethod
    def blacklist_admin_token(token: str, email: str, expires_at: datetime) -> bool:
        try:
            db.execute_query("""
                INSERT INTO admin_token_blacklist (token, email, expires_at)
                VALUES (:1, :2, :3)
            """, (token, email, expires_at))
            return True
        except Exception as e:
            logger.error(f"Failed to blacklist admin token: {e}")
            return False

    # ============================================================
    # ADMIN LOOKUP
    # ============================================================
    @staticmethod
    def get_admin_by_email(email: str):
        try:
            normalized = email.strip().lower() if email else email
            result = db.fetch_one("""
                SELECT id, email, password_hash, full_name, role, is_active,
                       is_verified, otp_verified_at, last_login
                FROM admins WHERE LOWER(email) = :1
            """, (normalized,))
            if result:
                return {
                    'id': result[0],
                    'email': result[1],
                    'password_hash': result[2],
                    'full_name': result[3],
                    'role': result[4],
                    'is_active': result[5],
                    'is_verified': result[6] or 'N',
                    'otp_verified_at': result[7],
                    'last_login': result[8],
                }
            return None
        except Exception as e:
            logger.error(f"Failed to get admin: {e}")
            return None

    @staticmethod
    def update_admin_last_login(email: str) -> bool:
        try:
            db.execute_query(
                "UPDATE admins SET last_login = CURRENT_TIMESTAMP WHERE LOWER(email) = :1",
                (email,)
            )
            return True
        except Exception as e:
            logger.error(f"Failed to update admin last login: {e}")
            return False

    # ============================================================
    # ADMIN OTP REGISTRATION
    # ============================================================
    @staticmethod
    def create_admin(full_name: str, email: str, password: str, role: str = 'admin') -> dict:
        """Create admin with is_verified='N' and send registration OTP."""
        try:
            email = email.strip().lower() if email else email
            hashed = AdminAuthService.hash_password(password)

            db.execute_query("""
                INSERT INTO admins (email, password_hash, full_name, role, is_active, is_verified)
                VALUES (:1, :2, :3, :4, 'Y', 'N')
            """, (email, hashed, full_name, role))

            otp_code = OTPService.generate_otp()
            OTPService.store_otp(email, otp_code, 'registration')
            OTPService.send_email_async(email, otp_code, 'registration', user_type='admin')

            return {'success': True, 'message': 'Admin created. OTP sent to email for verification.'}
        except Exception as e:
            logger.error(f"Failed to create admin: {e}")
            return {'success': False, 'message': str(e)}

    @staticmethod
    def mark_admin_verified(email: str) -> bool:
        try:
            db.execute_query("""
                UPDATE admins
                SET is_verified = 'Y',
                    otp_verified_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE LOWER(email) = :1
            """, (email,))
            return True
        except Exception as e:
            logger.error(f"Failed to mark admin verified: {e}")
            return False

    # ============================================================
    # ADMIN FORGOT PASSWORD
    # ============================================================
    @staticmethod
    def generate_reset_token() -> str:
        return secrets.token_urlsafe(48)

    @staticmethod
    def store_admin_reset_token(email: str, token: str, expires_at: datetime) -> bool:
        try:
            db.execute_query("""
                UPDATE admins
                SET reset_token = :1, reset_token_expires_at = :2
                WHERE LOWER(email) = :3
            """, (token, expires_at, email))
            return True
        except Exception as e:
            logger.error(f"Failed to store admin reset token: {e}")
            return False

    @staticmethod
    def verify_admin_reset_token(token: str):
        try:
            result = db.fetch_one("""
                SELECT email, reset_token_expires_at
                FROM admins WHERE reset_token = :1
            """, (token,))
            if not result:
                return None
            email, expires_at = result
            if datetime.now() > expires_at:
                return None
            return email
        except Exception as e:
            logger.error(f"Failed to verify admin reset token: {e}")
            return None

    @staticmethod
    def update_admin_password(email: str, new_password: str) -> bool:
        try:
            hashed = AdminAuthService.hash_password(new_password)
            db.execute_query("""
                UPDATE admins
                SET password_hash = :1,
                    reset_token = NULL,
                    reset_token_expires_at = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE LOWER(email) = :2
            """, (hashed, email))
            return True
        except Exception as e:
            logger.error(f"Failed to update admin password: {e}")
            return False

    # ============================================================
    # LIST ADMINS
    # ============================================================
    @staticmethod
    def list_admins():
        try:
            results = db.fetch_all("""
                SELECT id, email, full_name, role, is_active, is_verified,
                       last_login, created_at
                FROM admins ORDER BY created_at DESC
            """)
            return results or []
        except Exception as e:
            logger.error(f"Failed to list admins: {e}")
            return []
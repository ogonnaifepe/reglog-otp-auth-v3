from fastapi import APIRouter, HTTPException, status, Depends, Header
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
    CustomerNumberResponse
)
from app.database import db
from app.auth import AuthService
from app.otp import OTPService
from app.customer_service import CustomerService
from app.config import Config
import oracledb
from datetime import datetime
from typing import Optional

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required"
        )
    
    try:
        token = authorization.replace("Bearer ", "")
        payload = AuthService.decode_token(token)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired access token"
            )
        
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        if AuthService.is_token_blacklisted(token, "access"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked"
            )
        
        email = payload.get("sub")
        if not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload"
            )
        
        return email
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {str(e)}"
        )

@router.post("/token", response_model=dict)
async def generate_token(request: LoginRequest):
    try:
        query = "SELECT id, email, password_hash, is_verified FROM users WHERE email = :1"
        user = db.fetch_one(query, (request.email,))
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        user_id, email, password_hash, is_verified = user
        
        if not AuthService.verify_password(request.password, password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        if is_verified == 'N':
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Email not verified. Please verify your email first."
            )
        
        access_token = AuthService.create_access_token({"sub": email})
        refresh_token = AuthService.create_refresh_token({"sub": email})
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "email": email,
            "expires_in": Config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_expires_in": Config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            "message": "Tokens generated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token generation failed: {str(e)}"
        )

@router.post("/refresh", response_model=dict)
async def refresh_token(request: RefreshTokenRequest):
    try:
        result = AuthService.refresh_access_token(request.refresh_token)
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token"
            )
        
        return {
            "access_token": result["access_token"],
            "token_type": result["token_type"],
            "email": result["email"],
            "expires_in": result["expires_in"],
            "message": "Access token refreshed successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token refresh failed: {str(e)}"
        )

@router.post("/register", response_model=MessageResponse)
async def register(request: RegistrationRequest):
    try:
        check_query = "SELECT id FROM users WHERE email = :1"
        existing = db.fetch_one(check_query, (request.email,))
        
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        hashed_password = AuthService.hash_password(request.password)
        
        insert_query = """
            INSERT INTO users (email, password_hash, full_name, phone_number, is_verified)
            VALUES (:1, :2, :3, :4, 'N')
            RETURNING id INTO :5
        """
        
        cursor = db.connection.cursor()
        id_var = cursor.var(oracledb.NUMBER)
        cursor.execute(insert_query, (
            request.email, 
            hashed_password, 
            request.full_name, 
            request.phone_number, 
            id_var
        ))
        db.connection.commit()
        cursor.close()
        
        otp_code = OTPService.generate_otp()
        OTPService.store_otp(request.email, otp_code, 'registration')
        email_sent = OTPService.send_email(request.email, otp_code, 'registration')
        
        if not email_sent:
            delete_query = "DELETE FROM users WHERE email = :1"
            db.execute_query(delete_query, (request.email,))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send OTP email. Registration cancelled."
            )
        
        return {
            "message": "Registration successful. Please verify your email with OTP to get access tokens.",
            "success": True,
            "data": {
                "email": request.email,
                "full_name": request.full_name
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )

@router.post("/verify-otp", response_model=dict)
async def verify_otp(request: OTPVerifyRequest):
    try:
        is_valid, message = OTPService.verify_otp(
            request.email, 
            request.otp_code, 
            'registration'
        )
        
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message
            )
        
        check_query = "SELECT id, is_verified FROM users WHERE email = :1"
        result = db.fetch_one(check_query, (request.email,))
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        user_id, is_verified = result
        
        if is_verified == 'N':
            update_query = "UPDATE users SET is_verified = 'Y' WHERE email = :1"
            db.execute_query(update_query, (request.email,))
        
        access_token = AuthService.create_access_token({"sub": request.email})
        refresh_token = AuthService.create_refresh_token({"sub": request.email})
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "email": request.email,
            "is_verified": True,
            "expires_in": Config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_expires_in": Config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            "message": "Email verified and tokens generated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"OTP verification failed: {str(e)}"
        )

@router.post("/login", response_model=MessageResponse)
async def login(request: LoginRequest):
    try:
        query = "SELECT id, email, password_hash, is_verified FROM users WHERE email = :1"
        user = db.fetch_one(query, (request.email,))
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        user_id, email, password_hash, is_verified = user
        
        if not AuthService.verify_password(request.password, password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        if is_verified == 'N':
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Email not verified. Please verify your email first."
            )
        
        otp_code = OTPService.generate_otp()
        OTPService.store_otp(email, otp_code, 'login')
        email_sent = OTPService.send_email(email, otp_code, 'login')
        
        if not email_sent:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send OTP email"
            )
        
        return {
            "message": "Login successful. OTP sent to your email. Verify to get access tokens.",
            "success": True,
            "data": {"email": email}
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}"
        )

@router.post("/verify-login-otp", response_model=dict)
async def verify_login_otp(request: OTPVerifyRequest):
    try:
        is_valid, message = OTPService.verify_otp(
            request.email, 
            request.otp_code, 
            'login'
        )
        
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message
            )
        
        query = "SELECT is_verified FROM users WHERE email = :1"
        result = db.fetch_one(query, (request.email,))
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        is_verified = result[0]
        
        access_token = AuthService.create_access_token({"sub": request.email})
        refresh_token = AuthService.create_refresh_token({"sub": request.email})
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "email": request.email,
            "is_verified": is_verified == 'Y',
            "expires_in": Config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_expires_in": Config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            "message": "Login verified and tokens generated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login OTP verification failed: {str(e)}"
        )

@router.post("/logout", response_model=MessageResponse)
async def logout(
    authorization: Optional[str] = Header(None),
    refresh_token: Optional[str] = None
):
    try:
        email = None
        
        if authorization:
            token = authorization.replace("Bearer ", "")
            payload = AuthService.decode_token(token)
            
            if payload:
                email = payload.get("sub")
                expires_at = datetime.fromtimestamp(payload.get("exp"))
                
                query = """
                    INSERT INTO access_token_blacklist (token, email, expires_at)
                    VALUES (:1, :2, :3)
                """
                db.execute_query(query, (token, email, expires_at))
        
        if refresh_token:
            payload = AuthService.decode_token(refresh_token)
            if payload:
                email = payload.get("sub") or email
                expires_at = datetime.fromtimestamp(payload.get("exp"))
                
                query = """
                    INSERT INTO refresh_token_blacklist (token, email, expires_at)
                    VALUES (:1, :2, :3)
                """
                db.execute_query(query, (refresh_token, email, expires_at))
        
        return {
            "message": f"Logged out successfully",
            "success": True,
            "data": {"email": email or "unknown"}
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Logout failed: {str(e)}"
        )

@router.get("/profile", response_model=UserProfileResponse)
async def get_profile(current_user: str = Depends(get_current_user)):
    try:
        query = "SELECT id, email, full_name, phone_number, profile, customer_no, is_verified, created_at FROM users WHERE email = :1"
        user = db.fetch_one(query, (current_user,))
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        user_id, email, full_name, phone_number, profile, customer_no, is_verified, created_at = user
        
        return UserProfileResponse(
            id=user_id,
            email=email,
            full_name=full_name,
            phone_number=phone_number,
            profile=profile,
            customer_no=customer_no,
            is_verified=is_verified == 'Y',
            created_at=created_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get profile: {str(e)}"
        )

@router.put("/profile", response_model=MessageResponse)
async def update_profile(
    request: UpdateProfileRequest,
    current_user: str = Depends(get_current_user)
):
    try:
        update_fields = []
        params = []
        
        if request.full_name is not None:
            update_fields.append("full_name = :1")
            params.append(request.full_name)
        
        if request.phone_number is not None:
            update_fields.append("phone_number = :2")
            params.append(request.phone_number)
        
        if not update_fields:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No fields to update"
            )
        
        params.append(current_user)
        
        update_query = f"""
            UPDATE users 
            SET {', '.join(update_fields)}, updated_at = CURRENT_TIMESTAMP
            WHERE email = :{len(params)}
        """
        
        db.execute_query(update_query, tuple(params))
        
        return {
            "message": "Profile updated successfully",
            "success": True,
            "data": {
                "email": current_user,
                "updated_fields": [f.split('=')[0].strip() for f in update_fields]
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update profile: {str(e)}"
        )

# ============================================================
# NEW ENDPOINT 1: Get User Profile and Customer Info by Email
# ============================================================
@router.post("/get-customer-info", response_model=CustomerNumberResponse)
async def get_customer_info_by_email(request: CustomerNumberRequest):
    """
    Get user's profile and customer_no by email
    """
    try:
        user = CustomerService.get_user_by_email(request.email)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return CustomerNumberResponse(
            email=user['email'],
            customer_no=user['customer_no'],
            profile=user['profile'],
            account_name=None,
            account_number=None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get customer info: {str(e)}"
        )

# ============================================================
# NEW ENDPOINT 2: Link Customer Profile with Email
# ============================================================
@router.post("/link-customer-by-email", response_model=MessageResponse)
async def link_customer_by_email(
    account_number: str,
    email: str
):
    """
    Call external API with account number, get customer number,
    and update the specified user's profile and customer_no
    """
    try:
        # Step 1: Check if user exists
        user = CustomerService.get_user_by_email(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found with this email"
            )
        
        # Step 2: Call external API
        customer_data = CustomerService.get_customer_number_by_account(account_number)
        
        if not customer_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Customer not found for the provided account number"
            )
        
        # Step 3: Update user with customer info
        updated = CustomerService.update_user_with_customer_info(
            email=email,
            customer_number=customer_data['customer_number'],
            account_name=customer_data['account_name'],
            account_number=customer_data['account_number']
        )
        
        if not updated:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update user with customer information"
            )
        
        return {
            "message": "Customer profile linked successfully",
            "success": True,
            "data": {
                "email": email,
                "customer_no": customer_data['customer_number'],
                "account_name": customer_data['account_name'],
                "account_number": customer_data['account_number'],
                "profile": "Y"
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to link customer profile: {str(e)}"
        )
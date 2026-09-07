from pydantic import BaseModel, EmailStr, Field, validator
from typing import Literal, Optional
from datetime import datetime

class RegistrationRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=255)
    email: EmailStr
    phone_number: Optional[str] = Field(None, max_length=20)
    password: str = Field(..., min_length=8)
    confirm_password: str = Field(..., min_length=8)
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v
    
    @validator('phone_number')
    def validate_phone(cls, v):
        if v is not None:
            cleaned = ''.join(filter(str.isdigit, v))
            if len(cleaned) < 10 or len(cleaned) > 15:
                raise ValueError('Phone number must be between 10 and 15 digits')
        return v

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class OTPRequest(BaseModel):
    email: EmailStr
    purpose: Literal['registration', 'login']

class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp_code: str = Field(..., min_length=6, max_length=6)
    purpose: Literal['registration', 'login']

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    email: str
    is_verified: bool

class MessageResponse(BaseModel):
    message: str
    success: bool
    data: Optional[dict] = None

class UserVerificationStatus(BaseModel):
    email: str
    is_verified: bool
    status: str

class UserProfileResponse(BaseModel):
    id: int
    email: str
    full_name: Optional[str] = None
    phone_number: Optional[str] = None
    profile: str  # 'Y' or 'N'
    customer_no: Optional[str] = None
    is_verified: bool
    created_at: datetime

class UpdateProfileRequest(BaseModel):
    full_name: Optional[str] = Field(None, min_length=2, max_length=255)
    phone_number: Optional[str] = Field(None, max_length=20)

class CustomerNumberRequest(BaseModel):
    email: EmailStr

class AccountNumberRequest(BaseModel):
    account_number: str = Field(..., min_length=10, description="Account number to lookup")

class ExternalCustomerResponse(BaseModel):
    accountName: str
    accountNumber: str
    customerNumber: str

class CustomerNumberResponse(BaseModel):
    email: str
    customer_no: Optional[str] = None
    profile: str
    account_name: Optional[str] = None
    account_number: Optional[str] = None
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Literal, Optional, List
from datetime import datetime


# ============================================================
# MIXIN: normalize email (strip + lowercase)
# ============================================================
class EmailNormalizer(BaseModel):
    @validator('email', check_fields=False)
    def _normalize_email(cls, v):
        return v.strip().lower() if v else v


# ==================== CUSTOMER SCHEMAS ====================
class RegistrationRequest(EmailNormalizer):
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


class LoginRequest(EmailNormalizer):
    email: EmailStr
    password: str


class OTPRequest(EmailNormalizer):
    email: EmailStr
    purpose: Literal['registration', 'login']


class OTPVerifyRequest(EmailNormalizer):
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
    profile: str
    customer_no: Optional[str] = None
    is_verified: bool
    is_locked: str
    created_at: datetime


class UpdateProfileRequest(BaseModel):
    full_name: Optional[str] = Field(None, min_length=2, max_length=255)
    phone_number: Optional[str] = Field(None, max_length=20)


class CustomerNumberRequest(EmailNormalizer):
    email: EmailStr


class AccountNumberRequest(BaseModel):
    account_number: str = Field(..., min_length=6, max_length=20)


class CustomerNumberResponse(BaseModel):
    email: str
    customer_no: Optional[str] = None
    profile: str
    account_name: Optional[str] = None
    account_number: Optional[str] = None


class CheckCustomerNumberRequest(BaseModel):
    customer_number: str = Field(..., min_length=6)


class CheckCustomerNumberResponse(BaseModel):
    customer_number: str
    is_linked: bool
    linked_email: Optional[str] = None
    linked_name: Optional[str] = None
    message: str


# ==================== PASSWORD RESET (CUSTOMER) ====================
class ForgotPasswordRequest(EmailNormalizer):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)
    confirm_password: str = Field(..., min_length=8)

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v


# ==================== ADMIN SCHEMAS ====================
class AdminRegisterRequest(EmailNormalizer):
    full_name: str = Field(..., min_length=2, max_length=255)
    email: EmailStr
    password: str = Field(..., min_length=8)
    confirm_password: str = Field(..., min_length=8)
    role: Literal['super_admin', 'admin', 'viewer'] = 'admin'

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v


class AdminLoginRequest(EmailNormalizer):
    email: EmailStr
    password: str


class AdminOTPVerifyRequest(EmailNormalizer):
    email: EmailStr
    otp_code: str = Field(..., min_length=6, max_length=6)
    purpose: Literal['registration', 'login']


class AdminOTPResendRequest(EmailNormalizer):
    email: EmailStr
    purpose: Literal['registration', 'login']


class AdminForgotPasswordRequest(EmailNormalizer):
    email: EmailStr


class AdminResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)
    confirm_password: str = Field(..., min_length=8)

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v


class AdminResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    is_active: str
    is_verified: str
    last_login: Optional[datetime] = None
    created_at: datetime


class AdminListResponse(BaseModel):
    total: int
    admins: List[AdminResponse]


# ==================== ADMIN CUSTOMER MANAGEMENT ====================
class AdminRegisterCustomerRequest(EmailNormalizer):
    full_name: str = Field(..., min_length=2, max_length=255)
    email: EmailStr
    phone_number: Optional[str] = Field(None, max_length=20)


class AdminLockCustomerRequest(EmailNormalizer):
    email: EmailStr
    reason: Optional[str] = Field(None, max_length=500)


class AdminResetCustomerPasswordRequest(EmailNormalizer):
    email: EmailStr


class CustomerListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    customers: List[UserProfileResponse]


class CustomerSetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)
    confirm_password: str = Field(..., min_length=8)

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v


# ==================== ASSOCIATE PROFILE ====================
class AssociateProfileRequest(EmailNormalizer):
    account_number: str = Field(..., min_length=6, max_length=20)
    email: EmailStr


class AdminAssociateProfileRequest(EmailNormalizer):
    account_number: str = Field(..., min_length=6, max_length=20)
    email: EmailStr


class ApproveAssociationRequest(BaseModel):
    assoc_id: int
    review_notes: Optional[str] = Field(None, max_length=500)


class InvalidAssociationRequest(BaseModel):
    assoc_id: int
    review_notes: Optional[str] = Field(None, max_length=500)


class DissociateRequest(BaseModel):
    assoc_id: int
    review_notes: Optional[str] = Field(None, max_length=500)


class AssociationRecord(BaseModel):
    id: int
    email: str
    account_number: str
    customer_no: str
    customer_name: Optional[str] = None
    corebank_email: Optional[str] = None
    corebank_category: Optional[str] = None
    corebank_branch: Optional[str] = None
    corebank_cust_id: Optional[int] = None
    addr_line_1: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    primary_officer_name: Optional[str] = None
    registration_no: Optional[str] = None
    registration_dt: Optional[str] = None
    bu_nm: Optional[str] = None
    industry_desc: Optional[str] = None
    cust_seg_desc: Optional[str] = None
    disbursement_limit: Optional[float] = None
    term_cd: Optional[str] = None
    term_value: Optional[int] = None
    ref_desc: Optional[str] = None
    rec_st: Optional[str] = None
    status: str
    submitted_by: Optional[str] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None
    review_notes: Optional[str] = None
    is_verified: Optional[bool] = None
    profile: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class AssociationListResponse(BaseModel):
    total: int
    records: List[AssociationRecord]


# ==================== AUDIT TRAIL ====================
class AuditLogRequest(BaseModel):
    action: str = Field(..., min_length=1, max_length=255)
    page: Optional[str] = Field(None, max_length=500)
    when: Optional[datetime] = Field(None)


class AuditLogRecord(BaseModel):
    id: int
    email: str
    user_name: Optional[str] = None
    action: str
    page: Optional[str] = None
    when_logged: Optional[str] = None
    created_at: Optional[str] = None
    ip_address: Optional[str] = None


class AuditLogListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    records: List[AuditLogRecord]


# ==================== LOAN APIS ====================
class LoanListRequest(BaseModel):
    """Request body for POST /api/v1/auth/loan-list."""
    cust_num: str = Field(..., min_length=4, max_length=20, description="Customer number")


class LoanListItem(BaseModel):
    account_number: Optional[str] = None
    rec_st: Optional[str] = None
    status: Optional[str] = None
    product_description: Optional[str] = None


class LoanListResponse(BaseModel):
    total: int
    loans: List[LoanListItem]


class LoanDetailRequest(BaseModel):
    """Common request for summary, history, and repayment."""
    loan_account: str = Field(..., min_length=6, max_length=20, description="Loan account number")


class LoanSummaryRecord(BaseModel):
    account_number: Optional[str] = None
    account_name: Optional[str] = None
    overdue_principal: Optional[float] = None
    overdue_interest: Optional[float] = None
    due_principal: Optional[float] = None
    due_interest: Optional[float] = None
    total_principal_outstanding: Optional[float] = None
    total_interest_outstanding: Optional[float] = None
    principal_paid: Optional[float] = None
    interest_paid: Optional[float] = None
    total_paid: Optional[float] = None
    total_overdue: Optional[float] = None
    total_due_next: Optional[float] = None
    total_outstanding_all: Optional[float] = None
    total_due_now: Optional[float] = None
    original_loan_amount: Optional[float] = None
    charges: Optional[float] = None
    interest_rate: Optional[float] = None
    account_id: Optional[int] = None
    term_value: Optional[int] = None
    term_cd: Optional[str] = None
    cleared_balance: Optional[float] = None
    dr_int_accrued: Optional[float] = None
    last_accrual_date: Optional[str] = None
    dr_int_per_day: Optional[float] = None
    dr_int_accrued_ytd: Optional[float] = None
    total_charges: Optional[float] = None
    account_status: Optional[str] = None
    disbursed_balance: Optional[float] = None
    status_effective_date: Optional[str] = None
    maturity_date: Optional[str] = None


class LoanSummaryResponse(BaseModel):
    loan_account: str
    summary: Optional[LoanSummaryRecord] = None


class LoanHistoryRecord(BaseModel):
    debit_amount: Optional[float] = None
    transaction_reference: Optional[str] = None
    transaction_description: Optional[str] = None
    loan_account: Optional[str] = None
    amount: Optional[float] = None
    credit_amount: Optional[float] = None
    cleared_balance: Optional[float] = None
    event_code: Optional[str] = None
    channel_description: Optional[str] = None
    ledger_balance: Optional[float] = None
    business_unit: Optional[str] = None
    currency: Optional[str] = None
    value_date: Optional[str] = None
    date_timestamp: Optional[str] = None
    dr_cr: Optional[str] = None
    cheque_no: Optional[str] = None
    event_description: Optional[str] = None
    transaction_date: Optional[str] = None


class LoanHistoryResponse(BaseModel):
    loan_account: str
    total: int
    records: List[LoanHistoryRecord]


class LoanRepaymentRecord(BaseModel):
    installment_no: Optional[int] = None
    loan_account: Optional[str] = None
    due_date: Optional[str] = None
    event_type: Optional[str] = None
    currency_code: Optional[str] = None
    principal_amount: Optional[float] = None
    interest_amount: Optional[float] = None
    fee_amount: Optional[float] = None
    late_fee_amount: Optional[float] = None
    total_amount: Optional[float] = None
    serviced_amount: Optional[float] = None
    unserviced_amount: Optional[float] = None
    serviced_date: Optional[str] = None
    days_late: Optional[int] = None


class LoanRepaymentResponse(BaseModel):
    loan_account: str
    total: int
    records: List[LoanRepaymentRecord]

# ==================== STATEMENTS ====================
class StatementRequest(BaseModel):
    acc_no: str = Field(..., description="Account number")

class StatementDownloadRequest(BaseModel):
    date: str = Field(..., description="The date folder (from STMNT_FILE_PATH)")
    filename: str = Field(..., description="The filename (from STMNT_FILE_NM)")
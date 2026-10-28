from fastapi import APIRouter, HTTPException, status, Depends, Request,Response
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials
from typing import Optional

from app.schemas import (
    AdminRegisterCustomerRequest,
    AdminLockCustomerRequest,
    AdminResetCustomerPasswordRequest,
    CustomerListResponse,
    CustomerSetPasswordRequest,
    UserProfileResponse,
    MessageResponse,
    AdminAssociateProfileRequest,
    ApproveAssociationRequest,
    InvalidAssociationRequest,
    DissociateRequest,
    AssociationRecord,
    AssociationListResponse,
    # Loan Schemas
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
from app.customer_service import CustomerService
from app.admin_auth import AdminAuthService, bearer_scheme
from app.database import db
from app.otp import OTPService
from app.config import Config
from app import auth_logger
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/admin/customers", tags=["Admin - Customer Management"])


def get_current_admin(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Authorization header required",
                            headers={"WWW-Authenticate": "Bearer"})
    try:
        token = credentials.credentials
        payload = AdminAuthService.decode_token(token)

        if not payload:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        if payload.get("user_type") != "admin":
            raise HTTPException(status_code=401, detail="Not an admin token")
        if AdminAuthService.is_admin_token_blacklisted(token):
            raise HTTPException(status_code=401, detail="Token has been revoked")

        return payload.get("sub")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")


def _to_association_record(r: dict) -> AssociationRecord:
    return AssociationRecord(
        id=r['id'],
        email=r['email'],
        account_number=r['account_number'],
        customer_no=r['customer_no'],
        customer_name=r.get('customer_name'),
        corebank_email=r.get('corebank_email'),
        corebank_category=r.get('corebank_category'),
        corebank_branch=r.get('corebank_branch'),
        corebank_cust_id=r.get('corebank_cust_id'),
        addr_line_1=r.get('addr_line_1'),
        city=r.get('city'),
        state=r.get('state'),
        country=r.get('country'),
        primary_officer_name=r.get('primary_officer_name'),
        registration_no=r.get('registration_no'),
        registration_dt=r.get('registration_dt'),
        bu_nm=r.get('bu_nm'),
        industry_desc=r.get('industry_desc'),
        cust_seg_desc=r.get('cust_seg_desc'),
        disbursement_limit=r.get('disbursement_limit'),
        term_cd=r.get('term_cd'),
        term_value=r.get('term_value'),
        ref_desc=r.get('ref_desc'),
        rec_st=r.get('rec_st'),
        status=r['status'],
        submitted_by=r.get('submitted_by'),
        reviewed_by=r.get('reviewed_by'),
        reviewed_at=r.get('reviewed_at'),
        review_notes=r.get('review_notes'),
        is_verified=r.get('is_verified'),
        profile=r.get('profile'),
        created_at=r.get('created_at'),
        updated_at=r.get('updated_at'),
    )


# ============================================================
# CUSTOMERS - LIST
# ============================================================
@router.get("/list", response_model=CustomerListResponse)
async def list_customers(
    page: int = 1, page_size: int = 20, search: Optional[str] = None,
    current_admin: str = Depends(get_current_admin),
):
    try:
        if page < 1:
            page = 1
        if page_size < 1 or page_size > 100:
            page_size = 20

        result = CustomerService.list_customers(page, page_size, search)
        customers = []
        for c in result['customers']:
            customers.append(UserProfileResponse(
                id=c['id'], email=c['email'], full_name=c['full_name'],
                phone_number=c['phone_number'], profile=c['profile'],
                customer_no=c['customer_no'], is_verified=c['is_verified'],
                is_locked=c['is_locked'], created_at=c['created_at'],
            ))
        return CustomerListResponse(total=result['total'], page=page,
                                    page_size=page_size, customers=customers)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list customers: {str(e)}")


# ============================================================
# CUSTOMERS - REGISTER
# ============================================================
@router.post("/register", response_model=MessageResponse)
async def admin_register_customer(
    request: AdminRegisterCustomerRequest,
    current_admin: str = Depends(get_current_admin),
):
    try:
        result = CustomerService.admin_register_customer(
            full_name=request.full_name, email=request.email,
            phone_number=request.phone_number, registered_by=current_admin,
        )
        if not result['success']:
            raise HTTPException(status_code=400, detail=result['message'])

        setup_link = f"{Config.RESET_PASSWORD_BASE_URL}{Config.CUSTOMER_SETUP_PATH}?token={result['token']}"
        OTPService.send_password_reset_email_async(request.email, setup_link, "customer_setup",
                                                   recipient_name=request.full_name)

        return {
            "message": "Customer registered successfully. Setup link sent to email.",
            "success": True,
            "data": {"email": request.email, "full_name": request.full_name, "setup_link": setup_link},
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to register customer: {str(e)}")


# ============================================================
# CUSTOMERS - LOCK / UNLOCK
# ============================================================
@router.post("/lock", response_model=MessageResponse)
async def lock_customer(request: AdminLockCustomerRequest, current_admin: str = Depends(get_current_admin)):
    try:
        user = CustomerService.get_user_by_email(request.email)
        if not user:
            raise HTTPException(status_code=404, detail="Customer not found")
        if user['is_locked'] == 'Y':
            raise HTTPException(status_code=400, detail="Customer is already locked")

        result = CustomerService.lock_customer(email=request.email, reason=request.reason, locked_by=current_admin)
        if not result['success']:
            raise HTTPException(status_code=500, detail=result['message'])

        return {"message": result['message'], "success": True,
                "data": {"email": request.email, "reason": request.reason, "locked_by": current_admin}}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to lock customer: {str(e)}")


@router.post("/unlock", response_model=MessageResponse)
async def unlock_customer(request: AdminLockCustomerRequest, current_admin: str = Depends(get_current_admin)):
    try:
        user = CustomerService.get_user_by_email(request.email)
        if not user:
            raise HTTPException(status_code=404, detail="Customer not found")

        result = CustomerService.unlock_customer(request.email)
        if not result['success']:
            raise HTTPException(status_code=500, detail=result['message'])

        return {"message": result['message'], "success": True,
                "data": {"email": request.email, "unlocked_by": current_admin}}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to unlock customer: {str(e)}")


# ============================================================
# CUSTOMERS - RESET PASSWORD / SET PASSWORD
# ============================================================
@router.post("/reset-password", response_model=MessageResponse)
async def admin_reset_customer_password(
    request: AdminResetCustomerPasswordRequest,
    current_admin: str = Depends(get_current_admin),
):
    try:
        result = CustomerService.admin_reset_customer_password(request.email)
        if not result['success']:
            raise HTTPException(status_code=404, detail=result['message'])

        reset_link = f"{Config.RESET_PASSWORD_BASE_URL}{Config.CUSTOMER_RESET_PATH}?token={result['token']}"
        user = CustomerService.get_user_by_email(request.email)
        OTPService.send_password_reset_email_async(request.email, reset_link, "customer_password_reset",
                                                   recipient_name=user['full_name'] if user else None)

        return {"message": result['message'], "success": True,
                "data": {"email": request.email, "reset_link": reset_link,
                         "expires_at": str(result['expires_at'])}}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reset password: {str(e)}")


@router.post("/set-password", response_model=MessageResponse)
async def customer_set_password(request: CustomerSetPasswordRequest):
    try:
        result = CustomerService.set_customer_password(token=request.token, new_password=request.new_password)
        if not result['success']:
            raise HTTPException(status_code=400, detail=result['message'])
        return {"message": result['message'], "success": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to set password: {str(e)}")


# ============================================================
# ASSOCIATE PROFILE - LIST (MUST be before /{email})
# ============================================================
@router.get("/associations", response_model=AssociationListResponse)
async def list_associations(
    status: Optional[str] = None,
    email: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
    current_admin: str = Depends(get_current_admin),
):
    try:
        result = CustomerService.list_associations(status=status, email=email,
                                                   page=page, page_size=page_size)
        records = [_to_association_record(r) for r in result['records']]
        return AssociationListResponse(total=result['total'], records=records)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list associations: {str(e)}")


# ============================================================
# ASSOCIATE PROFILE - ADMIN SUBMITS
# ============================================================
@router.post("/associate-profile", response_model=MessageResponse)
async def admin_associate_profile(
    request: AdminAssociateProfileRequest,
    current_admin: str = Depends(get_current_admin),
):
    try:
        result = CustomerService.submit_profile_association(
            email=request.email,
            account_number=request.account_number,
            submitted_by=current_admin,
            corebank_email_lookup=request.email,
        )
        if not result['success']:
            raise HTTPException(status_code=400, detail=result['message'])

        record = result.get('record')
        return {
            "message": result['message'],
            "success": True,
            "data": _to_association_record(record).model_dump() if record else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to submit association: {str(e)}")


# ============================================================
# ASSOCIATE PROFILE - APPROVE / INVALID / DISSOCIATE
# ============================================================
@router.post("/associations/approve", response_model=MessageResponse)
async def approve_association(
    request: ApproveAssociationRequest,
    current_admin: str = Depends(get_current_admin),
):
    try:
        result = CustomerService.approve_association(
            assoc_id=request.assoc_id, reviewed_by=current_admin,
            review_notes=request.review_notes,
        )
        if not result['success']:
            raise HTTPException(status_code=400, detail=result['message'])

        record = result.get('record')
        return {
            "message": result['message'],
            "success": True,
            "data": _to_association_record(record).model_dump() if record else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Approval failed: {str(e)}")


@router.post("/associations/invalid", response_model=MessageResponse)
async def mark_invalid(
    request: InvalidAssociationRequest,
    current_admin: str = Depends(get_current_admin),
):
    try:
        result = CustomerService.mark_association_invalid(
            assoc_id=request.assoc_id, reviewed_by=current_admin,
            review_notes=request.review_notes,
        )
        if not result['success']:
            raise HTTPException(status_code=400, detail=result['message'])

        record = result.get('record')
        return {
            "message": result['message'],
            "success": True,
            "data": _to_association_record(record).model_dump() if record else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to mark invalid: {str(e)}")


@router.post("/associations/dissociate", response_model=MessageResponse)
async def dissociate(
    request: DissociateRequest,
    current_admin: str = Depends(get_current_admin),
):
    try:
        result = CustomerService.dissociate_profile(
            assoc_id=request.assoc_id, reviewed_by=current_admin,
            review_notes=request.review_notes,
        )
        if not result['success']:
            raise HTTPException(status_code=400, detail=result['message'])

        record = result.get('record')
        return {
            "message": result['message'],
            "success": True,
            "data": _to_association_record(record).model_dump() if record else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dissociation failed: {str(e)}")


# ============================================================
# CUSTOMERS - GET BY EMAIL (MUST be last dynamic route)
# ============================================================
@router.get("/{email}", response_model=UserProfileResponse)
async def get_customer(email: str, current_admin: str = Depends(get_current_admin)):
    try:
        user = CustomerService.get_user_by_email(email)
        if not user:
            raise HTTPException(status_code=404, detail="Customer not found")

        return UserProfileResponse(
            id=user['id'], email=user['email'], full_name=user['full_name'],
            phone_number=user['phone_number'], profile=user['profile'],
            customer_no=user['customer_no'], is_verified=user['is_verified'] == 'Y',
            is_locked=user['is_locked'], created_at=user['created_at'],
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get customer: {str(e)}")


# ============================================================
# ADMIN LOAN ENDPOINTS (NEW)
# ============================================================
@router.post("/loan-list", response_model=LoanListResponse)
async def admin_loan_list(
    request: LoanListRequest,
    http: Request,
    current_admin: str = Depends(get_current_admin),
):
    """
    [ADMIN] Return the customer's list of loans.
    """
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        loans = CustomerService.fetch_loan_list(request.cust_num)

        if not loans:
            auth_logger.log_event(
                "admin.loan.list.success",
                email=current_admin, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/admin/customers/loan-list", http_status=200,
                success=True, details={"cust_num": request.cust_num, "count": 0},
            )
            return LoanListResponse(total=0, loans=[])

        items = [LoanListItem(
            account_number=l['account_number'],
            rec_st=l['rec_st'],
            status=l['status'],
            product_description=l['product_description'],
        ) for l in loans]

        auth_logger.log_event(
            "admin.loan.list.success",
            email=current_admin, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/admin/customers/loan-list", http_status=200,
            success=True, details={"cust_num": request.cust_num, "count": len(items)},
        )

        return LoanListResponse(total=len(items), loans=items)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch loan list: {str(e)}")


@router.post("/loan-summary", response_model=LoanSummaryResponse)
async def admin_loan_summary(
    request: LoanDetailRequest,
    http: Request,
    current_admin: str = Depends(get_current_admin),
):
    """
    [ADMIN] Return the loan summary for the given loan account.
    """
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        summary = CustomerService.fetch_loan_summary(request.loan_account)

        if not summary:
            auth_logger.log_event(
                "admin.loan.summary.empty",
                email=current_admin, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/admin/customers/loan-summary", http_status=200,
                success=True, details={"loan_account": request.loan_account, "found": False},
            )
            return LoanSummaryResponse(loan_account=request.loan_account, summary=None)

        auth_logger.log_event(
            "admin.loan.summary.success",
            email=current_admin, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/admin/customers/loan-summary", http_status=200,
            success=True, details={"loan_account": request.loan_account},
        )

        return LoanSummaryResponse(
            loan_account=request.loan_account,
            summary=LoanSummaryRecord(**summary),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch loan summary: {str(e)}")


@router.post("/loan-history", response_model=LoanHistoryResponse)
async def admin_loan_history(
    request: LoanDetailRequest,
    http: Request,
    current_admin: str = Depends(get_current_admin),
):
    """
    [ADMIN] Return loan history for the given loan account.
    """
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        records = CustomerService.fetch_loan_history(request.loan_account)

        if not records:
            auth_logger.log_event(
                "admin.loan.history.empty",
                email=current_admin, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/admin/customers/loan-history", http_status=200,
                success=True, details={"loan_account": request.loan_account, "count": 0},
            )
            return LoanHistoryResponse(loan_account=request.loan_account, total=0, records=[])

        items = [LoanHistoryRecord(**r) for r in records]

        auth_logger.log_event(
            "admin.loan.history.success",
            email=current_admin, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/admin/customers/loan-history", http_status=200,
            success=True, details={"loan_account": request.loan_account, "count": len(items)},
        )

        return LoanHistoryResponse(
            loan_account=request.loan_account,
            total=len(items),
            records=items,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch loan history: {str(e)}")


@router.post("/loan-repayment", response_model=LoanRepaymentResponse)
async def admin_loan_repayment(
    request: LoanDetailRequest,
    http: Request,
    current_admin: str = Depends(get_current_admin),
):
    """
    [ADMIN] Return loan repayment schedule for the given loan account.
    """
    ip = auth_logger.get_client_ip(http)
    ua = auth_logger.get_user_agent(http)
    rid = auth_logger.get_request_id(http)

    try:
        records = CustomerService.fetch_loan_repayment(request.loan_account)

        if not records:
            auth_logger.log_event(
                "admin.loan.repayment.empty",
                email=current_admin, ip=ip, user_agent=ua, request_id=rid,
                http_method="POST", http_path="/api/v1/admin/customers/loan-repayment", http_status=200,
                success=True, details={"loan_account": request.loan_account, "count": 0},
            )
            return LoanRepaymentResponse(loan_account=request.loan_account, total=0, records=[])

        items = [LoanRepaymentRecord(**r) for r in records]

        auth_logger.log_event(
            "admin.loan.repayment.success",
            email=current_admin, ip=ip, user_agent=ua, request_id=rid,
            http_method="POST", http_path="/api/v1/admin/customers/loan-repayment", http_status=200,
            success=True, details={"loan_account": request.loan_account, "count": len(items)},
        )

        return LoanRepaymentResponse(
            loan_account=request.loan_account,
            total=len(items),
            records=items,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch loan repayment schedule: {str(e)}")

# ============================================================
# ADMIN - STATEMENT LIST
# ============================================================
@router.post("/statement-list")
async def admin_statement_list(
    request: StatementRequest,
    current_admin: str = Depends(get_current_admin),
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
# ADMIN - STATEMENT VIEW (STREAM)
# ============================================================
@router.post("/statement-view")
async def admin_statement_view(
    request: StatementDownloadRequest,
    current_admin: str = Depends(get_current_admin),
):
    try:
        pdf_bytes = CustomerService.download_statement_pdf(request.param1, request.param2)
        if not pdf_bytes:
            raise HTTPException(status_code=404, detail="Could not fetch the statement file.")

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'inline; filename="{request.param2}"'}
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"View failed: {str(e)}")
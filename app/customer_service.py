import requests
import logging
import json
from datetime import datetime, timedelta
import secrets
from app.config import Config
from app.database import db

logger = logging.getLogger(__name__)


class CustomerService:

    # ============================================================
    # EXTERNAL API - custInfo (account lookup)
    # ============================================================
    @staticmethod
    def fetch_customer_info(account_number: str):
        try:
            url = f"{Config.CUSTOMER_INFO_API_URL}?accNumber={account_number}"
            headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
            logger.info(f"Calling customer info API: {url}")
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code != 200:
                logger.error(f"Customer info API error: {response.status_code} - {response.text}")
                return None

            data = response.json()
            outputs = data.get('dbReferenceOutput') or []
            if not outputs:
                return None

            row = outputs[0]

            def _val(field, default=None):
                v = row.get(field, default)
                if isinstance(v, dict) and v.get('@nil') == 'true':
                    return None
                return v

            return {
                'account_number': _val('ACCT_NO'),
                'customer_number': _val('CUST_NO'),
                'customer_name': _val('CUST_NM'),
                'addr_line_1': _val('ADDR_LINE_1'),
                'city': _val('CITY'),
                'state': _val('STATE'),
                'country': _val('CNTRY_NM'),
                'primary_officer_name': _val('PRIMARY_OFFICER_NAME'),
                'registration_no': _val('REGISTRATION_NO'),
                'registration_dt': _val('REGISTRATION_DT'),
                'bu_nm': _val('BU_NM'),
                'industry_desc': _val('INDUSTRY_DESC'),
                'cust_seg_desc': _val('CUST_SEG_DESC'),
                'disbursement_limit': _val('DISBURSEMENT_LIMIT'),
                'term_cd': _val('TERM_CD'),
                'term_value': _val('TERM_VALUE'),
                'ref_desc': _val('REF_DESC'),
                'rec_st': _val('REC_ST'),
                'raw': json.dumps(row),
            }
        except Exception as e:
            logger.error(f"Customer info API error: {e}")
            return None

    # ============================================================
    # EXTERNAL API - getEmail (email + account lookup)
    # ============================================================
    @staticmethod
    def fetch_email_info(email: str, account_number: str):
        try:
            url = f"{Config.CUSTOMER_EMAIL_API_URL}?email={email}&accnumber={account_number}"
            headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
            logger.info(f"Calling customer email API: {url}")
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code != 200:
                logger.error(f"Customer email API error: {response.status_code} - {response.text}")
                return None

            try:
                data = response.json()
            except Exception:
                logger.warning("Customer email API returned non-JSON body; treating as no data")
                return None

            if data is None:
                logger.info("Customer email API returned null — treating as no match")
                return None

            outputs = data.get('getEmaildbReferenceOutput') or []
            if not outputs:
                return None

            row = outputs[0]

            def _val(field, default=None):
                v = row.get(field, default)
                if isinstance(v, dict) and v.get('@nil') == 'true':
                    return None
                return v

            return {
                'corebank_email': _val('email'),
                'corebank_category': _val('Category'),
                'corebank_branch': _val('branch'),
                'corebank_cust_id': _val('CUST_ID'),
                'raw': json.dumps(row),
            }
        except Exception as e:
            logger.error(f"Customer email API error: {e}")
            return None

    # ============================================================
    # USER LOOKUP
    # ============================================================
    @staticmethod
    def get_user_by_email(email: str):
        try:
            normalized = email.strip().lower() if email else email
            result = db.fetch_one("""
                SELECT id, email, full_name, phone_number, profile, customer_no,
                       is_verified, is_locked, created_at
                FROM users WHERE LOWER(email) = :1
            """, (normalized,))
            if result:
                return {
                    'id': result[0], 'email': result[1], 'full_name': result[2],
                    'phone_number': result[3], 'profile': result[4],
                    'customer_no': result[5], 'is_verified': result[6],
                    'is_locked': result[7] or 'N', 'created_at': result[8],
                }
            return None
        except Exception as e:
            logger.error(f"Failed to get user: {e}")
            return None

    @staticmethod
    def get_user_by_customer_number(customer_number: str):
        try:
            result = db.fetch_one("""
                SELECT id, email, full_name, phone_number, profile, customer_no,
                       is_verified, is_locked, created_at
                FROM users WHERE customer_no = :1
            """, (customer_number,))
            if result:
                return {
                    'id': result[0], 'email': result[1], 'full_name': result[2],
                    'phone_number': result[3], 'profile': result[4],
                    'customer_no': result[5], 'is_verified': result[6],
                    'is_locked': result[7] or 'N', 'created_at': result[8],
                }
            return None
        except Exception as e:
            logger.error(f"Failed to get user: {e}")
            return None

    # ============================================================
    # OWNERSHIP CHECKS
    # ============================================================
    @staticmethod
    def customer_owns_customer_no(email: str, cust_num: str) -> bool:
        """
        Verify that the given customer number belongs to this customer.
        Compares against users.customer_no for the token's email.
        """
        try:
            normalized = email.strip().lower() if email else email
            result = db.fetch_one("""
                SELECT 1 FROM users
                WHERE LOWER(email) = :1 AND customer_no = :2
                FETCH FIRST 1 ROW ONLY
            """, (normalized, cust_num))
            return result is not None
        except Exception as e:
            logger.error(f"customer_owns_customer_no check failed: {e}")
            return False

    @staticmethod
    def customer_owns_loan_account(email: str, loan_account: str) -> bool:
        """
        Verify that the given loan account belongs to this customer.
        Compares against associate_profile.account_number for the token's email,
        with status PROFILED or PENDING.
        """
        try:
            normalized = email.strip().lower() if email else email
            result = db.fetch_one("""
                SELECT 1 FROM associate_profile
                WHERE LOWER(email) = :1
                  AND account_number = :2
                  AND status IN ('PROFILED', 'PENDING')
                FETCH FIRST 1 ROW ONLY
            """, (normalized, loan_account))
            return result is not None
        except Exception as e:
            logger.error(f"customer_owns_loan_account check failed: {e}")
            return False

    # ============================================================
    # ASSOCIATE PROFILE - SUBMIT
    # ============================================================
    @staticmethod
    def submit_profile_association(email: str, account_number: str,
                                   submitted_by: str = None,
                                   corebank_email_lookup: str = None):
        user = CustomerService.get_user_by_email(email)
        if not user:
            return {'success': False, 'message': 'User not found', 'record': None}

        if user['profile'] == 'Y' and user['customer_no']:
            return {
                'success': False,
                'message': f"User already has a verified profile: {user['customer_no']}. "
                           f"Please ask an admin to dissociate first.",
                'record': None,
            }

        existing = db.fetch_one("""
            SELECT id FROM associate_profile
            WHERE email = :1 AND account_number = :2 AND status = 'PENDING'
        """, (email, account_number))
        if existing:
            return {'success': False, 'message': 'This account is already pending approval.', 'record': None}

        account_info = CustomerService.fetch_customer_info(account_number)
        email_to_check = corebank_email_lookup or email
        email_info = CustomerService.fetch_email_info(email_to_check, account_number)

        if not account_info and not email_info:
            return {'success': False, 'message': Config.ASSOC_MSG_BOTH_MISSING, 'record': None}
        if not account_info and email_info:
            return {'success': False, 'message': Config.ASSOC_MSG_ACCOUNT_MISSING, 'record': None}
        if account_info and not email_info:
            return {'success': False, 'message': Config.ASSOC_MSG_EMAIL_ACCOUNT_MISMATCH, 'record': None}

        customer_no = account_info.get('customer_number')
        if not customer_no:
            return {'success': False, 'message': Config.ASSOC_MSG_ACCOUNT_MISSING, 'record': None}

        already_profiled = db.fetch_one("""
            SELECT email FROM associate_profile
            WHERE customer_no = :1 AND status = 'PROFILED'
        """, (customer_no,))
        if already_profiled:
            return {
                'success': False,
                'message': f"Customer number {customer_no} is already profiled by another user.",
                'record': None,
            }

        import oracledb
        cursor = db.connection.cursor()
        id_var = cursor.var(oracledb.NUMBER)
        cursor.execute("""
            INSERT INTO associate_profile (
                email, account_number, customer_no, customer_name,
                addr_line_1, city, state, country, primary_officer_name,
                registration_no, registration_dt, bu_nm, industry_desc,
                cust_seg_desc, disbursement_limit, term_cd, term_value,
                ref_desc, rec_st,
                corebank_email, corebank_category, corebank_branch, corebank_cust_id,
                status, submitted_by, raw_response
            ) VALUES (
                :1, :2, :3, :4, :5, :6, :7, :8, :9, :10, :11, :12, :13,
                :14, :15, :16, :17, :18, :19, :20, :21, :22, :23,
                'PENDING', :24, :25
            )
            RETURNING id INTO :26
        """, (
            email, account_info['account_number'], customer_no, account_info['customer_name'],
            account_info['addr_line_1'], account_info['city'], account_info['state'], account_info['country'],
            account_info['primary_officer_name'], account_info['registration_no'], account_info['registration_dt'],
            account_info['bu_nm'], account_info['industry_desc'], account_info['cust_seg_desc'],
            account_info['disbursement_limit'], account_info['term_cd'], account_info['term_value'],
            account_info['ref_desc'], account_info['rec_st'],
            email_info['corebank_email'], email_info['corebank_category'], email_info['corebank_branch'],
            email_info['corebank_cust_id'],
            submitted_by or email,
            account_info['raw'],
            id_var,
        ))
        db.connection.commit()
        cursor.close()

        new_id = int(id_var.getvalue()[0]) if id_var.getvalue() else None
        record = CustomerService.get_association_full_by_id(new_id)

        return {
            'success': True,
            'message': 'Profile association submitted for admin approval.',
            'record': record,
        }

    # ============================================================
    # ASSOCIATE PROFILE - FETCH ONE
    # ============================================================
    @staticmethod
    def get_association_full_by_id(assoc_id: int):
        try:
            result = db.fetch_one("""
                SELECT
                    ap.id, ap.email, ap.account_number, ap.customer_no, ap.customer_name,
                    ap.addr_line_1, ap.city, ap.state, ap.country, ap.primary_officer_name,
                    ap.registration_no, ap.registration_dt, ap.bu_nm, ap.industry_desc,
                    ap.cust_seg_desc, ap.disbursement_limit, ap.term_cd, ap.term_value,
                    ap.ref_desc, ap.rec_st,
                    ap.corebank_email, ap.corebank_category, ap.corebank_branch, ap.corebank_cust_id,
                    ap.status, ap.submitted_by, ap.reviewed_by,
                    ap.reviewed_at, ap.review_notes, ap.created_at, ap.updated_at,
                    u.is_verified, u.profile
                FROM associate_profile ap
                LEFT JOIN users u ON u.email = ap.email
                WHERE ap.id = :1
            """, (assoc_id,))
            if not result:
                return None
            return CustomerService._row_to_association(result)
        except Exception as e:
            logger.error(f"Failed to fetch association: {e}")
            return None

    @staticmethod
    def _row_to_association(r):
        return {
            'id': r[0], 'email': r[1], 'account_number': r[2],
            'customer_no': r[3], 'customer_name': r[4],
            'addr_line_1': r[5], 'city': r[6], 'state': r[7], 'country': r[8],
            'primary_officer_name': r[9], 'registration_no': r[10],
            'registration_dt': r[11], 'bu_nm': r[12], 'industry_desc': r[13],
            'cust_seg_desc': r[14], 'disbursement_limit': r[15],
            'term_cd': r[16], 'term_value': r[17], 'ref_desc': r[18],
            'rec_st': r[19],
            'corebank_email': r[20], 'corebank_category': r[21],
            'corebank_branch': r[22], 'corebank_cust_id': r[23],
            'status': r[24], 'submitted_by': r[25], 'reviewed_by': r[26],
            'reviewed_at': str(r[27]) if r[27] else None,
            'review_notes': r[28],
            'created_at': str(r[29]) if r[29] else None,
            'updated_at': str(r[30]) if r[30] else None,
            'is_verified': (r[31] == 'Y') if r[31] is not None else None,
            'profile': r[32],
        }

    # ============================================================
    # ASSOCIATE PROFILE - LIST
    # ============================================================
    @staticmethod
    def list_associations(status: str = None, email: str = None,
                          page: int = 1, page_size: int = 20):
        try:
            offset = (page - 1) * page_size
            where = []
            params = []

            if status:
                where.append(f"ap.status = :{len(params)+1}")
                params.append(status.upper())
            if email:
                where.append(f"ap.email = :{len(params)+1}")
                params.append(email)

            where_sql = "WHERE " + " AND ".join(where) if where else ""

            count_sql = f"SELECT COUNT(*) FROM associate_profile ap {where_sql}"
            count_result = db.fetch_one(count_sql, tuple(params))
            total = count_result[0] if count_result else 0

            query = f"""
                SELECT
                    ap.id, ap.email, ap.account_number, ap.customer_no, ap.customer_name,
                    ap.addr_line_1, ap.city, ap.state, ap.country, ap.primary_officer_name,
                    ap.registration_no, ap.registration_dt, ap.bu_nm, ap.industry_desc,
                    ap.cust_seg_desc, ap.disbursement_limit, ap.term_cd, ap.term_value,
                    ap.ref_desc, ap.rec_st,
                    ap.corebank_email, ap.corebank_category, ap.corebank_branch, ap.corebank_cust_id,
                    ap.status, ap.submitted_by, ap.reviewed_by,
                    ap.reviewed_at, ap.review_notes, ap.created_at, ap.updated_at,
                    u.is_verified, u.profile
                FROM associate_profile ap
                LEFT JOIN users u ON u.email = ap.email
                {where_sql}
                ORDER BY ap.created_at DESC
                OFFSET :{len(params)+1} ROWS FETCH NEXT :{len(params)+2} ROWS ONLY
            """
            params.extend([offset, page_size])
            results = db.fetch_all(query, tuple(params))

            records = [CustomerService._row_to_association(r) for r in (results or [])]
            return {'total': total, 'records': records}
        except Exception as e:
            logger.error(f"Failed to list associations: {e}")
            return {'total': 0, 'records': []}

    # ============================================================
    # ASSOCIATE PROFILE - APPROVE
    # ============================================================
    @staticmethod
    def approve_association(assoc_id: int, reviewed_by: str, review_notes: str = None):
        try:
            assoc = db.fetch_one("""
                SELECT id, email, customer_no, status
                FROM associate_profile WHERE id = :1
            """, (assoc_id,))

            if not assoc:
                return {'success': False, 'message': 'Association not found'}

            _, email, customer_no, status = assoc

            if status != 'PENDING':
                return {'success': False, 'message': f"Association is already {status}."}

            conflict = db.fetch_one("""
                SELECT id FROM associate_profile
                WHERE customer_no = :1 AND status = 'PROFILED' AND id != :2
            """, (customer_no, assoc_id))
            if conflict:
                return {'success': False, 'message': 'Customer number is already profiled.'}

            user = CustomerService.get_user_by_email(email)
            if not user:
                return {'success': False, 'message': 'User not found'}
            if user['profile'] == 'Y' and user['customer_no'] and user['customer_no'] != customer_no:
                return {
                    'success': False,
                    'message': f"User already has a different profiled customer number: {user['customer_no']}"
                }

            db.execute_query("""
                UPDATE users
                SET customer_no = :1, profile = 'Y', updated_at = CURRENT_TIMESTAMP
                WHERE email = :2
            """, (customer_no, email))

            db.execute_query("""
                UPDATE associate_profile
                SET status = 'PROFILED', reviewed_by = :1,
                    reviewed_at = CURRENT_TIMESTAMP, review_notes = :2,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = :3
            """, (reviewed_by, review_notes, assoc_id))

            record = CustomerService.get_association_full_by_id(assoc_id)
            return {
                'success': True,
                'message': 'Profile approved and linked successfully.',
                'record': record,
            }
        except Exception as e:
            logger.error(f"Approve failed: {e}")
            return {'success': False, 'message': str(e)}

    # ============================================================
    # ASSOCIATE PROFILE - MARK INVALID
    # ============================================================
    @staticmethod
    def mark_association_invalid(assoc_id: int, reviewed_by: str, review_notes: str = None):
        try:
            assoc = db.fetch_one("SELECT id, status FROM associate_profile WHERE id = :1", (assoc_id,))
            if not assoc:
                return {'success': False, 'message': 'Association not found'}

            _, status = assoc
            if status == 'PROFILED':
                return {'success': False, 'message': 'Cannot mark a profiled record as invalid. Dissociate first.'}
            if status == 'INVALID':
                return {'success': False, 'message': 'Already marked invalid.'}

            db.execute_query("""
                UPDATE associate_profile
                SET status = 'INVALID', reviewed_by = :1,
                    reviewed_at = CURRENT_TIMESTAMP, review_notes = :2,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = :3
            """, (reviewed_by, review_notes, assoc_id))

            record = CustomerService.get_association_full_by_id(assoc_id)
            return {'success': True, 'message': 'Association marked as INVALID.', 'record': record}
        except Exception as e:
            logger.error(f"Mark invalid failed: {e}")
            return {'success': False, 'message': str(e)}

    # ============================================================
    # ASSOCIATE PROFILE - DISSOCIATE
    # ============================================================
    @staticmethod
    def dissociate_profile(assoc_id: int, reviewed_by: str, review_notes: str = None):
        try:
            assoc = db.fetch_one("""
                SELECT id, email, customer_no, status
                FROM associate_profile WHERE id = :1
            """, (assoc_id,))
            if not assoc:
                return {'success': False, 'message': 'Association not found'}

            _, email, customer_no, status = assoc

            if status != 'PROFILED':
                return {'success': False, 'message': f"Association is {status}, cannot dissociate."}

            db.execute_query("""
                UPDATE users
                SET customer_no = NULL, profile = 'N', updated_at = CURRENT_TIMESTAMP
                WHERE email = :1 AND customer_no = :2
            """, (email, customer_no))

            db.execute_query("""
                UPDATE associate_profile
                SET status = 'INVALID', reviewed_by = :1,
                    reviewed_at = CURRENT_TIMESTAMP, review_notes = :2,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = :3
            """, (reviewed_by, review_notes or 'Dissociated by admin', assoc_id))

            record = CustomerService.get_association_full_by_id(assoc_id)
            return {
                'success': True,
                'message': 'Profile dissociated successfully. User can now submit a new profile.',
                'record': record,
            }
        except Exception as e:
            logger.error(f"Dissociate failed: {e}")
            return {'success': False, 'message': str(e)}

    # ============================================================
    # LEGACY - CUSTOMERS
    # ============================================================
    @staticmethod
    def list_customers(page: int = 1, page_size: int = 20, search: str = None):
        try:
            offset = (page - 1) * page_size

            if search is not None:
                search = search.strip()
            if not search:
                search = None

            if search:
                pattern = f"%{search.upper()}%"

                count_sql = """
                    SELECT COUNT(*) FROM users
                    WHERE UPPER(email) LIKE :pat
                       OR UPPER(NVL(full_name, '')) LIKE :pat
                       OR UPPER(NVL(phone_number, '')) LIKE :pat
                       OR UPPER(NVL(customer_no, '')) LIKE :pat
                """
                count_result = db.fetch_one(count_sql, {'pat': pattern})
                total = count_result[0] if count_result else 0

                query = """
                    SELECT id, email, full_name, phone_number, profile, customer_no,
                           is_verified, is_locked, created_at
                    FROM users
                    WHERE UPPER(email) LIKE :pat
                       OR UPPER(NVL(full_name, '')) LIKE :pat
                       OR UPPER(NVL(phone_number, '')) LIKE :pat
                       OR UPPER(NVL(customer_no, '')) LIKE :pat
                    ORDER BY created_at DESC
                    OFFSET :offset ROWS FETCH NEXT :limit ROWS ONLY
                """
                results = db.fetch_all(query, {'pat': pattern, 'offset': offset, 'limit': page_size})
            else:
                count_result = db.fetch_one("SELECT COUNT(*) FROM users")
                total = count_result[0] if count_result else 0

                query = """
                    SELECT id, email, full_name, phone_number, profile, customer_no,
                           is_verified, is_locked, created_at
                    FROM users
                    ORDER BY created_at DESC
                    OFFSET :offset ROWS FETCH NEXT :limit ROWS ONLY
                """
                results = db.fetch_all(query, {'offset': offset, 'limit': page_size})

            customers = []
            for r in (results or []):
                customers.append({
                    'id': r[0], 'email': r[1], 'full_name': r[2],
                    'phone_number': r[3], 'profile': r[4], 'customer_no': r[5],
                    'is_verified': r[6] == 'Y', 'is_locked': r[7] or 'N',
                    'created_at': r[8],
                })
            return {'total': total, 'customers': customers}
        except Exception as e:
            logger.error(f"Failed to list customers: {e}")
            return {'total': 0, 'customers': []}

    @staticmethod
    def lock_customer(email: str, reason: str = None, locked_by: str = None):
        try:
            db.execute_query("""
                UPDATE users
                SET is_locked = 'Y', locked_reason = :1, locked_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE LOWER(email) = :2
            """, (reason, email))
            return {'success': True, 'message': f"Customer {email} has been locked"}
        except Exception as e:
            logger.error(f"Failed to lock customer: {e}")
            return {'success': False, 'message': str(e)}

    @staticmethod
    def unlock_customer(email: str):
        try:
            db.execute_query("""
                UPDATE users
                SET is_locked = 'N', locked_reason = NULL, locked_at = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE LOWER(email) = :1
            """, (email,))
            return {'success': True, 'message': f"Customer {email} has been unlocked"}
        except Exception as e:
            logger.error(f"Failed to unlock customer: {e}")
            return {'success': False, 'message': str(e)}

    @staticmethod
    def admin_register_customer(full_name: str, email: str, phone_number: str = None,
                                registered_by: str = None):
        try:
            email = email.strip().lower() if email else email

            existing = db.fetch_one("SELECT id FROM users WHERE LOWER(email) = :1", (email,))
            if existing:
                return {'success': False, 'message': "Email already registered"}

            if phone_number:
                phone_exists = db.fetch_one(
                    "SELECT email FROM users WHERE phone_number = :1", (phone_number,)
                )
                if phone_exists:
                    return {'success': False, 'message': "This phone number is already registered"}

            token = secrets.token_urlsafe(48)
            expires_at = datetime.now() + timedelta(hours=48)

            db.execute_query("""
                INSERT INTO users (
                    email, password_hash, full_name, phone_number,
                    is_verified, is_locked, reset_token, reset_token_expires_at,
                    registered_by_admin
                ) VALUES (:1, :2, :3, :4, 'N', 'N', :5, :6, :7)
            """, (email, "PENDING_SETUP", full_name, phone_number,
                  token, expires_at, registered_by))

            return {
                'success': True,
                'message': "Customer registered. Setup link sent to email.",
                'token': token,
                'expires_at': expires_at,
            }
        except Exception as e:
            logger.error(f"Failed to register customer: {e}")
            return {'success': False, 'message': str(e)}

    @staticmethod
    def admin_reset_customer_password(email: str):
        try:
            user = db.fetch_one("SELECT id FROM users WHERE LOWER(email) = :1", (email,))
            if not user:
                return {'success': False, 'message': "Customer not found"}

            token = secrets.token_urlsafe(48)
            expires_at = datetime.now() + timedelta(hours=24)

            db.execute_query("""
                UPDATE users
                SET reset_token = :1, reset_token_expires_at = :2,
                    updated_at = CURRENT_TIMESTAMP
                WHERE LOWER(email) = :3
            """, (token, expires_at, email))

            return {
                'success': True,
                'message': "Password reset link sent to customer email",
                'token': token,
                'expires_at': expires_at,
            }
        except Exception as e:
            logger.error(f"Failed to reset customer password: {e}")
            return {'success': False, 'message': str(e)}

    @staticmethod
    def verify_customer_setup_token(token: str):
        try:
            result = db.fetch_one("""
                SELECT email, reset_token_expires_at
                FROM users WHERE reset_token = :1
            """, (token,))
            if not result:
                return None
            email, expires_at = result
            if datetime.now() > expires_at:
                return None
            return email
        except Exception as e:
            logger.error(f"Failed to verify token: {e}")
            return None

    @staticmethod
    def set_customer_password(token: str, new_password: str):
        try:
            email = CustomerService.verify_customer_setup_token(token)
            if not email:
                return {'success': False, 'message': "Invalid or expired token"}

            from app.auth import AuthService
            hashed = AuthService.hash_password(new_password)

            db.execute_query("""
                UPDATE users
                SET password_hash = :1, is_verified = 'Y',
                    reset_token = NULL, reset_token_expires_at = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE LOWER(email) = :2
            """, (hashed, email))

            return {'success': True, 'message': "Password set successfully. You can now login."}
        except Exception as e:
            logger.error(f"Failed to set password: {e}")
            return {'success': False, 'message': str(e)}

    # ============================================================
    # AUDIT TRAIL
    # ============================================================
    @staticmethod
    def create_audit_log(email: str, action: str, page: str = None,
                         when_logged=None, ip_address: str = None):
        try:
            user_row = db.fetch_one(
                "SELECT full_name FROM users WHERE LOWER(email) = :1",
                (email.strip().lower() if email else email,)
            )
            user_name = user_row[0] if user_row else None

            import oracledb
            cursor = db.connection.cursor()
            id_var = cursor.var(oracledb.NUMBER)
            cursor.execute("""
                INSERT INTO audit_trail (
                    email, user_name, action, page, when_logged, ip_address
                ) VALUES (
                    :1, :2, :3, :4, :5, :6
                )
                RETURNING id INTO :7
            """, (email, user_name, action, page, when_logged, ip_address, id_var))
            db.connection.commit()
            cursor.close()

            new_id = int(id_var.getvalue()[0]) if id_var.getvalue() else None
            return {
                'success': True,
                'message': 'Audit log recorded.',
                'id': new_id,
                'email': email,
                'user_name': user_name,
            }
        except Exception as e:
            logger.error(f"Failed to create audit log: {e}")
            return {'success': False, 'message': str(e)}

    @staticmethod
    def list_audit_logs(email: str = None, action: str = None, page: str = None,
                        date_from=None, date_to=None, ip_address: str = None,
                        page_num: int = 1, page_size: int = 20):
        try:
            offset = (page_num - 1) * page_size
            where = []
            params = {}

            if email:
                where.append("LOWER(email) = :email")
                params['email'] = email.strip().lower()
            if action:
                where.append("UPPER(action) LIKE :action")
                params['action'] = f"%{action.strip().upper()}%"
            if page:
                where.append("UPPER(NVL(page, '')) LIKE :page")
                params['page'] = f"%{page.strip().upper()}%"
            if date_from:
                where.append("created_at >= :date_from")
                params['date_from'] = date_from
            if date_to:
                where.append("created_at <= :date_to")
                params['date_to'] = date_to
            if ip_address:
                where.append("LOWER(ip_address) = :ip_address")
                params['ip_address'] = ip_address.strip().lower()

            where_sql = "WHERE " + " AND ".join(where) if where else ""

            count_sql = f"SELECT COUNT(*) FROM audit_trail {where_sql}"
            count_result = db.fetch_one(count_sql, params)
            total = count_result[0] if count_result else 0

            query = f"""
                SELECT id, email, user_name, action, page,
                       when_logged, created_at, ip_address
                FROM audit_trail
                {where_sql}
                ORDER BY created_at DESC
                OFFSET :offset ROWS FETCH NEXT :limit ROWS ONLY
            """
            params['offset'] = offset
            params['limit'] = page_size
            results = db.fetch_all(query, params)

            records = []
            for r in (results or []):
                records.append({
                    'id': r[0],
                    'email': r[1],
                    'user_name': r[2],
                    'action': r[3],
                    'page': r[4],
                    'when_logged': str(r[5]) if r[5] else None,
                    'created_at': str(r[6]) if r[6] else None,
                    'ip_address': r[7],
                })

            return {'total': total, 'records': records}
        except Exception as e:
            logger.error(f"Failed to list audit logs: {e}")
            return {'total': 0, 'records': []}

    # ============================================================
    # LOAN APIS (CORE BANKING)
    # ============================================================
    @staticmethod
    def _call_boi_loan_api(url: str, output_key: str):
        """Generic caller for BOI loan APIs that return a list under output_key."""
        try:
            headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
            logger.info(f"Calling BOI loan API: {url}")
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code != 200:
                logger.error(f"BOI loan API error: {response.status_code} - {response.text}")
                return None

            try:
                data = response.json()
            except Exception:
                logger.warning("BOI loan API returned non-JSON; treating as no data")
                return None

            if data is None:
                return None

            outputs = data.get(output_key) or []
            if not outputs:
                return None

            return outputs
        except Exception as e:
            logger.error(f"BOI loan API error: {e}")
            return None

    @staticmethod
    def fetch_loan_list(cust_num: str):
        """Call BOI loan list API."""
        if not cust_num:
            return None
        url = f"{Config.LOAN_LIST_API_URL}?custNum={cust_num}"
        outputs = CustomerService._call_boi_loan_api(url, "loanListdbReferenceOutput")
        if not outputs:
            return None

        loans = []
        for row in outputs:
            loans.append({
                'account_number': row.get('ACCT_NO'),
                'rec_st': row.get('REC_ST'),
                'status': row.get('status'),
                'product_description': row.get('PROD_DESC'),
            })
        return loans

    @staticmethod
    def fetch_loan_summary(loan_account: str):
        """Call BOI loan statistics API."""
        if not loan_account:
            return None
        url = f"{Config.LOAN_SUMMARY_API_URL}?acctNum={loan_account}"
        outputs = CustomerService._call_boi_loan_api(url, "loanstatisticsdbReferenceOutput")
        if not outputs:
            return None

        row = outputs[0]
        return {
            'account_number': row.get('ACCT_NO'),
            'account_name': row.get('ACCT_NM'),
            'overdue_principal': row.get('OVERDUE_PRINCIPAL'),
            'overdue_interest': row.get('OVERDUE_INTEREST'),
            'due_principal': row.get('DUE_PRINCIPAL'),
            'due_interest': row.get('DUE_INTEREST'),
            'total_principal_outstanding': row.get('TOTAL_PRINCIPAL_OUTSTANDING'),
            'total_interest_outstanding': row.get('TOTAL_INTEREST_OUTSTANDING'),
            'principal_paid': row.get('PRINCIPAL_PAID'),
            'interest_paid': row.get('INTEREST_PAID'),
            'total_paid': row.get('TOTAL_PAID'),
            'total_overdue': row.get('TOTAL_OVERDUE'),
            'total_due_next': row.get('TOTAL_DUE_NEXT'),
            'total_outstanding_all': row.get('TOTAL_OUTSTANDING_ALL'),
            'total_due_now': row.get('TOTAL_DUE_NOW'),
            'original_loan_amount': row.get('ORIGINAL_LOAN_AMOUNT'),
            'charges': row.get('CHARGES'),
            'interest_rate': row.get('INTEREST_RATE'),
            'account_id': row.get('ACCT_ID'),
            'term_value': row.get('TERM_VALUE'),
            'term_cd': row.get('TERM_CD'),
            'cleared_balance': row.get('CLEARED_BAL'),
            'dr_int_accrued': row.get('DR_INT_ACCRUED'),
            'last_accrual_date': row.get('LAST_ACCRUAL_DT'),
            'dr_int_per_day': row.get('DR_INT_PER_DAY'),
            'dr_int_accrued_ytd': row.get('DR_INT_ACCRUED_YTD'),
            'total_charges': row.get('TOTAL_CHRGS'),
            'account_status': row.get('ACCOUNT_STATUS'),
            'disbursed_balance': row.get('DISBURSED_BAL'),
            'status_effective_date': row.get('STATUS_EFFECTIVE_DT'),
            'maturity_date': row.get('MATURITY_DT'),
        }

    @staticmethod
    def fetch_loan_history(loan_account: str):
        """Call BOI loan account history API."""
        if not loan_account:
            return None
        url = f"{Config.LOAN_HISTORY_API_URL}?LoanAccountNo={loan_account}"
        outputs = CustomerService._call_boi_loan_api(url, "loanAccountHistoryBusinessServiceOutput")
        if not outputs:
            return None

        records = []
        for row in outputs:
            records.append({
                'debit_amount': row.get('DebitAmt'),
                'transaction_reference': row.get('TransactionReference'),
                'transaction_description': row.get('TransactionDescription'),
                'loan_account': row.get('LoanAccount'),
                'amount': row.get('Amount'),
                'credit_amount': row.get('CreditAmt'),
                'cleared_balance': row.get('ClearedBalance'),
                'event_code': row.get('EventCode'),
                'channel_description': row.get('ChannelDescription'),
                'ledger_balance': row.get('LedgerBalance'),
                'business_unit': row.get('BusinessUnit'),
                'currency': row.get('Currency'),
                'value_date': row.get('ValueDate'),
                'date_timestamp': row.get('DateTimestamp'),
                'dr_cr': row.get('DrCr'),
                'cheque_no': row.get('ChequeNo'),
                'event_description': row.get('EventDescription'),
                'transaction_date': row.get('TransactionDate'),
            })
        return records

    @staticmethod
    def fetch_loan_repayment(loan_account: str):
        """Call BOI loan repayment schedule API."""
        if not loan_account:
            return None
        url = f"{Config.LOAN_REPAYMENT_API_URL}?loanAccount={loan_account}"
        outputs = CustomerService._call_boi_loan_api(url, "loanscheduledbReferenceOutput")
        if not outputs:
            return None

        records = []
        for row in outputs:
            records.append({
                'installment_no': row.get('InstallmentNo'),
                'loan_account': row.get('LoanAccount'),
                'due_date': row.get('DueDate'),
                'event_type': row.get('EventType'),
                'currency_code': row.get('CurrencyCode'),
                'principal_amount': row.get('PrincipalAmount'),
                'interest_amount': row.get('InterestAmount'),
                'fee_amount': row.get('FeeAmount'),
                'late_fee_amount': row.get('LateFeeAmount'),
                'total_amount': row.get('TotalAmount'),
                'serviced_amount': row.get('ServicedAmount'),
                'unserviced_amount': row.get('UnservicedAmount'),
                'serviced_date': row.get('ServicedDate'),
                'days_late': row.get('DaysLate'),
            })
        return records

    # ============================================================
    # STATEMENTS
    # ============================================================
    @staticmethod
    def fetch_statements(acc_no: str):
        """Call BOI API to get the list of available statements."""
        if not acc_no:
            return None
        url = f"{Config.CUSTOMER_STATEMENT_LIST_URL}?accNo={acc_no}"
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        
        try:
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code != 200:
                return None
            return response.json()
        except Exception as e:
            logger.error(f"Statement list error: {e}")
            return None

    @staticmethod
    def download_statement_pdf(date: str, filename: str):
        """Call BOI API to download the actual PDF file."""
        try:
            url = f"{Config.CUSTOMER_STATEMENT_PDF_URL}/{date}/{filename}"
            headers = {'Accept': 'application/pdf'}
            logger.info(f"Downloading statement PDF from: {url}")
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code != 200:
                logger.error(f"PDF download error: {response.status_code}")
                return None
            
            return response.content
        except Exception as e:
            logger.error(f"PDF download error: {e}")
            return None
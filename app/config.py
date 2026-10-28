import os
import subprocess
import logging
from pathlib import Path
from dotenv import load_dotenv
import re

logger = logging.getLogger(__name__)

# ============================================================
# CONFIGURATION LOADING (SOPS)
# ============================================================
PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ENV_PATH_ENV = os.getenv("ENV_PATH")

def _load_from_sops():
    enc_path = os.getenv("SOPS_ENV_FILE", str(PROJECT_ROOT / ".env.enc"))
    if not Path(enc_path).exists():
        logger.error(f"SOPS env file not found: {enc_path}")
        return False
    try:
        result = subprocess.run(
            ["/usr/local/bin/sops", "-d", "--input-type", "dotenv", "--output-type", "dotenv", enc_path],
            capture_output=True, text=True, check=True,
        )
    except FileNotFoundError:
        logger.error("SOPS binary not found at /usr/local/bin/sops")
        return False
    except subprocess.CalledProcessError as e:
        logger.error(f"SOPS decryption failed: {e.stderr or e.stdout or e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error running SOPS: {e}")
        return False

    loaded = 0
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key:
            os.environ[key] = value
            loaded += 1
    logger.info(f"SOPS env loaded: {loaded} keys from {enc_path}")
    return True

def _load_from_dotenv_file(path: Path):
    load_dotenv(dotenv_path=path, override=True)
    logger.info(f"Loaded .env from {path}")

if os.getenv("SOPS_DECRYPT_ON_LOAD", "false").lower() == "true":
    if not _load_from_sops():
        raise RuntimeError("SOPS_DECRYPT_ON_LOAD=true but decryption failed.")
elif os.getenv("ENV_PATH"):
    env_path = Path(os.getenv("ENV_PATH"))
    if env_path.exists():
        _load_from_dotenv_file(env_path)
    else:
        raise RuntimeError(f"ENV_PATH set but file not found: {env_path}")
elif (PROJECT_ROOT / ".env").exists():
    _load_from_dotenv_file(PROJECT_ROOT / ".env")
else:
    logger.warning(f"No configuration source found.")

# ============================================================
# CONFIG
# ============================================================
class Config:
    DATABASE_URL = os.getenv("DATABASE_URL")

    @classmethod
    def get_connection_params(cls):
        if not cls.DATABASE_URL:
            raise ValueError("DATABASE_URL not set.")
        url = cls.DATABASE_URL.replace('oracle://', '')
        patterns = [
            r'^([^:]+):([^@]+)@([^:]+):(\d+)/(.+)$',
            r'^([^:]+):([^@]+)@([^:]+):(\d+)\?service_name=(.+)$',
            r'^([^:]+):([^@]+)@([^:]+):(\d+):(.+)$',
        ]
        for pattern in patterns:
            match = re.match(pattern, url)
            if match:
                groups = match.groups()
                if len(groups) == 5:
                    username, password, host, port, service = groups
                    return {'user': username, 'password': password, 'host': host, 'port': int(port), 'service_name': service}
        return {'dsn': url}

    @classmethod
    def get_oracle_dsn(cls):
        params = cls.get_connection_params()
        if 'dsn' in params: return params['dsn']
        return f"{params['host']}:{params['port']}/{params['service_name']}"

    # JWT
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    ALGORITHM = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 5))
    REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))

    # OTP
    OTP_EXPIRE_MINUTES = int(os.getenv("OTP_EXPIRE_MINUTES", 5))
    OTP_EXPIRE_MINUTES_REGISTRATION = int(os.getenv("OTP_EXPIRE_MINUTES_REGISTRATION", 30))
    OTP_EXPIRE_MINUTES_LOGIN = int(os.getenv("OTP_EXPIRE_MINUTES_LOGIN", 5))

    # Email
    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_USE_AUTH = bool(SMTP_PASSWORD)

    # External APIs
    CUSTOMER_API_URL = os.getenv("CUSTOMER_API_URL", "http://192.168.177.26:7001/getCustomerNumber/getCustomerNumberRestService/getCustomerNumber")
    CUSTOMER_INFO_API_URL = os.getenv("CUSTOMER_INFO_API_URL", "http://192.168.177.26:7001/customerInfo/custInfoRestService/custInfo")
    CUSTOMER_EMAIL_API_URL = os.getenv("CUSTOMER_EMAIL_API_URL", "http://192.168.177.26:7001/getEmail/getEmailRestService/getEmail")

    # Loan APIs
    LOAN_LIST_API_URL = os.getenv("LOAN_LIST_API_URL", "http://192.168.177.26:7001/loanList/loanListRestService/loanList")
    LOAN_SUMMARY_API_URL = os.getenv("LOAN_SUMMARY_API_URL", "http://192.168.177.26:7001/loanStatistics/loanStatisticsRestService/execute")
    LOAN_HISTORY_API_URL = os.getenv("LOAN_HISTORY_API_URL", "http://192.168.177.26:7001/loanAccountHistory/loanAccountHistoryRestService/loanAccountHistory")
    LOAN_REPAYMENT_API_URL = os.getenv("LOAN_REPAYMENT_API_URL", "http://192.168.177.26:7001/loanRepaymentSchedule/loanScheduleRestService/loanSchedule")

    # Statement APIs
    CUSTOMER_STATEMENT_LIST_URL = os.getenv("CUSTOMER_STATEMENT_LIST_URL", "http://192.168.177.26:7001/getFiles/RestService/getFiles")
    CUSTOMER_STATEMENT_PDF_URL = os.getenv("CUSTOMER_STATEMENT_PDF_URL", "http://192.168.177.26:7001/pdfStream/PDF_API_Proxy/api/documents")

    # Association messages
    ASSOC_MSG_BOTH_MISSING = os.getenv("ASSOC_MSG_BOTH_MISSING", "Account number does not exist")
    ASSOC_MSG_EMAIL_MISSING = os.getenv("ASSOC_MSG_EMAIL_MISSING", "Email is not registered with Bank of Industry")
    ASSOC_MSG_ACCOUNT_MISSING = os.getenv("ASSOC_MSG_ACCOUNT_MISSING", "No loan account for this number")
    ASSOC_MSG_EMAIL_ACCOUNT_MISMATCH = os.getenv("ASSOC_MSG_EMAIL_ACCOUNT_MISMATCH", "Email does not match this loan account.")

    # Reset links
    RESET_PASSWORD_BASE_URL = os.getenv("RESET_PASSWORD_BASE_URL", "http://192.168.177.26:3000")
    CUSTOMER_RESET_PATH = os.getenv("CUSTOMER_RESET_PATH", "/customer/reset-password")
    CUSTOMER_SETUP_PATH = os.getenv("CUSTOMER_SETUP_PATH", "/customer/set-password")
    ADMIN_RESET_PATH = os.getenv("ADMIN_RESET_PATH", "/admin/reset-password")

    # Frontend URLs
    FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "http://192.168.177.26:3000")
    CUSTOMER_VERIFY_PATH = os.getenv("CUSTOMER_VERIFY_PATH", "/verify")
    CUSTOMER_LOGIN_PATH = os.getenv("CUSTOMER_LOGIN_PATH", "/login")
    ADMIN_BASE_URL = os.getenv("ADMIN_BASE_URL", FRONTEND_BASE_URL)
    ADMIN_VERIFY_PATH = os.getenv("ADMIN_VERIFY_PATH", "/admin/verify")
    ADMIN_LOGIN_PATH = os.getenv("ADMIN_LOGIN_PATH", "/admin/login")

    # Security
    ENABLE_DOCS = os.getenv("ENABLE_DOCS", "False").lower() == "true"
    _cors = os.getenv("CORS_ORIGINS", "http://localhost:3000")
    CORS_ORIGINS = [o.strip() for o in _cors.split(",") if o.strip()]
    LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", 5))
    LOGIN_WINDOW_MINUTES = int(os.getenv("LOGIN_WINDOW_MINUTES", 5))
    LOGIN_LOCKOUT_MINUTES = int(os.getenv("LOGIN_LOCKOUT_MINUTES", 15))
    ENABLE_SECURITY_HEADERS = os.getenv("ENABLE_SECURITY_HEADERS", "True").lower() == "true"

    # IP safelist
    _safelist = os.getenv("IP_SAFELIST_NETWORKS", "127.0.0.1/32")
    IP_SAFELIST_NETWORKS = [c.strip() for c in _safelist.split(",") if c.strip()]

    # Service identity
    APP_NAME = os.getenv("APP_NAME", "reglog-otp-auth")
    ENVIRONMENT = os.getenv("ENVIRONMENT", "uat")

    # Application
    APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
    APP_PORT = int(os.getenv("APP_PORT", 8000))
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
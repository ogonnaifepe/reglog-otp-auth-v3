import random
import string
import socket
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import threading

from app.database import db
from app.config import Config

logger = logging.getLogger(__name__)


# ============================================================
# EMAIL MESSAGE TEMPLATES
# ============================================================
EMAIL_MESSAGES = {
    "customer_password_reset": {
        "subject": "Password Reset Request",
        "greeting": "Hello {name},",
        "intro": "Your account password has been reset by an administrator. Click below to set a new password.",
        "button_text": "Reset Password",
        "footer": "This link expires in 24 hours. If you didn't request this, please ignore this email.",
    },
    "customer_setup": {
        "subject": "Welcome - Set Up Your Account",
        "greeting": "Hello {name},",
        "intro": "An account has been created for you. Click below to set your password and activate your account.",
        "button_text": "Set Up Account",
        "footer": "This link expires in 24 hours. If you didn't request this, please ignore this email.",
    },
    "admin_password_reset": {
        "subject": "Admin Password Reset Request",
        "greeting": "Hello {name},",
        "intro": "You requested a password reset for your admin account. Click below to set a new password.",
        "button_text": "Reset Admin Password",
        "footer": "This link expires in 24 hours. If you didn't request this, please ignore this email.",
    },
    "password_reset": {
        "subject": "Password Reset Request",
        "greeting": "Hello {name},",
        "intro": "You requested a password reset. Click below to continue.",
        "button_text": "Reset Password",
        "footer": "This link expires in 24 hours. If you didn't request this, please ignore this email.",
    },
}


# ============================================================
# SMTP CONNECTION POOL
# ============================================================
class SMTPConnection:
    def __init__(self):
        self.server = None
        self.lock = threading.Lock()

    def _create_connection(self):
        try:
            host_ip = socket.gethostbyname(Config.SMTP_HOST)  # force IPv4
        except socket.gaierror:
            logger.warning(f"IPv4 DNS failed for {Config.SMTP_HOST}, using hostname")
            host_ip = Config.SMTP_HOST

        # Connect
        server = smtplib.SMTP(
            host=host_ip,
            port=Config.SMTP_PORT,
            timeout=10,
        )
        server.ehlo()

        # Authenticate only if credentials are provided
        if Config.SMTP_USE_AUTH:
            server.starttls()
            server.ehlo()
            server.login(Config.SMTP_USERNAME, Config.SMTP_PASSWORD)
            logger.info(f"SMTP connection established to {host_ip}:{Config.SMTP_PORT} (with Auth)")
        else:
            logger.info(f"SMTP connection established to {host_ip}:{Config.SMTP_PORT} (No Auth / Internal Relay)")

        return server

    def get(self):
        if self.server is None:
            self.server = self._create_connection()
            return self.server
        try:
            self.server.noop()
            return self.server
        except Exception:
            logger.info("SMTP connection stale, reconnecting...")
            try:
                self.server.quit()
            except Exception:
                pass
            self.server = self._create_connection()
            return self.server

    def send(self, msg):
        with self.lock:
            try:
                server = self.get()
                server.send_message(msg)
                return True
            except Exception as e:
                logger.error(f"SMTP send failed, retrying once: {e}")
                try:
                    server = self._create_connection()
                    server.send_message(msg)
                    self.server = server
                    return True
                except Exception as e2:
                    logger.error(f"SMTP retry failed: {e2}")
                    self.server = None
                    return False


_smtp = SMTPConnection()


class OTPService:

    @staticmethod
    def generate_otp(length=6):
        return ''.join(random.choices(string.digits, k=length))

    @staticmethod
    def send_email(email, otp_code, purpose, user_type='customer'):
        try:
            if purpose == 'registration':
                if user_type == 'admin':
                    base = Config.ADMIN_BASE_URL
                    path = Config.ADMIN_VERIFY_PATH
                else:
                    base = Config.FRONTEND_BASE_URL
                    path = Config.CUSTOMER_VERIFY_PATH

                verify_link = f"{base}{path}?email={email}"
                expiry_minutes = Config.OTP_EXPIRE_MINUTES_REGISTRATION
                intro = ("Welcome! To complete your registration, "
                         "click the button below or use the OTP code shown.")
                action_heading = "Verify Your Account"
                link_block_html = f"""
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{verify_link}"
                       style="background-color: #0066cc; color: #ffffff; padding: 14px 32px;
                              text-decoration: none; border-radius: 5px; display: inline-block;
                              font-weight: bold; font-size: 16px;">
                        Verify My Account
                    </a>
                </div>
                <p style="color: #666; font-size: 13px;">Or copy this link into your browser:</p>
                <p style="color: #0066cc; word-break: break-all; font-size: 12px;">{verify_link}</p>
                """
                link_block_text = f"\nOr click this link:\n{verify_link}\n"

            elif purpose == 'login':
                expiry_minutes = Config.OTP_EXPIRE_MINUTES_LOGIN
                intro = "Use the OTP below to complete your login."
                action_heading = "Your Login OTP"
                link_block_html = ""
                link_block_text = ""

            else:
                expiry_minutes = Config.OTP_EXPIRE_MINUTES
                intro = f"Use the OTP below to complete your {purpose}."
                action_heading = "Your OTP"
                link_block_html = ""
                link_block_text = ""

            msg = MIMEMultipart('alternative')
            msg['From'] = Config.SMTP_USERNAME
            msg['To'] = email
            msg['Subject'] = f"Your OTP for {purpose}"

            text_body = f"""{intro}

Your OTP is: {otp_code}

This OTP expires in {expiry_minutes} minutes.
{link_block_text}"""

            html_body = f"""
<html>
<body style="font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px;">
  <div style="max-width: 600px; margin: 0 auto; background: #ffffff; padding: 30px;
              border-radius: 8px; border: 1px solid #e0e0e0;">
    <h2 style="color: #333; margin-top: 0;">{action_heading}</h2>
    <p style="color: #333;">{intro}</p>

    <div style="background-color: #f5f5f5; padding: 25px; text-align: center;
                border-radius: 8px; margin: 25px 0;">
      <p style="margin: 0 0 8px 0; color: #666; font-size: 14px;">Your OTP code:</p>
      <h1 style="color: #0066cc; font-size: 40px; margin: 0; letter-spacing: 6px;">
        {otp_code}
      </h1>
    </div>

    {link_block_html}

    <p style="color: #999; font-size: 12px; margin-top: 30px; border-top: 1px solid #eeeeee;
              padding-top: 15px;">
      This OTP expires in {expiry_minutes} minutes.
      If you didn't request this, please ignore this email.
    </p>
  </div>
</body>
</html>
"""

            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))

            ok = _smtp.send(msg)
            if ok:
                logger.info(f"OTP email sent to {email} (purpose={purpose}, user_type={user_type})")
            return ok

        except Exception as e:
            logger.error(f"Email send error: {e}")
            return False

    @staticmethod
    def send_password_reset_email(email, reset_link, purpose="password_reset", recipient_name=None):
        try:
            template = EMAIL_MESSAGES.get(purpose, EMAIL_MESSAGES["password_reset"])

            name = recipient_name or "there"
            greeting = template["greeting"].format(name=name)
            subject = template["subject"]
            intro = template["intro"]
            button_text = template["button_text"]
            footer = template["footer"]

            msg = MIMEMultipart('alternative')
            msg['From'] = Config.SMTP_USERNAME
            msg['To'] = email
            msg['Subject'] = subject

            text_body = f"""{greeting}

{intro}

Click this link to continue:
{reset_link}

{footer}
"""

            html_body = f"""
<html>
<body style="font-family: Arial, sans-serif;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;
                border: 1px solid #e0e0e0; border-radius: 5px;">
        <h2 style="color: #333;">{subject}</h2>
        <p>{greeting}</p>
        <p>{intro}</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{reset_link}"
               style="background-color: #0066cc; color: #ffffff; padding: 12px 30px;
                      text-decoration: none; border-radius: 5px; display: inline-block;
                      font-weight: bold;">
                {button_text}
            </a>
        </div>
        <p style="color: #666;">Or copy this link into your browser:</p>
        <p style="color: #0066cc; word-break: break-all; font-size: 13px;">{reset_link}</p>
        <p style="color: #999; font-size: 12px; margin-top: 30px;">{footer}</p>
    </div>
</body>
</html>
"""

            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))

            ok = _smtp.send(msg)
            if ok:
                logger.info(f"Password reset email sent to {email} (purpose={purpose})")
            return ok

        except Exception as e:
            logger.error(f"Password reset email send error: {e}")
            return False

    @staticmethod
    def send_email_async(email, otp_code, purpose, user_type='customer'):
        def _worker():
            try:
                OTPService.send_email(email, otp_code, purpose, user_type)
            except Exception as e:
                logger.error(f"Async OTP email failed: {e}")

        t = threading.Thread(target=_worker, daemon=True)
        t.start()

    @staticmethod
    def send_password_reset_email_async(email, reset_link, purpose="password_reset", recipient_name=None):
        def _worker():
            try:
                OTPService.send_password_reset_email(email, reset_link, purpose, recipient_name)
            except Exception as e:
                logger.error(f"Async password reset email failed: {e}")

        t = threading.Thread(target=_worker, daemon=True)
        t.start()

    @staticmethod
    def store_otp(email, otp_code, purpose):
        if purpose == 'registration':
            expiry_minutes = Config.OTP_EXPIRE_MINUTES_REGISTRATION
        elif purpose == 'login':
            expiry_minutes = Config.OTP_EXPIRE_MINUTES_LOGIN
        else:
            expiry_minutes = Config.OTP_EXPIRE_MINUTES

        expires_at = datetime.now() + timedelta(minutes=expiry_minutes)
        query = """
            INSERT INTO otp_codes (email, otp_code, purpose, expires_at)
            VALUES (:1, :2, :3, :4)
        """
        db.execute_query(query, (email, otp_code, purpose, expires_at))
        logger.info(f"OTP stored for {email} (purpose={purpose}, expires in {expiry_minutes} min)")

    @staticmethod
    def verify_otp(email, otp_code, purpose):
        query = """
            SELECT id, expires_at, is_used
            FROM otp_codes
            WHERE email = :1
            AND otp_code = :2
            AND purpose = :3
            AND is_used = 'N'
            ORDER BY created_at DESC
            FETCH FIRST 1 ROW ONLY
        """
        result = db.fetch_one(query, (email, otp_code, purpose))

        if not result:
            return False, "Invalid OTP"

        otp_id, expires_at, is_used = result

        if datetime.now() > expires_at:
            return False, "OTP has expired"

        update_query = "UPDATE otp_codes SET is_used = 'Y' WHERE id = :1"
        db.execute_query(update_query, (otp_id,))

        return True, "OTP verified successfully"

    @staticmethod
    def invalidate_old_otps(email, purpose):
        query = """
            UPDATE otp_codes
            SET is_used = 'Y'
            WHERE email = :1 AND purpose = :2 AND is_used = 'N'
        """
        db.execute_query(query, (email, purpose))
        logger.info(f"Invalidated old OTPs for {email} with purpose {purpose}")

    @staticmethod
    def can_resend(email, purpose, cooldown_seconds=60):
        query = """
            SELECT created_at FROM otp_codes
            WHERE email = :1 AND purpose = :2
            ORDER BY created_at DESC
            FETCH FIRST 1 ROW ONLY
        """
        result = db.fetch_one(query, (email, purpose))
        if not result:
            return True, 0

        last_created = result[0]
        elapsed = (datetime.now() - last_created).total_seconds()
        if elapsed >= cooldown_seconds:
            return True, 0
        return False, int(cooldown_seconds - elapsed)
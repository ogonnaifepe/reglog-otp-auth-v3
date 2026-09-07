import requests
import logging
from app.config import Config
from app.database import db

logger = logging.getLogger(__name__)

class CustomerService:
    @staticmethod
    def get_customer_number_by_account(account_number: str):
        """
        Call external API to get customer number by account number
        """
        try:
            url = f"{Config.CUSTOMER_API_URL}?AccountNumber={account_number}"
            
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            logger.info(f"Calling external API: {url}")
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                logger.info(f"External API response received")
                
                if 'getCustomerNumberdbReferenceOutput' in data:
                    output = data['getCustomerNumberdbReferenceOutput']
                    if output and len(output) > 0:
                        return {
                            'account_name': output[0].get('accountName'),
                            'account_number': output[0].get('accountNumber'),
                            'customer_number': output[0].get('customerNumber')
                        }
                
                return None
            else:
                logger.error(f"External API error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"External API request failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Error calling external API: {e}")
            return None
    
    @staticmethod
    def update_user_with_customer_info(email: str, customer_number: str, account_name: str = None, account_number: str = None):
        """
        Update user's customer_no and set profile to 'Y'
        """
        try:
            query = """
                UPDATE users 
                SET customer_no = :1, 
                    profile = 'Y',
                    updated_at = CURRENT_TIMESTAMP
                WHERE email = :2
            """
            
            db.execute_query(query, (customer_number, email))
            logger.info(f"Updated user {email} with customer_no: {customer_number}, profile set to Y")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update user: {e}")
            return False
    
    @staticmethod
    def get_user_by_email(email: str):
        """
        Get user details by email
        """
        try:
            query = """
                SELECT id, email, full_name, phone_number, profile, customer_no, is_verified
                FROM users 
                WHERE email = :1
            """
            result = db.fetch_one(query, (email,))
            
            if result:
                return {
                    'id': result[0],
                    'email': result[1],
                    'full_name': result[2],
                    'phone_number': result[3],
                    'profile': result[4],
                    'customer_no': result[5],
                    'is_verified': result[6]
                }
            return None
            
        except Exception as e:
            logger.error(f"Failed to get user: {e}")
            return None
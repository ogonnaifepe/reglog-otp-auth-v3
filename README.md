# reglog-otp-auth-v3

# This is a registration and login API with OTP built with python



# create oracle schema
schema creation.sql

# Create tables and object
schema creation.sql

# set oracle db credntials
.env


# test db connection

python test_simple.py



#to start the application


python run.py




# for API guide
check the doc file




Authentication Endpoints (/api/v1/auth)
#	Method	Endpoint	Description	Authentication
1	POST	/api/v1/auth/register	Register new user (sends OTP)	

2	POST	/api/v1/auth/verify-otp	Verify registration OTP & get tokens

3	POST	/api/v1/auth/login	Login (sends OTP)	

4	POST	/api/v1/auth/verify-login-otp	Verify login OTP & get tokens	

5	POST	/api/v1/auth/token	Generate tokens directly (username+password)	

6	POST	/api/v1/auth/refresh	Refresh expired access token	

7	POST	/api/v1/auth/logout	Logout (blacklist tokens)	✅ Yes (Access Token)

8	GET	/api/v1/auth/profile	Get user profile	✅ Yes (Access Token)



OTP Management Endpoints (/api/v1/otp)

#	Method	Endpoint	Description	Authentication
9	POST	/api/v1/otp/generate	Generate & send OTP	

10	POST	/api/v1/otp/verify	Verify OTP	

11	POST	/api/v1/otp/resend	Resend OTP	

12	POST	/api/v1/otp/validate	Validate OTP (testing)	

13	GET	/api/v1/otp/check-verification/{email}	Check verification status	

14	DELETE	/api/v1/otp/invalidate/{email}	Invalidate user's OTPs	




System Endpoints
#	Method	Endpoint	Description	Authentication
15	GET	/	API information	

16	GET	/health	Health check	

17	GET	/docs	Swagger UI documentation	

18	GET	/redoc	ReDoc documentation	




This what an update from reglog-otp-auth

Updated API Endpoints
#	Method	Endpoint	Description	Authentication
1	POST	/api/v1/auth/register	Register with full_name, email, phone_number, password	

2	POST	/api/v1/auth/verify-otp	Verify registration OTP & get tokens	

3	POST	/api/v1/auth/login	Login with email + password (sends OTP)	

4	POST	/api/v1/auth/verify-login-otp	Verify login OTP & get tokens	

5	POST	/api/v1/auth/token	Generate tokens with email + password	

6	POST	/api/v1/auth/refresh	Refresh access token	

7	POST	/api/v1/auth/logout	Logout	

8	GET	/api/v1/auth/profile	Get full user profile	

9	PUT	/api/v1/auth/profile	Update profile (full_name/phone)	




Testing Examples
# 1. Register with Full Name, Email, Phone, Password

# bash
curl -X POST "http://localhost:8002/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "full_name": "John Doe",
    "email": "johndoe@gmail.com",
    "phone_number": "+1234567890",
    "password": "Test12345",
    "confirm_password": "Test12345"
  }'


# Response:

json
{
  "message": "Registration successful. Please verify your email with OTP to get access tokens.",
  "success": true,
  "data": {
    "email": "johndoe@gmail.com",
    "full_name": "John Doe",
    "phone_number": "+1234567890"
  }
}


# 3. Verify OTP (Get Tokens)
bash
curl -X POST "http://localhost:8002/api/v1/auth/verify-otp" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "johndoe@gmail.com",
    "otp_code": "655636",
    "purpose": "registration"
  }'


# Response:
json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "full_name": "John Doe",
    "email": "johndoe@gmail.com",
    "phone_number": "+1234567890",
    "is_verified": true
  },
  "expires_in": 300,
  "refresh_expires_in": 604800,
  "message": "Email verified and tokens generated successfully"
}

# 4. Login (Email + Password)
bash
curl -X POST "http://localhost:8002/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "johndoe@gmail.com",
    "password": "Test12345"
  }'

# 5. Get Profile (Returns Full User Info)
bash
ACCESS_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

curl -X GET "http://localhost:8002/api/v1/auth/profile" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# Response:
json
{
  "id": 1,
  "full_name": "John Doe",
  "email": "johndoe@gmail.com",
  "phone_number": "+1234567890",
  "is_verified": true,
  "created_at": "2024-01-15T10:30:00",
  "updated_at": "2024-01-15T10:30:00"
}


# 5. Update Profile
bash
# Update full_name only
curl -X PUT "http://localhost:8002/api/v1/auth/profile?full_name=Jane Doe" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# Update phone_number only
curl -X PUT "http://localhost:8002/api/v1/auth/profile?phone_number=+1987654321" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# Update both
curl -X PUT "http://localhost:8002/api/v1/auth/profile?full_name=Jane Doe&phone_number=+1987654321" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

  
  
  
  
#  How to Call Endpoints in Postman
Prerequisites
1.	Your application is running on http://localhost:8002
2.	You have registered a user and verified OTP
3.	You have an access token
4.	Here we walk through the process of registration and linking customer on loan portal with the core banking solution
   
________________________________________
# 1. Register User (POST)
URL: http://localhost:8002/api/v1/auth/register
Method: POST
Headers:
text
Content-Type: application/json
Body (raw JSON):
json
{
  "full_name": "Ogonna Ifepe",
  "email": "ogonnaifepe@gmail.com",
  "phone_number": "08086008539",
  "password": "stringst123",
  "confirm_password": "stringst123"
}
Postman Setup:
1.	Select POST method
2.	Enter URL
3.	Go to Body → raw → JSON
4.	Paste the JSON above
5.	Click Send


# Expected Response:
json
{
  "message": "Registration successful. Please verify your email with OTP to get access tokens.",
  "success": true,
  "data": {
    "email": "ogonnaifepe@gmail.com",
    "full_name": "Ogonna Ifepe"
  }
}
________________________________________

# 2. Verify OTP (POST)
URL: http://localhost:8002/api/v1/auth/verify-otp
Method: POST
Headers:
text
Content-Type: application/json
Body (raw JSON):
json
{
  "email": "ogonnaifepe@gmail.com",
  "otp_code": "123456",
  "purpose": "registration"
}
Note: Replace 123456 with the actual OTP from your logs/email.

# Postman Setup: Same as registration.
# Expected Response:
json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "email": "ogonnaifepe@gmail.com",
  "is_verified": true,
  "expires_in": 300,
  "refresh_expires_in": 604800,
  "message": "Email verified and tokens generated successfully"
}
________________________________________
# 3. Get Profile (GET) - Requires Token
URL: http://localhost:8002/api/v1/auth/profile
Method: GET
Headers:
text
Authorization: Bearer YOUR_ACCESS_TOKEN
Content-Type: application/json
Postman Setup:
1.	Select GET method
2.	Enter URL
3.	Go to Headers tab
4.	Add header: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
5.	Click Send


# Expected Response:
json
{
  "id": 1,
  "email": "ogonnaifepe@gmail.com",
  "full_name": "Ogonna Ifepe",
  "phone_number": "08086008539",
  "profile": "N",
  "customer_no": null,
  "is_verified": true,
  "created_at": "2024-01-15 10:30:00"
}
________________________________________

# 4. Get Customer Info by Email (POST)
URL: http://localhost:8002/api/v1/auth/get-customer-info
Method: POST
Headers:
text
Content-Type: application/json
Body (raw JSON):
json
{
  "email": "ogonnaifepe@gmail.com"
}

# Expected Response:
json
{
  "email": "ogonnaifepe@gmail.com",
  "customer_no": null,
  "profile": "N",
  "account_name": null,
  "account_number": null
}
________________________________________

# 5. Link Customer Profile by Email (POST)
URL: http://localhost:8002/api/v1/auth/link-customer-by-email?account_number=5000152687&email=ogonnaifepe@gmail.com
Method: POST
Headers:
text
Content-Type: application/json
Postman Setup:
1.	Select POST method
2.	Enter URL with query parameters: http://localhost:8002/api/v1/auth/link-customer-by-email?account_number=5000152687&email=ogonnaifepe@gmail.com
3.	Headers: Content-Type: application/json
4.	Body: empty (or {})
5.	Click Send


# Expected Response:
json
{
  "message": "Customer profile linked successfully",
  "success": true,
  "data": {
    "email": "ogonnaifepe@gmail.com",
    "customer_no": "0000035668",
    "account_name": "Toyin Nora Oladapo",
    "account_number": "5000152687",
    "profile": "Y"
  }
}
________________________________________


# 6. Get Profile After Linking (GET)
URL: http://localhost:8002/api/v1/auth/profile
Method: GET
Headers:
text
Authorization: Bearer YOUR_ACCESS_TOKEN
Content-Type: application/json


# Expected Response (After Linking):
json
{
  "id": 1,
  "email": "ogonnaifepe@gmail.com",
  "full_name": "Ogonna Ifepe",
  "phone_number": "08086008539",
  "profile": "Y",
  "customer_no": "0000035668",
  "is_verified": true,
  "created_at": "2024-01-15 10:30:00"
}
________________________________________
Quick Postman Collection

# You can create a Postman collection with these requests:
#	Name	Method	URL
1	Register	POST	/api/v1/auth/register
2	Verify OTP	POST	/api/v1/auth/verify-otp
3	Get Profile	GET	/api/v1/auth/profile (Auth required)
4	Get Customer Info	POST	/api/v1/auth/get-customer-info
5	Link Customer	POST	/api/v1/auth/link-customer-by-email?account_number=5000152687&email=ogonnaifepe@gmail.com
________________________________________

for 5) please reach out to me as this endpoint calls and internal endpoint
email: ogonnaifepe@gmail.com

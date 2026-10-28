from app.routes.auth_routes import router as auth_router
from app.routes.otp_routes import router as otp_router
from app.routes.admin_routes import router as admin_router
from app.routes.admin_customer_routes import router as admin_customer_router

__all__ = ['auth_router', 'otp_router', 'admin_router', 'admin_customer_router']
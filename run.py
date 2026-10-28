# run.py  minimal, no reload
import uvicorn
import os
from dotenv import load_dotenv

# Load .env from project root
from pathlib import Path
ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env", override=True)

if __name__ == "__main__":
    host = os.getenv("APP_HOST", "0.0.0.0")
    port = int(os.getenv("APP_PORT", 8002))
    print(f"Starting on {host}:{port}")

    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        #ssl_keyfile="./certs/key.pem",
        #ssl_certfile="./certs/cert.pem",
        reload=False,       # HARD-CODED OFF
        workers=1,          # HARD-CODED SINGLE WORKER
        log_level="info",
    )
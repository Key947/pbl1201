from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import logging
import uuid

# -----------------------------
# App & Security Setup
# -----------------------------
app = FastAPI()

SECRET_KEY = "SUPER_SECRET_KEY"
serializer = URLSafeTimedSerializer(SECRET_KEY)

# In-memory session store (demo only)
sessions = {}

# -----------------------------
# Logging (Secure #3)
# -----------------------------
logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log(request: Request, message: str):
    logging.info(f"{request.client.host} - {message}")

# -----------------------------
# Secure #1: Token for Safe URL
# -----------------------------
@app.get("/generate-link")
def generate_safe_link(request: Request):
    token = serializer.dumps({"user_id": 1})
    log(request, "Generated secure URL token")

    return {
        "safe_url": f"/protected?token={token}"
    }

@app.get("/protected")
def protected_url(request: Request, token: str):
    try:
        data = serializer.loads(token, max_age=300)  # 5 minutes
        log(request, f"Valid token access for user {data['user_id']}")
        return {"message": "Token valid", "data": data}
    except SignatureExpired:
        log(request, "Expired token access attempt")
        raise HTTPException(status_code=401, detail="Token expired")
    except BadSignature:
        log(request, "Invalid token access attempt")
        raise HTTPException(status_code=401, detail="Invalid token")

# -----------------------------
# Secure #2: Session
# -----------------------------
@app.post("/login")
def login(request: Request, response: Response):
    session_id = str(uuid.uuid4())
    sessions[session_id] = {"user_id": 1}

    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True
    )

    log(request, f"User logged in with session {session_id}")
    return {"message": "Logged in"}

@app.get("/dashboard")
def dashboard(request: Request):
    session_id = request.cookies.get("session_id")

    if not session_id or session_id not in sessions:
        log(request, "Unauthorized dashboard access")
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = sessions[session_id]
    log(request, f"Dashboard accessed by user {user['user_id']}")
    return {"message": "Welcome to dashboard", "user": user}

@app.post("/logout")
def logout(request: Request, response: Response):
    session_id = request.cookies.get("session_id")

    if session_id in sessions:
        del sessions[session_id]

    response.delete_cookie("session_id")
    log(request, "User logged out")
    return {"message": "Logged out"}

# -----------------------------
# Global Error Logging
# -----------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log(request, f"Unhandled error: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"}
    )

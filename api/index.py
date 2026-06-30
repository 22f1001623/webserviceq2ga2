import os
import uvicorn
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import jwt

app = FastAPI()

# Cleaned up multi-line key string structure
PUBLIC_KEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY\n"
    "cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID\n"
    "EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc\n"
    "WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW\n"
    "ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI\n"
    "SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX\n"
    "dQIDAQAB\n"
    "-----END PUBLIC KEY-----"
)

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-tmxxa5s0.apps.exam.local"

class TokenRequest(BaseModel):
    token: str = Field(description="The JWT token string to verify")

class ValidTokenResponse(BaseModel):
    valid: str
    email: str  
    sub: str
    aud: str

@app.post("/verify", response_model=ValidTokenResponse)
async def verify_token(payload: TokenRequest):
    try:
        # Decode and strictly validate claims
        decoded_claims = jwt.decode(
            payload.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
                "require": ["exp", "iss", "aud", "sub", "email"]
            }
        )

        return ValidTokenResponse(
            valid=True,
            email=str(decoded_claims.get("email")),
            sub=str(decoded_claims.get("sub")),
            aud=str(decoded_claims.get("aud"))
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"valid": False}
        )

if __name__ == "__main__":
    # Hugging Face runs applications on port 7860 by default
    uvicorn.run(app, host="0.0.0.0", port=7860)

from pydantic import BaseModel, EmailStr, Field

from app.models.user import UserPublic


class LoginResult(BaseModel):
    """Résultat de /auth/login : session ouverte directement, ou code 2FA requis."""

    totp_required: bool
    pending_token: str | None = None
    user: UserPublic | None = None


class TotpSetupResult(BaseModel):
    """Secret et URI à afficher pour configurer une application TOTP."""

    secret: str
    uri: str


class TotpCodeInput(BaseModel):
    """Code à 6 chiffres généré par l'application TOTP."""

    code: str = Field(pattern=r"^\d{6}$")


class TotpLoginVerify(BaseModel):
    """Finalisation d'une connexion en attente de code 2FA."""

    pending_token: str
    code: str = Field(pattern=r"^\d{6}$")


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

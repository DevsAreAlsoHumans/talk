from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi import HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import secrets
from app.config import settings

# Context de hachage des mots de passe
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Schéma de sécurité OAuth2
security = HTTPBearer()


class SecurityUtils:
    """Utilitaires de sécurité pour le projet talk."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash un mot de passe avec bcrypt."""
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Vérifie un mot de passe en clair contre son hash."""
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Crée un token JWT d'accès."""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        return encoded_jwt

    @staticmethod
    def verify_token(token: str) -> Dict[str, Any]:
        """Vérifie un token JWT et retourne son payload."""
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            user_id = payload.get("sub")
            if user_id is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token invalide",
                )
            return payload
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token invalide",
            )

    @staticmethod
    def generate_csrf_token() -> str:
        """Génère un jeton CSRF."""
        return secrets.token_urlsafe(32)

    @staticmethod
    def validate_csrf_token(token: str) -> bool:
        """Valide un token CSRF (implémentation de base)."""
        # Dans une implémentation réelle, vous devriez vérifier ce token contre un stock de jetons CSRF
        # Pour l'instant, nous validons simplement qu'il est présent et a une longueur décente
        return bool(token and len(token) >= 32)

    @staticmethod
    def extract_user_id_from_token(token: str) -> str:
        """Extrait l'ID utilisateur d'un token."""
        payload = SecurityUtils.verify_token(token)
        return payload.get("sub")

    @staticmethod
    def generate_session_id() -> str:
        """Génère un ID de session unique."""
        return secrets.token_urlsafe(32)

    @staticmethod
    def sanitize_input(text: str, max_length: int = 1000) -> str:
        """Sanitize une chaîne d'entrée."""
        if not text:
            return text

        # Truncate à la longueur maximale
        if len(text) > max_length:
            text = text[:max_length]

        # Basic XSS prevention
        dangerous_chars = ['<script>', '</script>', 'javascript:', 'onerror=', 'onload=']
        for char in dangerous_chars:
            text = text.replace(char, '')

        return text.strip()
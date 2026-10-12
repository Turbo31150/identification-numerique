"""
Middleware ASGI / FastAPI pour l'Identification Numérique Souveraine.
Permet de sécuriser n'importe quelle API ou agent cognitif avec Bearer Token en temps constant.
"""

from __future__ import annotations
from typing import Optional, Callable
from .core import SovereignIdentityManager, VerificationResult

try:
    from fastapi import Request, HTTPException, status
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
except ImportError:
    pass


class SovereignSecurityBearer:
    """
    Dépendance FastAPI pour protéger des routes via Identification Numérique.
    Usage:
        auth = SovereignSecurityBearer(required_scope="orbe")
        @app.get("/api/secure", dependencies=[Depends(auth)])
        async def secure_endpoint():
            ...
    """

    def __init__(self, required_scope: Optional[str] = None, allow_loopback: bool = True):
        self.required_scope = required_scope
        self.allow_loopback = allow_loopback
        self.manager = SovereignIdentityManager()

    async def __call__(self, request: Request) -> VerificationResult:
        # Autorisation du loopback local sans token si activé
        client_host = request.client.host if request.client else "unknown"
        if self.allow_loopback and client_host in ("127.0.0.1", "::1", "localhost"):
            return VerificationResult(valid=True, reason="Loopback local autorisé")

        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="En-tête 'Authorization: Bearer <token>' requis."
            )

        token = auth_header[7:].strip()
        result = self.manager.verify(token, required_scope=self.required_scope)

        if not result.valid:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Accès refusé par l'Identification Numérique: {result.reason}"
            )

        return result

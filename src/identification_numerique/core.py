"""
Cœur cryptographique du gestionnaire d'Identification Numérique Souveraine.
Génération, signature, validation zero-trust et cycle de vie des identités.
"""

from __future__ import annotations
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, List, Dict, Any

DEFAULT_STORAGE = Path(os.environ.get("IDENTITY_STORAGE_PATH", Path.home() / ".turbo" / "identities.json"))


def parse_ttl(ttl_str: str | int) -> int:
    """Convertit une chaîne TTL ('30d', '24h', '30m', '0') en secondes."""
    if isinstance(ttl_str, int):
        return ttl_str
    ttl_str = str(ttl_str).strip().lower()
    if ttl_str in ("0", "never", "infinite", "unlimited"):
        return 0
    m = re.match(r"^(\d+)([smhdwy]?)$", ttl_str)
    if not m:
        raise ValueError(f"Format TTL invalide: {ttl_str}. Utiliser par exemple '30d', '24h', '60m'.")
    value, unit = int(m.group(1)), m.group(2)
    multipliers = {
        "": 1,
        "s": 1,
        "m": 60,
        "h": 3600,
        "d": 86400,
        "w": 604800,
        "y": 31536000
    }
    return value * multipliers.get(unit, 1)


def format_duration(seconds: int) -> str:
    """Formatte une durée en secondes en version lisible."""
    if seconds <= 0:
        return "Illimité"
    if seconds >= 86400:
        days = seconds // 86400
        return f"{days}j"
    if seconds >= 3600:
        hours = seconds // 3600
        return f"{hours}h"
    if seconds >= 60:
        minutes = seconds // 60
        return f"{minutes}m"
    return f"{seconds}s"


@dataclass
class IdentityRecord:
    id: str
    label: str
    scope: str
    fingerprint: str  # Hash SHA-256 du token
    created_at: int
    expires_at: int   # 0 = jamais
    revoked: bool = False
    revoked_at: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None

    @property
    def is_expired(self) -> bool:
        if self.expires_at == 0:
            return False
        return time.time() > self.expires_at

    @property
    def is_valid(self) -> bool:
        return not self.revoked and not self.is_expired


@dataclass
class VerificationResult:
    valid: bool
    record: Optional[IdentityRecord] = None
    reason: Optional[str] = None


class SovereignIdentityManager:
    """
    Gestionnaire souverain d'identités numériques et de jetons d'accès.
    Stockage décentralisé, zero-trust (seuls les fingerprints SHA-256 sont persistés).
    """

    def __init__(self, storage_path: Path = DEFAULT_STORAGE):
        self.storage_path = Path(storage_path)
        self._ensure_storage()

    def _ensure_storage(self) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.storage_path.exists():
            self._save_records([])
        try:
            os.chmod(self.storage_path, 0o600)
        except OSError:
            pass

    def _load_records(self) -> List[IdentityRecord]:
        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return [IdentityRecord(**item) for item in data]
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    def _save_records(self, records: List[IdentityRecord]) -> None:
        tmp_path = self.storage_path.with_suffix(".tmp")
        data = [asdict(r) for r in records]
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, self.storage_path)
        try:
            os.chmod(self.storage_path, 0o600)
        except OSError:
            pass

    @staticmethod
    def hash_token(raw_token: str) -> str:
        """Génère l'empreinte cryptographique SHA-256 d'un jeton."""
        return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()

    def create_identity(
        self,
        label: str,
        scope: str = "standard",
        ttl: str | int = "30d",
        prefix: str = "id_sec",
        metadata: Optional[Dict[str, Any]] = None
    ) -> tuple[str, IdentityRecord]:
        """
        Crée une identité numérique et génère son secret d'accès unique.
        Le secret n'est retourné qu'à la création et n'est jamais stocké en clair.
        """
        duration = parse_ttl(ttl)
        now = int(time.time())
        expires_at = now + duration if duration > 0 else 0

        identity_id = f"id_{secrets.token_hex(6)}"
        secret_part = secrets.token_urlsafe(32)
        raw_token = f"{prefix}_{secret_part}"
        fingerprint = self.hash_token(raw_token)

        record = IdentityRecord(
            id=identity_id,
            label=label.strip(),
            scope=scope.strip(),
            fingerprint=fingerprint,
            created_at=now,
            expires_at=expires_at,
            revoked=False,
            metadata=metadata or {}
        )

        records = self._load_records()
        records.append(record)
        self._save_records(records)

        return raw_token, record

    def verify(self, raw_token: str, required_scope: Optional[str] = None) -> VerificationResult:
        """
        Vérifie la validité d'une identité numérique en temps constant.
        """
        if not raw_token or not raw_token.strip():
            return VerificationResult(valid=False, reason="Jeton absent ou vide")

        candidate_fp = self.hash_token(raw_token)
        records = self._load_records()

        matched: Optional[IdentityRecord] = None
        for r in records:
            if hmac.compare_digest(r.fingerprint, candidate_fp):
                matched = r
                break

        if not matched:
            return VerificationResult(valid=False, reason="Identité inconnue ou empreinte non reconnue")

        if matched.revoked:
            return VerificationResult(valid=False, record=matched, reason="Identité révoquée")

        if matched.is_expired:
            return VerificationResult(valid=False, record=matched, reason="Identité expirée")

        if required_scope and required_scope != "*":
            # Scopes multiples supportés (séparés par virgule ou espace)
            granted_scopes = [s.strip() for s in matched.scope.replace(",", " ").split()]
            if "*" not in granted_scopes and required_scope not in granted_scopes:
                return VerificationResult(
                    valid=False,
                    record=matched,
                    reason=f"Permissions insuffisantes (requis: {required_scope}, accordé: {matched.scope})"
                )

        return VerificationResult(valid=True, record=matched)

    def revoke(self, identity_id: str) -> bool:
        """Révoque immédiatement une identité numérique."""
        records = self._load_records()
        modified = False
        now = int(time.time())

        for r in records:
            if r.id == identity_id or r.label.lower() == identity_id.lower():
                if not r.revoked:
                    r.revoked = True
                    r.revoked_at = now
                    modified = True

        if modified:
            self._save_records(records)
        return modified

    def list_identities(self, include_revoked: bool = True) -> List[IdentityRecord]:
        """Liste les identités enregistrées."""
        records = self._load_records()
        if not include_revoked:
            return [r for r in records if not r.revoked]
        return records

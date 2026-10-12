"""
Identification Numérique Souveraine — Package officiel.
"""

from .core import SovereignIdentityManager, IdentityRecord, VerificationResult, parse_ttl

__version__ = "1.0.0"
__all__ = ["SovereignIdentityManager", "IdentityRecord", "VerificationResult", "parse_ttl"]

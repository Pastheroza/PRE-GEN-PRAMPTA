"""PRAMPTA — Python SDK for the PRE-GEN verification API.

Usage:
    from prampta import Prampta

    pp = Prampta(
        base_url="https://api2.prampta.com",
        provider_id="openai",
        licensee_id="acme-corp",
        token="pair-token-here",
    )

    result = pp.verify("leonardo-da-vinci", modality="image")
    if result.allowed:
        generate(...)  # proceed
    else:
        print(result.reason)  # PG_NO_LICENSE, PG_SUBJECT_OPTED_OUT, etc.
"""

from prampta.client import (
    Prampta, VerifyResult, IntendedUse,
    PramptaError, PramptaSignatureError, PramptaSchemaError, PramptaRefused,
)
from prampta.matcher import match_subjects, normalize_for_match, SubjectIndexCache

__version__ = "0.1.0"
__all__ = [
    "Prampta", "VerifyResult", "IntendedUse",
    "PramptaError", "PramptaSignatureError", "PramptaSchemaError", "PramptaRefused",
    "match_subjects", "normalize_for_match", "SubjectIndexCache",
]

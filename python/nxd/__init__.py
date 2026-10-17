"""
NXD — encrypted agent operating system.

Three guarantees:
  1. The agent works fully
  2. The agent sees nothing when shielding or safe vault usage is applied correctly
  3. The operator holds the keys, locally or via the hosted Vault backend
"""

from __future__ import annotations

import importlib
from typing import Any, Literal

from nxd.audit import anchor_now as audit_anchor_now
from nxd.audit import configure_anchor as audit_configure_anchor
from nxd.audit import export as audit_export
from nxd.audit import log as audit_log
from nxd.audit import recover as audit_recover
from nxd.audit import reset as audit_reset
from nxd.audit import verify as audit_verify
from nxd.bind import BindingError, bind
from nxd.bind import open as open_bound

open = open_bound  # backward-compatible attribute (nxd.open); not exported via __all__
from nxd.blur import PrivacyBudgetExceededError, blur, blur_dataset, blur_guide, blur_report, privacy_budget
from nxd.channel import Channel, ChannelClosedError, channel
from nxd.checkpoint import checkpoint
from nxd.handoff import ExpiredTokenError, Handoff, ReplayError
from nxd.redact import deredact, deredact_strict, redact, redact_strict
from nxd.search import SearchIndex, build_index, retrieve, search
from nxd.seal import seal, seal_text, unseal, unseal_text
from nxd.shield import send_to_model, shield, unshield
from nxd.sign import AgentKeyNotFoundError, register_agent, sign, sign_record, verify_record, verify_signature
from nxd.secure import SecureString, SecurityWarning
from nxd.split import (
    InsufficientSharesError,
    distribute,
    reconstruct,
    reconstruct_strict,
    reconstruct_vss,
    split,
    split_vss,
    verify_share,
)
from nxd.tokenize import detokenize, tokenize, tokenize_record
from nxd.vault import CredentialLeakError, Vault, VaultError
from nxd.verify import LockedError, register, unlock, verify

Mode = Literal["auto", "fast", "secure"]
_FHE_UNAVAILABLE_MESSAGE = (
    "FHE primitives require Python 3.10-3.11 and concrete-ml. "
    "Run: pyenv install 3.11.15\npip install 'nxd[fhe]'"
)

try:
    importlib.import_module("concrete.ml.sklearn")
except ModuleNotFoundError:
    def _fhe_unavailable(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError(_FHE_UNAVAILABLE_MESSAGE)

    score = _fhe_unavailable
    match = _fhe_unavailable
    aggregate = _fhe_unavailable
else:
    from nxd.fhe import aggregate, match, score

__all__ = [
    "score", "match", "aggregate", "receive",
    "Vault", "VaultError", "CredentialLeakError", "Handoff", "ReplayError", "ExpiredTokenError",
    "shield", "unshield", "send_to_model",
    "build_index", "search", "retrieve", "SearchIndex",
    "register", "verify", "unlock", "LockedError",
    "tokenize", "detokenize", "tokenize_record",
    "redact", "deredact", "redact_strict", "deredact_strict",
    "seal", "unseal", "seal_text", "unseal_text",
    "channel", "Channel", "ChannelClosedError",
    "checkpoint",
    "sign", "verify_signature", "sign_record", "verify_record", "register_agent", "AgentKeyNotFoundError",
    "SecureString", "SecurityWarning",
    "blur", "blur_dataset", "blur_report", "blur_guide", "privacy_budget", "PrivacyBudgetExceededError",
    "split", "reconstruct", "reconstruct_strict", "split_vss", "reconstruct_vss", "verify_share", "distribute", "InsufficientSharesError",
    "bind", "open_bound", "BindingError",
    "audit_log", "audit_verify", "audit_export", "audit_recover", "audit_reset", "audit_configure_anchor", "audit_anchor_now",
    "Mode",
]


def receive(model: Any, token: str, handoff: Handoff, mode: Mode = "auto") -> list[int]:
    """Agent B scores encrypted handoff context."""
    context = handoff.unpack(token)
    clients = context if isinstance(context, list) else [context]
    return score(model, clients, mode=mode)


class audit:
    log = staticmethod(audit_log)
    verify = staticmethod(audit_verify)
    export = staticmethod(audit_export)
    recover = staticmethod(audit_recover)
    reset = staticmethod(audit_reset)
    configure_anchor = staticmethod(audit_configure_anchor)
    anchor_now = staticmethod(audit_anchor_now)

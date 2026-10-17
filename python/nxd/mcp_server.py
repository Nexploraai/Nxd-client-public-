from __future__ import annotations

import importlib
from typing import Any, Literal

import numpy as np
from mcp.server.fastmcp import FastMCP

import nxd
from nxd.operator import queue_reveal

SERVER_NAME = "nxd"
try:
    from importlib.metadata import version as _pkg_version
    SERVER_VERSION = _pkg_version("nxd")
except Exception:  # pragma: no cover
    SERVER_VERSION = "0.0.0"
ToolMode = Literal["fast", "secure"]
FheLogisticRegression = Any
FheLinearRegression = Any


def _ok(**payload: Any) -> dict[str, Any]:
    return {"ok": True, **payload}


def _error(exc: Exception) -> dict[str, Any]:
    return {"ok": False, "error": str(exc)}


def _normalize_mode(mode: ToolMode) -> ToolMode:
    if mode not in {"fast", "secure"}:
        raise ValueError("mode must be 'fast' or 'secure'")
    return mode


def _require_fhe_backend() -> tuple[type[Any], type[Any]]:
    try:
        module = importlib.import_module("concrete.ml.sklearn")
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "FHE primitives require Python 3.10-3.11 and concrete-ml. "
            "Run: pyenv install 3.11.15\npip install 'nxd[fhe]'"
        ) from exc
    return module.LogisticRegression, module.LinearRegression


def _as_2d_float_array(name: str, values: list[list[float]]) -> np.ndarray:
    arr = np.asarray(values, dtype=np.float64)
    if arr.ndim != 2 or arr.size == 0:
        raise ValueError(f"{name} must be a non-empty 2D numeric array")
    return arr


def _as_1d_float_array(name: str, values: list[float]) -> np.ndarray:
    arr = np.asarray(values, dtype=np.float64)
    if arr.ndim != 1 or arr.size == 0:
        raise ValueError(f"{name} must be a non-empty 1D numeric array")
    return arr


def _as_1d_int_array(name: str, values: list[int]) -> np.ndarray:
    arr = np.asarray(values, dtype=np.int64)
    if arr.ndim != 1 or arr.size == 0:
        raise ValueError(f"{name} must be a non-empty 1D integer array")
    return arr


def _build_score_model(training_features: list[list[float]], training_labels: list[int]) -> FheLogisticRegression:
    LogisticRegression, _ = _require_fhe_backend()
    X = _as_2d_float_array("training_features", training_features)
    y = _as_1d_int_array("training_labels", training_labels)
    if len(X) != len(y):
        raise ValueError("training_features and training_labels must have the same length")
    if len(set(y.tolist())) < 2:
        raise ValueError("training_labels must contain at least two classes")
    model = LogisticRegression(n_bits=8)
    model.fit(X, y)
    return model


def _build_match_model(reference_a: list[list[float]], reference_b: list[list[float]]) -> FheLogisticRegression:
    LogisticRegression, _ = _require_fhe_backend()
    left = _as_2d_float_array("reference_a", reference_a)
    right = _as_2d_float_array("reference_b", reference_b)
    if left.shape != right.shape:
        raise ValueError("reference_a and reference_b must have the same shape")
    if len(left) < 2:
        raise ValueError("reference_a and reference_b must contain at least 2 aligned examples")
    positive = np.hstack([left, right])
    negative = np.hstack([left, np.roll(right, shift=1, axis=0)])
    X = np.vstack([positive, negative])
    y = np.array([1] * len(positive) + [0] * len(negative))
    model = LogisticRegression(n_bits=8)
    model.fit(X, y)
    return model


def _run_match(model: FheLogisticRegression, candidate_a: list[float], candidate_b: list[float], mode: ToolMode) -> bool:
    a = _as_1d_float_array("candidate_a", candidate_a)
    b = _as_1d_float_array("candidate_b", candidate_b)
    if len(a) != len(b):
        raise ValueError("candidate_a and candidate_b must have the same length")
    pair = np.concatenate([a, b]).reshape(1, -1)
    result = bool(int(nxd.fhe._predict(model, pair, mode)[0]) == 1)
    return result


def _build_aggregate_model(training_values: list[float]) -> FheLinearRegression:
    _, LinearRegression = _require_fhe_backend()
    values = _as_1d_float_array("training_values", training_values)
    model = LinearRegression(n_bits=8)
    model.fit(values.reshape(-1, 1), values)
    return model


def _run_aggregate(model: FheLinearRegression, values: list[float], mode: ToolMode) -> float:
    arr = _as_1d_float_array("values", values).reshape(-1, 1)
    predicted = nxd.fhe._predict(model, arr, mode)
    return float(np.mean(predicted))


def create_server() -> FastMCP:
    server = FastMCP(
        name=SERVER_NAME,
        instructions=(
            f"NXD MCP server. Version {SERVER_VERSION}. Use these tools to run encrypted-data "
            "NXD operations over stdio from any MCP-compatible agent."
        ),
    )

    @server.tool(
        name="nxd_score",
        description="Run FHE risk scoring on numeric records. Provide training features and labels, then score new records.",
    )
    def nxd_score(
        training_features: list[list[float]],
        training_labels: list[int],
        records: list[list[float]],
        mode: ToolMode = "fast",
    ) -> dict[str, Any]:
        try:
            tool_mode = _normalize_mode(mode)
            model = _build_score_model(training_features, training_labels)
            scores = nxd.score(model, records, mode=tool_mode)
            return _ok(mode=tool_mode, scores=scores, count=len(scores))
        except Exception as exc:
            return _error(exc)

    @server.tool(
        name="nxd_match",
        description="Run encrypted-data record matching. Train on aligned example pairs and test one candidate pair.",
    )
    def nxd_match(
        reference_a: list[list[float]],
        reference_b: list[list[float]],
        candidate_a: list[float],
        candidate_b: list[float],
        mode: ToolMode = "fast",
    ) -> dict[str, Any]:
        try:
            tool_mode = _normalize_mode(mode)
            model = _build_match_model(reference_a, reference_b)
            is_match = _run_match(model, candidate_a, candidate_b, tool_mode)
            return _ok(mode=tool_mode, match=is_match)
        except Exception as exc:
            return _error(exc)

    @server.tool(
        name="nxd_aggregate",
        description="Compute a population-level aggregate without exposing individual values. Trains a simple encrypted aggregation model from reference values.",
    )
    def nxd_aggregate(
        training_values: list[float],
        values: list[float],
        mode: ToolMode = "fast",
    ) -> dict[str, Any]:
        try:
            tool_mode = _normalize_mode(mode)
            model = _build_aggregate_model(training_values)
            aggregate_value = _run_aggregate(model, values, tool_mode)
            return _ok(mode=tool_mode, aggregate=aggregate_value, count=len(values))
        except Exception as exc:
            return _error(exc)

    @server.tool(
        name="nxd_shield",
        description="Encrypt text or source code before sending it to any AI system.",
    )
    def nxd_shield(text: str) -> dict[str, Any]:
        try:
            return _ok(token=nxd.shield(text))
        except Exception as exc:
            return _error(exc)

    @server.tool(
        name="nxd_unshield",
        description="Decrypt shielded content locally so plaintext never needs to leave the machine.",
    )
    def nxd_unshield(token: str) -> dict[str, Any]:
        try:
            plaintext = nxd.unshield(token)
            return _ok(
                **queue_reveal(
                    "unshield",
                    plaintext,
                    metadata={"source": "nxd_unshield"},
                )
            )
        except Exception as exc:
            return _error(exc)

    @server.tool(
        name="nxd_redact",
        description="Best-effort detection of common PII and secret patterns in text, replacing matches with safe placeholders.",
    )
    def nxd_redact(text: str) -> dict[str, Any]:
        try:
            redacted_text, mapping = nxd.redact(text)
            reveal = queue_reveal(
                "redact_mapping",
                mapping,
                metadata={"source": "nxd_redact"},
            )
            return _ok(
                redacted_text=redacted_text,
                placeholders=len(mapping),
                restore_reveal_id=reveal["reveal_id"],
                plaintext_available_to_agent=False,
                operator_action=reveal["operator_action"],
                expires_at=reveal["expires_at"],
            )
        except Exception as exc:
            return _error(exc)

    @server.tool(
        name="nxd_tokenize",
        description="Replace a sensitive value with a safe token that can be stored or passed to an agent.",
    )
    def nxd_tokenize(value: str) -> dict[str, Any]:
        try:
            return _ok(token=nxd.tokenize(value))
        except Exception as exc:
            return _error(exc)

    @server.tool(
        name="nxd_detokenize",
        description="Recover the original value from a token previously created by NXD.",
    )
    def nxd_detokenize(token: str) -> dict[str, Any]:
        try:
            plaintext = nxd.detokenize(token)
            return _ok(
                **queue_reveal(
                    "detokenize",
                    plaintext,
                    metadata={"source": "nxd_detokenize", "token": token},
                )
            )
        except Exception as exc:
            return _error(exc)

    @server.tool(
        name="nxd_seal_text",
        description="Encrypt arbitrary text into an opaque blob for local-only decryption later.",
    )
    def nxd_seal_text(text: str) -> dict[str, Any]:
        try:
            return _ok(token=nxd.seal_text(text))
        except Exception as exc:
            return _error(exc)

    @server.tool(
        name="nxd_unseal_text",
        description="Decrypt a sealed text blob produced by NXD.",
    )
    def nxd_unseal_text(token: str) -> dict[str, Any]:
        try:
            plaintext = nxd.unseal_text(token)
            return _ok(
                **queue_reveal(
                    "unseal_text",
                    plaintext,
                    metadata={"source": "nxd_unseal_text"},
                )
            )
        except Exception as exc:
            return _error(exc)

    return server


def main() -> None:
    from nxd.operator import purge_legacy_reveals

    purge_legacy_reveals()
    create_server().run(transport="stdio")


if __name__ == "__main__":
    main()

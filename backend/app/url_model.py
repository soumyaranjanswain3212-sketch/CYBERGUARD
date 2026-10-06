from __future__ import annotations

import ipaddress
import math
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import joblib
import numpy as np

MODEL_VERSION = "cyberguard-phiusiil-url-v1"
DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "phiusiil_url_model.joblib"
SUSPICIOUS_TERMS = (
    "account", "auth", "bank", "billing", "confirm", "login", "password",
    "secure", "signin", "support", "update", "verify", "wallet",
)
FEATURE_NAMES = (
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    "dot_count",
    "subdomain_count",
    "hyphen_count",
    "underscore_count",
    "at_count",
    "percent_count",
    "digit_count",
    "digit_ratio",
    "special_char_ratio",
    "path_depth",
    "query_parameter_count",
    "is_ip_host",
    "uses_https",
    "has_punycode",
    "has_nonstandard_port",
    "character_entropy",
    "suspicious_term_count",
    "has_login_path",
    "has_auth_query",
    "tld_length",
)


def extract_url_features(url: str) -> list[float]:
    candidate = url.strip()
    normalized = candidate if "://" in candidate else f"http://{candidate}"
    try:
        parsed = urlsplit(normalized)
        host = (parsed.hostname or "").casefold().rstrip(".")
        path = parsed.path
        query = parsed.query
        port = parsed.port
    except ValueError:
        host, path, query, port = "", "", "", None

    host_labels = [label for label in host.split(".") if label]
    hostname_is_ip = 0.0
    try:
        ipaddress.ip_address(host)
        hostname_is_ip = 1.0
    except ValueError:
        pass

    lowered = candidate.casefold()
    path_and_query = f"{path}?{query}".casefold()
    length = max(len(candidate), 1)
    digit_count = sum(character.isdigit() for character in candidate)
    special_char_count = sum(
        not character.isalnum() and character not in "-._~:/?#[]@!$&'()*+,;=%"
        for character in candidate
    )
    frequencies: dict[str, int] = {}
    for character in lowered:
        frequencies[character] = frequencies.get(character, 0) + 1
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in frequencies.values()
    )
    suspicious_count = sum(term in lowered for term in SUSPICIOUS_TERMS)
    try:
        query_parameter_count = len([part for part in query.split("&") if part])
    except ValueError:
        query_parameter_count = 0

    values = {
        "url_length": len(candidate),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "dot_count": candidate.count("."),
        "subdomain_count": max(0, len(host_labels) - 2),
        "hyphen_count": candidate.count("-"),
        "underscore_count": candidate.count("_"),
        "at_count": candidate.count("@"),
        "percent_count": candidate.count("%"),
        "digit_count": digit_count,
        "digit_ratio": digit_count / length,
        "special_char_ratio": special_char_count / length,
        "path_depth": sum(bool(part) for part in path.split("/")),
        "query_parameter_count": query_parameter_count,
        "is_ip_host": hostname_is_ip,
        "uses_https": float(parsed.scheme.casefold() == "https"),
        "has_punycode": float("xn--" in host),
        "has_nonstandard_port": float(port is not None and port not in {80, 443}),
        "character_entropy": float(entropy),
        "suspicious_term_count": suspicious_count,
        "has_login_path": float(bool(re.search(r"(?:login|signin|auth)", path_and_query))),
        "has_auth_query": float(bool(re.search(r"(?:token|password|credential|session)", query.casefold()))),
        "tld_length": len(host_labels[-1]) if host_labels else 0,
    }
    return [float(values[name]) for name in FEATURE_NAMES]


def _model_path() -> Path:
    configured_path = os.getenv("CYBERGUARD_URL_MODEL_PATH")
    return Path(configured_path).expanduser().resolve() if configured_path else DEFAULT_MODEL_PATH


@lru_cache(maxsize=4)
def _load_artifact(path: str) -> dict[str, Any] | None:
    model_path = Path(path)
    if not model_path.is_file():
        return None
    artifact = joblib.load(model_path)
    if (
        not isinstance(artifact, dict)
        or artifact.get("model_version") != MODEL_VERSION
        or artifact.get("feature_names") != FEATURE_NAMES
        or not 0.0 < float(artifact.get("threshold", 0)) < 1.0
        or not hasattr(artifact.get("model"), "predict_proba")
    ):
        raise RuntimeError(f"URL model artifact at {model_path} has an unsupported format.")
    return artifact


def get_url_model_status() -> dict[str, Any]:
    artifact = _load_artifact(str(_model_path()))
    if artifact is None:
        return {"available": False, "model": None}
    return {
        "available": True,
        "model": artifact["model_version"],
        "threshold": artifact["threshold"],
        "runtime_latency": artifact["runtime_latency"],
        "validation_metrics": artifact["validation_metrics"],
        "test_metrics": artifact["test_metrics"],
    }


def score_url(url: str) -> dict[str, Any] | None:
    artifact = _load_artifact(str(_model_path()))
    if artifact is None:
        return None
    features = np.asarray([extract_url_features(url)], dtype=np.float64)
    classes = list(artifact["model"].classes_)
    phishing_index = classes.index(1)
    phishing_score = float(artifact["model"].predict_proba(features)[0, phishing_index])
    threshold = float(artifact["threshold"])
    return {
        "model": artifact["model_version"],
        "phishing_score": phishing_score,
        "threshold": threshold,
        "flagged": phishing_score >= threshold,
    }

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter_ns
from urllib.error import URLError
from urllib.request import urlopen

import joblib
import numpy as np
import sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from backend.app.url_model import FEATURE_NAMES, MODEL_VERSION, extract_url_features

DATA_URL = "https://archive.ics.uci.edu/static/public/967/data.csv"
DATASET_CITATION = (
    "Prasad, A., & Chandra, S. (2023). PhiUSIIL: A diverse security profile "
    "empowered phishing URL detection framework based on similarity index "
    "and incremental learning. Computers & Security, 103545. "
    "https://doi.org/10.1016/j.cose.2023.103545"
)
MAX_VALIDATION_FALSE_POSITIVE_RATE = 0.001
MIN_PHISHING_THRESHOLD = 0.5


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as dataset:
        for chunk in iter(lambda: dataset.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download_if_missing(dataset_path: Path) -> None:
    if dataset_path.is_file():
        return
    dataset_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = dataset_path.with_suffix(dataset_path.suffix + ".part")
    try:
        with urlopen(DATA_URL, timeout=60) as response, temporary_path.open("wb") as output:
            if response.status != 200:
                raise RuntimeError(f"UCI dataset download returned HTTP {response.status}.")
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
        temporary_path.replace(dataset_path)
    except (OSError, RuntimeError, URLError):
        temporary_path.unlink(missing_ok=True)
        raise


def _load_dataset(dataset_path: Path) -> tuple[np.ndarray, np.ndarray, np.ndarray, str]:
    capacity = 262_144
    features = np.empty((capacity, len(FEATURE_NAMES)), dtype=np.float32)
    labels = np.empty(capacity, dtype=np.int8)
    groups = np.empty(capacity, dtype=object)
    row_count = 0
    with dataset_path.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        required_fields = {"URL", "Domain", "label"}
        if not reader.fieldnames or not required_fields.issubset(reader.fieldnames):
            raise ValueError("UCI CSV must include URL, Domain, and label columns.")
        for row_number, record in enumerate(reader, 2):
            url = (record.get("URL") or "").strip()
            domain = (record.get("Domain") or "").strip().casefold().rstrip(".")
            try:
                label = int(record["label"])
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError(f"Invalid target label on CSV row {row_number}.") from error
            if not url or not domain or label not in {0, 1}:
                raise ValueError(f"Missing URL/domain or unsupported label on CSV row {row_number}.")
            if row_count == capacity:
                capacity *= 2
                features = np.resize(features, (capacity, len(FEATURE_NAMES)))
                labels = np.resize(labels, capacity)
                groups = np.resize(groups, capacity)
            features[row_count] = extract_url_features(url)
            labels[row_count] = int(label == 0)
            groups[row_count] = domain
            row_count += 1

    if row_count < 100:
        raise ValueError("The UCI CSV contains too few rows to train and evaluate a model.")
    source_hash = _sha256(dataset_path)
    return features[:row_count], labels[:row_count], groups[:row_count], source_hash


def _select_threshold(labels: np.ndarray, scores: np.ndarray) -> float:
    legitimate_scores = np.sort(scores[labels == 0])
    if legitimate_scores.size == 0:
        raise ValueError("Threshold selection requires legitimate validation URLs.")

    candidates = np.unique(np.concatenate((
        scores,
        np.asarray([
            MIN_PHISHING_THRESHOLD,
            np.nextafter(float(np.max(scores)), np.inf),
        ]),
    )))
    candidates = candidates[candidates >= MIN_PHISHING_THRESHOLD]
    false_positive_counts = legitimate_scores.size - np.searchsorted(
        legitimate_scores,
        candidates,
        side="left",
    )
    valid = candidates[
        false_positive_counts / legitimate_scores.size
        <= MAX_VALIDATION_FALSE_POSITIVE_RATE
    ]
    if valid.size == 0:
        raise ValueError("Could not select a threshold within the validation false-positive limit.")
    return float(np.min(valid))


def _evaluate(labels: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    predictions = scores >= threshold
    matrix = confusion_matrix(labels, predictions, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = matrix.ravel()
    return {
        "rows": int(len(labels)),
        "phishing_rate": float(np.mean(labels)),
        "threshold": float(threshold),
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(labels, scores)),
        "average_precision": float(average_precision_score(labels, scores)),
        "false_positive_rate": float(false_positive / (false_positive + true_negative)),
        "confusion_matrix": {
            "true_negative": int(true_negative),
            "false_positive": int(false_positive),
            "false_negative": int(false_negative),
            "true_positive": int(true_positive),
        },
    }


def _measure_runtime_latency(model, dataset_path: Path, sample_limit: int = 1000) -> dict:
    samples: list[float] = []
    with dataset_path.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        for record in reader:
            url = (record.get("URL") or "").strip()
            if not url:
                continue
            started = perf_counter_ns()
            features = np.asarray([extract_url_features(url)], dtype=np.float64)
            model.predict_proba(features)
            samples.append((perf_counter_ns() - started) / 1_000_000)
            if len(samples) >= sample_limit:
                break
    if not samples:
        raise ValueError("Could not measure inference latency because the dataset has no usable URLs.")
    return {
        "sample_count": len(samples),
        "p50_ms": float(np.percentile(samples, 50)),
        "p95_ms": float(np.percentile(samples, 95)),
        "scope": "single-URL local CPU feature extraction and inference; excludes HTTP/network time",
    }


def train(dataset_path: Path, model_path: Path) -> dict:
    _download_if_missing(dataset_path)
    features, labels, groups, dataset_hash = _load_dataset(dataset_path)
    first_split = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_validation_indices, test_indices = next(
        first_split.split(features, labels, groups)
    )
    second_split = GroupShuffleSplit(n_splits=1, test_size=0.125, random_state=43)
    train_relative, validation_relative = next(
        second_split.split(
            features[train_validation_indices],
            labels[train_validation_indices],
            groups[train_validation_indices],
        )
    )
    train_indices = train_validation_indices[train_relative]
    validation_indices = train_validation_indices[validation_relative]

    model = make_pipeline(
        StandardScaler(),
        LogisticRegression(
            C=1.0,
            max_iter=500,
            solver="lbfgs",
            random_state=42,
        ),
    )
    model.fit(features[train_indices], labels[train_indices])
    validation_scores = model.predict_proba(features[validation_indices])[:, 1]
    threshold = _select_threshold(labels[validation_indices], validation_scores)
    validation_metrics = _evaluate(
        labels[validation_indices],
        validation_scores,
        threshold,
    )
    test_scores = model.predict_proba(features[test_indices])[:, 1]
    test_metrics = _evaluate(labels[test_indices], test_scores, threshold)
    runtime_latency = _measure_runtime_latency(model, dataset_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "model_version": MODEL_VERSION,
        "model": model,
        "feature_names": FEATURE_NAMES,
        "threshold": threshold,
        "validation_metrics": validation_metrics,
        "test_metrics": test_metrics,
        "runtime_latency": runtime_latency,
        "dataset": {
            "name": "PhiUSIIL Phishing URL (Website)",
            "uci_id": 967,
            "url": DATA_URL,
            "license": "Creative Commons Attribution 4.0 International (CC BY 4.0)",
            "citation": DATASET_CITATION,
            "sha256": dataset_hash,
            "rows": int(len(labels)),
            "label_mapping": "UCI label 0 = phishing, label 1 = legitimate",
        },
        "training": {
            "algorithm": "StandardScaler + LogisticRegression",
            "scikit_learn_version": sklearn.__version__,
            "input_features": "URL-derived lexical and structure features only",
            "split": "group holdout by exact UCI Domain; random_state 42/43",
            "train_rows": int(len(train_indices)),
            "validation_rows": int(len(validation_indices)),
            "test_rows": int(len(test_indices)),
            "threshold_selection": (
                "lowest threshold >= 0.50 with validation false-positive rate <= "
                f"{MAX_VALIDATION_FALSE_POSITIVE_RATE:.1%}"
            ),
            "created_at": datetime.now(UTC).isoformat(),
        },
    }
    joblib.dump(artifact, model_path, compress=3)
    report_path = model_path.with_suffix(".metrics.json")
    report_path.write_text(
        json.dumps({key: value for key, value in artifact.items() if key != "model"}, indent=2),
        encoding="utf-8",
    )
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and evaluate CyberGuard's pre-click URL classifier.")
    parser.add_argument(
        "--data",
        type=Path,
        default=Path("backend/data/phiusiil.csv"),
        help="Path to the UCI PhiUSIIL CSV; downloaded from UCI if missing.",
    )
    parser.add_argument(
        "--model-out",
        type=Path,
        default=Path("backend/models/phiusiil_url_model.joblib"),
    )
    arguments = parser.parse_args()
    started = time.perf_counter()
    artifact = train(arguments.data, arguments.model_out)
    print(json.dumps({
        "model": str(arguments.model_out),
        "report": str(arguments.model_out.with_suffix(".metrics.json")),
        "dataset_sha256": artifact["dataset"]["sha256"],
        "training": artifact["training"],
        "test_metrics": artifact["test_metrics"],
        "runtime_latency": artifact["runtime_latency"],
        "elapsed_seconds": round(time.perf_counter() - started, 2),
    }, indent=2))


if __name__ == "__main__":
    main()

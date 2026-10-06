from __future__ import annotations

import gzip
import io
import json
import zlib

MAX_COMPRESSED_BYTES = 10 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 5 * 1024 * 1024
MAX_RECORDS_PER_BATCH = 10_000


class CloudflareBatchError(ValueError):
    pass


def decode_logpush_batch(body: bytes, content_encoding: str) -> tuple[list[dict], bool]:
    if len(body) > MAX_COMPRESSED_BYTES:
        raise CloudflareBatchError("Compressed Logpush batch exceeds the 10 MiB request limit.")
    if content_encoding.casefold().strip() != "gzip" and not body.startswith(b"\x1f\x8b"):
        raise CloudflareBatchError("Cloudflare Logpush batches must use gzip compression.")

    try:
        with gzip.GzipFile(fileobj=io.BytesIO(body), mode="rb") as compressed:
            chunks: list[bytes] = []
            total_bytes = 0
            while True:
                chunk = compressed.read(64 * 1024)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > MAX_UNCOMPRESSED_BYTES:
                    raise CloudflareBatchError("Uncompressed Logpush batch exceeds the 5 MiB limit.")
                chunks.append(chunk)
    except (OSError, EOFError, zlib.error) as error:
        raise CloudflareBatchError("Logpush request body is not a valid gzip stream.") from error

    try:
        text = b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as error:
        raise CloudflareBatchError("Logpush batch must contain UTF-8 NDJSON.") from error

    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) == 1:
        try:
            probe = json.loads(lines[0])
        except json.JSONDecodeError:
            probe = None
        if probe == {"content": "tests"}:
            return [], True

    if not lines:
        raise CloudflareBatchError("Logpush batch contains no records.")
    if len(lines) > MAX_RECORDS_PER_BATCH:
        raise CloudflareBatchError("Logpush batch exceeds the 10,000-record limit.")

    records: list[dict] = []
    for line_number, line in enumerate(lines, 1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise CloudflareBatchError(f"Invalid JSON on Logpush record line {line_number}.") from error
        if not isinstance(record, dict):
            raise CloudflareBatchError(f"Logpush record on line {line_number} must be a JSON object.")
        if not isinstance(record.get("Action"), str) or not record["Action"].strip():
            raise CloudflareBatchError(f"Logpush record on line {line_number} is missing Action.")
        if "Datetime" not in record:
            raise CloudflareBatchError(f"Logpush record on line {line_number} is missing Datetime.")
        record["observed_at"] = record.pop("Datetime")
        records.append(record)

    return records, False

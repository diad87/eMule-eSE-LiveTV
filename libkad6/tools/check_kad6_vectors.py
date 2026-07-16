#!/usr/bin/env python3
"""Strict schema/hex audit for the external K6-0 vector corpus."""
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FILES = ("address", "frame", "tags", "tickets", "records", "shaped", "crypto")
STATUSES = {
    "Ok", "Truncated", "Malformed", "UnsupportedVersion", "UnsupportedOption",
    "TooLarge", "BadValue", "NullArgument", "AuthFailed", "StaleEpoch",
    "TargetForbidden", "Expired",
}


def is_hex(value: str) -> bool:
    return len(value) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in value)


def main() -> int:
    seen: set[str] = set()
    total = 0
    for name in FILES:
        path = ROOT / "vectors" / f"{name}.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data.get("schema") == "kad6-vector-v1", f"{path}: bad schema"
        vectors = data.get("vectors")
        assert isinstance(vectors, list) and len(vectors) >= 2, f"{path}: need golden + adversarial"
        for vector in vectors:
            ident = vector.get("id")
            assert isinstance(ident, str) and ident and ident not in seen, f"{path}: bad/duplicate id"
            seen.add(ident)
            assert "input" in vector or "input_hex" in vector, f"{ident}: input missing"
            assert vector.get("expected_status") in STATUSES, f"{ident}: bad status"
            assert isinstance(vector.get("reason"), str) and vector["reason"], f"{ident}: reason missing"
            for key, value in vector.items():
                if key.endswith("_hex"):
                    assert isinstance(value, str) and is_hex(value), f"{ident}.{key}: invalid hex"
            total += 1

    shaped = json.loads((ROOT / "vectors" / "shaped.json").read_text(encoding="utf-8"))
    golden = next(v for v in shaped["vectors"] if v["id"] == "shaped-one-layer-fixed-17000")
    exact_size = len(bytes.fromhex(golden["expected_header_hex"]))
    exact_size += len(bytes.fromhex(golden["expected_prefix_hex"])) * int(golden["expected_prefix_repeat"])
    exact_size += len(bytes.fromhex(golden["expected_tail_hex"])) * int(golden["expected_tail_repeat"])
    assert exact_size == 17000, "shaped vector does not specify exactly 17000 bytes"

    crypto = json.loads((ROOT / "vectors" / "crypto.json").read_text(encoding="utf-8"))
    for vector in crypto["vectors"]:
        assert isinstance(vector.get("source"), str) and vector["source"], f"{vector['id']}: source missing"

    print(f"Kad6 vectors: {len(FILES)} files, {total} vectors, schema and hex OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

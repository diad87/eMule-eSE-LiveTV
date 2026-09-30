#!/usr/bin/env python3
"""Structural gate for the frozen eMule AI parity/superiority matrix."""

from __future__ import annotations

from collections import Counter
import hashlib
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
MATRIX = ROOT / "docs" / "EMULEAI_PARITY_AND_SUPERIORITY_PROGRAM.md"
ROADMAP = ROOT / "docs" / "EMULEAI_INTEGRATED_RELEASE_ROADMAP.md"
DELTA = ROOT / "docs" / "EMULEAI_V1.6_DELTA_BASELINE.md"
INDEX = ROOT / "docs" / "INDEX.md"
EXPECTED_LEGACY_BASELINE = "de8e27e2029044d533f7090f173c95856fe4635a"
EXPECTED_CURRENT_BASELINE = "a2f05dc8db772a11ca874adf0a16baaf30560519"
# These fingerprints freeze the full normative rows, not merely their IDs or
# aggregate counts. Update them only as part of an explicitly reviewed baseline
# change.
EXPECTED_MATRIX_ROWS_SHA256 = "1d6d8fabd78f9a9c2da2fc0d7a95ed658ce53da8306b55e1c23725e9585c3b8c"
EXPECTED_DELTA_ROWS_SHA256 = "7a5de053cab2bd83c3fdc3f073e7605dd486fae7df62d8c2f0e3d1cad30ab66e"
VALID_STATES = {
    "BRECHA",
    "PARCIAL",
    "PARIDAD",
    "ESE-BETA",
    "ESE-SUPERA",
    "NO-ADOPTAR",
    "EN CURSO",
}

EXPECTED_CLOSURE_MAP = {
    "B0-BASE": {
        "AI-F24", "AI-F32", "AI-F44", "AI-I03", "AI-I31", "AI-I36", "AI-I39",
    },
    "V92-ALIGNED": {
        "AI-F04", "AI-F08", "AI-F15", "AI-F23", "AI-F49", "AI-I11", "AI-I16",
        "AI-I28",
    },
    "V95-CORE": {
        "AI-F06", "AI-F18", "AI-F19", "AI-F20", "AI-F21", "AI-F33", "AI-F40",
        "AI-F45", "AI-I01", "AI-I05", "AI-I06", "AI-I09", "AI-I12", "AI-I21",
        "AI-I22", "AI-I25", "AI-I29", "AI-I30", "AI-I35", "AI-I37", "AI-I42",
    },
    "V96-PRODUCT": {
        "AI-F02", "AI-F05", "AI-F07", "AI-F09", "AI-F12", "AI-F13", "AI-F22",
        "AI-F25", "AI-F27", "AI-F28", "AI-F29", "AI-F30", "AI-F34", "AI-F35",
        "AI-F36", "AI-F37", "AI-F38", "AI-F41", "AI-F42", "AI-F43", "AI-F46",
        "AI-F47", "AI-F48", "AI-I02", "AI-I04", "AI-I07", "AI-I08", "AI-I10",
        "AI-I13", "AI-I17", "AI-I18", "AI-I24", "AI-I26", "AI-I27", "AI-I32",
        "AI-I33", "AI-I34", "AI-I38", "AI-I40", "AI-I41",
    },
    "V97-NETWORK": {
        "AI-F01", "AI-F03", "AI-F10", "AI-F11", "AI-F14", "AI-F16", "AI-F17",
        "AI-F26", "AI-F31", "AI-F39", "AI-I14", "AI-I15", "AI-I19", "AI-I20",
        "AI-I23", "AI-I43",
    },
}

CLOSURE_TO_WINDOW = {
    "B0-BASE": "B0",
    "V92-ALIGNED": "V92",
    "V95-CORE": "V95",
    "V96-PRODUCT": "V96",
    "V97-NETWORK": "V97",
}

EXPECTED_STATE_COUNTS = {
    "B0-BASE": Counter({"PARIDAD": 6, "NO-ADOPTAR": 1}),
    "V92-ALIGNED": Counter({"PARCIAL": 6, "PARIDAD": 1, "ESE-BETA": 1}),
    "V95-CORE": Counter({"BRECHA": 11, "PARCIAL": 10}),
    "V96-PRODUCT": Counter({"BRECHA": 28, "PARCIAL": 12}),
    "V97-NETWORK": Counter({"BRECHA": 8, "PARCIAL": 8}),
}

EXPECTED_TOTAL_STATES = Counter(
    {"BRECHA": 47, "PARCIAL": 36, "PARIDAD": 7, "ESE-BETA": 1, "NO-ADOPTAR": 1}
)

EXPECTED_DELTA_MAP = {
    "AI16-D01": (
        "Revisión del Download Validator",
        {"AI-F21", "AI-I32", "AI-F28", "AI-F13"},
        {"V95", "V96"},
    ),
    "AI16-D02": ("Menor huella de traducciones en el ejecutable", {"AI-F22"}, {"V96"}),
    "AI16-D03": ("Tooltips ampliados", {"AI-F42", "AI-I32"}, {"V96"}),
    "AI16-D04": (
        "Opciones, DPI, layout y ayuda corregidos",
        {"AI-F12", "AI-I32", "AI-I34"},
        {"V96"},
    ),
    "AI16-D05": (
        "País y ciudad en detalles de cliente",
        {"AI-F30", "AI-F41", "AI-I04"},
        {"V96"},
    ),
    "AI16-D06": ("Reset de preferencias", {"AI-F46", "AI-I32"}, {"V96"}),
    "AI16-D07": ("Mover todas las fuentes A4AF", {"AI-F13", "AI-I10"}, {"V96"}),
    "AI16-D08": (
        "Multiselección en la lista de clientes",
        {"AI-F13", "AI-I10", "AI-I18"},
        {"V96"},
    ),
    "AI16-D09": (
        "Progreso traducido de arranque y cierre",
        {"AI-F05", "AI-F22"},
        {"V96"},
    ),
    "AI16-D10": (
        "Menos falsos positivos de abuso tras una subida válida",
        {"AI-F11", "AI-F16"},
        {"V97"},
    ),
    "AI16-D11": (
        "Corrección de Last Reception obsoleto",
        {"AI-F07", "AI-F13"},
        {"V96"},
    ),
    "AI16-D12": (
        "Fuentes expandidas asociadas al fichero correcto",
        {"AI-F13", "AI-I07", "AI-I08"},
        {"V96"},
    ),
    "AI16-D13": (
        "Scroll de fuentes expandidas sin argumento inválido",
        {"AI-F13", "AI-I07"},
        {"V96"},
    ),
    "AI16-D14": (
        "“Asked another file” sin paréntesis vacíos",
        {"AI-F13", "AI-F42"},
        {"V96"},
    ),
    "AI16-D15": (
        "Indicadores de comentario y rating corregidos",
        {"AI-F13", "AI-F42"},
        {"V96"},
    ),
    "AI16-D16": (
        "Obfuscation dual-stack en LowID/firewall",
        {"AI-F14", "AI-F15"},
        {"V92", "V97"},
    ),
    "AI16-D17": (
        "Compatibilidad con tags legacy de subida MLDonkey",
        {"AI-F11", "AI-F16"},
        {"V97"},
    ),
    "AI16-D18": (
        "Menos falsos reportes agresivos por conflicto de hash",
        {"AI-F11", "AI-F16", "AI-F21"},
        {"V95", "V97"},
    ),
    "AI16-D19": (
        "Retirada de reglas de phishing de username obsoletas",
        {"AI-F11", "AI-F16"},
        {"V97"},
    ),
}


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def extract_rows(text: str, prefix: str) -> dict[int, tuple[str, str]]:
    pattern = re.compile(
        rf"^\| `AI-{prefix}(\d{{2}})` \| ([^|]+) \| `([^`]+)` \| ([^|]+) \|$",
        re.MULTILINE,
    )
    rows: dict[int, tuple[str, str]] = {}
    for match in pattern.finditer(text):
        number = int(match.group(1))
        if number in rows:
            fail(f"duplicate AI-{prefix}{number:02d}")
        state = match.group(3).strip()
        objective = match.group(4).strip()
        if state not in VALID_STATES:
            fail(f"AI-{prefix}{number:02d} has invalid state {state!r}")
        if len(objective) < 20:
            fail(f"AI-{prefix}{number:02d} has no measurable objective")
        rows[number] = (state, objective)
    return rows


def require_contiguous(rows: dict[int, tuple[str, str]], prefix: str, count: int) -> None:
    expected = set(range(1, count + 1))
    actual = set(rows)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        fail(f"AI-{prefix} coverage mismatch: missing={missing}, extra={extra}")


def parse_state_counts(cell: str) -> Counter[str]:
    return Counter(
        {
            state: int(count)
            for count, state in re.findall(r"(\d+) `([^`]+)`", cell)
        }
    )


def main() -> int:
    text = MATRIX.read_text(encoding="utf-8")
    provenance_patterns = {
        "legacy": (
            r"^- baseline histórico congelado: eMule AI `eMuleAI_v1\.5\.2`, "
            rf"commit[ \t]*\n[ \t]*`{EXPECTED_LEGACY_BASELINE}`;$"
        ),
        "current": (
            r"^- baseline público actual candidato: eMule AI `eMuleAI_v1\.6`, "
            rf"commit[ \t]*\n[ \t]*`{EXPECTED_CURRENT_BASELINE}`;$"
        ),
    }
    for label, pattern in provenance_patterns.items():
        if not re.search(pattern, text, re.MULTILINE):
            fail(f"{label} baseline provenance line drifted or is missing")

    matrix_pattern = re.compile(
        r"^\| `(AI-[FI]\d{2})` \| ([^|]+) \| `([^`]+)` \| ([^|]+) \|$",
        re.MULTILINE,
    )
    matrix_rows = list(matrix_pattern.finditer(text))
    canonical_matrix = "\n".join(
        "\x1f".join(group.strip() for group in match.groups())
        for match in matrix_rows
    )
    matrix_digest = hashlib.sha256(canonical_matrix.encode("utf-8")).hexdigest()
    if matrix_digest != EXPECTED_MATRIX_ROWS_SHA256:
        fail(
            "frozen 92-row matrix content drifted: "
            f"expected={EXPECTED_MATRIX_ROWS_SHA256}, actual={matrix_digest}"
        )

    delta = DELTA.read_text(encoding="utf-8")
    index = INDEX.read_text(encoding="utf-8")
    for commit, label in (
        (EXPECTED_LEGACY_BASELINE, "legacy"),
        (EXPECTED_CURRENT_BASELINE, "current"),
    ):
        if commit not in delta:
            fail(f"{label} baseline commit is missing from the 1.6 delta")
    delta_pattern = re.compile(
        r"^\| `AI16-D(\d{2})` \| ([^|]+) \| ([^|]+) \| ([^|]+) \| ([^|]+) \|$",
        re.MULTILINE,
    )
    delta_rows = list(delta_pattern.finditer(delta))
    delta_ids = [int(match.group(1)) for match in delta_rows]
    if delta_ids != list(range(1, 20)):
        fail(f"AI 1.6 delta coverage mismatch: found={delta_ids}")
    delta_provenance_lines = {
        f"| Commit histórico | `{EXPECTED_LEGACY_BASELINE}` |",
        f"| Commit del tag 1.6 | `{EXPECTED_CURRENT_BASELINE}` |",
    }
    missing_delta_provenance = sorted(
        line for line in delta_provenance_lines if line not in delta.splitlines()
    )
    if missing_delta_provenance:
        fail(f"delta provenance rows drifted: {missing_delta_provenance}")
    canonical_delta = "\n".join(
        "\x1f".join(
            [
                f"AI16-D{match.group(1)}",
                *(match.group(index).strip() for index in range(2, 6)),
            ]
        )
        for match in delta_rows
    )
    delta_digest = hashlib.sha256(canonical_delta.encode("utf-8")).hexdigest()
    if delta_digest != EXPECTED_DELTA_ROWS_SHA256:
        fail(
            "frozen 19-row v1.6 delta content drifted: "
            f"expected={EXPECTED_DELTA_ROWS_SHA256}, actual={delta_digest}"
        )
    if "separately tracked current candidate\n    baseline" not in index:
        fail("index no longer describes eMule AI 1.6 as a gated candidate baseline")
    if "separately promoted current baseline" in index:
        fail("index promotes eMule AI 1.6 before its v9.2 freeze gate")

    feature_rows = extract_rows(text, "F")
    improvement_rows = extract_rows(text, "I")
    require_contiguous(feature_rows, "F", 49)
    require_contiguous(improvement_rows, "I", 43)

    roadmap = ROADMAP.read_text(encoding="utf-8")
    begin_marker = "<!-- SUPERIORITY-CLOSURE-MAP:BEGIN -->"
    end_marker = "<!-- SUPERIORITY-CLOSURE-MAP:END -->"
    if roadmap.count(begin_marker) != 1 or roadmap.count(end_marker) != 1:
        fail("roadmap closure map markers are missing or duplicated")
    closure_map = roadmap.split(begin_marker, 1)[1].split(end_marker, 1)[0]
    if "AI16-" in closure_map:
        fail("AI 1.6 delta IDs must not duplicate the frozen 92-case closure map")
    assigned = re.findall(r"`AI-([FI])(\d{2})`", closure_map)
    expected = {
        *[("F", f"{number:02d}") for number in range(1, 50)],
        *[("I", f"{number:02d}") for number in range(1, 44)],
    }
    duplicates = sorted(
        f"AI-{prefix}{number}"
        for prefix, number in set(assigned)
        if assigned.count((prefix, number)) > 1
    )
    actual = set(assigned)
    missing = sorted(f"AI-{prefix}{number}" for prefix, number in expected - actual)
    extra = sorted(f"AI-{prefix}{number}" for prefix, number in actual - expected)
    if duplicates or missing or extra or len(assigned) != 92:
        fail(
            "roadmap assignment mismatch: "
            f"duplicates={duplicates}, missing={missing}, extra={extra}"
        )

    closure_rows = {
        match.group(1): set(re.findall(r"AI-[FI]\d{2}", match.group(2)))
        for match in re.finditer(
            r"^\| `([^`]+)` \| ([^|]+) \|$", closure_map, re.MULTILINE
        )
    }
    if set(closure_rows) != set(EXPECTED_CLOSURE_MAP):
        fail(f"roadmap closure trains drifted: {sorted(closure_rows)}")
    for train, expected_cases in EXPECTED_CLOSURE_MAP.items():
        actual_cases = closure_rows[train]
        if actual_cases != expected_cases:
            fail(
                f"{train} assignment drifted: "
                f"missing={sorted(expected_cases - actual_cases)}, "
                f"extra={sorted(actual_cases - expected_cases)}"
            )

    state_by_id = {
        **{f"AI-F{number:02d}": state for number, (state, _) in feature_rows.items()},
        **{f"AI-I{number:02d}": state for number, (state, _) in improvement_rows.items()},
    }
    computed_total: Counter[str] = Counter()
    summary_rows = {
        match.group(1): (int(match.group(2)), parse_state_counts(match.group(3)))
        for match in re.finditer(
            r"^\| `([^`]+)` \| (\d+) \| ([^|]+) \|$", roadmap, re.MULTILINE
        )
        if match.group(1) in EXPECTED_CLOSURE_MAP
    }
    if set(summary_rows) != set(EXPECTED_CLOSURE_MAP):
        fail(f"roadmap state-summary trains drifted: {sorted(summary_rows)}")
    for train, cases in EXPECTED_CLOSURE_MAP.items():
        actual_counts = Counter(state_by_id[case_id] for case_id in cases)
        computed_total.update(actual_counts)
        if actual_counts != EXPECTED_STATE_COUNTS[train]:
            fail(
                f"{train} state distribution drifted: "
                f"expected={EXPECTED_STATE_COUNTS[train]}, actual={actual_counts}"
            )
        written_case_count, written_counts = summary_rows[train]
        if written_case_count != len(cases) or written_counts != actual_counts:
            fail(
                f"{train} written summary disagrees with matrix: "
                f"cases={written_case_count}, states={written_counts}"
            )
    if computed_total != EXPECTED_TOTAL_STATES:
        fail(
            "global state distribution drifted: "
            f"expected={EXPECTED_TOTAL_STATES}, actual={computed_total}"
        )
    total_match = re.search(
        r"^\| \*\*Total\*\* \| \*\*(\d+)\*\* \| \*\*(.+)\*\* \|$",
        roadmap,
        re.MULTILINE,
    )
    if not total_match:
        fail("roadmap total state-summary row is missing")
    if int(total_match.group(1)) != 92 or parse_state_counts(total_match.group(2)) != computed_total:
        fail("roadmap total state-summary row disagrees with the frozen matrix")

    owner_window = {
        owner: CLOSURE_TO_WINDOW[train]
        for train, owners in EXPECTED_CLOSURE_MAP.items()
        for owner in owners
    }
    if set(EXPECTED_DELTA_MAP) != {f"AI16-D{number:02d}" for number in delta_ids}:
        fail("explicit eMule AI 1.6 delta map does not cover the 19 rows exactly")
    for match in delta_rows:
        delta_id = f"AI16-D{match.group(1)}"
        title = match.group(2).strip()
        owners = set(re.findall(r"AI-[FI]\d{2}", match.group(3)))
        if not owners:
            fail(f"{delta_id} has no existing owner")
        unknown_owners = sorted(owners - set(owner_window))
        if unknown_owners:
            fail(f"{delta_id} has unknown owners: {unknown_owners}")
        window_cell = match.group(4)
        if re.search(r"(?<![A-Z])9\.[2567]", window_cell):
            fail(f"{delta_id} uses an ambiguous release label: {window_cell!r}")
        actual_windows = set(re.findall(r"\b(?:B\d+|V\d+)\b", window_cell))
        expected_title, expected_owners, expected_windows = EXPECTED_DELTA_MAP[delta_id]
        if title != expected_title:
            fail(f"{delta_id} title drifted: {title!r}")
        if owners != expected_owners:
            fail(
                f"{delta_id} owners drifted: "
                f"expected={sorted(expected_owners)}, actual={sorted(owners)}"
            )
        owner_derived_windows = {owner_window[owner] for owner in expected_owners}
        if expected_windows != owner_derived_windows:
            fail(f"internal expected map for {delta_id} disagrees with closure ownership")
        if actual_windows != expected_windows:
            fail(
                f"{delta_id} owner/window mismatch: "
                f"expected={sorted(expected_windows)}, actual={sorted(actual_windows)}"
            )

    print(
        "eMule AI superiority matrix: PASS "
        f"({len(feature_rows)} features, {len(improvement_rows)} improvements, "
        f"{len(assigned)} scheduled once, {len(delta_ids)} v1.6 deltas crosswalked)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

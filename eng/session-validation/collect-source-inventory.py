#!/usr/bin/env python3
"""SVS-00: deterministic source identity and static SQL audit, never authentication.

No endpoint, credential, process environment, cache payload or token is read.
Tool version probes are opt-in and cannot count as live dependency qualification.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

BASELINE_MANIFEST_SHA256 = "647ac53c980932abb65c079dadc795e0bc5a12c6677b2afb9758273587988371"
ARCHIVE_SHA256 = "4f824b11f91c3f3a7f7541cf15c11f9297c665b6fcc3c890451c9ca4e854d5ec"
SQL_PATH = "Rigging/Database/Baseline/000_canonical_database.sql"
SQL_MIRROR = "Rigging/Database/Baseline/000_treehammock_canonical_database.sql"
ROOTS = ["get_session", "validate_cached_session_trust", "cor20_resolve_account", "cor02_lock_account_authority"]
IGNORED_DIRS = {".git", "bin", "obj", "__pycache__"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def write_json(path, value):
    path.write_bytes(encoded(value))


def source_inventory(root):
    result = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in IGNORED_DIRS for part in rel.parts) or path.suffix == ".pyc":
            continue
        if path.is_symlink():
            raise ValueError("Symlink in source tree: " + rel.as_posix())
        if path.is_file():
            data = path.read_bytes()
            result[rel.as_posix()] = {"sha256": sha(data), "size_bytes": len(data)}
    return result


def sql_code(text):
    # This scanner covers the pinned baseline's untagged dollar-quoted functions.
    # It is not a general SQL parser or proof of deployed ACLs/search_path.
    return re.sub(r"--[^\n]*|/\*.*?\*/|'(?:''|[^'])*'", " ", text, flags=re.S)


def sql_audit(text):
    matches = list(re.finditer(
        r"create\s+or\s+replace\s+function\s+(\w+)\s*\(.*?\bas\s*\$\$(.*?)\$\$\s*;",
        text, re.I | re.S))
    routines = {}
    for match in matches:
        name = match.group(1).lower()
        if name in routines:
            raise ValueError("Overloaded/redefined routine needs explicit review: " + name)
        routines[name] = match
    if not all(name in routines for name in ROOTS):
        raise ValueError("Missing SQL audit root")
    triggers = []
    for match in re.finditer(r"create\s+trigger\s+(\w+)\s+(.*?)\s+on\s+(\w+)\s+.*?execute\s+function\s+(\w+)\s*\(\s*\)\s*;", text, re.I | re.S):
        events = re.findall(r"\b(insert|update|delete)\b", match.group(2), re.I)
        triggers.append({"trigger": match.group(1).lower(), "events": [e.lower() for e in events],
                         "table": match.group(3).lower(), "function": match.group(4).lower()})
    pending = list(ROOTS)
    nodes = {}
    while pending:
        name = pending.pop()
        if name in nodes:
            continue
        if name not in routines:
            raise ValueError("Unresolved trigger function: " + name)
        match = routines[name]
        body = sql_code(match.group(2)).lower()
        calls = sorted(n for n in routines if re.search(r"\b" + re.escape(n) + r"\s*\(", body))
        writes = [{"operation": m.group(1).lower().split()[0], "table": m.group(2).lower()}
                  for m in re.finditer(r"\b(update|insert\s+into|delete\s+from)\s+(\w+)", body)]
        writes = sorted({(w["operation"], w["table"]) for w in writes})
        edges = sorted(t["function"] for t in triggers
                       if any(t["table"] == table and op in t["events"] for op, table in writes))
        header = sql_code(match.group(0).split("$$", 1)[0]).lower()
        nodes[name] = {
            "source": SQL_PATH, "line": text.count("\n", 0, match.start()) + 1,
            "definition_sha256": sha(match.group(0).encode()), "calls": calls,
            "trigger_calls": edges,
            "writes": [{"operation": op, "table": table} for op, table in writes],
            "row_locks": bool(re.search(r"\bfor\s+(update|share)\b", body)),
            "dynamic_sql": bool(re.search(r"\bexecute\b", body)),
            "security": "definer" if "security definer" in header else "invoker (default)",
            "volatility": next((v for v in ["immutable", "stable", "volatile"] if re.search(r"\b" + v + r"\b", header)), "volatile (default)")}
        pending.extend(calls + edges)
    return {"scope": "static pinned SQL definitions including DML-trigger edges; not live privileges",
            "roots": ROOTS, "routines": dict(sorted(nodes.items())),
            "all_reachable_routines_classified": True,
            "live_readonly_conformance": "NotRun", "safe_for_readonly_role": False,
            "external_dependencies": ["pgcrypto digest", "pg_roles", "pg_has_role", "clock_timestamp",
                                      "PostgreSQL/YSQL built-in JSON, calendar and array functions"],
            "limitations": ["Scope is these frozen untagged function definitions, not arbitrary SQL syntax.",
                            "Conditional trigger edges are conservatively included even when an update may not satisfy their predicates.",
                            "Operator-defined triggers, RLS, ownership, inherited roles, PUBLIC grants and deployed search_path require live audit."]}


def validate_matrix(matrix, root):
    ids = set()
    for case in matrix["cases"]:
        if case["id"] in ids:
            raise ValueError("Duplicate matrix ID")
        ids.add(case["id"])
        if case["native_status"] != "NotRun":
            raise ValueError("SVS-00 cannot claim native fixture execution")
        if case["public_result"] not in {"Authenticated", "Unauthenticated", "Unavailable", "Bypass", "ReviewRequired"}:
            raise ValueError("Invalid matrix outcome")
        for ref in case["references"]:
            if Path(ref).is_absolute() or ".." in Path(ref).parts:
                raise ValueError("Matrix reference escapes source root")
            if not (root / ref).is_file():
                raise ValueError("Missing matrix reference: " + ref)
    required = {"active", "rotated", "revoked", "twofactor_pending", "access_expired", "wrong_purpose", "locked_cached", "locked_cold", "entitlement_boundary", "cache_only_db_down"}
    if not required <= ids:
        raise ValueError("Missing required parity cases")
    return {"cases": len(ids), "structural_validation": "PASS", "native_execution": "NotRun"}


def tool_capabilities():
    probes = {"dotnet": ["--info"], "docker": ["--version"], "psql": ["--version"], "redis-cli": ["--version"]}
    result = {}
    for tool, args in probes.items():
        executable = shutil.which(tool)
        if executable is None:
            result[tool] = {"status": "Unavailable", "exit_code": None, "output": ""}
            continue
        try:
            p = subprocess.run([executable, *args], capture_output=True, text=True, timeout=15, check=False)
            result[tool] = {"status": "Available" if p.returncode == 0 else "ProbeFailed",
                            "exit_code": p.returncode, "output": (p.stdout + p.stderr)[:32768]}
        except (OSError, subprocess.TimeoutExpired):
            result[tool] = {"status": "ProbeFailed", "exit_code": None, "output": "Probe failed or exceeded 15 seconds."}
    return {"tools": result, "live_ysql": "NotRun", "live_dragonfly": "NotRun",
            "native_cases_executed": 0, "tracing": "NotRun", "credentials_or_endpoints_read": False}


def collect(root, output, probe_tools=False):
    root = root.resolve()
    output = output.resolve()
    if output == root or root in output.parents:
        raise ValueError("Evidence output must be outside source root to avoid self-inventory drift")
    baseline_path = root / "docs/session-validation/COR25_Q06_SOURCE_SHA256.json"
    data = baseline_path.read_bytes()
    if sha(data) != BASELINE_MANIFEST_SHA256:
        raise ValueError("Frozen baseline manifest identity mismatch")
    baseline = json.loads(data)
    current = source_inventory(root)
    changed = sorted(p for p, h in baseline.items() if p in current and current[p]["sha256"] != h)
    missing = sorted(set(baseline) - set(current))
    added = sorted(set(current) - set(baseline))
    unexpected = [p for p in added if not p.startswith(("docs/session-validation/", "eng/session-validation/"))]
    audit = sql_audit((root / SQL_PATH).read_text())
    mirror_matches = (root / SQL_PATH).read_bytes() == (root / SQL_MIRROR).read_bytes()
    matrix = validate_matrix(json.loads((root / "eng/session-validation/session-decision-matrix.json").read_text()), root)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "SOURCE_INVENTORY.json", current)
    write_json(output / "SQL_DEPENDENCIES.json", audit)
    project = ET.parse(root / "treehammock.csproj").getroot()
    write_json(output / "DECLARED_CAPABILITIES.json", {
        "scope": "source declarations, not running dependency capabilities",
        "target_frameworks": [e.text for e in project.iter() if e.tag in {"TargetFramework", "TargetFrameworks"}],
        "sdk": json.loads((root / "global.json").read_text())["sdk"],
        "packages": sorted([dict(e.attrib) for e in project.iter("PackageReference")], key=lambda e: e.get("Include", "")),
        "sql_mirrors_match": mirror_matches, "sql_dependency_routines": len(audit["routines"]),
        "server_versions": {"YSQL": "NotRun", "Dragonfly": "NotRun"},
        "readonly_role_proof": "NotRun", "native_tracing": "NotRun"})
    report = {"pr": "SVS-00", "baseline_archive_sha256": ARCHIVE_SHA256,
              "baseline_manifest_sha256": BASELINE_MANIFEST_SHA256, "baseline_files": len(baseline),
              "candidate_files": len(current), "candidate_inventory_sha256": sha(encoded(current)),
              "changed_baseline_files": changed, "missing_baseline_files": missing, "added_files": added,
              "unexpected_additions": unexpected, "sql_mirrors_match": mirror_matches, "matrix": matrix,
              "static_status": "PASS" if not (changed or missing or unexpected) and mirror_matches else "FAIL",
              "native_status": "Blocked/NotRun", "release_ready": False,
              "cor25_q01_q06": "Unchanged: Blocked/NotRun"}
    write_json(output / "BASELINE_CHECK.json", report)
    if probe_tools:
        write_json(output / "CAPABILITIES.json", tool_capabilities())
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True, help="Evidence directory outside source root")
    parser.add_argument("--probe-tools", action="store_true", help="Run local version commands only; never connect to dependencies")
    args = parser.parse_args()
    try:
        report = collect(args.root, args.output, args.probe_tools)
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
        print("SVS-00 inventory failed: " + str(error), file=sys.stderr)
        return 2
    print(json.dumps({k: report[k] for k in ["static_status", "baseline_files", "candidate_files", "native_status", "release_ready"]}))
    return 0 if report["static_status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())

"""
Convert REVEAL JSON files (vulnerables.json, non-vulnerables.json) into the
PrimeVul / pre-data expected CSV format: data/raw/reveal.csv

Handles two JSON layouts:
- dict mapping hash -> record
- list of records (each record contains 'hash' or similar)

Expected per-record keys in REVEAL: 'code', 'hash', 'project', 'size'
If fields differ, adjust the mapping in normalize_record().
"""
import os
import json
import pandas as pd

RAW_DIR = os.path.join("data", "raw")
VULN_FILE = os.path.join(RAW_DIR, "vulnerables.json")
NONVULN_FILE = os.path.join(RAW_DIR, "non-vulnerables.json")
OUT_FILE = os.path.join(RAW_DIR, "reveal.csv")


def load_json(path):
    """Load JSON file with a few fallback encodings."""
    # 1) try utf-8
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except UnicodeDecodeError:
        pass

    # 2) read raw bytes, try common encodings
    with open(path, "rb") as f:
        raw_bytes = f.read()

    for enc in ("utf-8", "latin-1", "cp1252", "gbk", "gb18030"):
        try:
            text = raw_bytes.decode(enc)
            return json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue

    raise UnicodeError(
        f"Cannot decode JSON file {path} with utf-8/latin-1/cp1252/gbk/gb18030. "
        "Please convert it to UTF-8 first."
    )


def iter_records(data):
    """
    Yield normalized dicts from either dict or list shaped JSON.
    """
    if isinstance(data, dict):
        # dict: key -> value
        for k, v in data.items():
            # If value already contains hash field, prefer that; else use key.
            if isinstance(v, dict):
                v_hash = v.get("hash") or k
                v["hash"] = v_hash
                yield v
            else:
                # unexpected shape: wrap
                yield {"hash": k, "code": str(v)}
    elif isinstance(data, list):
        for item in data:
            yield item
    else:
        raise ValueError("Unsupported JSON top-level type: expected dict or list")


def normalize_record(rec, is_vuln, dataset_name="reveal"):
    """
    Map REVEAL fields to PrimeVul expected columns.
    - commit_id: "reveal_<hash>"
    - func_before: "" (not available)
    - func_after: code
    - is_security_related / is_vulnerable: based on file
    - other meta kept as extra columns
    """
    code = rec.get("code") or rec.get("source_code") or rec.get("snippet") or ""
    h = rec.get("hash") or rec.get("id") or ""
    project = rec.get("project") or rec.get("origin") or ""
    size = rec.get("size") or ""
    # safe string coercions
    commit_id = f"reveal_{h}" if h else f"reveal_{abs(hash(code))}"
    return {
        "commit_id": commit_id,
        "func_before": "",
        "func_after": code,
        "is_security_related": bool(is_vuln),
        "is_vulnerable": bool(is_vuln),
        "cve_id": "",
        "commit_time": "",      # not provided by REVEAL
        "file_path": "",
        "func_name": "",
        "source_dataset": dataset_name,
        "project": project,
        "size": size,
        "orig_hash": h,
    }


def collect_and_write():
    records = []
    for path, is_vuln in ((VULN_FILE, True), (NONVULN_FILE, False)):
        if not os.path.exists(path):
            print(f"Warning: {path} not found, skipping.")
            continue
        raw = load_json(path)
        for rec in iter_records(raw):
            nr = normalize_record(rec, is_vuln=is_vuln)
            records.append(nr)

    if not records:
        print("No records collected. Please check input JSON files.")
        return

    df = pd.DataFrame(records)
    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    df.to_csv(OUT_FILE, index=False, encoding="utf-8")
    print(f"Wrote {len(df)} rows to {OUT_FILE}")


if __name__ == "__main__":
    collect_and_write()
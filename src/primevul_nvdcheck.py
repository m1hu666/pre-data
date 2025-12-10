"""PrimeVul NVDCheck labeling.

Implements a simplified version of the NVDCheck rule from the PrimeVul paper:

For each security-related commit that can be linked to an NVD CVE entry:

  1. Load the NVD description text for the commit's CVE id.
  2. For each function in that commit, if the NVD description explicitly
     mentions the function name, mark that function's post-commit version as
     vulnerable with labeling_method="nvdcheck".

File-name based rule from the original paper is omitted here, because some
sources (e.g., DiverseVul) do not provide file paths.

This module only sets additional "vulnerable" labels. It does not label
benign functions nor drop any rows. A later consolidation step should:

  - For commits with at least one vulnerable function: mark all remaining
    functions in that commit as benign.
  - For commits with no vulnerable functions at all: drop them.
"""

from __future__ import annotations

import json
import re
from typing import Dict, Optional, Tuple

import pandas as pd


def load_nvd_descriptions(nvd_path: str) -> Dict[str, str]:
    """Load NVD CVE descriptions from a JSON file.

    The JSON file is expected to be either:
      - A dict: {"CVE-XXXX-YYYY": {"description": "..."}, ...}
      - A list of objects, each containing fields like
        {"cve_id": "CVE-...", "description": "..."}

    Returns a dict mapping upper-cased CVE ids to description strings.
    """
    try:
        with open(nvd_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}

    desc_map: Dict[str, str] = {}

    if isinstance(data, dict):
        for cve, val in data.items():
            if isinstance(val, dict):
                desc = (
                    val.get("description")
                    or val.get("desc")
                    or val.get("summary")
                    or ""
                )
            else:
                desc = str(val)
            desc_map[str(cve).upper()] = desc
    elif isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            cve = (
                item.get("cve_id")
                or item.get("cve")
                or item.get("id")
            )
            if not cve:
                continue
            desc = (
                item.get("description")
                or item.get("desc")
                or item.get("summary")
                or ""
            )
            desc_map[str(cve).upper()] = desc

    return desc_map


_FUNC_NAME_PATTERNS = [
    # Very simple C-like function definition pattern.
    re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
]


def extract_function_name(code: str) -> Optional[str]:
    """Best-effort extraction of a function name from source code.

    This is intentionally simple and language-agnostic. For C-like code it
    works reasonably well. If extraction fails, returns None.
    """
    if not isinstance(code, str):
        return None
    for pat in _FUNC_NAME_PATTERNS:
        m = pat.search(code)
        if m:
            return m.group(1)
    return None


def _func_name_mentioned(desc: str, func_name: str) -> bool:
    if not desc or not func_name:
        return False
    pat = re.compile(r"\b" + re.escape(func_name) + r"\b", re.IGNORECASE)
    return bool(pat.search(desc))


def apply_nvdcheck_labeling(
    df: pd.DataFrame,
    nvd_path: Optional[str] = None,
) -> pd.DataFrame:
    """Apply NVDCheck labeling on top of existing labels.

    Expected columns in `df`:
        - commit_id: commit identifier
        - cve_id: CVE id string (may be empty)
        - func_after: post-commit function code
        - func_name: function name (may be empty / None)
        - label: may already contain "vulnerable" from OneFunc

    Behavior:
        - If NVD data cannot be loaded, the function is a no-op.
        - For each commit with a known CVE and NVD description, functions
          whose names are mentioned in the description are marked
          vulnerable (label="vulnerable", labeling_method="nvdcheck"),
          unless they are already labeled as vulnerable.
    """
    if "commit_id" not in df.columns or "cve_id" not in df.columns:
        raise ValueError(
            "apply_nvdcheck_labeling: DataFrame must have 'commit_id' and 'cve_id'"
        )

    df = df.copy()

    # Ensure columns exist
    if "label" not in df.columns:
        df["label"] = None
    if "labeling_method" not in df.columns:
        df["labeling_method"] = None

    if not nvd_path:
        return df

    nvd_descs = load_nvd_descriptions(nvd_path)
    if not nvd_descs:
        return df

    # Fill func_name if missing, using heuristic extraction.
    if "func_name" not in df.columns:
        df["func_name"] = df.get("func_after", "").apply(extract_function_name)
    else:
        df["func_name"] = df["func_name"].where(
            df["func_name"].notna(),
            df.get("func_after", "").apply(extract_function_name),
        )

    # Process per commit
    for commit_id, group_idx in df.groupby("commit_id").groups.items():
        idxs = list(group_idx)
        cve_vals = df.loc[idxs, "cve_id"].astype(str)
        cve_candidates = [c for c in cve_vals if c]
        if not cve_candidates:
            continue
        # Use the first non-empty CVE id
        cve_id = cve_candidates[0].upper()
        desc = nvd_descs.get(cve_id)
        if not desc:
            continue

        for idx in idxs:
            # Respect existing vulnerable labels (e.g., from OneFunc)
            if df.at[idx, "label"] == "vulnerable":
                continue
            func_name = df.at[idx, "func_name"]
            if not isinstance(func_name, str) or not func_name:
                continue
            if _func_name_mentioned(desc, func_name):
                df.at[idx, "label"] = "vulnerable"
                df.at[idx, "labeling_method"] = "nvdcheck"

    return df

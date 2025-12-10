"""Helper utilities for PrimeVul-style labeling flows.

This module provides small shared helpers that can be reused across
pipelines and datasets.
"""

from __future__ import annotations

import re
from typing import Optional

import pandas as pd


_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def extract_cve_id(text: str) -> str:
    """Extract the first CVE id from a piece of text.

    Returns an upper-cased CVE string like "CVE-2020-1234" or an empty
    string if no CVE is found.
    """
    if not isinstance(text, str):
        return ""
    m = _CVE_PATTERN.search(text)
    if not m:
        return ""
    return m.group(0).upper()


def finalize_labels_by_commit(df: pd.DataFrame) -> pd.DataFrame:
    """Finalize labels following PrimeVul's rules.

    For each commit:
        - If at least one function is labeled as vulnerable, then all
          remaining (previously unlabeled) functions in that commit are
          marked as benign.
        - If no function is labeled as vulnerable, the entire commit is
          dropped.

    The function expects columns:
        - commit_id
        - label (string or None/NaN)
        - labeling_method (string or None/NaN)
    """
    if "commit_id" not in df.columns or "label" not in df.columns:
        raise ValueError(
            "finalize_labels_by_commit: DataFrame must have 'commit_id' and 'label'"
        )

    df = df.copy()
    if "labeling_method" not in df.columns:
        df["labeling_method"] = None

    groups = []

    for commit_id, group in df.groupby("commit_id"):
        vuln_mask = group["label"] == "vulnerable"
        if not vuln_mask.any():
            # Drop this commit entirely
            continue
        # Mark remaining functions as benign
        none_mask = group["label"].isna()
        group.loc[none_mask, "label"] = "benign"
        group.loc[none_mask, "labeling_method"] = group.loc[
            none_mask, "labeling_method"
        ].fillna("benign_from_commit")
        groups.append(group)

    if not groups:
        # Return an empty DataFrame with the same columns
        return df.head(0)

    return pd.concat(groups, ignore_index=True)

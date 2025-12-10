"""PrimeVul OneFunc labeling.

Implements the OneFunc rule from the PrimeVul paper:

- For security-related commits (here we assume `is_security_related` is True
  for rows we care about), if a commit modifies exactly ONE function in the
  dataset, the post-commit version of this function is labeled as
  "vulnerable".
- Other commits are left for further processing (e.g., NVDCheck).

The function does not drop any rows; it only fills `label` and
`labeling_method` when the rule applies. Later stages can decide how to
handle unlabeled rows.
"""

from __future__ import annotations

from typing import Dict

import pandas as pd


def apply_onefunc_labeling(df: pd.DataFrame) -> pd.DataFrame:
    """Apply the OneFunc labeling rule.

    Expected columns in `df`:
        - commit_id: identifier of the commit
        - is_security_related: bool (True if the commit is security related)

    Added/updated columns:
        - label: "vulnerable" or left untouched (None/NaN)
        - labeling_method: "onefunc" for functions labeled here
    """
    if "commit_id" not in df.columns:
        raise ValueError("apply_onefunc_labeling: DataFrame must have 'commit_id'")

    # Default: assume all rows are security-related if the column is missing.
    if "is_security_related" not in df.columns:
        df = df.copy()
        df["is_security_related"] = True

    df = df.copy()

    # Ensure columns exist
    if "label" not in df.columns:
        df["label"] = None
    if "labeling_method" not in df.columns:
        df["labeling_method"] = None

    # Count functions per commit (only security-related ones matter).
    sec_mask = df["is_security_related"].astype(bool)
    commit_sizes: Dict[str, int] = (
        df.loc[sec_mask]
        .groupby("commit_id")
        .size()
        .to_dict()
    )

    # Apply OneFunc: if a security-related commit has exactly one function
    # in the dataset, label that function as vulnerable.
    for idx, row in df.loc[sec_mask].iterrows():
        cid = row["commit_id"]
        if commit_sizes.get(cid, 0) == 1:
            df.at[idx, "label"] = "vulnerable"
            df.at[idx, "labeling_method"] = "onefunc"

    return df

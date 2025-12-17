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

try:
    from config import GIT_REPOS  # type: ignore
    from git_diff_utils import get_total_changed_functions
except Exception:  # pragma: no cover - optional dependency
    GIT_REPOS = {}
    get_total_changed_functions = None  # type: ignore


def apply_onefunc_labeling(
    df: pd.DataFrame,
    project_column: str = "project",
) -> pd.DataFrame:
    """Apply ONEFUNC labeling based on Git commit diff analysis.

    This implementation directly reads Git commit diffs to determine whether
    a security-related commit modified exactly ONE function. If so, that
    function is labeled as vulnerable.

    Logic:
        - Group by (project, commit_id)
        - Use GIT_REPOS[project] to locate the repository and read the commit diff
        - If the commit changed exactly 1 function in Git, mark all rows in that
          commit group as label="vulnerable", labeling_method="onefunc_git"
        - If Git repo is missing or git command fails, skip that commit

    Expected columns in `df`:
        - commit_id: identifier of the commit
        - project: project name (used to look up repo path)
        - is_security_related: bool (optional, defaults to True)

    Added/updated columns:
        - label: "vulnerable" or left untouched (None/NaN)
        - labeling_method: "onefunc_git" for functions labeled here

    Note:
        This assumes each row in the DataFrame represents a "changed function"
        in that commit, consistent with the paper's semantics.
    """
    if "commit_id" not in df.columns:
        raise ValueError("apply_onefunc_labeling_from_git: DataFrame must have 'commit_id'")

    df = df.copy()

    # 默认：如果没有 is_security_related 列,则视为全部 security-related。
    if "is_security_related" not in df.columns:
        df["is_security_related"] = True

    # 确保标签列存在
    if "label" not in df.columns:
        df["label"] = None
    if "labeling_method" not in df.columns:
        df["labeling_method"] = None

    if not GIT_REPOS or get_total_changed_functions is None:
        # 没有配置 Git 仓库信息，无法进行 Git 驱动的 ONEFUNC 标注
        print("Warning: GIT_REPOS not configured, ONEFUNC labeling skipped.")
        return df

    # 只考虑 security-related 的行
    sec_mask = df["is_security_related"].astype(bool)
    df_sec = df.loc[sec_mask]

    if project_column in df.columns:
        group_keys = [project_column, "commit_id"]
    else:
        # 没有 project 列时,只能按 commit_id 分组,使用第一个仓库。
        group_keys = ["commit_id"]

    for key, idxs in df_sec.groupby(group_keys).groups.items():
        if isinstance(key, tuple) and len(key) == 2:
            project, commit_id = key
        else:
            project, commit_id = None, key  # type: ignore[assignment]

        repo_path = None
        if project is not None:
            repo_path = GIT_REPOS.get(str(project))
        else:
            # 没有 project 列时,如果 GIT_REPOS 里只有一个仓库就用它。
            if len(GIT_REPOS) == 1:
                repo_path = next(iter(GIT_REPOS.values()))

        if not repo_path:
            continue

        try:
            total_changed = get_total_changed_functions(repo_path, str(commit_id))  # type: ignore[call-arg]
        except Exception:
            # Git 失败则跳过该 commit
            continue

        if total_changed != 1:
            continue

        # 该 commit 在 Git 层面只改了 1 个函数 → 视作 ONEFUNC 成立
        for idx in idxs:
            if df.at[idx, "label"] == "vulnerable":
                continue
            df.at[idx, "label"] = "vulnerable"
            # 如果之前未设置 labeling_method,则标记为 onefunc_git
            if not df.at[idx, "labeling_method"]:
                df.at[idx, "labeling_method"] = "onefunc_git"

    return df

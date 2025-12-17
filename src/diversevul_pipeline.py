"""DiverseVul-only PrimeVul-style processing pipeline.

Input:
    - /home/m1hu/pre-data/data/raw/diversevul_20230702.json
      (schema example: see data/raw/1.json)

It implements, for this single dataset, the four high-level stages
from the paper "Vulnerability Detection with Code Language Models:
How Far Are We?":

    1) Data merging  -> here: only one source, DiverseVul
    2) Thorough dedup -> function-level text normalization + MD5 hash
    3) Labeling      -> PrimeVul-style OneFunc + NVDCheck
    4) Temporal split-> synthetic commit-time ordering (no real timestamps)
    5) Paired subset -> pair vulnerable/benign functions with >X% similarity

Outputs (under data/output/):
    - diversevul_all.csv      : all deduplicated & labeled samples
    - diversevul_train.csv    : train split
    - diversevul_dev.csv      : dev split
    - diversevul_test.csv     : test split
    - diversevul_paired.csv   : paired functions (vuln, patch) with split column

This file is self-contained and does not rely on multi-dataset merging.
"""

import os
import sys
import json
import re
import hashlib
from dataclasses import dataclass
from typing import List, Dict, Tuple
from datetime import datetime, timedelta

import pandas as pd
from tqdm import tqdm

# Ensure project root is on sys.path so that `config` can be imported
ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from config import NVD_DATA_PATH, GIT_REPOS
from primevul_onefunc import apply_onefunc_labeling
from primevul_nvdcheck import apply_nvdcheck_labeling, extract_function_name
from primevul_label_utils import extract_cve_id, finalize_labels_by_commit
from git_diff_utils import reconstruct_function_before, get_commit_time


# ---------------------------------------------------------------------------
# 1. Loading DiverseVul JSON
# ---------------------------------------------------------------------------

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
RAW_DIR = os.path.join(ROOT_DIR, "data", "raw")
OUTPUT_DIR = os.path.join(ROOT_DIR, "data", "output")

DIVERSEVUL_PATH = os.path.join(RAW_DIR, "diversevul_20230702.json")


def load_diversevul(path: str, max_samples: int | None = None) -> pd.DataFrame:
    """Load DiverseVul JSON into a pandas DataFrame.

    The file may be either a JSON array or JSON-lines (one JSON object per line).

    Each record is expected to contain (example from data/raw/1.json):
        - func:   code snippet (string)
        - target: 1 (vulnerable) or 0 (benign)
        - cwe:    list of CWE IDs
        - project: project name (e.g., "qemu")
        - commit_id: underlying VCS commit id
        - hash:  numeric hash used by the dataset
        - size:  code size (e.g., LOC or tokens)
        - message: commit message (often containing CVE id text)
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"DiverseVul file not found: {path}")

    records: List[Dict] = []

    # Try to parse as a single JSON value first.
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            for rec in data:
                records.append(rec)
                if max_samples is not None and len(records) >= max_samples:
                    break
        else:
            raise ValueError("Expected top-level list in DiverseVul JSON")
    except json.JSONDecodeError:
        # Fallback: treat as JSON lines
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                records.append(rec)
                if max_samples is not None and len(records) >= max_samples:
                    break

    if not records:
        raise RuntimeError("No records loaded from DiverseVul JSON.")

    df = pd.DataFrame.from_records(records)

    # Normalize essential columns and make them explicit.
    # We keep the original fields but also create canonical names.
    df["func"] = df["func"].astype(str)
    df["target"] = df["target"].astype(int)

    # Ensure these columns exist (fill with default if missing in original).
    for col, default in [
        ("project", ""),
        ("commit_id", ""),
        ("hash", ""),
        ("size", 0),
        ("message", ""),
        ("cwe", []),
    ]:
        if col not in df.columns:
            df[col] = default

    return df


# ---------------------------------------------------------------------------
# 2. Deduplication (function-level, MD5 over normalized code)
# ---------------------------------------------------------------------------

def normalize_code_text(code: str) -> str:
    """Normalize function text by removing all whitespace characters.

    This mirrors the paper's idea: remove spaces, tabs, newlines, etc., so
    that formatting-only differences are ignored.
    """
    if not isinstance(code, str):
        code = "" if code is None else str(code)
    # Remove all whitespace characters
    return re.sub(r"[\s\t\n\r]", "", code)


@dataclass
class DedupStats:
    total: int
    unique: int
    duplicates: int

    @property
    def rate(self) -> float:
        return self.duplicates / self.total if self.total else 0.0


def deduplicate_functions(df: pd.DataFrame) -> tuple[pd.DataFrame, DedupStats]:
    """Perform function-level deduplication via normalized-text MD5 hashes.

    - Create `norm_code` by stripping whitespace.
    - Compute `code_hash` = MD5(norm_code).
    - Drop duplicates on `code_hash` (keep the first occurrence).
    """
    df = df.copy()
    df["norm_code"] = df["func"].apply(normalize_code_text)
    df["code_hash"] = df["norm_code"].apply(
        lambda s: hashlib.md5(s.encode("utf-8")).hexdigest()
    )

    total = len(df)
    df_dedup = df.drop_duplicates(subset=["code_hash"]).reset_index(drop=True)
    unique = len(df_dedup)
    duplicates = total - unique

    stats = DedupStats(total=total, unique=unique, duplicates=duplicates)
    return df_dedup, stats


# ---------------------------------------------------------------------------
# 3. Labeling (PrimeVul OneFunc + NVDCheck)
# ---------------------------------------------------------------------------

def prepare_for_labeling(df: pd.DataFrame) -> pd.DataFrame:
    """Prepare DiverseVul records for PrimeVul-style labeling.

    This function:
        - maps `func` to `func_after` (post-commit version);
        - creates empty `func_before` (not available in DiverseVul);
        - ensures `commit_id` is non-empty (fallback to project+hash-based id);
        - marks all rows as `is_security_related = True`;
        - extracts `func_name` from code when possible;
        - derives `cve_id` from existing column or from the commit message;
        - initializes `label` and `labeling_method` columns.
    """

    df = df.copy()

    # Post-commit code
    df["func_after"] = df["func"].astype(str)
    
    # Ensure commit_id is non-empty; fall back to a synthetic id
    if "commit_id" not in df.columns:
        df["commit_id"] = ""

    def _fallback_commit_id(row: pd.Series) -> str:
        cid = str(row.get("commit_id", "") or "")
        if cid:
            return cid
        project = str(row.get("project", "unknown"))
        h = str(row.get("hash", ""))
        return f"dv_{project}_{h}"

    df["commit_id"] = df.apply(_fallback_commit_id, axis=1)

    # Try to reconstruct func_before from Git diff
    print("  Attempting to reconstruct func_before from Git diff...")
    func_before_list = []
    
    for idx, row in tqdm(df.iterrows(), total=len(df), desc="  Reconstructing func_before"):
        project = str(row.get("project", ""))
        commit_id = str(row.get("commit_id", ""))
        func_after = str(row.get("func_after", ""))
        
        # Extract function name for better matching
        func_name_val = extract_function_name(func_after)
        
        func_before = ""
        if project and commit_id and GIT_REPOS:
            repo_path = GIT_REPOS.get(project)
            if repo_path:
                try:
                    func_before = reconstruct_function_before(
                        repo_path, 
                        commit_id, 
                        func_after,
                        func_name_val
                    )
                except Exception:
                    pass
        
        func_before_list.append(func_before)
    
    df["func_before"] = func_before_list
    reconstructed_count = sum(1 for fb in func_before_list if fb)
    print(f"  Successfully reconstructed {reconstructed_count}/{len(df)} func_before entries")

    # Mark all commits as security-related for this dataset
    df["is_security_related"] = True

    # File path is not provided by DiverseVul; keep it empty for now
    if "file_path" not in df.columns:
        df["file_path"] = ""

    # Function name: try to extract from code
    df["func_name"] = df["func_after"].apply(extract_function_name)

    # CVE id: use existing cve_id if present, else extract from message
    if "cve_id" not in df.columns:
        df["cve_id"] = ""

    def _combine_cve(row: pd.Series) -> str:
        cve = str(row.get("cve_id", "") or "")
        if cve:
            return cve.upper()
        msg = row.get("message", "")
        return extract_cve_id(msg)

    df["cve_id"] = df.apply(_combine_cve, axis=1)

    # Initialize label columns if missing
    if "label" not in df.columns:
        df["label"] = None
    if "labeling_method" not in df.columns:
        df["labeling_method"] = None

    return df


# ---------------------------------------------------------------------------
# 4. Temporal-style split (synthetic commit-time ordering)
# ---------------------------------------------------------------------------

@dataclass
class SplitConfig:
    train_ratio: float = 0.8
    dev_ratio: float = 0.1
    test_ratio: float = 0.1


@dataclass
class SplitResult:
    train: pd.DataFrame
    dev: pd.DataFrame
    test: pd.DataFrame


def assign_commit_time_from_git(df: pd.DataFrame) -> pd.DataFrame:
    """Assign commit_time from actual Git commit timestamps.

    Reads the real commit timestamp from Git repository for each commit.
    Falls back to synthetic time (based on commit order) if:
    - Git repository is not configured
    - Commit doesn't exist in the repository
    - Git command fails

    The resulting `commit_time` is an ISO-8601 string.
    """
    df = df.copy()

    # Ensure commit_id is valid
    commit_ids = df["commit_id"].fillna("").replace("", "__no_commit__")
    df["commit_id"] = commit_ids

    # Determine project column
    project_column = "project" if "project" in df.columns else None

    commit_time_map: Dict[str, str] = {}
    fallback_commits = []  # Commits that need synthetic time

    # Group by project and commit to get unique combinations
    if project_column:
        groups = df.groupby([project_column, "commit_id"])
    else:
        groups = df.groupby("commit_id")

    print("  Fetching commit timestamps from Git...")
    for key, _ in tqdm(groups.groups.items(), desc="  Reading commit times"):
        if project_column:
            project, commit_id = key
            repo_path = GIT_REPOS.get(str(project))
        else:
            commit_id = key
            # Use first available repo if no project column
            repo_path = next(iter(GIT_REPOS.values())) if GIT_REPOS else None

        commit_id = str(commit_id)
        
        # Try to get real commit time from Git
        if repo_path and commit_id != "__no_commit__":
            try:
                commit_time = get_commit_time(repo_path, commit_id)
                if commit_time:
                    commit_time_map[commit_id] = commit_time
                else:
                    fallback_commits.append(commit_id)
            except Exception:
                fallback_commits.append(commit_id)
        else:
            fallback_commits.append(commit_id)

    # Assign synthetic times to commits that couldn't be read from Git
    if fallback_commits:
        print(f"  Using synthetic time for {len(fallback_commits)} commits (Git unavailable)")
        base_time = datetime(2000, 1, 1, 0, 0, 0)
        for idx, cid in enumerate(sorted(set(fallback_commits))):
            if cid not in commit_time_map:
                t = base_time + timedelta(seconds=idx)
                commit_time_map[cid] = t.isoformat()

    df["commit_time"] = df["commit_id"].map(commit_time_map)
    
    # Count how many used real vs synthetic time
    real_time_count = sum(1 for c in df["commit_id"].unique() if c in commit_time_map and c not in fallback_commits)
    print(f"  Successfully fetched {real_time_count}/{len(df['commit_id'].unique())} commit times from Git")
    
    return df


def temporal_split(df: pd.DataFrame, cfg: SplitConfig) -> SplitResult:
    """Perform commit-level split into train/dev/test according to ratios.

    - Sort unique commits by `commit_time` (from Git or synthetic fallback).
    - First 80% -> train, next 10% -> dev, last 10% -> test.
    - All functions from the same commit go into the same split.
    """
    assert abs(cfg.train_ratio + cfg.dev_ratio + cfg.test_ratio - 1.0) < 1e-6

    df = df.copy()
    if "commit_time" not in df.columns:
        df = assign_commit_time_from_git(df)

    # Get commit -> time
    commit_times = (
        df[["commit_id", "commit_time"]]
        .drop_duplicates()
        .sort_values("commit_time")
    )

    commit_ids = commit_times["commit_id"].tolist()
    total_commits = len(commit_ids)

    train_end = int(total_commits * cfg.train_ratio)
    dev_end = train_end + int(total_commits * cfg.dev_ratio)

    train_commits = set(commit_ids[:train_end])
    dev_commits = set(commit_ids[train_end:dev_end])
    test_commits = set(commit_ids[dev_end:])

    train_df = df[df["commit_id"].isin(train_commits)].copy()
    dev_df = df[df["commit_id"].isin(dev_commits)].copy()
    test_df = df[df["commit_id"].isin(test_commits)].copy()

    train_df["split"] = "train"
    dev_df["split"] = "dev"
    test_df["split"] = "test"

    return SplitResult(train=train_df, dev=dev_df, test=test_df)


# ---------------------------------------------------------------------------
# 5. Paired functions (vulnerable vs "patched" benign, similarity-based)
# ---------------------------------------------------------------------------

def compute_similarity(a: str, b: str) -> float:
    """Compute a simple character-level Jaccard-like similarity.

    To avoid heavy O(n^2) SequenceMatcher on large corpora, we approximate
    similarity by token/character set overlap. This is not identical to the
    paper but respects the idea of requiring substantial overlap.
    """
    if not a or not b:
        return 0.0
    set_a = set(a)
    set_b = set(b)
    inter = len(set_a & set_b)
    union = len(set_a | set_b) or 1
    return inter / union


def build_paired_functions(
    df: pd.DataFrame,
    min_similarity: float = 0.8,
    max_candidates_per_project: int = 500,
) -> pd.DataFrame:
    """Build (vulnerable, benign) function pairs.

    Strategy (adapted for DiverseVul):
        - For each vulnerable function (label == "vulnerable"),
          search benign candidates within the same project.
        - Optionally subsample benign candidates per project to limit cost.
        - For each vulnerable function, pick the benign function with the
          highest character-set similarity; accept if >= min_similarity.
        - The pair inherits the `split` of the vulnerable function.

    This approximates the paired-functions idea from the paper, but uses
    DiverseVul's existing labels instead of patch commits.
    """
    df = df.copy()

    vuln_df = df[df["label"] == "vulnerable"].reset_index(drop=True)
    benign_df = df[df["label"] == "benign"].reset_index(drop=True)

    if vuln_df.empty or benign_df.empty:
        return pd.DataFrame()

    # Pre-group benign functions by project for faster lookup.
    benign_by_project: Dict[str, pd.DataFrame] = {}
    for project, group in benign_df.groupby("project"):
        if len(group) > max_candidates_per_project:
            benign_by_project[project] = group.sample(
                n=max_candidates_per_project, random_state=42
            ).reset_index(drop=True)
        else:
            benign_by_project[project] = group.reset_index(drop=True)

    pairs: List[Dict] = []

    for _, v_row in tqdm(vuln_df.iterrows(), total=len(vuln_df), desc="Pairing"):
        project = v_row.get("project", "")
        v_code = v_row["func"]

        candidates = benign_by_project.get(project)
        if candidates is None or candidates.empty:
            continue

        best_sim = 0.0
        best_row = None

        for _, b_row in candidates.iterrows():
            sim = compute_similarity(v_code, b_row["func"])
            if sim > best_sim:
                best_sim = sim
                best_row = b_row

        if best_row is None or best_sim < min_similarity:
            continue

        pairs.append(
            {
                "pair_id": f"pair_{len(pairs)}",
                "project": project,
                "vuln_commit_id": v_row.get("commit_id", ""),
                "benign_commit_id": best_row.get("commit_id", ""),
                "vuln_code": v_row["func"],
                "benign_code": best_row["func"],
                "vuln_label": v_row["label"],
                "benign_label": best_row["label"],
                "similarity": best_sim,
                "cwe": v_row.get("cwe", ""),
                "split": v_row.get("split", ""),  # inherit vulnerable split
            }
        )

    if not pairs:
        return pd.DataFrame()

    return pd.DataFrame(pairs)


# ---------------------------------------------------------------------------
# 6. Orchestrating the full pipeline
# ---------------------------------------------------------------------------

def run_diversevul_pipeline(
    input_path: str | None = None,
    output_dir: str | None = None,
    split_cfg: SplitConfig | None = None,
    min_similarity: float = 0.8,
) -> None:
    """Run the full processing pipeline on DiverseVul.

    Steps:
        1) Load DiverseVul JSON
        2) Deduplicate by normalized function text
        3) PrimeVul-style labeling (OneFunc + NVDCheck)
        4) Synthetic temporal split (train/dev/test)
        5) Build paired functions
        6) Save CSV files under `data/output/`
    """
    input_path = input_path or DIVERSEVUL_PATH
    output_dir = output_dir or OUTPUT_DIR
    split_cfg = split_cfg or SplitConfig()

    os.makedirs(output_dir, exist_ok=True)

    print("[1/6] Loading DiverseVul...")
    df_raw = load_diversevul(input_path)
    print(f"  Loaded {len(df_raw):,} records from {input_path}")

    print("[2/6] Deduplicating functions (MD5 over normalized code)...")
    df_dedup, d_stats = deduplicate_functions(df_raw)
    print(
        f"  Total: {d_stats.total:,}, Unique: {d_stats.unique:,}, "
        f"Duplicates: {d_stats.duplicates:,} "
        f"(rate={d_stats.rate*100:.2f}%)"
    )

    print("[3/6] PrimeVul-style labeling (OneFunc + NVDCheck)...")
    df_for_label = prepare_for_labeling(df_dedup)

    # 3.1 OneFunc: 基于 Git diff 的 ONEFUNC
    df_after_onefunc = apply_onefunc_labeling(df_for_label)

    # 3.2 NVDCheck: function name mentioned in NVD description
    df_after_nvd = apply_nvdcheck_labeling(df_after_onefunc, nvd_path=NVD_DATA_PATH)

    # 3.3 Finalization: per-commit consolidation (vuln/benign) and pruning
    df_labeled = finalize_labels_by_commit(df_after_nvd)

    vuln_count = (df_labeled["label"] == "vulnerable").sum()
    benign_count = (df_labeled["label"] == "benign").sum()
    print(
        f"  After labeling: {len(df_labeled):,} samples "
        f"({vuln_count:,} vulnerable, {benign_count:,} benign)"
    )

    print("[4/6] Temporal-style split (synthetic commit ordering)...")
    split_res = temporal_split(df_labeled, split_cfg)
    train_df, dev_df, test_df = split_res.train, split_res.dev, split_res.test
    print(
        f"  Train: {len(train_df):,}  Dev: {len(dev_df):,}  "
        f"Test: {len(test_df):,}"
    )

    print("[5/6] Building paired vulnerable/benign functions...")
    df_all = pd.concat([train_df, dev_df, test_df], ignore_index=True)
    df_paired = build_paired_functions(df_all, min_similarity=min_similarity)
    print(f"  Paired functions: {len(df_paired):,}")

    print("[6/6] Saving CSV files to output directory...")
    all_path = os.path.join(output_dir, "diversevul_all.csv")
    train_path = os.path.join(output_dir, "diversevul_train.csv")
    dev_path = os.path.join(output_dir, "diversevul_dev.csv")
    test_path = os.path.join(output_dir, "diversevul_test.csv")
    paired_path = os.path.join(output_dir, "diversevul_paired.csv")

    df_all.to_csv(all_path, index=False)
    train_df.to_csv(train_path, index=False)
    dev_df.to_csv(dev_path, index=False)
    test_df.to_csv(test_path, index=False)
    df_paired.to_csv(paired_path, index=False)

    print("  Saved:")
    print(f"    - {all_path}")
    print(f"    - {train_path}")
    print(f"    - {dev_path}")
    print(f"    - {test_path}")
    print(f"    - {paired_path}")
    print("Done.")


if __name__ == "__main__":
    run_diversevul_pipeline()

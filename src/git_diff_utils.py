"""Helpers for reading Git commit diffs and estimating changed functions.

This module provides lightweight utilities to inspect a Git repository
and approximate how many *functions* are changed in a given commit,
optionally per file. It is intentionally simple and language-agnostic,
using regex heuristics on diff hunks.

It is **not** meant to be a perfect parser, but good enough to drive
PRIMEVUL-ONEFUNC / PRIMEVUL-NVDCHECK style rules:

- ONEFUNC: a commit modifies exactly ONE function in total.
- NVDCHECK file rule: in a given commit, a file has exactly ONE changed
  function.

All helpers are best-effort and will fall back to empty results if the
repository is missing or Git commands fail.
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import Dict


# Very simple C-like function definition heuristic on a single source line.
# We operate on diff lines starting with '+' or '-' (but not '+++', '---').
_FUNC_DEF_PATTERN = re.compile(
    r"^[+-]\s*"  # diff marker
    r"(?:[A-Za-z_][A-Za-z0-9_\s\*]+\s+)?"  # optional return type
    r"([A-Za-z_][A-Za-z0-9_]*)"  # function name
    r"\s*\("  # opening parenthesis
)


def _run_git(repo_path: str, args: list[str]) -> str:
    """Run a git command in the given repository and return stdout as text.

    On any error, returns an empty string.
    """
    if not repo_path or not os.path.isdir(repo_path):
        return ""
    try:
        completed = subprocess.run(
            ["git"] + args,
            cwd=repo_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except OSError:
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout or ""


def get_commit_time(repo_path: str, commit_id: str) -> str:
    """Get the commit timestamp in ISO-8601 format.

    Returns the author date of the commit as an ISO-8601 string.
    Returns empty string if the commit doesn't exist or on error.
    """
    if not commit_id:
        return ""
    # Use %aI to get author date in ISO-8601 format
    result = _run_git(repo_path, ["show", "-s", "--format=%aI", commit_id])
    return result.strip() if result else ""


def get_commit_diff(repo_path: str, commit_id: str) -> str:
    """Return the unified diff of a commit vs its first parent.

    We use `git show` with `--pretty=format:` to output only the diff.
    Using --unified=3 to get better context for function identification.
    """
    if not commit_id:
        return ""
    return _run_git(repo_path, ["show", "--pretty=format:", "--unified=3", commit_id])


def estimate_changed_functions_per_file(diff_text: str) -> Dict[str, int]:
    """Estimate how many *functions* are changed per file in a diff.

    This method first tries to use Git hunk headers (@@ lines) which provide
    accurate function context. If that yields no results (e.g., for non-C code
    or diffs without context), falls back to pattern matching on changed lines.

    Returns a mapping {file_path -> changed_function_count} where
    file_path is the path as it appears in the diff (e.g., `src/foo.c`).
    """
    # Primary method: parse hunk headers
    result = estimate_changed_functions_from_hunks(diff_text)
    
    # If no functions found, try legacy pattern matching as fallback
    if not result or sum(result.values()) == 0:
        result = estimate_changed_functions_per_file_legacy(diff_text)
    
    return result


def estimate_changed_functions_from_hunks(diff_text: str) -> Dict[str, int]:
    """Estimate changed functions by parsing @@ hunk headers.

    Git's unified diff format includes function context in hunk headers:
        @@ -690,8 +710,8 @@ static int cirrus_bitblt_videotovideo_patterncopy

    This method extracts function names from these headers, which is more
    accurate than pattern matching on changed lines, especially when only
    the function body (not signature) is modified.

    Returns a mapping {file_path -> changed_function_count}.
    """
    result: Dict[str, int] = {}
    current_file: str | None = None
    seen_funcs_per_file: Dict[str, set[str]] = {}

    # Match @@ lines with optional function context
    # Format: @@ -start,count +start,count @@ optional context
    hunk_header_pattern = re.compile(r'^@@ .* @@\s*(.*)$')
    # Extract function name from context (C-style)
    func_name_pattern = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')

    for line in diff_text.splitlines():
        if line.startswith("+++"):
            # Track current file
            parts = line.split()
            if len(parts) >= 2:
                path = parts[1]
                if path.startswith("a/") or path.startswith("b/"):
                    path = path[2:]
                current_file = path
                if current_file not in seen_funcs_per_file:
                    seen_funcs_per_file[current_file] = set()

        elif line.startswith("@@") and current_file:
            # Parse hunk header for function context
            m = hunk_header_pattern.match(line)
            if m:
                context = m.group(1).strip()
                if context:
                    # Try to extract function name from context
                    func_match = func_name_pattern.search(context)
                    if func_match:
                        func_name = func_match.group(1)
                        # Filter out common false positives (keywords)
                        if func_name not in ['if', 'for', 'while', 'switch', 'return']:
                            seen_funcs_per_file[current_file].add(func_name)

    for path, names in seen_funcs_per_file.items():
        result[path] = len(names)

    return result


def estimate_changed_functions_per_file_legacy(diff_text: str) -> Dict[str, int]:
    """Legacy method: Estimate functions by pattern matching on changed lines.

    This is a heuristic:
      - Track the current file from `+++ b/<path>` lines.
      - For each added/removed line starting with '+' or '-' (excluding
        `+++` / `---`), apply a simple C-like function definition regex.
      - Count unique function names per file.

    Note: This method only detects changes to function signatures, not
    changes within function bodies. Use estimate_changed_functions_from_hunks
    for better accuracy.

    Returns a mapping {file_path -> changed_function_count} where
    file_path is the path as it appears in the diff (e.g., `src/foo.c`).
    """
    result: Dict[str, int] = {}
    current_file: str | None = None
    seen_funcs_per_file: Dict[str, set[str]] = {}

    for line in diff_text.splitlines():
        if line.startswith("+++"):
            # Example: +++ b/src/foo.c
            parts = line.split()  # ["+++", "b/src/foo.c"]
            if len(parts) >= 2:
                path = parts[1]
                # Strip leading a/ or b/
                if path.startswith("a/") or path.startswith("b/"):
                    path = path[2:]
                current_file = path
                if current_file not in seen_funcs_per_file:
                    seen_funcs_per_file[current_file] = set()
            continue
        if line.startswith("---"):
            # old file header; ignore
            continue
        if not line.startswith("+") and not line.startswith("-"):
            continue
        # Skip diff metadata like +++, --- (already handled) or @@
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        if current_file is None:
            continue
        m = _FUNC_DEF_PATTERN.match(line)
        if not m:
            continue
        func_name = m.group(1)
        if not func_name:
            continue
        seen_funcs_per_file.setdefault(current_file, set()).add(func_name)

    for path, names in seen_funcs_per_file.items():
        result[path] = len(names)
    return result


def estimate_changed_functions_total(diff_text: str) -> int:
    """Estimate how many unique functions are changed in the given diff.

    This simply sums over `estimate_changed_functions_per_file`.
    """
    per_file = estimate_changed_functions_per_file(diff_text)
    return sum(per_file.values())


def get_changed_function_counts(
    repo_path: str,
    commit_id: str,
) -> Dict[str, int]:
    """High-level helper: return {file_path -> changed_function_count}.

    If anything fails (no repo, git error, etc.), returns an empty dict.
    """
    diff = get_commit_diff(repo_path, commit_id)
    if not diff:
        return {}
    return estimate_changed_functions_per_file(diff)


def get_total_changed_functions(repo_path: str, commit_id: str) -> int:
    """High-level helper: return total changed functions in a commit.

    If anything fails, returns 0.
    """
    diff = get_commit_diff(repo_path, commit_id)
    if not diff:
        return 0
    return estimate_changed_functions_total(diff)


def get_file_content_at_commit(repo_path: str, commit_id: str, file_path: str) -> str:
    """Get the content of a file at a specific commit.

    Args:
        repo_path: Path to the Git repository
        commit_id: Commit hash
        file_path: Relative path to the file in the repository

    Returns:
        File content as string, or empty string if the file doesn't exist or on error.
    """
    if not commit_id or not file_path:
        return ""
    return _run_git(repo_path, ["show", f"{commit_id}:{file_path}"])


def get_file_before_commit(repo_path: str, commit_id: str, file_path: str) -> str:
    """Get the content of a file before a commit (parent version).

    Args:
        repo_path: Path to the Git repository
        commit_id: Commit hash
        file_path: Relative path to the file in the repository

    Returns:
        File content before the commit, or empty string on error.
    """
    if not commit_id or not file_path:
        return ""
    return _run_git(repo_path, ["show", f"{commit_id}^:{file_path}"])


def reconstruct_function_before(
    repo_path: str,
    commit_id: str,
    func_after: str,
    func_name: str | None = None,
) -> str:
    """Attempt to reconstruct the before version of a function from Git diff.

    This implementation:
    1. Gets the full commit diff
    2. Parses all changed hunks to extract before/after line pairs
    3. Tries to match func_after with the reconstructed 'after' code
    4. Returns the corresponding 'before' code if match succeeds

    Args:
        repo_path: Path to the Git repository
        commit_id: Commit hash
        func_after: The function code after the commit (from dataset)
        func_name: Optional function name to help matching

    Returns:
        Reconstructed function before the commit, or empty string if reconstruction fails.
    """
    diff = get_commit_diff(repo_path, commit_id)
    if not diff:
        return ""

    # Parse the diff to extract file-level before/after versions
    files_before = {}  # file_path -> before content
    files_after = {}   # file_path -> after content
    
    current_file = None
    current_before_lines = []
    current_after_lines = []
    
    for line in diff.splitlines():
        if line.startswith("--- a/"):
            # Save previous file if any
            if current_file and (current_before_lines or current_after_lines):
                files_before[current_file] = "\n".join(current_before_lines)
                files_after[current_file] = "\n".join(current_after_lines)
            
            # Start new file
            current_file = line[6:]  # Remove "--- a/"
            current_before_lines = []
            current_after_lines = []
            
        elif line.startswith("+++ b/"):
            # Confirm file path
            file_path = line[6:]  # Remove "+++ b/"
            if current_file is None:
                current_file = file_path
                
        elif line.startswith("@@"):
            # New hunk - just continue collecting lines
            continue
            
        elif current_file is not None:
            if line.startswith("-") and not line.startswith("---"):
                # Line in before version
                current_before_lines.append(line[1:])
            elif line.startswith("+") and not line.startswith("+++"):
                # Line in after version
                current_after_lines.append(line[1:])
            elif line.startswith(" "):
                # Context line (in both versions)
                current_before_lines.append(line[1:])
                current_after_lines.append(line[1:])
    
    # Save last file
    if current_file and (current_before_lines or current_after_lines):
        files_before[current_file] = "\n".join(current_before_lines)
        files_after[current_file] = "\n".join(current_after_lines)
    
    # Now try to match func_after against the after versions
    func_after_normalized = func_after.strip().replace(" ", "").replace("\t", "").replace("\n", "").replace("\r", "")
    
    if not func_after_normalized:
        return ""
    
    best_match_file = None
    best_match_score = 0.0
    
    for file_path, after_content in files_after.items():
        # Try to find func_after in this file's after content
        after_normalized = after_content.strip().replace(" ", "").replace("\t", "").replace("\n", "").replace("\r", "")
        
        if not after_normalized:
            continue
            
        # Check if func_after is a substring or very similar
        if func_after_normalized in after_normalized:
            # Perfect substring match
            best_match_file = file_path
            best_match_score = 1.0
            break
        
        # Calculate similarity (character-level intersection)
        common_len = 0
        min_len = min(len(func_after_normalized), len(after_normalized))
        
        # Sliding window approach to find best alignment
        for offset in range(-min(1000, len(after_normalized)), min(1000, len(func_after_normalized))):
            match_count = 0
            for i in range(min_len):
                j = i + offset
                if 0 <= j < len(after_normalized) and i < len(func_after_normalized):
                    if func_after_normalized[i] == after_normalized[j]:
                        match_count += 1
            
            if match_count > common_len:
                common_len = match_count
        
        similarity = common_len / max(len(func_after_normalized), len(after_normalized), 1)
        
        if similarity > best_match_score:
            best_match_score = similarity
            best_match_file = file_path
    
    # If we found a good match (>50% similarity), return the before version
    if best_match_file and best_match_score > 0.5:
        before_content = files_before.get(best_match_file, "")
        
        # Try to extract just the function from before_content if func_name is provided
        if func_name and before_content:
            # Simple heuristic: look for function definition with func_name
            lines = before_content.split("\n")
            func_start = -1
            
            for i, line in enumerate(lines):
                if func_name in line and "(" in line:
                    # Potential function definition
                    func_start = i
                    break
            
            if func_start >= 0:
                # Try to extract the function by counting braces
                brace_count = 0
                func_lines = []
                in_function = False
                
                for i in range(func_start, len(lines)):
                    line = lines[i]
                    func_lines.append(line)
                    
                    # Count braces
                    for char in line:
                        if char == "{":
                            brace_count += 1
                            in_function = True
                        elif char == "}":
                            brace_count -= 1
                            if in_function and brace_count == 0:
                                # End of function
                                return "\n".join(func_lines)
                
                # If we collected something, return it
                if func_lines:
                    return "\n".join(func_lines)
        
        # Return the whole before content if we can't extract just the function
        return before_content
    
    return ""

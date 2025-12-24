"""
Match functions between raw_code and patch to identify vulnerable functions.
"""

import re
from typing import List, Set, Dict, Optional


def extract_function_names_from_code(code: str) -> Dict[str, str]:
    """
    Extract function names and their full definitions from source code.
    
    Returns:
        Dict mapping function_name -> function_code
    """
    functions = {}
    
    # Keywords to exclude
    keywords = {'if', 'for', 'while', 'switch', 'return', 'case', 'default',
                'template', 'typename', 'struct', 'class', 'enum', 'union',
                'const', 'static', 'inline', 'virtual', 'explicit', 'operator',
                'namespace', 'using', 'typedef', 'sizeof', 'delete', 'new'}
    
    # Pattern for C/C++ function definitions
    # Matches: return_type function_name(...) { ... }
    func_pattern = re.compile(
        r'(?:^|\n)'  # Start of line
        r'(?:[\w\s\*&:<>,]+\s+)?'  # Return type (optional for constructors)
        r'([\w:]+(?:<[^>]+>)?::\w+|\w+)'  # Function name (Class::method or function)
        r'\s*\([^)]*\)'  # Parameters
        r'(?:\s+const)?'  # Optional const
        r'\s*\{',  # Opening brace
        re.MULTILINE
    )
    
    for match in func_pattern.finditer(code):
        func_name = match.group(1)
        # Extract just the method name if qualified
        if '::' in func_name:
            func_name = func_name.split('::')[-1]
        
        # Skip keywords
        if func_name.lower() in keywords:
            continue
        
        # Try to extract the full function body
        start_pos = match.start()
        # Find matching closing brace (simplified - may not handle nested braces perfectly)
        brace_count = 0
        end_pos = match.end()
        for i, char in enumerate(code[match.end():], match.end()):
            if char == '{':
                brace_count += 1
            elif char == '}':
                if brace_count == 0:
                    end_pos = i + 1
                    break
                brace_count -= 1
        
        func_code = code[start_pos:end_pos]
        functions[func_name] = func_code
    
    return functions


def extract_changed_function_names_from_patch(patch: str) -> Set[str]:
    """
    Extract function names that are modified in a patch.
    
    Uses two methods:
    1. From @@ hunk headers (function context)
    2. From function definitions in added/removed lines
    
    Returns:
        Set of function names
    """
    changed_funcs = set()
    
    # Method 1: Extract from @@ lines
    hunk_pattern = re.compile(r'^@@ .* @@\s*(.*)$', re.MULTILINE)
    for match in hunk_pattern.finditer(patch):
        context = match.group(1).strip()
        if context:
            # Try to extract function name from context
            func_match = re.search(r'([\w:]+)\s*\(', context)
            if func_match:
                func_name = func_match.group(1)
                if '::' in func_name:
                    func_name = func_name.split('::')[-1]
                # Filter keywords
                if func_name not in ['if', 'for', 'while', 'switch', 'return', 
                                     'case', 'const', 'static', 'inline']:
                    changed_funcs.add(func_name)
    
    # Method 2: Extract from function definitions in diff lines
    # Remove outer wrapper if exists (patch of patch format)
    if '\n+diff --git ' in patch or '\n+--- ' in patch:
        lines = []
        for line in patch.splitlines():
            if line.startswith('+') and not line.startswith('+++'):
                lines.append(line[1:])
            else:
                lines.append(line)
        patch = '\n'.join(lines)
    
    # Look for function definitions in added/removed lines
    func_def_pattern = re.compile(
        r'^[+-]\s*'  # Added or removed line
        r'(?:template\s*<[^>]+>\s*)?'
        r'(?:virtual\s+|static\s+|inline\s+|explicit\s+|const\s+|constexpr\s+)*'
        r'[\w:<>,\s\*&]+\s+'
        r'([\w:]+(?:<[^>]+>)?::\w+|\w+)'
        r'\s*\(',
        re.MULTILINE
    )
    
    for match in func_def_pattern.finditer(patch):
        func_name = match.group(1)
        if '::' in func_name:
            func_name = func_name.split('::')[-1]
        if func_name not in ['if', 'for', 'while', 'switch', 'return',
                             'case', 'const', 'static', 'inline', 'template']:
            changed_funcs.add(func_name)
    
    return changed_funcs


def match_vulnerable_functions(raw_code: str, patch: str, cve_id: str) -> Dict:
    """
    Match functions between raw_code and patch to identify vulnerable code.
    
    Args:
        raw_code: Complete source code containing vulnerable function(s)
        patch: Diff showing the fix
        cve_id: CVE identifier for context
    
    Returns:
        Dict with:
        - changed_functions: List of function names changed in patch
        - matched_functions: List of function names found in both patch and raw_code
        - changed_functions_total: Total number of changed functions
        - vulnerable_code: The specific vulnerable function code (if ONEFUNC)
        - label: 'vulnerable' if ONEFUNC matched, else None
    """
    result = {
        'changed_functions': [],
        'matched_functions': [],
        'changed_functions_total': 0,
        'vulnerable_code': None,
        'label': None,
        'labeling_method': None
    }
    
    # Extract functions from raw_code
    code_functions = extract_function_names_from_code(raw_code)
    
    # Extract changed functions from patch
    changed_funcs = extract_changed_function_names_from_patch(patch)
    result['changed_functions'] = sorted(list(changed_funcs))
    result['changed_functions_total'] = len(changed_funcs)
    
    # Find matches: functions that appear in both patch and raw_code
    matched = []
    for func_name in changed_funcs:
        if func_name in code_functions:
            matched.append(func_name)
    
    result['matched_functions'] = sorted(matched)
    
    # Apply ONEFUNC rule (PrimeVul paper): 
    # A function is vulnerable if it's the ONLY function changed by the commit
    # 论文原文: "regards a function as vulnerable if it's the only function
    # changed by a security-related commit"
    if len(changed_funcs) == 1:
        # Only 1 function was changed in the patch
        if len(matched) == 1:
            # And it was found in raw_code
            result['label'] = 'vulnerable'
            result['labeling_method'] = 'onefunc'
            result['vulnerable_code'] = code_functions[matched[0]]
        else:
            # Changed 1 function but not found in raw_code
            result['labeling_method'] = 'onefunc_unmatched'
    
    return result


def apply_function_matching_labeling(df, raw_code_column='raw_code', 
                                     patch_column='patch', cve_column='cve_id'):
    """
    Apply function matching and ONEFUNC labeling to dataframe.
    
    This is the correct implementation that matches functions between
    raw_code (vulnerable code) and patch (fix).
    
    Args:
        df: DataFrame with raw_code, patch, cve_id columns
        raw_code_column: Name of column containing vulnerable code
        patch_column: Name of column containing fix patch
        cve_column: Name of column containing CVE ID
    
    Returns:
        DataFrame with added columns:
        - changed_functions: JSON string of function names in patch
        - matched_functions: JSON string of matched function names
        - changed_functions_total: Count of changed functions
        - vulnerable_code: Extracted vulnerable function code
        - label: 'vulnerable' or None
        - labeling_method: Method used for labeling
    """
    import pandas as pd
    import json
    
    # Validate columns
    required = [raw_code_column, patch_column, cve_column]
    missing = [col for col in required if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")
    
    results = []
    
    for idx, row in df.iterrows():
        raw_code = str(row[raw_code_column]) if pd.notna(row[raw_code_column]) else ""
        patch = str(row[patch_column]) if pd.notna(row[patch_column]) else ""
        cve_id = str(row[cve_column]) if pd.notna(row[cve_column]) else ""
        
        if not raw_code or not patch:
            # No code or patch to analyze
            results.append({
                'changed_functions': '[]',
                'matched_functions': '[]',
                'changed_functions_total': 0,
                'vulnerable_code': None,
                'label': None,
                'labeling_method': None
            })
            continue
        
        match_result = match_vulnerable_functions(raw_code, patch, cve_id)
        
        # Convert lists to JSON strings for storage
        results.append({
            'changed_functions': json.dumps(match_result['changed_functions']),
            'matched_functions': json.dumps(match_result['matched_functions']),
            'changed_functions_total': match_result['changed_functions_total'],
            'vulnerable_code': match_result['vulnerable_code'],
            'label': match_result['label'],
            'labeling_method': match_result['labeling_method']
        })
    
    # Add columns to dataframe
    result_df = pd.DataFrame(results)
    for col in result_df.columns:
        df[col] = result_df[col]
    
    return df

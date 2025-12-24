#!/usr/bin/env python3
"""
Complete PrimeVul-style pipeline for query_C++.jsonl dataset.
Implements: dedup → ONEFUNC → NVDCheck → temporal split → paired subset
"""

import os
import sys
import json
import hashlib
import pandas as pd
from pathlib import Path
import re

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import NVD_DATA_PATH, SPLIT_CONFIG, OUTPUT_DIR
from src.code_function_matcher import apply_function_matching_labeling
from src.primevul_nvdcheck import apply_nvdcheck_labeling


def load_jsonl_with_details(filepath):
    """Load JSONL file and flatten details array per CVE record."""
    records = []
    
    with open(filepath, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            try:
                cve_record = json.loads(line.strip())
                cve_id = cve_record.get('cve_id', f'UNKNOWN_{line_num}')
                index = cve_record.get('index', line_num)
                language = cve_record.get('language', 'C++')
                cvss = cve_record.get('cvss')
                origin_message = cve_record.get('origin_message', '')
                url = cve_record.get('html_url', '')
                
                # Flatten details array (each detail becomes a separate record)
                for detail_idx, detail in enumerate(cve_record.get('details', [])):
                    records.append({
                        'source_id': f"{index}_{detail_idx}",
                        'cve_id': cve_id,
                        'file_index': detail_idx,
                        'language': language,
                        'cvss': cvss,
                        'origin_message': origin_message,
                        'url': url,
                        'raw_url': detail.get('raw_url', ''),
                        'raw_code': detail.get('raw_code', ''),
                        'patch': detail.get('patch', '')
                    })
            except json.JSONDecodeError as e:
                print(f"Warning: Failed to parse line {line_num}: {e}")
                continue
    
    print(f"Loaded {len(records)} detail records from {filepath}")
    return pd.DataFrame(records)


def deduplicate_by_code_hash(df):
    """
    Remove duplicate code blocks using MD5 hash of normalized content.
    Normalize by removing all whitespace before hashing.
    """
    print(f"\\n=== Deduplication ===")
    print(f"Records before dedup: {len(df)}")
    
    def normalize_code(code_str):
        """Remove all whitespace for consistent hashing."""
        if pd.isna(code_str) or not code_str:
            return ""
        return re.sub(r'\s+', '', str(code_str))
    
    def compute_md5(text):
        """Compute MD5 hash of text."""
        if not text:
            return None
        return hashlib.md5(text.encode('utf-8')).hexdigest()
    
    # Use raw_code for deduplication (the actual vulnerable code)
    df['normalized_code'] = df['raw_code'].apply(normalize_code)
    df['code_hash'] = df['normalized_code'].apply(compute_md5)
    
    # Keep first occurrence of each hash
    df_dedup = df.drop_duplicates(subset='code_hash', keep='first')
    
    print(f"Records after dedup: {len(df_dedup)}")
    print(f"Duplicates removed: {len(df) - len(df_dedup)}")
    
    # Drop temporary columns
    df_dedup = df_dedup.drop(columns=['normalized_code', 'code_hash'])
    
    return df_dedup


def apply_temporal_split(df):
    """
    Apply temporal split based on CVE year extracted from CVE ID.
    PrimeVul uses commit time; we use CVE year as proxy for temporal ordering.
    """
    print(f"\\n=== Temporal Split ===")
    
    def extract_cve_year(cve_id):
        """Extract year from CVE ID like CVE-2022-47015 → 2022."""
        match = re.match(r'CVE-(\d{4})-\d+', cve_id)
        if match:
            return int(match.group(1))
        return 9999  # Unknown CVEs go to end
    
    df['cve_year'] = df['cve_id'].apply(extract_cve_year)
    
    # Sort by year for temporal order
    df_sorted = df.sort_values('cve_year').reset_index(drop=True)
    
    # Get split ratios from config (default 80/10/10)
    train_ratio = SPLIT_CONFIG.get('train_ratio', 0.8)
    dev_ratio = SPLIT_CONFIG.get('dev_ratio', 0.1)
    
    total = len(df_sorted)
    train_end = int(total * train_ratio)
    dev_end = train_end + int(total * dev_ratio)
    
    # Assign splits
    df_sorted['split'] = 'test'
    df_sorted.loc[:train_end-1, 'split'] = 'train'
    df_sorted.loc[train_end:dev_end-1, 'split'] = 'dev'
    
    print(f"Train: {len(df_sorted[df_sorted['split']=='train'])} samples")
    print(f"Dev: {len(df_sorted[df_sorted['split']=='dev'])} samples")
    print(f"Test: {len(df_sorted[df_sorted['split']=='test'])} samples")
    print(f"Year range: {df_sorted['cve_year'].min()} - {df_sorted['cve_year'].max()}")
    
    return df_sorted


def generate_paired_subset(df):
    """
    Generate paired function subset for contrastive learning.
    Match vulnerable functions with similar benign code based on simple string similarity.
    """
    print(f"\\n=== Paired Function Generation ===")
    
    # Filter to labeled vulnerable samples only
    vulnerable = df[df['label'] == 'vulnerable'].copy()
    print(f"Vulnerable samples: {len(vulnerable)}")
    
    # For query_C++.jsonl, we don't have explicit benign samples
    # This is a limitation - PrimeVul requires both vulnerable and benign code
    # We can only create a reduced vulnerable-only subset for now
    
    print("Note: No benign samples available in query_C++.jsonl dataset")
    print("Cannot create true paired subset without benign code")
    print("Returning vulnerable-only subset instead")
    
    # Return vulnerable samples as "paired" subset (placeholder)
    paired = vulnerable.copy()
    paired['pair_type'] = 'vulnerable_only'
    
    return paired


def run_query_cpp_pipeline(input_jsonl, output_dir):
    """
    Execute complete PrimeVul-style processing pipeline.
    
    Steps:
    1. Load JSONL and flatten details array
    2. Deduplicate by code hash
    3. Apply ONEFUNC labeling (patch-based)
    4. Apply NVDCheck labeling (CVE description matching) - if NVD data available
    5. Temporal split by CVE year
    6. Generate paired subset (limited without benign samples)
    7. Save all outputs
    """
    print(f"\\n{'='*60}")
    print(f"query_C++.jsonl Pipeline - PrimeVul Style")
    print(f"{'='*60}")
    
    # Step 1: Load data
    print(f"\\nLoading {input_jsonl}...")
    df = load_jsonl_with_details(input_jsonl)
    
    if df.empty:
        print("Error: No records loaded")
        return 1
    
    # Step 2: Deduplicate
    df = deduplicate_by_code_hash(df)
    
    # Step 3: Function Matching and ONEFUNC labeling
    print(f"\n=== Function Matching & ONEFUNC Labeling ===")
    print("Matching functions between raw_code and patch...")
    try:
        df = apply_function_matching_labeling(
            df, 
            raw_code_column='raw_code',
            patch_column='patch', 
            cve_column='cve_id'
        )
        vulnerable_count = len(df[df['label']=='vulnerable'])
        print(f"ONEFUNC matched: {vulnerable_count} vulnerable samples")
        
        # Statistics
        total_changed = df['changed_functions_total'].sum()
        total_matched = df['matched_functions'].apply(
            lambda x: len(json.loads(x)) if pd.notna(x) and x else 0
        ).sum()
        print(f"Total functions changed in patches: {int(total_changed)}")
        print(f"Total functions matched in raw_code: {int(total_matched)}")
        
    except Exception as e:
        print(f"Warning: Function matching failed: {e}")
        import traceback
        traceback.print_exc()
        # Add placeholder columns if matching fails
        df['changed_functions'] = '[]'
        df['matched_functions'] = '[]'
        df['changed_functions_total'] = 0
        df['vulnerable_code'] = None
        df['vulnerable_code'] = None
        df['label'] = None
        df['labeling_method'] = None
    
    # Step 4: NVDCheck labeling (补充标注)
    print(f"\n=== NVDCheck Labeling ===")
    if NVD_DATA_PATH and os.path.exists(NVD_DATA_PATH):
        print(f"Loading NVD data from: {NVD_DATA_PATH}")
        try:
            # NVDCheck 需要特定列名，创建临时映射
            nvd_df = df.copy()
            nvd_df['func_after'] = nvd_df['raw_code']  # 使用 raw_code 作为函数代码
            nvd_df['commit_id'] = nvd_df['source_id']  # 使用 source_id 作为标识
            
            # Apply NVDCheck
            nvd_df = apply_nvdcheck_labeling(nvd_df, nvd_path=NVD_DATA_PATH)
            
            # 合并 NVDCheck 结果（只更新未标记的样本）
            for idx in df.index:
                if pd.isna(df.loc[idx, 'label']) or df.loc[idx, 'label'] != 'vulnerable':
                    if nvd_df.loc[idx, 'label'] == 'vulnerable':
                        df.loc[idx, 'label'] = 'vulnerable'
                        df.loc[idx, 'labeling_method'] = nvd_df.loc[idx, 'labeling_method']
            
            nvd_vulnerable = len(df[df['labeling_method'].str.contains('nvdcheck', na=False)])
            print(f"NVDCheck added: {nvd_vulnerable} vulnerable samples")
        except Exception as e:
            print(f"Warning: NVDCheck labeling failed: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("NVD data not configured, skipping NVDCheck")
    
    # Step 5: Temporal split
    df = apply_temporal_split(df)
    
    # Step 6: Generate paired subset
    paired_df = generate_paired_subset(df)
    
    # Step 7: Save outputs
    print(f"\\n=== Saving Outputs ===")
    os.makedirs(output_dir, exist_ok=True)
    
    # Save full dataset
    all_output = os.path.join(output_dir, 'query_cpp_all.csv')
    df.to_csv(all_output, index=False)
    print(f"Saved full dataset: {all_output} ({len(df)} records)")
    
    # Save train/dev/test splits
    for split_name in ['train', 'dev', 'test']:
        split_df = df[df['split'] == split_name]
        split_output = os.path.join(output_dir, f'query_cpp_{split_name}.csv')
        split_df.to_csv(split_output, index=False)
        print(f"Saved {split_name} split: {split_output} ({len(split_df)} records)")
    
    # Save paired subset
    paired_output = os.path.join(output_dir, 'query_cpp_paired.csv')
    paired_df.to_csv(paired_output, index=False)
    print(f"Saved paired subset: {paired_output} ({len(paired_df)} records)")
    
    # Print summary statistics
    print(f"\\n{'='*60}")
    print(f"Pipeline Complete - Summary")
    print(f"{'='*60}")
    print(f"Total records processed: {len(df)}")
    print(f"Vulnerable samples (ONEFUNC): {len(df[df['label']=='vulnerable'])}")
    print(f"Train/Dev/Test: {len(df[df['split']=='train'])}/{len(df[df['split']=='dev'])}/{len(df[df['split']=='test'])}")
    print(f"Outputs saved to: {output_dir}")
    
    return 0


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Process query_C++.jsonl with PrimeVul pipeline')
    parser.add_argument(
        '--input',
        default='data/raw/query_C++.jsonl',
        help='Input JSONL file path (default: data/raw/query_C++.jsonl)'
    )
    parser.add_argument(
        '--output',
        default=OUTPUT_DIR,
        help=f'Output directory (default: {OUTPUT_DIR})'
    )
    
    args = parser.parse_args()
    
    # Resolve relative paths from project root
    project_root = Path(__file__).parent.parent
    input_path = project_root / args.input
    output_path = project_root / args.output
    
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)
    
    sys.exit(run_query_cpp_pipeline(str(input_path), str(output_path)))

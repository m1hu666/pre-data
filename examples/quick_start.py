# -*- coding: gbk -*-

"""
快速开始示例：从头构建一个小型 PrimeVul 数据集
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import pandas as pd
import json
from datetime import datetime, timedelta

from src.deduplication import deduplicate_dataset
from src.labeling_onefunc import apply_onefunc_labeling
from src.labeling_nvdcheck import apply_nvdcheck_labeling
from src.temporal_split import temporal_split
from src.paired_functions import build_paired_dataset, split_paired_dataset


def create_sample_data():
    """
    创建示例数据用于演示
    """
    # 模拟一些安全相关的 commits
    base_time = datetime(2020, 1, 1)
    
    sample_data = []
    
    # Commit 1: 单函数修改 (应被 OneFunc 标注为 vulnerable)
    sample_data.append({
        'commit_id': 'c001',
        'func_before': 'int authenticate(char *password) { if(strcmp(password, "admin") == 0) return 1; return 0; }',
        'func_after': 'int authenticate(char *password) { /* vulnerable: hardcoded password */ if(strcmp(password, "admin") == 0) return 1; return 0; }',
        'is_security_related': True,
        'cve_id': 'CVE-2020-0001',
        'commit_time': base_time + timedelta(days=10),
        'file_path': 'src/auth.c',
        'func_name': 'authenticate'
    })
    
    # Commit 1 的修复版本
    sample_data.append({
        'commit_id': 'c002',
        'func_before': 'int authenticate(char *password) { /* vulnerable: hardcoded password */ if(strcmp(password, "admin") == 0) return 1; return 0; }',
        'func_after': 'int authenticate(char *password) { /* fixed: use secure password check */ return secure_password_check(password); }',
        'is_security_related': False,
        'cve_id': '',
        'commit_time': base_time + timedelta(days=20),
        'file_path': 'src/auth.c',
        'func_name': 'authenticate'
    })
    
    # Commit 2: 多函数修改 (应被 NVDCheck 处理)
    sample_data.append({
        'commit_id': 'c003',
        'func_before': 'void process_input(char *buf) { strcpy(buffer, buf); }',
        'func_after': 'void process_input(char *buf) { /* vulnerable: buffer overflow */ strcpy(buffer, buf); }',
        'is_security_related': True,
        'cve_id': 'CVE-2020-0002',
        'commit_time': base_time + timedelta(days=30),
        'file_path': 'src/input.c',
        'func_name': 'process_input'
    })
    
    sample_data.append({
        'commit_id': 'c003',
        'func_before': 'void validate_input(char *buf) { return; }',
        'func_after': 'void validate_input(char *buf) { /* validation */ check_length(buf); }',
        'is_security_related': True,
        'cve_id': 'CVE-2020-0002',
        'commit_time': base_time + timedelta(days=30),
        'file_path': 'src/input.c',
        'func_name': 'validate_input'
    })
    
    # 添加一些 benign 样本
    for i in range(5):
        sample_data.append({
            'commit_id': f'c{100+i}',
            'func_before': f'int func_{i}(int x) {{ return x * {i}; }}',
            'func_after': f'int func_{i}(int x) {{ return x * {i+1}; }}',
            'is_security_related': False,
            'cve_id': '',
            'commit_time': base_time + timedelta(days=40 + i*5),
            'file_path': f'src/utils{i}.c',
            'func_name': f'func_{i}'
        })
    
    return pd.DataFrame(sample_data)


def run_quick_start():
    """
    运行快速开始示例
    """
    print("=" * 80)
    print("PrimeVul 快速开始示例")
    print("=" * 80)
    
    # 创建示例数据
    print("\n1. 创建示例数据...")
    data = create_sample_data()
    print(f"   创建了 {len(data)} 条记录")
    
    # 去重
    print("\n2. 数据去重...")
    deduplicated_data, dedup_stats = deduplicate_dataset(data, has_before_after=True)
    print(f"   去重后: {len(deduplicated_data)} 条")
    
    # OneFunc 标注
    print("\n3. OneFunc 标注...")
    labeled_data, onefunc_stats = apply_onefunc_labeling(deduplicated_data)
    print(f"   OneFunc 标注: {onefunc_stats['onefunc_labeled']} 个 vulnerable")
    
    # NVDCheck 标注（创建模拟 NVD 数据）
    print("\n4. NVDCheck 标注...")
    
    # 创建临时 NVD 数据
    nvd_data = {
        'CVE-2020-0001': {
            'description': 'Hardcoded password in authenticate function allows unauthorized access'
        },
        'CVE-2020-0002': {
            'description': 'Buffer overflow vulnerability in input.c file'
        }
    }
    
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(nvd_data, f)
        nvd_path = f.name
    
    try:
        labeled_data, nvdcheck_stats = apply_nvdcheck_labeling(labeled_data, nvd_path)
        print(f"   NVDCheck 标注: {nvdcheck_stats['nvdcheck_labeled']} 个 vulnerable")
    finally:
        os.unlink(nvd_path)
    
    # 过滤未标注的数据
    labeled_data = labeled_data[labeled_data['label'].notna()].copy()
    
    # 时间划分
    print("\n5. 时间划分...")
    train_data, dev_data, test_data, split_stats = temporal_split(
        labeled_data, train_ratio=0.6, dev_ratio=0.2, test_ratio=0.2
    )
    
    # 构建成对数据
    print("\n6. 构建成对函数...")
    all_data = pd.concat([train_data, dev_data, test_data], ignore_index=True)
    paired_data, paired_stats = build_paired_dataset(all_data, min_similarity=0.5)
    print(f"   成功配对: {paired_stats['paired_count']} 对")
    
    # 显示结果
    print("\n" + "=" * 80)
    print("结果摘要")
    print("=" * 80)
    
    print(f"\n数据集划分:")
    print(f"  训练集: {len(train_data)} 样本")
    print(f"  验证集: {len(dev_data)} 样本")
    print(f"  测试集: {len(test_data)} 样本")
    
    print(f"\n标签分布:")
    print(f"  Vulnerable: {(labeled_data['label'] == 'vulnerable').sum()}")
    print(f"  Benign: {(labeled_data['label'] == 'benign').sum()}")
    
    print(f"\n成对数据: {len(paired_data)} 对")
    
    # 显示一些示例
    print("\n" + "=" * 80)
    print("示例数据")
    print("=" * 80)
    
    print("\nVulnerable 函数示例:")
    vuln_sample = labeled_data[labeled_data['label'] == 'vulnerable'].iloc[0]
    print(f"  Commit: {vuln_sample['commit_id']}")
    print(f"  CVE: {vuln_sample['cve_id']}")
    print(f"  标注方法: {vuln_sample['labeling_method']}")
    print(f"  代码预览: {vuln_sample['func_after'][:100]}...")
    
    if len(paired_data) > 0:
        print("\n函数对示例:")
        pair_sample = paired_data.iloc[0]
        print(f"  相似度: {pair_sample['similarity']:.3f}")
        print(f"  Vuln Commit: {pair_sample['vuln_commit_id']}")
        print(f"  Patch Commit: {pair_sample['patch_commit_id']}")
    
    print("\n" + "=" * 80)
    print("快速开始示例完成！")
    print("=" * 80)


if __name__ == '__main__':
    run_quick_start()

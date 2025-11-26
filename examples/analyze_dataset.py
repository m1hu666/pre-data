# -*- coding: gbk -*-

"""
数据集分析示例脚本
演示如何分析和可视化 PrimeVul 数据集
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import pandas as pd
import json
from src.utils import (
    print_dataset_statistics,
    validate_dataset,
    print_validation_results,
    visualize_dataset_distribution
)
from config import OUTPUT_FILES


def analyze_dataset():
    """
    分析 PrimeVul 数据集
    """
    print("=" * 80)
    print("PrimeVul 数据集分析")
    print("=" * 80)
    
    # 加载统计信息
    if os.path.exists(OUTPUT_FILES['statistics']):
        with open(OUTPUT_FILES['statistics'], 'r') as f:
            stats = json.load(f)
        
        print_dataset_statistics(stats)
    else:
        print("统计文件不存在，跳过统计信息打印")
    
    # 加载并验证各个数据集
    datasets = {
        'train_all': OUTPUT_FILES['train_all'],
        'dev_all': OUTPUT_FILES['dev_all'],
        'test_all': OUTPUT_FILES['test_all'],
    }
    
    loaded_datasets = {}
    
    for name, filepath in datasets.items():
        if os.path.exists(filepath):
            print(f"\n加载 {name}...")
            df = pd.read_csv(filepath)
            loaded_datasets[name] = df
            
            # 验证数据集
            validation_result = validate_dataset(df)
            print_validation_results(validation_result)
        else:
            print(f"\n{name} 不存在: {filepath}")
    
    # 可视化数据分布
    if all(k in loaded_datasets for k in ['train_all', 'dev_all', 'test_all']):
        print("\n生成数据分布可视化...")
        output_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'output')
        viz_path = os.path.join(output_dir, 'dataset_distribution.png')
        
        try:
            visualize_dataset_distribution(
                loaded_datasets['train_all'],
                loaded_datasets['dev_all'],
                loaded_datasets['test_all'],
                output_path=viz_path
            )
        except Exception as e:
            print(f"可视化失败: {e}")
            print("(提示: 需要安装 matplotlib 和 seaborn)")
    
    # 分析代码长度分布
    print("\n" + "=" * 80)
    print("代码长度分析")
    print("=" * 80)
    
    for name, df in loaded_datasets.items():
        if 'func_after' in df.columns:
            df['code_length'] = df['func_after'].astype(str).str.len()
            
            print(f"\n{name}:")
            print(f"  平均长度: {df['code_length'].mean():.0f} 字符")
            print(f"  中位数: {df['code_length'].median():.0f} 字符")
            print(f"  最小: {df['code_length'].min()}")
            print(f"  最大: {df['code_length'].max()}")
    
    # 分析标签分布
    print("\n" + "=" * 80)
    print("标签分布分析")
    print("=" * 80)
    
    for name, df in loaded_datasets.items():
        if 'label' in df.columns:
            label_dist = df['label'].value_counts()
            vuln_ratio = label_dist.get('vulnerable', 0) / len(df) * 100
            
            print(f"\n{name}:")
            print(f"  Vulnerable: {label_dist.get('vulnerable', 0):,} ({vuln_ratio:.2f}%)")
            print(f"  Benign: {label_dist.get('benign', 0):,} ({100-vuln_ratio:.2f}%)")
    
    # 分析成对数据集
    print("\n" + "=" * 80)
    print("成对数据集分析")
    print("=" * 80)
    
    paired_datasets = {
        'train_paired': OUTPUT_FILES['train_paired'],
        'dev_paired': OUTPUT_FILES['dev_paired'],
        'test_paired': OUTPUT_FILES['test_paired'],
    }
    
    for name, filepath in paired_datasets.items():
        if os.path.exists(filepath):
            df = pd.read_csv(filepath)
            
            print(f"\n{name}:")
            print(f"  函数对数量: {len(df):,}")
            
            if 'similarity' in df.columns:
                print(f"  平均相似度: {df['similarity'].mean():.3f}")
                print(f"  相似度范围: [{df['similarity'].min():.3f}, {df['similarity'].max():.3f}]")
    
    print("\n" + "=" * 80)
    print("分析完成！")
    print("=" * 80)


if __name__ == '__main__':
    analyze_dataset()

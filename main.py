"""
PrimeVul 数据集构建主流程
"""
import os
import sys
import json
import pandas as pd
from datetime import datetime

# 添加项目根目录到路径
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from config import *
from src.data_loader import DataLoader, load_nvd_data
from src.deduplication import deduplicate_dataset
from src.labeling_onefunc import apply_onefunc_labeling
from src.labeling_nvdcheck import apply_nvdcheck_labeling
from src.temporal_split import temporal_split
from src.paired_functions import build_paired_dataset, split_paired_dataset


def main():
    """
    PrimeVul 数据集构建主流程
    """
    print("=" * 80)
    print("PrimeVul 数据集构建流程")
    print("=" * 80)
    print(f"开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # 用于收集所有统计信息
    all_stats = {}
    
    # ========================================================================
    # 步骤 1: 数据加载与合并
    # ========================================================================
    print("\n" + "=" * 80)
    print("步骤 1/6: 数据加载与合并")
    print("=" * 80)
    
    loader = DataLoader(DATA_SOURCES)
    merged_data = loader.merge_all()
    
    if len(merged_data) == 0:
        print("错误: 没有加载到任何数据，请检查数据源配置")
        return
    
    all_stats['initial_count'] = len(merged_data)
    all_stats['initial_commits'] = merged_data['commit_id'].nunique()
    
    # ========================================================================
    # 步骤 2: 数据去重
    # ========================================================================
    print("\n" + "=" * 80)
    print("步骤 2/6: 数据去重")
    print("=" * 80)
    
    deduplicated_data, dedup_stats = deduplicate_dataset(merged_data, has_before_after=True)
    all_stats.update(dedup_stats)
    
    # ========================================================================
    # 步骤 3: 数据标注 - OneFunc
    # ========================================================================
    print("\n" + "=" * 80)
    print("步骤 3/6: 数据标注 - OneFunc")
    print("=" * 80)
    
    if LABELING_CONFIG['onefunc_enabled']:
        labeled_data, onefunc_stats = apply_onefunc_labeling(deduplicated_data)
        all_stats.update(onefunc_stats)
    else:
        print("OneFunc 标注已禁用，跳过")
        labeled_data = deduplicated_data.copy()
        labeled_data['label'] = None
        labeled_data['labeling_method'] = None
    
    # ========================================================================
    # 步骤 4: 数据标注 - NVDCheck
    # ========================================================================
    print("\n" + "=" * 80)
    print("步骤 4/6: 数据标注 - NVDCheck")
    print("=" * 80)
    
    if LABELING_CONFIG['nvdcheck_enabled']:
        nvd_data_path = NVD_DATA_PATH if os.path.exists(NVD_DATA_PATH) else None
        labeled_data, nvdcheck_stats = apply_nvdcheck_labeling(labeled_data, nvd_data_path)
        all_stats.update(nvdcheck_stats)
    else:
        print("NVDCheck 标注已禁用，跳过")
    
    # 过滤掉未被标注的数据（label 为 None 的）
    labeled_data = labeled_data[labeled_data['label'].notna()].copy()
    
    print(f"\n标注完成后剩余: {len(labeled_data)} 条")
    print(f"  - Vulnerable: {(labeled_data['label'] == 'vulnerable').sum()}")
    print(f"  - Benign: {(labeled_data['label'] == 'benign').sum()}")
    
    all_stats['labeled_count'] = len(labeled_data)
    all_stats['vulnerable_count'] = (labeled_data['label'] == 'vulnerable').sum()
    all_stats['benign_count'] = (labeled_data['label'] == 'benign').sum()
    
    # ========================================================================
    # 步骤 5: 时间划分 (Train/Dev/Test)
    # ========================================================================
    print("\n" + "=" * 80)
    print("步骤 5/6: 时间划分 (Train/Dev/Test)")
    print("=" * 80)
    
    if SPLIT_CONFIG['temporal_split']:
        train_data, dev_data, test_data, split_stats = temporal_split(
            labeled_data,
            train_ratio=SPLIT_CONFIG['train_ratio'],
            dev_ratio=SPLIT_CONFIG['dev_ratio'],
            test_ratio=SPLIT_CONFIG['test_ratio']
        )
        all_stats.update(split_stats)
    else:
        print("时间划分已禁用，使用随机划分")
        # 简单的随机划分（不推荐）
        from sklearn.model_selection import train_test_split
        train_data, temp = train_test_split(labeled_data, test_size=0.2, random_state=42)
        dev_data, test_data = train_test_split(temp, test_size=0.5, random_state=42)
        train_data['split'] = 'train'
        dev_data['split'] = 'dev'
        test_data['split'] = 'test'
    
    # 合并所有划分（用于构建成对数据）
    all_labeled_data = pd.concat([train_data, dev_data, test_data], ignore_index=True)
    
    # ========================================================================
    # 步骤 6: 构建成对函数数据集
    # ========================================================================
    print("\n" + "=" * 80)
    print("步骤 6/6: 构建成对函数数据集")
    print("=" * 80)
    
    paired_data, paired_stats = build_paired_dataset(
        all_labeled_data,
        min_similarity=LABELING_CONFIG['min_similarity_for_paired']
    )
    all_stats.update(paired_stats)
    
    # 划分成对数据
    train_paired, dev_paired, test_paired = split_paired_dataset(paired_data)
    
    # ========================================================================
    # 步骤 7: 保存结果
    # ========================================================================
    print("\n" + "=" * 80)
    print("保存数据集")
    print("=" * 80)
    
    # 保存 All 版本
    train_data.to_csv(OUTPUT_FILES['train_all'], index=False)
    print(f"保存训练集 (All): {OUTPUT_FILES['train_all']}")
    
    dev_data.to_csv(OUTPUT_FILES['dev_all'], index=False)
    print(f"保存验证集 (All): {OUTPUT_FILES['dev_all']}")
    
    test_data.to_csv(OUTPUT_FILES['test_all'], index=False)
    print(f"保存测试集 (All): {OUTPUT_FILES['test_all']}")
    
    # 保存 Paired 版本
    if len(train_paired) > 0:
        train_paired.to_csv(OUTPUT_FILES['train_paired'], index=False)
        print(f"保存训练集 (Paired): {OUTPUT_FILES['train_paired']}")
    
    if len(dev_paired) > 0:
        dev_paired.to_csv(OUTPUT_FILES['dev_paired'], index=False)
        print(f"保存验证集 (Paired): {OUTPUT_FILES['dev_paired']}")
    
    if len(test_paired) > 0:
        test_paired.to_csv(OUTPUT_FILES['test_paired'], index=False)
        print(f"保存测试集 (Paired): {OUTPUT_FILES['test_paired']}")
    
    # 保存统计信息
    with open(OUTPUT_FILES['statistics'], 'w') as f:
        json.dump(all_stats, f, indent=2)
    print(f"保存统计信息: {OUTPUT_FILES['statistics']}")
    
    # ========================================================================
    # 打印最终统计
    # ========================================================================
    print("\n" + "=" * 80)
    print("数据集构建完成！")
    print("=" * 80)
    
    print("\n数据集统计 (All):")
    print(f"  训练集: {len(train_data):,} 样本 ({all_stats.get('train_vulnerable', 0):,} vuln, {all_stats.get('train_benign', 0):,} benign)")
    print(f"  验证集: {len(dev_data):,} 样本 ({all_stats.get('dev_vulnerable', 0):,} vuln, {all_stats.get('dev_benign', 0):,} benign)")
    print(f"  测试集: {len(test_data):,} 样本 ({all_stats.get('test_vulnerable', 0):,} vuln, {all_stats.get('test_benign', 0):,} benign)")
    
    print("\n数据集统计 (Paired):")
    print(f"  训练集: {len(train_paired):,} 对")
    print(f"  验证集: {len(dev_paired):,} 对")
    print(f"  测试集: {len(test_paired):,} 对")
    
    print(f"\n完成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)


if __name__ == '__main__':
    main()

"""
工具函数模块
"""
import pandas as pd
import json
from typing import Dict, List
import matplotlib.pyplot as plt
import seaborn as sns


def print_dataset_statistics(stats: Dict):
    """
    美化打印数据集统计信息
    
    Args:
        stats: 统计信息字典
    """
    print("\n" + "=" * 80)
    print("数据集统计信息")
    print("=" * 80)
    
    # 基本统计
    if 'initial_count' in stats:
        print(f"\n初始数据:")
        print(f"  样本数: {stats['initial_count']:,}")
        print(f"  Commits: {stats.get('initial_commits', 'N/A'):,}")
    
    # 去重统计
    if 'total_processed' in stats:
        print(f"\n去重统计:")
        print(f"  处理样本: {stats['total_processed']:,}")
        print(f"  重复样本: {stats['duplicates_found']:,}")
        print(f"  去重率: {stats['deduplication_rate']*100:.2f}%")
        print(f"  唯一函数: {stats['unique_functions']:,}")
    
    # 标注统计
    if 'onefunc_labeled' in stats or 'nvdcheck_labeled' in stats:
        print(f"\n标注统计:")
        if 'onefunc_labeled' in stats:
            print(f"  OneFunc 标注: {stats['onefunc_labeled']:,}")
        if 'nvdcheck_labeled' in stats:
            print(f"  NVDCheck 标注: {stats['nvdcheck_labeled']:,}")
        if 'vulnerable_count' in stats:
            print(f"  总 Vulnerable: {stats['vulnerable_count']:,}")
            print(f"  总 Benign: {stats['benign_count']:,}")
    
    # 划分统计
    if 'train_total' in stats:
        print(f"\n数据集划分:")
        for split in ['train', 'dev', 'test']:
            total_key = f'{split}_total'
            vuln_key = f'{split}_vulnerable'
            benign_key = f'{split}_benign'
            commits_key = f'{split}_commits'
            
            if total_key in stats:
                print(f"  {split.capitalize()}:")
                print(f"    样本: {stats[total_key]:,}")
                print(f"    Vulnerable: {stats.get(vuln_key, 0):,}")
                print(f"    Benign: {stats.get(benign_key, 0):,}")
                print(f"    Commits: {stats.get(commits_key, 0):,}")
    
    # 成对数据统计
    if 'paired_count' in stats:
        print(f"\n成对数据统计:")
        print(f"  成功配对: {stats['paired_count']:,}")
        print(f"  未找到 Patch: {stats.get('skipped_no_patch', 0):,}")
        print(f"  相似度过低: {stats.get('skipped_low_similarity', 0):,}")
    
    print("=" * 80)


def visualize_dataset_distribution(train_data: pd.DataFrame,
                                   dev_data: pd.DataFrame,
                                   test_data: pd.DataFrame,
                                   output_path: str = None):
    """
    可视化数据集分布
    
    Args:
        train_data: 训练集
        dev_data: 验证集
        test_data: 测试集
        output_path: 保存图片的路径（可选）
    """
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    
    # 统计各划分的样本数
    splits = ['Train', 'Dev', 'Test']
    datasets = [train_data, dev_data, test_data]
    
    vuln_counts = [(d['label'] == 'vulnerable').sum() for d in datasets]
    benign_counts = [(d['label'] == 'benign').sum() for d in datasets]
    
    # 图 1: 样本数量对比
    x = range(len(splits))
    width = 0.35
    
    axes[0].bar([i - width/2 for i in x], vuln_counts, width, label='Vulnerable', color='#e74c3c')
    axes[0].bar([i + width/2 for i in x], benign_counts, width, label='Benign', color='#3498db')
    
    axes[0].set_xlabel('Split')
    axes[0].set_ylabel('Count')
    axes[0].set_title('Dataset Distribution by Split')
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(splits)
    axes[0].legend()
    axes[0].grid(axis='y', alpha=0.3)
    
    # 图 2: 比例饼图
    total_vuln = sum(vuln_counts)
    total_benign = sum(benign_counts)
    
    axes[1].pie([total_vuln, total_benign],
                labels=['Vulnerable', 'Benign'],
                colors=['#e74c3c', '#3498db'],
                autopct='%1.1f%%',
                startangle=90)
    axes[1].set_title('Overall Label Distribution')
    
    plt.tight_layout()
    
    if output_path:
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"可视化图片已保存: {output_path}")
    else:
        plt.show()


def export_dataset_to_json(data: pd.DataFrame, output_path: str):
    """
    将数据集导出为 JSON 格式
    
    Args:
        data: 数据集
        output_path: 输出文件路径
    """
    records = data.to_dict('records')
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(records, f, indent=2, ensure_ascii=False)
    
    print(f"数据集已导出为 JSON: {output_path}")


def validate_dataset(data: pd.DataFrame) -> Dict:
    """
    验证数据集的完整性和正确性
    
    Args:
        data: 数据集
        
    Returns:
        验证结果字典
    """
    issues = []
    warnings = []
    
    # 检查必需列
    required_columns = ['commit_id', 'func_after', 'label']
    missing_columns = [col for col in required_columns if col not in data.columns]
    
    if missing_columns:
        issues.append(f"缺少必需列: {missing_columns}")
    
    # 检查空值
    for col in required_columns:
        if col in data.columns:
            null_count = data[col].isna().sum()
            if null_count > 0:
                warnings.append(f"列 '{col}' 有 {null_count} 个空值")
    
    # 检查标签分布
    if 'label' in data.columns:
        label_counts = data['label'].value_counts()
        if len(label_counts) == 0:
            issues.append("没有任何标签")
        elif 'vulnerable' not in label_counts:
            warnings.append("没有 vulnerable 样本")
        elif 'benign' not in label_counts:
            warnings.append("没有 benign 样本")
        else:
            vuln_ratio = label_counts.get('vulnerable', 0) / len(data)
            if vuln_ratio < 0.01:
                warnings.append(f"Vulnerable 样本占比过低: {vuln_ratio*100:.2f}%")
            elif vuln_ratio > 0.99:
                warnings.append(f"Vulnerable 样本占比过高: {vuln_ratio*100:.2f}%")
    
    # 检查重复 commit
    if 'commit_id' in data.columns:
        duplicate_commits = data[data.duplicated(subset=['commit_id', 'func_after'], keep=False)]
        if len(duplicate_commits) > 0:
            warnings.append(f"发现 {len(duplicate_commits)} 个可能的重复样本")
    
    result = {
        'valid': len(issues) == 0,
        'issues': issues,
        'warnings': warnings,
        'total_samples': len(data),
        'total_commits': data['commit_id'].nunique() if 'commit_id' in data.columns else 0
    }
    
    return result


def print_validation_results(validation_result: Dict):
    """
    打印验证结果
    
    Args:
        validation_result: 验证结果字典
    """
    print("\n" + "=" * 80)
    print("数据集验证结果")
    print("=" * 80)
    
    if validation_result['valid']:
        print("\n? 数据集验证通过")
    else:
        print("\n? 数据集验证失败")
    
    if validation_result['issues']:
        print("\n严重问题:")
        for issue in validation_result['issues']:
            print(f"  - {issue}")
    
    if validation_result['warnings']:
        print("\n警告:")
        for warning in validation_result['warnings']:
            print(f"  - {warning}")
    
    print(f"\n基本信息:")
    print(f"  总样本数: {validation_result['total_samples']:,}")
    print(f"  总 Commits: {validation_result['total_commits']:,}")
    
    print("=" * 80)


if __name__ == '__main__':
    # 测试验证函数
    test_data = pd.DataFrame({
        'commit_id': ['c1', 'c2', 'c3'],
        'func_after': ['code1', 'code2', 'code3'],
        'label': ['vulnerable', 'benign', 'benign']
    })
    
    result = validate_dataset(test_data)
    print_validation_results(result)

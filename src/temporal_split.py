# -*- coding: gbk -*-

"""
时间划分模块：实现按 commit 时间进行 Train/Dev/Test 划分
"""
import pandas as pd
from typing import Dict, List, Tuple
from datetime import datetime
from tqdm import tqdm


class TemporalSplitter:
    """
    实现 PrimeVul 的时间划分策略：
    1. 按 commit 时间排序
    2. 按比例划分：80% train, 10% dev, 10% test
    3. 确保同一 commit 的所有样本在同一子集中
    """
    
    def __init__(self, train_ratio: float = 0.8, 
                 dev_ratio: float = 0.1, 
                 test_ratio: float = 0.1):
        """
        初始化时间划分器
        
        Args:
            train_ratio: 训练集比例
            dev_ratio: 验证集比例
            test_ratio: 测试集比例
        """
        assert abs(train_ratio + dev_ratio + test_ratio - 1.0) < 1e-6, \
            "比例之和必须为 1.0"
        
        self.train_ratio = train_ratio
        self.dev_ratio = dev_ratio
        self.test_ratio = test_ratio
        
    def parse_commit_time(self, timestamp) -> datetime:
        """
        解析 commit 时间戳
        
        Args:
            timestamp: 时间戳（可以是字符串或 datetime 对象）
            
        Returns:
            datetime 对象
        """
        if isinstance(timestamp, datetime):
            return timestamp
        
        if isinstance(timestamp, str):
            # 尝试多种时间格式
            formats = [
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d',
                '%Y/%m/%d %H:%M:%S',
                '%Y/%m/%d',
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(timestamp, fmt)
                except ValueError:
                    continue
            
            # 如果都失败，尝试 ISO 格式
            try:
                return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                pass
        
        # 如果是数字，假设是 Unix 时间戳
        if isinstance(timestamp, (int, float)):
            return datetime.fromtimestamp(timestamp)
        
        raise ValueError(f"无法解析时间戳: {timestamp}")
    
    def split_by_commits(self, data: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        按 commit 进行时间划分
        
        Args:
            data: 输入数据集，应包含以下列：
                  - commit_id: commit 标识符
                  - commit_time: commit 时间戳
                  
        Returns:
            (train_data, dev_data, test_data)
        """
        print("开始时间划分...")
        
        # 获取每个 commit 的时间
        commit_times = {}
        for commit_id, group in data.groupby('commit_id'):
            # 取该 commit 的第一个样本的时间
            time_val = group.iloc[0]['commit_time']
            try:
                commit_times[commit_id] = self.parse_commit_time(time_val)
            except Exception as e:
                print(f"警告: 无法解析 commit {commit_id} 的时间: {e}")
                # 使用默认时间
                commit_times[commit_id] = datetime.min
        
        # 按时间排序 commits
        sorted_commits = sorted(commit_times.items(), key=lambda x: x[1])
        commit_ids = [c[0] for c in sorted_commits]
        
        print(f"总共 {len(commit_ids)} 个 commits")
        print(f"时间范围: {sorted_commits[0][1]} 到 {sorted_commits[-1][1]}")
        
        # 计算划分点
        total_commits = len(commit_ids)
        train_end = int(total_commits * self.train_ratio)
        dev_end = train_end + int(total_commits * self.dev_ratio)
        
        # 划分 commit IDs
        train_commits = set(commit_ids[:train_end])
        dev_commits = set(commit_ids[train_end:dev_end])
        test_commits = set(commit_ids[dev_end:])
        
        print(f"\nCommit 划分:")
        print(f"  Train: {len(train_commits)} commits")
        print(f"  Dev:   {len(dev_commits)} commits")
        print(f"  Test:  {len(test_commits)} commits")
        
        # 根据 commit ID 划分数据
        train_data = data[data['commit_id'].isin(train_commits)].copy()
        dev_data = data[data['commit_id'].isin(dev_commits)].copy()
        test_data = data[data['commit_id'].isin(test_commits)].copy()
        
        # 添加 split 列
        train_data['split'] = 'train'
        dev_data['split'] = 'dev'
        test_data['split'] = 'test'
        
        print(f"\n样本划分:")
        print(f"  Train: {len(train_data)} 样本")
        print(f"  Dev:   {len(dev_data)} 样本")
        print(f"  Test:  {len(test_data)} 样本")
        
        # 统计各划分中的 vulnerable/benign 比例
        for name, split_data in [('Train', train_data), ('Dev', dev_data), ('Test', test_data)]:
            vuln_count = (split_data['label'] == 'vulnerable').sum()
            benign_count = (split_data['label'] == 'benign').sum()
            print(f"  {name}: {vuln_count} vulnerable, {benign_count} benign")
        
        return train_data, dev_data, test_data
    
    def get_statistics(self, train_data: pd.DataFrame, 
                      dev_data: pd.DataFrame, 
                      test_data: pd.DataFrame) -> Dict:
        """
        获取划分统计信息
        
        Args:
            train_data: 训练集
            dev_data: 验证集
            test_data: 测试集
            
        Returns:
            统计信息字典
        """
        def get_split_stats(data: pd.DataFrame, split_name: str) -> Dict:
            return {
                f'{split_name}_total': len(data),
                f'{split_name}_vulnerable': (data['label'] == 'vulnerable').sum(),
                f'{split_name}_benign': (data['label'] == 'benign').sum(),
                f'{split_name}_commits': data['commit_id'].nunique(),
            }
        
        stats = {}
        stats.update(get_split_stats(train_data, 'train'))
        stats.update(get_split_stats(dev_data, 'dev'))
        stats.update(get_split_stats(test_data, 'test'))
        
        return stats


def temporal_split(data: pd.DataFrame, 
                  train_ratio: float = 0.8,
                  dev_ratio: float = 0.1,
                  test_ratio: float = 0.1) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, Dict]:
    """
    执行时间划分的便捷函数
    
    Args:
        data: 输入数据集
        train_ratio: 训练集比例
        dev_ratio: 验证集比例
        test_ratio: 测试集比例
        
    Returns:
        (train_data, dev_data, test_data, statistics)
    """
    splitter = TemporalSplitter(train_ratio, dev_ratio, test_ratio)
    train_data, dev_data, test_data = splitter.split_by_commits(data)
    stats = splitter.get_statistics(train_data, dev_data, test_data)
    
    return train_data, dev_data, test_data, stats


if __name__ == '__main__':
    # 测试代码
    import numpy as np
    
    test_data = pd.DataFrame({
        'commit_id': ['c1', 'c1', 'c2', 'c3', 'c4', 'c5'],
        'commit_time': [
            '2020-01-01 10:00:00',
            '2020-01-01 10:00:00',
            '2020-06-01 12:00:00',
            '2021-01-01 14:00:00',
            '2021-06-01 16:00:00',
            '2022-01-01 18:00:00',
        ],
        'label': ['vulnerable', 'benign', 'vulnerable', 'benign', 'vulnerable', 'benign']
    })
    
    print("测试时间划分:\n")
    train, dev, test, stats = temporal_split(test_data)
    
    print("\n训练集:")
    print(train[['commit_id', 'commit_time', 'label']])
    
    print("\n验证集:")
    print(dev[['commit_id', 'commit_time', 'label']])
    
    print("\n测试集:")
    print(test[['commit_id', 'commit_time', 'label']])
    
    print("\n统计信息:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

# -*- coding: gbk -*-

"""
数据去重模块：实现函数文本规范化和基于 MD5 的去重逻辑
"""
import hashlib
import re
from typing import Dict, List, Set, Tuple
import pandas as pd
from tqdm import tqdm


class FunctionDeduplicator:
    """
    函数去重器，实现 PrimeVul 论文中的去重策略：
    1. 规范化函数文本（删除空格、制表符、换行符等）
    2. 计算 MD5 哈希
    3. 基于哈希值进行全局去重
    """
    
    def __init__(self):
        self.seen_hashes: Set[str] = set()
        self.duplicate_count = 0
        self.total_count = 0
        
    def normalize_function_text(self, code: str) -> str:
        """
        规范化函数文本，删除所有空白字符
        
        Args:
            code: 原始函数代码
            
        Returns:
            规范化后的代码字符串
        """
        if not isinstance(code, str):
            return ""
        
        # 删除所有空格、制表符、换行符、回车符
        normalized = re.sub(r'[\s\t\n\r]', '', code)
        return normalized
    
    def compute_md5_hash(self, text: str) -> str:
        """
        计算文本的 MD5 哈希值
        
        Args:
            text: 输入文本
            
        Returns:
            MD5 哈希字符串
        """
        return hashlib.md5(text.encode('utf-8')).hexdigest()
    
    def is_duplicate(self, code: str) -> bool:
        """
        检查函数是否重复
        
        Args:
            code: 函数代码
            
        Returns:
            True 如果是重复的，False 否则
        """
        self.total_count += 1
        normalized = self.normalize_function_text(code)
        code_hash = self.compute_md5_hash(normalized)
        
        if code_hash in self.seen_hashes:
            self.duplicate_count += 1
            return True
        
        self.seen_hashes.add(code_hash)
        return False
    
    def deduplicate_within_commit(self, commit_data: pd.DataFrame) -> pd.DataFrame:
        """
        在单个 commit 内部去重：
        - 如果函数修改前后规范化文本相同，则认为实际上没有改变，丢弃
        
        Args:
            commit_data: 单个 commit 的数据，包含 'func_before' 和 'func_after' 列
            
        Returns:
            去重后的数据
        """
        filtered_rows = []
        
        for idx, row in commit_data.iterrows():
            func_before = row.get('func_before', '')
            func_after = row.get('func_after', '')
            
            # 规范化前后版本
            norm_before = self.normalize_function_text(func_before)
            norm_after = self.normalize_function_text(func_after)
            
            # 如果前后相同，则跳过
            if norm_before == norm_after:
                continue
                
            filtered_rows.append(row)
        
        return pd.DataFrame(filtered_rows)
    
    def deduplicate_global(self, data: pd.DataFrame, 
                          code_column: str = 'func_after') -> pd.DataFrame:
        """
        全局去重：基于规范化函数的 MD5 哈希去除重复
        
        Args:
            data: 输入数据集
            code_column: 包含代码的列名
            
        Returns:
            去重后的数据集
        """
        print(f"开始全局去重，原始数据量: {len(data)}")
        
        filtered_rows = []
        for idx, row in tqdm(data.iterrows(), total=len(data), desc="全局去重"):
            code = row.get(code_column, '')
            if not self.is_duplicate(code):
                filtered_rows.append(row)
        
        result = pd.DataFrame(filtered_rows)
        print(f"去重完成: 保留 {len(result)} 条，删除 {self.duplicate_count} 条重复")
        print(f"去重率: {self.duplicate_count / self.total_count * 100:.2f}%")
        
        return result
    
    def get_statistics(self) -> Dict:
        """
        获取去重统计信息
        
        Returns:
            包含统计信息的字典
        """
        return {
            'total_processed': self.total_count,
            'duplicates_found': self.duplicate_count,
            'unique_functions': len(self.seen_hashes),
            'deduplication_rate': self.duplicate_count / self.total_count if self.total_count > 0 else 0
        }


def deduplicate_dataset(data: pd.DataFrame, 
                       has_before_after: bool = True) -> Tuple[pd.DataFrame, Dict]:
    """
    对整个数据集执行完整的去重流程
    
    Args:
        data: 输入数据集，应包含以下列：
              - commit_id: commit 标识符
              - func_before: 修改前的函数代码（如果 has_before_after=True）
              - func_after: 修改后的函数代码
        has_before_after: 是否包含修改前后两个版本
        
    Returns:
        (去重后的数据集, 统计信息字典)
    """
    deduplicator = FunctionDeduplicator()
    
    # 步骤 1: 如果有 before/after，先在 commit 内部去重
    if has_before_after and 'commit_id' in data.columns:
        print("步骤 1: commit 内部去重（删除前后相同的函数）")
        
        deduplicated_commits = []
        for commit_id, commit_group in tqdm(data.groupby('commit_id'), desc="处理 commits"):
            filtered = deduplicator.deduplicate_within_commit(commit_group)
            if len(filtered) > 0:
                deduplicated_commits.append(filtered)
        
        if deduplicated_commits:
            data = pd.concat(deduplicated_commits, ignore_index=True)
        else:
            data = pd.DataFrame()
        
        print(f"commit 内部去重后剩余: {len(data)} 条")
    
    # 步骤 2: 全局去重
    print("\n步骤 2: 全局去重（基于 MD5 哈希）")
    result = deduplicator.deduplicate_global(data, code_column='func_after')
    
    # 获取统计信息
    stats = deduplicator.get_statistics()
    
    return result, stats


if __name__ == '__main__':
    # 测试代码
    import numpy as np
    
    # 创建测试数据
    test_data = pd.DataFrame({
        'commit_id': ['c1', 'c1', 'c2', 'c3', 'c4'],
        'func_before': [
            'int foo() { return 1; }',
            'int bar() {  return  2;  }',  # 空格不同
            'int baz() { return 3; }',
            'int foo() { return 1; }',  # 与第一个重复
            'int qux() { return 4; }'
        ],
        'func_after': [
            'int foo() { return 1; }',  # 前后相同，应被删除
            'int bar() { return 2; }',  # 规范化后与 before 相同
            'int baz() { return 5; }',  # 已修改
            'int foo() { return 1; }',  # 重复
            'int qux() { return 6; }'
        ]
    })
    
    print("测试数据去重功能:\n")
    result, stats = deduplicate_dataset(test_data)
    
    print("\n去重结果:")
    print(result)
    print("\n统计信息:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

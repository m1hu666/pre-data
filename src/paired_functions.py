# -*- coding: gbk -*-

"""
成对函数构建模块：构建 vulnerable-patch 函数对
"""
import pandas as pd
from typing import Dict, List, Tuple, Set
from difflib import SequenceMatcher
from tqdm import tqdm


class PairedFunctionBuilder:
    """
    实现 PrimeVul 成对函数构建策略：
    1. 对每个 vulnerable 函数，寻找其修复后的 patch 函数
    2. 要求 vulnerable 和 patch 函数共享至少 80% 的字符相似度
    3. 构建 (vulnerable, benign-patched) 函数对
    """
    
    def __init__(self, min_similarity: float = 0.8):
        """
        初始化成对函数构建器
        
        Args:
            min_similarity: 最小相似度阈值（默认 0.8）
        """
        self.min_similarity = min_similarity
        self.paired_count = 0
        self.skipped_no_patch = 0
        self.skipped_low_similarity = 0
    
    def compute_similarity(self, text1: str, text2: str) -> float:
        """
        计算两个文本的相似度（基于字符级别）
        
        Args:
            text1: 第一个文本
            text2: 第二个文本
            
        Returns:
            相似度分数 (0-1)
        """
        if not text1 or not text2:
            return 0.0
        
        # 使用 SequenceMatcher 计算相似度
        matcher = SequenceMatcher(None, text1, text2)
        return matcher.ratio()
    
    def find_patch_function(self, vuln_row: pd.Series, 
                           all_data: pd.DataFrame) -> pd.Series:
        """
        为 vulnerable 函数找到对应的 patch 函数
        
        Args:
            vuln_row: vulnerable 函数的数据行
            all_data: 完整数据集
            
        Returns:
            patch 函数的数据行，如果未找到则返回 None
        """
        # 获取 vulnerable 函数的信息
        commit_id = vuln_row['commit_id']
        file_path = vuln_row.get('file_path', '')
        func_name = vuln_row.get('func_name', '')
        vuln_code = vuln_row.get('func_after', '')
        
        # 在数据集中查找同一文件路径、同一函数名的 benign 函数
        # 并且 commit 时间晚于 vulnerable commit
        candidates = all_data[
            (all_data['label'] == 'benign') &
            (all_data['file_path'] == file_path) &
            (all_data.get('func_name', '') == func_name) &
            (all_data['commit_id'] != commit_id)
        ]
        
        # 如果没有候选，尝试放宽条件（只要求文件路径相同）
        if len(candidates) == 0:
            candidates = all_data[
                (all_data['label'] == 'benign') &
                (all_data['file_path'] == file_path) &
                (all_data['commit_id'] != commit_id)
            ]
        
        # 在候选中找到相似度最高且满足阈值的函数
        best_patch = None
        best_similarity = 0.0
        
        for _, candidate in candidates.iterrows():
            patch_code = candidate.get('func_after', '')
            similarity = self.compute_similarity(vuln_code, patch_code)
            
            if similarity >= self.min_similarity and similarity > best_similarity:
                best_similarity = similarity
                best_patch = candidate
        
        return best_patch
    
    def build_pairs(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        构建成对函数数据集
        
        Args:
            data: 输入数据集，应包含 vulnerable 和 benign 函数
            
        Returns:
            成对函数数据集，每行包含一对 (vulnerable, patch) 函数
        """
        print("构建成对函数...")
        
        # 获取所有 vulnerable 函数
        vuln_functions = data[data['label'] == 'vulnerable']
        
        print(f"找到 {len(vuln_functions)} 个 vulnerable 函数")
        
        pairs = []
        
        for idx, vuln_row in tqdm(vuln_functions.iterrows(), 
                                  total=len(vuln_functions),
                                  desc="匹配 patch 函数"):
            # 查找对应的 patch 函数
            patch_row = self.find_patch_function(vuln_row, data)
            
            if patch_row is None:
                self.skipped_no_patch += 1
                continue
            
            # 检查相似度
            similarity = self.compute_similarity(
                vuln_row.get('func_after', ''),
                patch_row.get('func_after', '')
            )
            
            if similarity < self.min_similarity:
                self.skipped_low_similarity += 1
                continue
            
            # 创建函数对
            pair = {
                'pair_id': f"pair_{len(pairs)}",
                'vuln_commit_id': vuln_row['commit_id'],
                'patch_commit_id': patch_row['commit_id'],
                'file_path': vuln_row.get('file_path', ''),
                'func_name': vuln_row.get('func_name', ''),
                'vuln_code': vuln_row.get('func_after', ''),
                'patch_code': patch_row.get('func_after', ''),
                'similarity': similarity,
                'cve_id': vuln_row.get('cve_id', ''),
                'split': vuln_row.get('split', ''),  # 继承 vulnerable 函数的划分
            }
            
            pairs.append(pair)
            self.paired_count += 1
        
        result = pd.DataFrame(pairs)
        
        print(f"\n成对函数构建完成:")
        print(f"  - 成功配对: {self.paired_count}")
        print(f"  - 未找到 patch: {self.skipped_no_patch}")
        print(f"  - 相似度过低: {self.skipped_low_similarity}")
        
        return result
    
    def get_statistics(self) -> Dict:
        """
        获取统计信息
        
        Returns:
            统计信息字典
        """
        return {
            'paired_count': self.paired_count,
            'skipped_no_patch': self.skipped_no_patch,
            'skipped_low_similarity': self.skipped_low_similarity
        }


def build_paired_dataset(data: pd.DataFrame, 
                        min_similarity: float = 0.8) -> Tuple[pd.DataFrame, Dict]:
    """
    构建成对函数数据集的便捷函数
    
    Args:
        data: 输入数据集（应该已经标注并划分）
        min_similarity: 最小相似度阈值
        
    Returns:
        (成对函数数据集, 统计信息)
    """
    builder = PairedFunctionBuilder(min_similarity)
    paired_data = builder.build_pairs(data)
    stats = builder.get_statistics()
    
    return paired_data, stats


def split_paired_dataset(paired_data: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    将成对函数数据集按 split 列划分为 train/dev/test
    
    Args:
        paired_data: 成对函数数据集
        
    Returns:
        (train_paired, dev_paired, test_paired)
    """
    train_paired = paired_data[paired_data['split'] == 'train'].copy()
    dev_paired = paired_data[paired_data['split'] == 'dev'].copy()
    test_paired = paired_data[paired_data['split'] == 'test'].copy()
    
    print(f"\n成对数据集划分:")
    print(f"  Train: {len(train_paired)} 对")
    print(f"  Dev:   {len(dev_paired)} 对")
    print(f"  Test:  {len(test_paired)} 对")
    
    return train_paired, dev_paired, test_paired


if __name__ == '__main__':
    # 测试代码
    test_data = pd.DataFrame({
        'commit_id': ['c1', 'c2', 'c3', 'c4'],
        'file_path': ['src/vuln.c', 'src/vuln.c', 'src/other.c', 'src/other.c'],
        'func_name': ['foo', 'foo', 'bar', 'bar'],
        'func_after': [
            'int foo() { vulnerable_code(); }',  # vulnerable
            'int foo() { safe_code(); }',        # patch (相似但修复)
            'int bar() { another_vuln(); }',     # vulnerable
            'int bar() { completely_different(); }'  # 不相似，不应配对
        ],
        'label': ['vulnerable', 'benign', 'vulnerable', 'benign'],
        'cve_id': ['CVE-2021-1234', '', 'CVE-2021-5678', ''],
        'split': ['train', 'train', 'dev', 'dev']
    })
    
    print("测试成对函数构建:\n")
    paired, stats = build_paired_dataset(test_data, min_similarity=0.5)
    
    print("\n成对函数:")
    print(paired[['pair_id', 'vuln_commit_id', 'patch_commit_id', 'similarity']])
    
    print("\n统计信息:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

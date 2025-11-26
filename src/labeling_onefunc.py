# -*- coding: gbk -*-

"""
OneFunc 标注方法：对只修改一个函数的 security-related commit 进行标注
"""
import pandas as pd
from typing import Dict, List, Tuple
from collections import defaultdict
from tqdm import tqdm


class OneFuncLabeler:
    """
    实现 PrimeVul-OneFunc 标注策略：
    - 如果一个 security-related commit 只修改了一个函数，
      则该函数的 post-commit 版本标记为 vulnerable
    - 如果修改了多个函数，则不使用 OneFunc 规则
    """
    
    def __init__(self):
        self.labeled_count = 0
        self.skipped_multi_func = 0
        
    def label_dataset(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        对数据集应用 OneFunc 标注规则
        
        Args:
            data: 输入数据集，应包含以下列：
                  - commit_id: commit 标识符
                  - func_after: 修改后的函数代码
                  - is_security_related: 是否为安全相关的 commit
                  
        Returns:
            标注后的数据集，新增 'label' 列和 'labeling_method' 列
        """
        print("应用 OneFunc 标注规则...")
        
        # 按 commit_id 分组，统计每个 commit 修改的函数数量
        commit_func_counts = data.groupby('commit_id').size()
        
        # 创建结果列表
        labeled_data = []
        
        for idx, row in tqdm(data.iterrows(), total=len(data), desc="OneFunc 标注"):
            commit_id = row['commit_id']
            is_security = row.get('is_security_related', False)
            
            # 初始化标签
            label = None
            method = None
            
            # 只处理安全相关的 commits
            if is_security:
                func_count = commit_func_counts.get(commit_id, 0)
                
                if func_count == 1:
                    # 只修改了一个函数，标记为 vulnerable
                    label = 'vulnerable'
                    method = 'onefunc'
                    self.labeled_count += 1
                else:
                    # 修改了多个函数，跳过 OneFunc 规则
                    self.skipped_multi_func += 1
                    # 这些样本将由 NVDCheck 处理
            
            # 添加标注信息
            row_dict = row.to_dict()
            row_dict['label'] = label
            row_dict['labeling_method'] = method
            labeled_data.append(row_dict)
        
        result = pd.DataFrame(labeled_data)
        
        print(f"OneFunc 标注完成:")
        print(f"  - 标记为 vulnerable: {self.labeled_count}")
        print(f"  - 跳过（多函数修改）: {self.skipped_multi_func}")
        
        return result
    
    def get_statistics(self) -> Dict:
        """
        获取标注统计信息
        
        Returns:
            统计信息字典
        """
        return {
            'onefunc_labeled': self.labeled_count,
            'onefunc_skipped_multi_func': self.skipped_multi_func
        }


def apply_onefunc_labeling(data: pd.DataFrame) -> Tuple[pd.DataFrame, Dict]:
    """
    应用 OneFunc 标注方法的便捷函数
    
    Args:
        data: 输入数据集
        
    Returns:
        (标注后的数据集, 统计信息)
    """
    labeler = OneFuncLabeler()
    labeled_data = labeler.label_dataset(data)
    stats = labeler.get_statistics()
    
    return labeled_data, stats


if __name__ == '__main__':
    # 测试代码
    test_data = pd.DataFrame({
        'commit_id': ['c1', 'c2', 'c2', 'c3', 'c4'],
        'func_after': [
            'int foo() { return 1; }',
            'int bar() { return 2; }',
            'int baz() { return 3; }',
            'int qux() { return 4; }',
            'int quux() { return 5; }'
        ],
        'is_security_related': [True, True, True, False, True]
    })
    
    print("测试 OneFunc 标注:\n")
    result, stats = apply_onefunc_labeling(test_data)
    
    print("\n标注结果:")
    print(result[['commit_id', 'is_security_related', 'label', 'labeling_method']])
    print("\n统计信息:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

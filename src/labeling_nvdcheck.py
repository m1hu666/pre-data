# -*- coding: gbk -*-

"""
NVDCheck 标注方法：基于 NVD 描述文本进行精确标注
"""
import json
import re
import pandas as pd
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict
from tqdm import tqdm


class NVDCheckLabeler:
    """
    实现 PrimeVul-NVDCheck 标注策略：
    1. 将 security-related commits 与 CVE 编号和 NVD 描述对齐
    2. 如果 NVD 描述中明确提到函数名，标记为 vulnerable
    3. 如果 NVD 描述中提到文件名，且该文件中只有一个函数被修改，标记为 vulnerable
    """
    
    def __init__(self, nvd_data_path: Optional[str] = None):
        """
        初始化 NVDCheck 标注器
        
        Args:
            nvd_data_path: NVD 数据文件路径（JSON 格式）
        """
        self.nvd_data = {}
        self.labeled_count = 0
        self.skipped_no_cve = 0
        self.skipped_no_match = 0
        
        if nvd_data_path:
            self.load_nvd_data(nvd_data_path)
    
    def load_nvd_data(self, nvd_data_path: str):
        """
        加载 NVD 数据
        
        Args:
            nvd_data_path: NVD JSON 文件路径
        """
        print(f"加载 NVD 数据: {nvd_data_path}")
        try:
            with open(nvd_data_path, 'r', encoding='utf-8') as f:
                self.nvd_data = json.load(f)
            print(f"成功加载 {len(self.nvd_data)} 条 CVE 记录")
        except FileNotFoundError:
            print(f"警告: NVD 数据文件不存在: {nvd_data_path}")
        except json.JSONDecodeError as e:
            print(f"警告: NVD 数据文件格式错误: {e}")
    
    def get_nvd_description(self, cve_id: str) -> str:
        """
        获取 CVE 的 NVD 描述文本
        
        Args:
            cve_id: CVE 编号（如 "CVE-2021-1234"）
            
        Returns:
            NVD 描述文本，如果不存在则返回空字符串
        """
        if cve_id in self.nvd_data:
            return self.nvd_data[cve_id].get('description', '')
        return ''
    
    def extract_function_name(self, func_code: str) -> Optional[str]:
        """
        从函数代码中提取函数名
        
        Args:
            func_code: 函数代码
            
        Returns:
            函数名，如果无法提取则返回 None
        """
        # C/C++ 函数名提取的简单正则表达式
        # 匹配形式：返回类型 函数名(参数)
        patterns = [
            r'\b(\w+)\s*\(',  # 基本函数调用或定义
            r'(?:static\s+|inline\s+|extern\s+)*(?:\w+\s+\*?\s*)+(\w+)\s*\(',  # 带修饰符
        ]
        
        for pattern in patterns:
            match = re.search(pattern, func_code)
            if match:
                return match.group(1)
        
        return None
    
    def extract_filename(self, filepath: str) -> str:
        """
        从文件路径中提取文件名
        
        Args:
            filepath: 文件路径
            
        Returns:
            文件名（不含路径）
        """
        if not filepath:
            return ''
        return filepath.split('/')[-1]
    
    def check_function_mentioned(self, nvd_desc: str, func_name: str) -> bool:
        """
        检查 NVD 描述中是否提到函数名
        
        Args:
            nvd_desc: NVD 描述文本
            func_name: 函数名
            
        Returns:
            True 如果提到，False 否则
        """
        if not nvd_desc or not func_name:
            return False
        
        # 不区分大小写的搜索，使用单词边界
        pattern = r'\b' + re.escape(func_name) + r'\b'
        return bool(re.search(pattern, nvd_desc, re.IGNORECASE))
    
    def check_file_mentioned(self, nvd_desc: str, filename: str) -> bool:
        """
        检查 NVD 描述中是否提到文件名
        
        Args:
            nvd_desc: NVD 描述文本
            filename: 文件名
            
        Returns:
            True 如果提到，False 否则
        """
        if not nvd_desc or not filename:
            return False
        
        # 搜索文件名（可能带或不带扩展名）
        filename_base = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        # 检查完整文件名或基础文件名
        patterns = [
            r'\b' + re.escape(filename) + r'\b',
            r'\b' + re.escape(filename_base) + r'\b'
        ]
        
        for pattern in patterns:
            if re.search(pattern, nvd_desc, re.IGNORECASE):
                return True
        
        return False
    
    def label_dataset(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        对数据集应用 NVDCheck 标注规则
        
        Args:
            data: 输入数据集，应包含以下列：
                  - commit_id: commit 标识符
                  - cve_id: CVE 编号
                  - func_after: 修改后的函数代码
                  - func_name: 函数名（可选）
                  - file_path: 文件路径
                  - label: 已有标签（可能来自 OneFunc）
                  
        Returns:
            标注后的数据集
        """
        print("应用 NVDCheck 标注规则...")
        
        if not self.nvd_data:
            print("警告: NVD 数据未加载，跳过 NVDCheck 标注")
            return data
        
        labeled_data = []
        
        # 按 commit 分组处理
        for commit_id, commit_group in tqdm(data.groupby('commit_id'), desc="NVDCheck 标注"):
            cve_id = commit_group.iloc[0].get('cve_id', '')
            
            # 如果没有 CVE ID，跳过
            if not cve_id or pd.isna(cve_id):
                self.skipped_no_cve += len(commit_group)
                for _, row in commit_group.iterrows():
                    labeled_data.append(row.to_dict())
                continue
            
            # 获取 NVD 描述
            nvd_desc = self.get_nvd_description(cve_id)
            
            if not nvd_desc:
                self.skipped_no_cve += len(commit_group)
                for _, row in commit_group.iterrows():
                    labeled_data.append(row.to_dict())
                continue
            
            # 处理该 commit 中的每个函数
            for idx, row in commit_group.iterrows():
                row_dict = row.to_dict()
                
                # 如果已经被 OneFunc 标注，跳过
                if row_dict.get('label') == 'vulnerable':
                    labeled_data.append(row_dict)
                    continue
                
                # 提取函数名和文件名
                func_name = row_dict.get('func_name', '')
                if not func_name:
                    func_name = self.extract_function_name(row_dict.get('func_after', ''))
                
                file_path = row_dict.get('file_path', '')
                filename = self.extract_filename(file_path)
                
                # 检查 NVD 描述中是否提到函数名
                func_mentioned = self.check_function_mentioned(nvd_desc, func_name)
                
                # 检查 NVD 描述中是否提到文件名
                file_mentioned = self.check_file_mentioned(nvd_desc, filename)
                
                # 应用标注规则
                is_vulnerable = False
                
                # 规则 1: NVD 描述中明确提到函数名
                if func_mentioned:
                    is_vulnerable = True
                
                # 规则 2: NVD 描述中提到文件名，且该文件中只有一个函数被修改
                elif file_mentioned:
                    # 统计该 commit 中同一文件的函数数量
                    same_file_funcs = commit_group[
                        commit_group['file_path'] == file_path
                    ]
                    if len(same_file_funcs) == 1:
                        is_vulnerable = True
                
                # 设置标签
                if is_vulnerable:
                    row_dict['label'] = 'vulnerable'
                    row_dict['labeling_method'] = 'nvdcheck'
                    self.labeled_count += 1
                else:
                    # 同一 commit 中未被标记的函数标为 benign
                    if pd.isna(row_dict.get('label')):
                        row_dict['label'] = 'benign'
                        row_dict['labeling_method'] = 'nvdcheck_benign'
                
                labeled_data.append(row_dict)
        
        result = pd.DataFrame(labeled_data)
        
        print(f"NVDCheck 标注完成:")
        print(f"  - 标记为 vulnerable: {self.labeled_count}")
        print(f"  - 跳过（无 CVE）: {self.skipped_no_cve}")
        
        return result
    
    def get_statistics(self) -> Dict:
        """
        获取标注统计信息
        
        Returns:
            统计信息字典
        """
        return {
            'nvdcheck_labeled': self.labeled_count,
            'nvdcheck_skipped_no_cve': self.skipped_no_cve,
            'nvdcheck_skipped_no_match': self.skipped_no_match
        }


def apply_nvdcheck_labeling(data: pd.DataFrame, 
                           nvd_data_path: Optional[str] = None) -> Tuple[pd.DataFrame, Dict]:
    """
    应用 NVDCheck 标注方法的便捷函数
    
    Args:
        data: 输入数据集
        nvd_data_path: NVD 数据文件路径
        
    Returns:
        (标注后的数据集, 统计信息)
    """
    labeler = NVDCheckLabeler(nvd_data_path)
    labeled_data = labeler.label_dataset(data)
    stats = labeler.get_statistics()
    
    return labeled_data, stats


if __name__ == '__main__':
    # 测试代码
    test_data = pd.DataFrame({
        'commit_id': ['c1', 'c2', 'c2', 'c3'],
        'cve_id': ['CVE-2021-1234', 'CVE-2021-5678', 'CVE-2021-5678', 'CVE-2021-9999'],
        'func_after': [
            'int vulnerable_func() { return 1; }',
            'int safe_func() { return 2; }',
            'int another_func() { return 3; }',
            'int test_func() { return 4; }'
        ],
        'func_name': ['vulnerable_func', 'safe_func', 'another_func', 'test_func'],
        'file_path': ['src/vuln.c', 'src/main.c', 'src/utils.c', 'src/test.c'],
        'label': [None, None, None, None]
    })
    
    # 创建模拟 NVD 数据
    nvd_test_data = {
        'CVE-2021-1234': {
            'description': 'A vulnerability in the vulnerable_func function allows...'
        },
        'CVE-2021-5678': {
            'description': 'A security issue in main.c affects...'
        }
    }
    
    # 保存测试 NVD 数据
    import tempfile
    import os
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(nvd_test_data, f)
        nvd_path = f.name
    
    try:
        print("测试 NVDCheck 标注:\n")
        result, stats = apply_nvdcheck_labeling(test_data, nvd_path)
        
        print("\n标注结果:")
        print(result[['commit_id', 'cve_id', 'func_name', 'label', 'labeling_method']])
        print("\n统计信息:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
    finally:
        # 清理临时文件
        os.unlink(nvd_path)

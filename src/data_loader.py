"""
数据加载模块：从多个源加载和合并数据
"""
import pandas as pd
import json
from typing import Dict, List, Optional
import os


class DataLoader:
    """
    从多个数据源加载并合并数据
    支持的数据源：BigVul, CrossVul, CVE/fixes, DiverseVul
    """
    
    def __init__(self, data_sources: Dict[str, str]):
        """
        初始化数据加载器
        
        Args:
            data_sources: 数据源字典，键为数据源名称，值为文件路径
        """
        self.data_sources = data_sources
        
    def load_bigvul(self, filepath: str) -> pd.DataFrame:
        """
        加载 BigVul 数据集
        
        预期格式：CSV 文件，包含列：
        - commit_id, func_before, func_after, is_vulnerable, cve_id, commit_time, file_path, func_name
        """
        print(f"加载 BigVul: {filepath}")
        if not os.path.exists(filepath):
            print(f"  警告: 文件不存在，跳过")
            return pd.DataFrame()
        
        df = pd.read_csv(filepath)
        df['data_source'] = 'bigvul'
        df['is_security_related'] = df.get('is_vulnerable', False)
        
        return df
    
    def load_crossvul(self, filepath: str) -> pd.DataFrame:
        """
        加载 CrossVul 数据集
        
        预期格式：CSV 文件
        """
        print(f"加载 CrossVul: {filepath}")
        if not os.path.exists(filepath):
            print(f"  警告: 文件不存在，跳过")
            return pd.DataFrame()
        
        df = pd.read_csv(filepath)
        df['data_source'] = 'crossvul'
        df['is_security_related'] = True  # CrossVul 都是安全相关
        
        return df
    
    def load_cve_fixes(self, filepath: str) -> pd.DataFrame:
        """
        加载 CVE/fixes 数据集
        
        预期格式：CSV 文件
        """
        print(f"加载 CVE/fixes: {filepath}")
        if not os.path.exists(filepath):
            print(f"  警告: 文件不存在，跳过")
            return pd.DataFrame()
        
        df = pd.read_csv(filepath)
        df['data_source'] = 'cve_fixes'
        df['is_security_related'] = True
        
        return df
    
    def load_diversevul(self, filepath: str) -> pd.DataFrame:
        """
        加载 DiverseVul 数据集
        
        预期格式：CSV 文件
        """
        print(f"加载 DiverseVul: {filepath}")
        if not os.path.exists(filepath):
            print(f"  警告: 文件不存在，跳过")
            return pd.DataFrame()
        
        df = pd.read_csv(filepath)
        df['data_source'] = 'diversevul'
        df['is_security_related'] = True
        
        return df
    
    def normalize_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        统一列名
        
        确保所有数据源都有以下列：
        - commit_id, func_before, func_after, is_security_related, 
          cve_id, commit_time, file_path, func_name
        """
        # 定义列名映射
        column_mapping = {
            'id': 'commit_id',
            'commit': 'commit_id',
            'before': 'func_before',
            'after': 'func_after',
            'vulnerable': 'is_security_related',
            'cve': 'cve_id',
            'time': 'commit_time',
            'timestamp': 'commit_time',
            'path': 'file_path',
            'file': 'file_path',
            'function': 'func_name',
            'name': 'func_name',
        }
        
        # 重命名列
        df = df.rename(columns=column_mapping)
        
        # 确保必需列存在
        required_columns = [
            'commit_id', 'func_before', 'func_after', 'is_security_related',
            'cve_id', 'commit_time', 'file_path', 'func_name'
        ]
        
        for col in required_columns:
            if col not in df.columns:
                df[col] = None
        
        return df
    
    def merge_all(self) -> pd.DataFrame:
        """
        加载并合并所有数据源
        
        Returns:
            合并后的数据集
        """
        print("=" * 60)
        print("开始加载数据...")
        print("=" * 60)
        
        all_dataframes = []
        
        # 加载各个数据源
        loaders = {
            'bigvul': self.load_bigvul,
            'crossvul': self.load_crossvul,
            'cve_fixes': self.load_cve_fixes,
            'diversevul': self.load_diversevul,
        }
        
        for source_name, filepath in self.data_sources.items():
            if source_name in loaders:
                df = loaders[source_name](filepath)
                if len(df) > 0:
                    df = self.normalize_columns(df)
                    all_dataframes.append(df)
                    print(f"  {source_name}: {len(df)} 条记录")
        
        # 合并所有数据
        if not all_dataframes:
            print("警告: 没有加载到任何数据")
            return pd.DataFrame()
        
        merged = pd.concat(all_dataframes, ignore_index=True)
        
        print(f"\n合并完成: 总共 {len(merged)} 条记录")
        print(f"来自 {merged['data_source'].nunique()} 个数据源")
        print(f"涉及 {merged['commit_id'].nunique()} 个 commits")
        
        return merged


def load_nvd_data(nvd_path: str) -> Dict:
    """
    加载 NVD CVE 描述数据
    
    Args:
        nvd_path: NVD JSON 文件路径
        
    Returns:
        CVE ID 到描述的字典
    """
    if not os.path.exists(nvd_path):
        print(f"警告: NVD 数据文件不存在: {nvd_path}")
        return {}
    
    try:
        with open(nvd_path, 'r', encoding='utf-8') as f:
            nvd_data = json.load(f)
        print(f"成功加载 {len(nvd_data)} 条 NVD 记录")
        return nvd_data
    except Exception as e:
        print(f"加载 NVD 数据失败: {e}")
        return {}


if __name__ == '__main__':
    # 测试代码
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    
    from config import DATA_SOURCES
    
    loader = DataLoader(DATA_SOURCES)
    
    # 创建示例数据文件用于测试
    test_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'raw')
    os.makedirs(test_dir, exist_ok=True)
    
    # 创建示例 CSV
    test_bigvul = pd.DataFrame({
        'commit_id': ['c1', 'c2'],
        'func_before': ['int foo() { return 1; }', 'int bar() { return 2; }'],
        'func_after': ['int foo() { return 2; }', 'int bar() { return 3; }'],
        'is_vulnerable': [True, False],
        'cve_id': ['CVE-2021-1234', ''],
        'commit_time': ['2021-01-01', '2021-02-01'],
        'file_path': ['src/foo.c', 'src/bar.c'],
        'func_name': ['foo', 'bar']
    })
    
    test_file = os.path.join(test_dir, 'test_bigvul.csv')
    test_bigvul.to_csv(test_file, index=False)
    
    # 测试加载
    test_sources = {'bigvul': test_file}
    test_loader = DataLoader(test_sources)
    merged = test_loader.merge_all()
    
    print("\n合并数据示例:")
    print(merged.head())
    
    # 清理测试文件
    os.remove(test_file)

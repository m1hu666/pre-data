"""
Configuration file for PrimeVul dataset construction.
"""
import os

# 数据路径配置
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
RAW_DATA_DIR = os.path.join(DATA_DIR, 'raw')
PROCESSED_DATA_DIR = os.path.join(DATA_DIR, 'processed')
OUTPUT_DIR = os.path.join(DATA_DIR, 'output')

# 创建必要的目录
os.makedirs(RAW_DATA_DIR, exist_ok=True)
os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 数据源配置
DATA_SOURCES = {
    'bigvul': os.path.join(RAW_DATA_DIR, 'bigvul.csv'),
    'crossvul': os.path.join(RAW_DATA_DIR, 'crossvul.csv'),
    'cve_fixes': os.path.join(RAW_DATA_DIR, 'cve_fixes.csv'),
    'diversevul': os.path.join(RAW_DATA_DIR, 'diversevul.csv'),
}

# NVD 数据路径
NVD_DATA_PATH = os.path.join(RAW_DATA_DIR, 'nvd_cve_descriptions.json')

# 去重配置
NORMALIZATION_CONFIG = {
    'remove_whitespace': True,
    'remove_comments': False,  # 可选：是否删除注释
    'lowercase': False,  # 不转小写，保持代码原样
}

# 标注配置
LABELING_CONFIG = {
    'onefunc_enabled': True,
    'nvdcheck_enabled': True,
    'min_similarity_for_paired': 0.8,  # paired functions 最小相似度
}

# 数据集划分配置
SPLIT_CONFIG = {
    'train_ratio': 0.8,
    'dev_ratio': 0.1,
    'test_ratio': 0.1,
    'temporal_split': True,  # 使用时间划分
}

# 输出文件路径
OUTPUT_FILES = {
    'train_all': os.path.join(OUTPUT_DIR, 'train_all.csv'),
    'dev_all': os.path.join(OUTPUT_DIR, 'dev_all.csv'),
    'test_all': os.path.join(OUTPUT_DIR, 'test_all.csv'),
    'train_paired': os.path.join(OUTPUT_DIR, 'train_paired.csv'),
    'dev_paired': os.path.join(OUTPUT_DIR, 'dev_paired.csv'),
    'test_paired': os.path.join(OUTPUT_DIR, 'test_paired.csv'),
    'statistics': os.path.join(OUTPUT_DIR, 'dataset_statistics.json'),
}

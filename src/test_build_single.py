"""测试单个样本的处理"""
import json
import sys
from pathlib import Path
import yaml

current_file = Path(__file__)
absolute_path = current_file.resolve()
directory_name = absolute_path.parent
root_dir = directory_name.parent
sys.path.append(str(directory_name))

from build_primevul_dataset import REEFDatasetBuilder

def test_single_sample():
    """测试处理单个样本"""
    # 配置文件路径
    config_path = directory_name / 'data_preprocess.yaml'
    
    # 创建构建器
    builder = REEFDatasetBuilder(config_path)
    
    # 读取单个样本
    sample_file = root_dir / 'data' / 'raw' / 'REEF' / '1.json'
    with open(sample_file, 'r', encoding='utf-8') as f:
        sample = json.load(f)
    
    print(f"处理样本: {sample.get('cve_id', 'N/A')}")
    print(f"URL: {sample.get('url', 'N/A')}")
    print(f"Details数量: {len(sample.get('details', []))}")
    
    # 处理样本
    result = builder.process_reef_sample(sample)
    
    if result:
        print(f"\n处理成功!")
        print(f"标记函数数: {len(result['labeled_functions'])}")
        print(f"函数对数: {len(result['function_pairs'])}")
        
        # 打印一些结果
        if result['labeled_functions']:
            print("\n前3个标记函数:")
            for i, func in enumerate(result['labeled_functions'][:3]):
                print(f"\n{i+1}. 函数名: {func['func_name']}")
                print(f"   标签: {func['label']}")
                print(f"   来源: {func['source']}")
                print(f"   代码长度: {len(func['func_code'])} 字符")
        
        if result['function_pairs']:
            print("\n函数对:")
            for i, pair in enumerate(result['function_pairs']):
                print(f"\n{i+1}. 函数名: {pair['func_name']}")
                print(f"   修复前代码长度: {len(pair['func_before'])} 字符")
                print(f"   修复后代码长度: {len(pair['func_after'])} 字符")
    else:
        print("\n处理失败或无有效结果")
    
    # 打印统计信息
    print("\n" + "="*50)
    print("处理统计:")
    for key, value in builder.stats.items():
        print(f"{key}: {value}")
    print("="*50)

if __name__ == '__main__':
    test_single_sample()

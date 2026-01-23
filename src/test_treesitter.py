#!/usr/bin/env python3
"""
TreeSitter语言解析测试脚本
测试各语言的TreeSitter配置是否正确
"""

import yaml
from pathlib import Path
from tree_sitter_parse import TreeSitterParse

# 测试代码示例
test_codes = {
    'Python': '''
def hello_world():
    print("Hello, World!")
    return 42

def another_function(x, y):
    return x + y
''',
    'C': '''
int hello_world() {
    printf("Hello, World!");
    return 42;
}

void another_function(int x, int y) {
    printf("%d", x + y);
}
''',
    'GO': '''
func helloWorld() int {
    fmt.Println("Hello, World!")
    return 42
}

func anotherFunction(x int, y int) int {
    return x + y
}
''',
    'JS': '''
function helloWorld() {
    console.log("Hello, World!");
    return 42;
}

const anotherFunction = (x, y) => {
    return x + y;
};
''',
    'Java': '''
public class Test {
    public int helloWorld() {
        System.out.println("Hello, World!");
        return 42;
    }
    
    public int anotherFunction(int x, int y) {
        return x + y;
    }
}
''',
    'C++': '''
int hello_world() {
    std::cout << "Hello, World!" << std::endl;
    return 42;
}

void another_function(int x, int y) {
    std::cout << x + y << std::endl;
}
''',
    'C#': '''
public class Test {
    public int HelloWorld() {
        Console.WriteLine("Hello, World!");
        return 42;
    }
    
    public int AnotherFunction(int x, int y) {
        return x + y;
    }
}
'''
}

def test_language(lang_name, config):
    """测试单个语言的TreeSitter解析"""
    print(f"\n{'='*60}")
    print(f"测试语言: {lang_name}")
    print(f"{'='*60}")
    
    try:
        # 获取配置
        lang_config = config['data_preprocess'].get(lang_name)
        if not lang_config:
            print(f"❌ 配置文件中未找到 {lang_name} 的配置")
            return
        
        print(f"配置信息:")
        print(f"  - language: {lang_config.get('language')}")
        print(f"  - function_types: {lang_config.get('function_types')}")
        print(f"  - post_fix: {lang_config.get('post_fix')}")
        
        # 初始化解析器
        try:
            parser = TreeSitterParse(lang_config)
            print(f"✓ TreeSitterParse 初始化成功")
        except Exception as e:
            print(f"❌ TreeSitterParse 初始化失败: {e}")
            return
        
        # 解析测试代码
        test_code = test_codes.get(lang_name, '')
        if not test_code:
            print(f"❌ 没有测试代码")
            return
        
        try:
            tree = parser.parse_code(test_code)
            print(f"✓ 代码解析成功")
        except Exception as e:
            print(f"❌ 代码解析失败: {e}")
            import traceback
            traceback.print_exc()
            return
        
        # 提取函数
        try:
            functions = parser.get_functions(tree)
            print(f"✓ 函数提取成功，找到 {len(functions)} 个函数")
            for i, (func_name, func_node) in enumerate(functions, 1):
                func_code = func_node.text.decode('utf-8')
                lines = func_code.split('\n')
                preview = lines[0][:60] if lines else ''
                print(f"  {i}. {func_name}: {preview}...")
        except Exception as e:
            print(f"❌ 函数提取失败: {e}")
            import traceback
            traceback.print_exc()
            return
            
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()

def main():
    # 加载配置
    config_path = Path(__file__).parent / 'data_preprocess.yaml'
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.load(f, Loader=yaml.FullLoader)
    
    print("TreeSitter语言解析测试")
    print("=" * 60)
    
    # 测试所有语言
    languages = ['Python', 'C', 'GO', 'JS', 'Java', 'C++', 'C#']
    
    for lang in languages:
        test_language(lang, config)
    
    print(f"\n{'='*60}")
    print("测试完成")
    print(f"{'='*60}")

if __name__ == '__main__':
    main()

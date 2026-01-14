# REEF 数据集处理快速启动指南

## 已完成的工作

✅ 完整实现了REEF数据集到PrimeVul格式的转换流程
✅ 测试验证了所有核心功能
✅ 创建了完整的文档

## 文件说明

### 核心脚本

1. **build_primevul_dataset.py** - 主要的数据集构建脚本
   - 完整实现所有功能（URL解析、patch反打、函数提取、标记等）
   - 支持批量处理REEF数据集
   - 自动生成两个输出文件

2. **test_build_dataset.py** - 单元测试脚本
   - 测试数据加载
   - 测试URL解析
   - 测试语言检测

3. **simple_test.py** - 简化测试脚本
   - Patch反打补丁演示
   - REEF样本处理演示
   - 文件名提取演示

### 现有脚本（参考）

- **tree_sitter_parse.py** - TreeSitter解析器
- **extract_func_pair.py** - 函数对提取
- **reef_preprocess.py** - REEF数据预处理
- **reef_visualization.py** - 数据可视化

## 快速开始

### 1. 环境准备

```bash
cd /home/m1hu/pre-data

# 激活虚拟环境（如果需要）
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

### 2. 运行测试

```bash
# 基础测试
python src/test_build_dataset.py

# 详细测试（包括patch演示）
python src/simple_test.py
```

### 3. 构建数据集

```bash
# 处理C++数据集
python src/build_primevul_dataset.py
```

## 输出文件

处理完成后会在 `data/output/` 目录生成：

1. **reef_labeled_functions.csv**
   - 包含所有函数及其标签（vulnerable/benign）
   - 包含元数据（CVE、CWE、文件名等）

2. **reef_vulnerability_pairs.csv**
   - 包含漏洞函数对（修复前/修复后）
   - 用于训练修复模型

## 数据处理流程总结

```
输入: query_C++.jsonl (REEF原始数据)
  │
  ├─> 1. 从GitHub API获取commit信息
  │       - 文件名
  │       - 文件状态 (modified/added/deleted)
  │       - 变更统计
  │
  ├─> 2. 应用反向patch
  │       - 输入: raw_code (修复后) + patch
  │       - 输出: code_before (修复前)
  │
  ├─> 3. TreeSitter提取函数
  │       - 解析修复前后代码
  │       - 识别变更的函数
  │       - 提取未变更的函数
  │
  ├─> 4. OneFunc标记
  │       - 单函数变更 → 标记
  │       - 多函数变更 → 丢弃
  │
  ├─> 5. NVDCheck验证
  │       - 函数名在CVE描述中 → vulnerable
  │       - 文件名在CVE描述中 → 检查
  │
  └─> 输出:
        - reef_labeled_functions.csv
        - reef_vulnerability_pairs.csv
```

## 关键功能实现

### 1. URL解析与文件名提取
```python
# 从GitHub raw URL提取文件路径
from urllib.parse import unquote
filepath = unquote(raw_url.split('/raw/')[-1].split('/', 1)[-1])
```

### 2. Patch反打补丁
```python
# 使用patch命令反向应用补丁
subprocess.run(['patch', '-R', '-i', patch_file, before_file])
```

### 3. 函数对提取
```python
# 使用TreeSitter解析代码
parser = TreeSitterParse(lang_config)
tree = parser.parse_code(source_code)
functions = parser.get_functions(tree)
changed_funcs = parser.compare_functions(tree_before, tree_after)
```

### 4. OneFunc标记
```python
if len(func_pairs) == 1:
    func_before -> label: 'vulnerable'
    func_after -> label: 'benign'
    unchanged_funcs -> label: 'benign'
elif len(func_pairs) > 1:
    discard_sample()
```

### 5. NVDCheck
```python
if func_name in nvd_description:
    label = 'vulnerable'
if filename in nvd_description and len(func_pairs) == 1:
    apply_onefunc_logic()
```

## 配置文件

`src/data_preprocess.yaml` 包含各语言的配置：

```yaml
C++:
  language: 'CPP'
  comment_types: ['comment']
  function_types: ['function_definition']
  string_types: ['string_literal', 'raw_string_literal', 'char_literal']
  post_fix: 'cpp'
  target_file_types: ['cpp', 'cc', 'cxx']
```

## 扩展到其他语言

要处理其他语言的REEF数据集：

1. 修改 `build_primevul_dataset.py` 的 `main()` 函数
2. 更改输入文件名：
   ```python
   jsonl_file = builder.raw_dir / 'query_Python.jsonl'  # Python
   jsonl_file = builder.raw_dir / 'query_Java.jsonl'    # Java
   # 等等
   ```

## 注意事项

1. **GitHub API限流**
   - 未认证: 60次/小时
   - 认证后: 5000次/小时
   - 建议配置 GitHub Token

2. **NVD数据文件**
   - 文件很大 (>50MB)
   - 加载需要时间
   - 如果没有会自动跳过NVDCheck

3. **TreeSitter依赖**
   - 需要预编译语法文件
   - 已在 `tree_sitter_parse.py` 中实现

4. **Patch命令**
   - 必须安装系统的 `patch` 工具
   - Ubuntu/Debian: `sudo apt-get install patch`

## 性能优化建议

1. **缓存GitHub API响应**
   - 已实现在 `data/cache/commit_info/` 
   - 避免重复请求

2. **批量处理**
   - 可以分批处理大数据集
   - 使用tqdm显示进度

3. **并行处理**
   - 可以使用多进程加速
   - 注意API限流

## 故障排除

### 问题: 模块导入错误
```bash
# 解决方案
pip install -r requirements.txt
```

### 问题: Patch命令失败
```bash
# 检查patch是否安装
which patch

# 安装patch
sudo apt-get install patch
```

### 问题: TreeSitter编译错误
```bash
# 确保有编译工具
sudo apt-get install build-essential

# 检查语法文件目录
ls tools/tree-sitter-*
```

## 联系与支持

如有问题，请检查：
1. README_BUILD_DATASET.md - 完整文档
2. 示例代码中的注释
3. 测试脚本的输出

## 下一步

1. 运行完整数据集处理
2. 分析输出结果
3. 根据需要调整标记策略
4. 扩展到其他编程语言

---

**版本**: 1.0  
**更新日期**: 2026-01-06  
**状态**: 已完成并测试

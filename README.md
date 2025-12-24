# query_C++.jsonl 数据处理管线

完整的 PrimeVul 风格数据处理管线，用于处理 `query_C++.jsonl` 数据集并生成漏洞标注数据。

## 项目概述

本项目实现了完整的函数级漏洞标注系统，基于 PrimeVul 论文方法：
- **ONEFUNC 标注**: 检测单函数修改的安全补丁
- **NVDCheck 标注**: 基于 CVE 描述的补充标注
- **函数匹配**: 在原始代码和补丁之间匹配函数
- **时间切分**: 基于 CVE 年份的训练/验证/测试划分 //待修改

## 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 运行完整管线
python src/query_cpp_pipeline.py

# 或使用虚拟环境
source venv/bin/activate
python src/query_cpp_pipeline.py
```

## 数据集结构

### 输入格式
`data/raw/query_C++.jsonl`:
```json
{
  "index": 84,
  "cve_id": "CVE-2022-47015",
  "language": "C++",
  "cvss": "9.8",
  "origin_message": "fixed overflow vulnerability",
  "url": "https://github.com/...",
  "details": [
    {
      "raw_url": "https://github.com/.../file.cpp",
      "raw_code": "...",
      "patch": "@@ -100,5 +100,7 @@ function_name..."
    }
  ]
}
```

### 输出文件

所有输出保存在 `data/output/`:

| 文件 | 描述 | 大小 | 记录数 | Vulnerable |
|------|------|------|--------|-----------|
| `query_cpp_all.csv` | 完整数据集 | 44.9 MB | 1064 | 149 (14.0%) |
| `query_cpp_train.csv` | 训练集 (2012-2020) | 38.2 MB | 851 | 127 (14.9%) |
| `query_cpp_dev.csv` | 验证集 (2020-2021) | 3.6 MB | 106 | 11 (10.4%) |
| `query_cpp_test.csv` | 测试集 (2021-2023) | 3.2 MB | 107 | 11 (10.3%) |
| `query_cpp_paired.csv` | Vulnerable 子集 | 12.7 MB | 149 | 149 (100%) |

## 处理流程

### 1. 数据加载与扁平化
```
411 CVE records → 1184 detail records
```
- 读取 JSONL 文件
- 将每个 CVE 的 `details` 数组展开为独立记录

### 2. 去重
```
1184 records → 1064 records (-120 duplicates)
```
- 对 `raw_code` 进行标准化（移除空白符）
- 基于 MD5 哈希去重

### 3. 函数匹配与 ONEFUNC 标注
```
Patch 函数检测: 2334 functions detected
Raw_code 匹配: 996 functions matched (42.7% match rate)
ONEFUNC 标注: 149 vulnerable samples
```

**核心逻辑** (基于 PrimeVul 论文):
```python
if changed_functions_total == 1:  # 补丁仅修改一个函数
    if len(matched) == 1:          # 且该函数在原始代码中
        label = 'vulnerable'       # 标记为漏洞
```

**关键特性**:
- 从 patch 的 unified diff 中提取函数名
- 支持 C++ 限定名 (`Class::method`)
- 支持模板函数 (`Class<T>::method`)
- 严格遵循"单函数修改"原则

### 4. NVDCheck 标注
```
NVD 数据: 34,665 CVE entries loaded
新增标注: 0 samples (时间不匹配)
```

**标注规则**:
1. **Rule 1**: CVE 描述中明确提到函数名 → vulnerable
2. **Rule 2**: CVE 描述提到文件名 + 该文件仅修改 1 个函数 → vulnerable

**当前状态**:
- ✅ 完全集成，支持 NVD API 2.0 格式
- ⚠️ 数据集 CVE 年份 (2012-2023) vs NVD 数据年份 (2025) 不匹配
- 需要获取历史 NVD 数据以激活此功能

### 5. 时间切分
```
Train: 851 samples (2012-2020) - 127 vulnerable (14.9%)
Dev:   106 samples (2020-2021) - 11 vulnerable (10.4%)
Test:  107 samples (2021-2023) - 11 vulnerable (10.3%)
```

- 从 CVE ID 提取年份
- 按时间顺序排序后 80/10/10 划分
- 避免数据泄露

## 输出字段说明

| 列名 | 类型 | 描述 |
|------|------|------|
| `source_id` | str | 唯一标识符 `{index}_{file_index}` |
| `cve_id` | str | CVE 编号 |
| `cve_year` | int | CVE 年份 |
| `file_index` | int | 文件在 details 数组中的索引 |
| `language` | str | 编程语言 (C++) |
| `cvss` | float | CVSS 评分 |
| `origin_message` | str | 原始提交消息 |
| `url` | str | GitHub 提交 URL |
| `raw_url` | str | 源文件 URL |
| `raw_code` | str | 原始代码（漏洞版本） |
| `patch` | str | Unified diff 补丁 |
| `label` | str | 标签: `vulnerable` / `None` |
| `labeling_method` | str | 标注方法: `onefunc` / `None` |
| `changed_functions_total` | int | 补丁修改的函数总数 |
| `changed_functions_names` | str | 修改的函数名列表（逗号分隔） |
| `matched_functions_names` | str | 在 raw_code 中匹配的函数名 |
| `split` | str | 数据集划分: `train` / `dev` / `test` |

## 核心算法说明

### 函数提取（从 Patch）

从 unified diff 的 `@@ ... @@ function_context` 提取函数名：

```python
# 示例 1: C++ 成员函数
@@ -238,12 +238,16 @@ void SmallVectorTemplateBase<T, isPodLike>::grow(size_t MinSize) {
→ 提取: SmallVectorTemplateBase<T, isPodLike>::grow

# 示例 2: 命名空间函数
@@ -100,5 +100,8 @@ static int connect(int sockfd) {
→ 提取: connect

# 示例 3: 模板函数
@@ -50,3 +50,5 @@ template<typename T> void process(T value) {
→ 提取: process
```

**支持的 C++ 语法**:
- 限定名: `namespace::Class::method`
- 模板: `Class<T, U>::method<V>`
- 操作符重载: `operator+`, `operator[]`
- 构造/析构函数: `Class::Class()`, `Class::~Class()`

### 函数匹配（在 Raw Code）

在 `raw_code` 中搜索提取的函数定义：

```python
# 匹配模式
\b(?:[\w:]+::)?function_name\s*\(

# 示例
"void SmallVectorTemplateBase<T>::grow(size_t MinSize) {"
→ 匹配成功: grow
```

**过滤规则**:
- 排除关键字: `if`, `for`, `while`, `switch`, `template`, `typename`
- 排除过短函数名: 长度 < 2
- 排除纯符号: `operator` 必须在前

### ONEFUNC 判断逻辑

```python
# 统计补丁修改的函数总数
changed_functions_total = count_unique_functions_in_patch(patch)

# 匹配到 raw_code 中的函数
matched_functions = find_functions_in_raw_code(raw_code, changed_functions)

# 标注逻辑
if changed_functions_total == 1:      # 关键: 补丁仅修改 1 个函数
    if len(matched_functions) == 1:   # 且该函数在 raw_code 中
        label = 'vulnerable'
    else:
        label = 'onefunc_unmatched'   # 函数未在 raw_code 中找到
else:
    label = None                       # 多函数修改，不符合 ONEFUNC
```

## 统计摘要

```
总输入: 411 CVE records
扁平化: 1184 detail records
去重后: 1064 unique records

函数检测:
  - Patch 中检测到的函数: 2334
  - 在 Raw_code 中匹配的函数: 996
  - 匹配率: 42.7%

ONEFUNC 标注:
  - Changed == 1 且 Matched == 1: 149 (vulnerable)
  - Changed == 1 但 Matched == 0: 31 (onefunc_unmatched)
  - Changed != 1: 884 (无标签)

数据集划分:
  - Train: 851 (80.0%) - 127 vulnerable (14.9%)
  - Dev:   106 (10.0%) - 11 vulnerable (10.4%)
  - Test:  107 (10.0%) - 11 vulnerable (10.3%)

输出文件: 5 个 CSV, 总计 102.6 MB
```

## 文件结构

```
pre-data/
├── README.md                          # 本文档
├── QUERY_CPP_PIPELINE.md              # 详细技术文档（旧版）
├── requirements.txt                   # Python 依赖
├── config.py                          # 配置文件
├── main.py                            # 主入口（待更新）
├── data/
│   ├── raw/
│   │   ├── query_C++.jsonl           # 输入数据
│   │   ├── diversevul_20230702.json  # DiverseVul 数据
│   │   └── nvd_cve_descriptions.json # NVD CVE 描述
│   ├── processed/                     # 中间处理文件
│   └── output/                        # 最终输出
│       ├── query_cpp_all.csv
│       ├── query_cpp_train.csv
│       ├── query_cpp_dev.csv
│       ├── query_cpp_test.csv
│       └── query_cpp_paired.csv
└── src/
    ├── query_cpp_pipeline.py          # 主处理管线
    ├── code_function_matcher.py       # 函数匹配模块
    ├── primevul_nvdcheck.py           # NVDCheck 标注
    ├── primevul_onefunc.py            # ONEFUNC 标注（legacy）
    ├── primevul_label_utils.py        # 标签合并工具
```

## 配置说明

编辑 `config.py` 自定义路径：

```python
# 输入数据
QUERY_CPP_FILE = "data/raw/query_C++.jsonl"
NVD_DATA_PATH = "data/raw/nvd_cve_descriptions.json"

# 输出目录
OUTPUT_DIR = "data/output"

# 数据集划分比例
SPLIT_CONFIG = {
    "train": 0.8,
    "dev": 0.1,
    "test": 0.1
}
```

## 依赖项

```
Python >= 3.8
pandas >= 1.3.0
hashlib (标准库)
re (标准库)
json (标准库)
```

安装所有依赖:
```bash
pip install -r requirements.txt
```

## 使用示例

### 基础使用

```python
from src.query_cpp_pipeline import QueryCppPipeline

# 运行完整管线
pipeline = QueryCppPipeline()
pipeline.run()
```

### 自定义配置

```python
pipeline = QueryCppPipeline(
    input_file="data/raw/query_C++.jsonl",
    output_dir="data/output",
    train_ratio=0.8,
    dev_ratio=0.1
)
pipeline.run()
```


### 当前限制

1. **函数名提取依赖 Patch 格式**
   - 需要 `@@ ... @@ function_context` 格式
   - 部分 patch 缺少函数上下文 → 无法提取函数名
   - 改进方向: 使用 AST 解析 raw_code

2. **C++ 语法支持不完整**
   - 支持: 限定名、模板、操作符重载
   - 不支持: Lambda 表达式、宏定义函数
   - 改进方向: 集成 Clang AST

3. **无 Benign 标注**
   - 数据集仅含漏洞代码
   - 无法训练对比学习模型
   - 改进方向: 使用 Git 历史获取修复后代码

## 引用

如果使用本代码，请引用 PrimeVul 论文:

```bibtex
@article{li2022primevul,
  title={PrimeVul: Interpreting Deep Learning-based Vulnerability Detector Predictions Based on Heuristic Searching},
  author={Li, Yi and Wang, Shaohua and Nguyen, Tien N.},
  journal={ACM Transactions on Software Engineering and Methodology (TOSEM)},
  year={2022}
}
```

## License

本项目遵循 MIT License。详见 [LICENSE](LICENSE) 文件。

## 更新日志

### v1.1 (2024-12-24)
- ✅ 修复 ONEFUNC 逻辑错误（changed vs matched）
- ✅ 添加完整的函数匹配统计
- ✅ 集成 NVD API 2.0 支持
- ✅ 验证 PrimeVul 论文合规性

### v1.0 (2024-12-23)
- ✅ 初始实现：函数匹配、ONEFUNC、时间切分
- ✅ 生成 5 个输出 CSV 文件
- ✅ 支持 C++ 限定名和模板

## 联系方式

如有问题或建议，请提交 Issue 或 Pull Request。

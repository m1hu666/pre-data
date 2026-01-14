# REEF数据集构建使用指南

## 概述

本项目实现了将REEF数据集按照PrimeVul的构建方法进行处理，生成带标签的函数数据集和漏洞函数对数据集。

## 主要功能

1. **URL获取文件信息**：从GitHub API获取commit信息，提取filename和file status
2. **反向patch应用**：使用修复后的代码和patch反向生成修复前的代码
3. **TreeSitter函数提取**：提取修复前后的函数对
4. **OneFunc标记**：只有一个变更函数对时进行标记
5. **NVDCheck验证**：使用NVD描述进行额外验证

## 使用方法

### 1. 基本使用

```bash
# 处理全部数据
python src/build_primevul_dataset.py

# 处理指定数量的样本（用于测试）
python src/build_primevul_dataset.py --max-samples 10

# 指定输入文件
python src/build_primevul_dataset.py --input query_Python.jsonl
```

### 2. GitHub API速率限制

GitHub API对未认证请求有速率限制（每小时60次）。为避免这个限制，需要使用GitHub Token：

#### 创建GitHub Token

1. 访问 https://github.com/settings/tokens
2. 点击 "Generate new token" -> "Generate new token (classic)"
3. 设置名称，如 "REEF Dataset Builder"
4. 选择权限：只需要 `public_repo` 权限
5. 点击 "Generate token"
6. 复制生成的token（只显示一次！）

#### 使用GitHub Token

方法1：环境变量（推荐）
```bash
export GITHUB_TOKEN="your_token_here"
python src/build_primevul_dataset.py
```

方法2：在脚本中修改
编辑 `src/build_primevul_dataset.py`，在 `fetch_commit_info` 方法中添加token：

```python
headers = {
    'Authorization': 'token YOUR_GITHUB_TOKEN',
    'Accept': 'application/vnd.github.v3+json'
}
response = requests.get(url, headers=headers, timeout=30)
```

### 3. 输出文件

处理完成后，会在 `data/output/` 目录下生成两个CSV文件：

1. **reef_labeled_functions.csv** - 带标签的函数数据集
   - 字段：func_name, func_code, label, source, cve_id, language, filename, file_status, project_language, cvss, cwe
   - label取值：vulnerable（漏洞函数）, benign（正常函数）

2. **reef_vulnerability_pairs.csv** - 漏洞函数对数据集
   - 字段：func_name, func_before, func_after, cve_id, language, filename, cwe, cvss, project_language
   - 包含修复前后的函数代码对

### 4. 单样本测试

```bash
# 测试单个样本的处理
python src/test_build_single.py
```

## OneFunc和NVDCheck策略

### OneFunc策略

- 如果一个文件的变更中只有一个函数对发生变化：
  - 修复前函数标记为 `vulnerable`
  - 修复后函数标记为 `benign`
  - 文件中其他未变更的函数标记为 `benign`
- 如果有多个函数对变更：丢弃该样本

### NVDCheck策略

使用CVE的NVD描述进行额外验证：
- 如果函数名在描述中被提及：标记为 `vulnerable`
- 如果文件名在描述中被提及，且只有一个变更函数：按OneFunc方法标记

## 数据统计

处理完成后会显示统计信息：
- `total_samples`: 总样本数
- `successful_patch`: 成功应用patch的样本数
- `failed_patch`: patch应用失败的样本数
- `onefunc_labeled`: OneFunc标记的函数数
- `nvdcheck_labeled`: NVDCheck标记的函数数
- `discarded_multi_func`: 因多函数变更而丢弃的样本数

## 支持的语言

- C
- C++ (.cpp, .cc, .cxx)
- Python (.py)
- Java (.java)
- JavaScript (.js)
- Go (.go)
- C# (.cs)

## 依赖要求

```bash
pip install -r requirements.txt
```

主要依赖：
- tree-sitter==0.21.3 (用于代码解析)
- unidiff (用于patch处理)
- requests (用于API请求)
- pandas (用于数据处理)
- PyYAML (用于配置文件)

## TreeSitter语言解析器设置

首次运行前需要设置TreeSitter语言解析器：

```bash
chmod +x setup_tree_sitter.sh
./setup_tree_sitter.sh
```

这会自动克隆所有支持语言的tree-sitter解析器到 `tools/` 目录。

## 常见问题

### 1. GitHub API 403错误

原因：达到GitHub API速率限制
解决：使用GitHub Token（见上文）

### 2. TreeSitter编译失败

原因：缺少C编译器或tree-sitter语言解析器
解决：
```bash
# Ubuntu/Debian
sudo apt-get install build-essential

# 运行设置脚本
./setup_tree_sitter.sh
```

### 3. Patch应用失败

原因：patch格式不正确或代码不匹配
影响：该样本会被跳过，不影响其他样本处理

### 4. 内存不足

原因：处理大量数据时内存消耗较大
解决：使用 `--max-samples` 参数分批处理

## 性能优化

1. **缓存机制**：commit信息会缓存到 `data/cache/commit_info/`，避免重复请求
2. **并行处理**：可以将数据集分割后并行处理
3. **批量处理**：使用 `--max-samples` 控制每批处理的样本数

## 示例工作流

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 设置TreeSitter
./setup_tree_sitter.sh

# 3. 设置GitHub Token
export GITHUB_TOKEN="your_token_here"

# 4. 小批量测试
python src/build_primevul_dataset.py --max-samples 10

# 5. 检查结果
head data/output/reef_labeled_functions.csv
head data/output/reef_vulnerability_pairs.csv

# 6. 完整处理
python src/build_primevul_dataset.py
```

## 输出示例

### reef_labeled_functions.csv
```csv
func_name,func_code,label,source,cve_id,language,filename,file_status,project_language,cvss,cwe
exec_query_2000,"int spider_db_mbase::exec_query(...)",vulnerable,onefunc,CVE-2023-24832,C++,storage/spider/spd_db_mysql.cc,modified,C++,7.5,CWE-89
exec_query_2000,"int spider_db_mbase::exec_query(...)",benign,onefunc,CVE-2023-24832,C++,storage/spider/spd_db_mysql.cc,modified,C++,7.5,CWE-89
```

### reef_vulnerability_pairs.csv
```csv
func_name,func_before,func_after,cve_id,language,filename,cwe,cvss,project_language
exec_query_2000,"int spider_db_mbase::exec_query(...修复前...)","int spider_db_mbase::exec_query(...修复后...)",CVE-2023-24832,C++,storage/spider/spd_db_mysql.cc,CWE-89,7.5,C++
```

## 许可证

本项目继承原项目的许可证。详见 LICENSE 文件。

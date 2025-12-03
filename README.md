# PrimeVul 数据集构建工具

本仓库实现了论文 *"Vulnerability Detection with Code Language Models: How Far Are We"* 中 PrimeVul 数据集的完整构建流程。

##  目录

- [概述](#概述)
- [数据集构建流程](#数据集构建流程)
- [安装](#安装)
- [使用方法](#使用方法)
- [数据格式](#数据格式)
- [项目结构](#项目结构)
- [配置说明](#配置说明)

##  概述

PrimeVul 是一个高质量的代码漏洞检测数据集，通过严格的数据去重和精确的标注方法构建而成。本仓库提供了从原始数据到最终数据集的完整处理流程。

### 主要特性

- **彻底去重**: 基于 MD5 哈希的函数级去重，消除训练/测试泄露
- **精确标注**: 
  - OneFunc: 针对单函数修改的 commits
  - NVDCheck: 基于 NVD 描述的精确匹配
- **时间划分**: 按 commit 时间进行 80/10/10 划分，模拟真实场景
- **成对数据**: 构建 vulnerable-patch 函数对，用于深度分析

##  数据集构建流程

```
原始数据 (BigVul, CrossVul, CVE/fixes, DiverseVul)
    ↓
1. 数据合并与规范化
    ↓
2. 彻底去重 (MD5 哈希 + 文本规范化)
    ↓
3. OneFunc 标注 (单函数修改) 4. NVDCheck 标注 (基于 NVD 描述)
    ↓
5. 时间划分 (Train 80% / Dev 10% / Test 10%)
    ↓
6. 构建成对函数 (>80% 相似度)
    ↓
最终数据集 (All + Paired 版本)
```

##  安装

### 要求

- Python 3.7+
- pandas
- numpy
- tqdm
- scikit-learn

### 安装步骤

```bash
# 克隆仓库
git clone https://github.com/m1hu666/PrimeVul.git
cd PrimeVul

# 安装依赖
pip install -r requirements.txt
```

##  使用方法

### 1. 准备原始数据

将原始数据文件放置在 `data/raw/` 目录下：

```
data/raw/
├── bigvul.csv
├── crossvul.csv
├── cve_fixes.csv
├── diversevul.csv
└── nvd_cve_descriptions.json
```

**数据格式要求** (CSV):

- `commit_id`: Commit 标识符
- `func_before`: 修改前的函数代码
- `func_after`: 修改后的函数代码
- `cve_id`: CVE 编号 (可选)
- `commit_time`: Commit 时间戳
- `file_path`: 文件路径
- `func_name`: 函数名 (可选)
- `is_security_related`: 是否为安全相关 commit

### 2. 运行数据处理流程

```bash
# 运行完整流程
python main.py
```

### 3. 输出结果

处理完成后，数据集将保存在 `data/output/` 目录：

```
data/output/
├── train_all.csv          # 训练集 (所有样本)
├── dev_all.csv            # 验证集 (所有样本)
├── test_all.csv           # 测试集 (所有样本)
├── train_paired.csv       # 训练集 (成对样本)
├── dev_paired.csv         # 验证集 (成对样本)
├── test_paired.csv        # 测试集 (成对样本)
└── dataset_statistics.json # 统计信息
```

##  数据格式

### All 版本 (所有样本)

| 列名 | 描述 |
|------|------|
| `commit_id` | Commit 唯一标识符 |
| `func_after` | 函数代码 (post-commit 版本) |
| `label` | 标签 (`vulnerable` 或 `benign`) |
| `labeling_method` | 标注方法 (`onefunc` 或 `nvdcheck`) |
| `cve_id` | CVE 编号 |
| `file_path` | 文件路径 |
| `func_name` | 函数名 |
| `commit_time` | Commit 时间戳 |
| `split` | 数据划分 (`train`, `dev`, `test`) |

### Paired 版本 (成对样本)

| 列名 | 描述 |
|------|------|
| `pair_id` | 函数对唯一标识符 |
| `vuln_code` | Vulnerable 函数代码 |
| `patch_code` | Patch (修复后) 函数代码 |
| `vuln_commit_id` | Vulnerable commit ID |
| `patch_commit_id` | Patch commit ID |
| `similarity` | 相似度分数 (0-1) |
| `cve_id` | CVE 编号 |
| `split` | 数据划分 |

##  项目结构

```
PrimeVul/
├── config.py                 # 配置文件
├── main.py                   # 主流程脚本
├── requirements.txt          # 依赖列表
├── README.md                 # 说明文档
├── src/
│   ├── data_loader.py        # 数据加载模块
│   ├── deduplication.py      # 去重模块
│   ├── labeling_onefunc.py   # OneFunc 标注
│   ├── labeling_nvdcheck.py  # NVDCheck 标注
│   ├── temporal_split.py     # 时间划分
│   ├── paired_functions.py   # 成对函数构建
│   └── utils.py              # 工具函数
├── data/
│   ├── raw/                  # 原始数据
│   ├── processed/            # 中间处理数据
│   └── output/               # 最终输出
└── examples/
    └── analyze_dataset.py    # 数据集分析示例
```

##  配置说明

编辑 `config.py` 以自定义数据处理流程：

```python
# 数据源配置
DATA_SOURCES = {
    'bigvul': 'data/raw/bigvul.csv',
    'crossvul': 'data/raw/crossvul.csv',
    # ...
}

# 标注配置
LABELING_CONFIG = {
    'onefunc_enabled': True,
    'nvdcheck_enabled': True,
    'min_similarity_for_paired': 0.8,  # 成对函数最小相似度
}

# 数据集划分配置
SPLIT_CONFIG = {
    'train_ratio': 0.8,
    'dev_ratio': 0.1,
    'test_ratio': 0.1,
    'temporal_split': True,  # 使用时间划分
}
```

##  测试单个模块

每个模块都可以独立测试：

```bash
# 测试去重模块
python src/deduplication.py

# 测试 OneFunc 标注
python src/labeling_onefunc.py

# 测试 NVDCheck 标注
python src/labeling_nvdcheck.py

# 测试时间划分
python src/temporal_split.py

# 测试成对函数构建
python src/paired_functions.py
```

##  数据集统计

运行完成后，查看 `data/output/dataset_statistics.json` 获取详细统计信息：

```json
{
  "initial_count": 235768,
  "total_processed": 235768,
  "duplicates_found": 50234,
  "unique_functions": 185534,
  "vulnerable_count": 6968,
  "benign_count": 228800,
  "train_total": 184427,
  "dev_total": 25430,
  "test_total": 25911,
  "paired_count": 5480
}
```

##  高级用法

### 自定义数据加载器

```python
from src.data_loader import DataLoader

# 创建自定义加载器
loader = DataLoader({
    'my_dataset': 'path/to/my_data.csv'
})

# 加载数据
data = loader.merge_all()
```

### 单独使用去重功能

```python
from src.deduplication import deduplicate_dataset
import pandas as pd

data = pd.read_csv('my_data.csv')
deduplicated, stats = deduplicate_dataset(data, has_before_after=True)
```

### 自定义标注规则

```python
from src.labeling_onefunc import OneFuncLabeler

labeler = OneFuncLabeler()
labeled_data = labeler.label_dataset(your_data)
```

##  引用

如果您使用本数据集或代码，请引用原论文：

```bibtex
@inproceedings{primevul2023,
  title={Vulnerability Detection with Code Language Models: How Far Are We},
  author={...},
  booktitle={...},
  year={2023}
}
```

##  许可证

本项目采用 MIT 许可证。

##  贡献

欢迎提交 Issue 和 Pull Request！

##  联系方式

如有问题，请通过 GitHub Issues 联系。

---

**注意**: 本仓库仅提供数据处理代码框架。原始数据需要从相应的数据源获取：
- BigVul: [链接]
- CrossVul: [链接]
- CVE/fixes: [链接]
- DiverseVul: [链接]
- NVD: https://nvd.nist.gov/

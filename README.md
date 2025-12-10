# PrimeVul-Style Processing for DiverseVul

本仓库基于论文 *“Vulnerability Detection with Code Language Models: How Far Are We?”*，对 **DiverseVul** 单一数据源实现 PrimeVul 风格的数据处理流程，包括：

- 函数级去重（规范化 + MD5）
- PrimeVul-OneFunc 标注
- PrimeVul-NVDCheck 标注
- 按“伪时间”划分 Train / Dev / Test
- 构建 vulnerable–benign 成对函数子集

---

## 目录结构

- `data/raw/diversevul_20230702.json`：DiverseVul 原始数据（大文件）
- `data/raw/nvd_cve_descriptions.json`：NVD CVE 描述（`CVE -> description` 映射）
- `data/output/`：流水线输出目录
- `src/diversevul_pipeline.py`：DiverseVul 端到端处理脚本
- `src/primevul_onefunc.py`：OneFunc 标注实现
- `src/primevul_nvdcheck.py`：NVDCheck 标注实现（基于 CVE 描述 + 函数名匹配）
- `src/primevul_label_utils.py`：标注辅助函数（提取 CVE、按 commit 汇总标签）

---

## 安装依赖和运行

```bash
cd /home/m1hu/pre-data
pip install -r requirements.txt

# 运行完整 DiverseVul 流水线
python3 -m src.diversevul_pipeline
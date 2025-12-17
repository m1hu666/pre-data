# PrimeVul-Style Processing for DiverseVul

本仓库基于论文 *“Vulnerability Detection with Code Language Models: How Far Are We?”*，对单一数据源实现 PrimeVul 风格的数据处理流程，包括：

- 函数级去重（规范化 + MD5）
- PrimeVul-OneFunc 标注
- PrimeVul-NVDCheck 标注
- 按时间划分 Train / Dev / Test
- 构建 vulnerable–benign 成对函数子集

---

## 目录结构

- `data/raw/diversevul_20230702.json`：DiverseVul 原始数据（大文件）
- `data/raw/nvd_cve_descriptions.json`：NVD CVE 描述（`CVE -> description` 映射）
- `data/output/`：流水线输出目录
- `src/diversevul_pipeline.py`：DiverseVul 端到端处理脚本
- `src/primevul_onefunc.py`：OneFunc 标注实现 //func单独是在commit中单独提及
- `src/primevul_nvdcheck.py`：NVDCheck 标注实现（基于 CVE 描述 + 函数名匹配--同样也是在commit中）
- `src/primevul_label_utils.py`：标注辅助函数（提取 CVE、按 commit 汇总标签）

---

## 安装依赖和运行

```bash
cd /home/m1hu/pre-data
pip install -r requirements.txt

# 运行完整 DiverseVul 流水线
python3 -m src/diversevul_pipeline.py

#record
this week:
1.原本逻辑理解错误，当commit_id为数据集中唯一才将此函数标注为漏洞(筛得只剩五百多条)，现修改为根据repo+commit_id得到patch，扫描pacth看是否此函数是否为此次commit中唯一被修改的函数

@@ -690,8 +710,8 @@ static int func_name
                          ↑ 函数名被 Git 自动标注

onefunc：it’s the only function changed by a security-related commit
nvdcheck：(1) NVD description explicitlymentions its name, or (2) NVD description mentions its filename, and it is the only function changed by the securityrelated commit in that file
merge the sets and deduplicate the functions again

2.diversul包含的仓库很多，取qemu作为一个测试，比较合理

3.时间划分。将按哈希值排序自递增设置时间改为由patch提交时间确定，让commit-time从Git仓库读取真实的补丁提交时间，而不是使用合成时间。

4.论文中所提到的修改前的函数理论上也可以根据patch反向得到。

最后一次info:
[1/6] Loading DiverseVul...
  Loaded 330,492 records from /home/m1hu/pre-data/data/raw/diversevul_20230702.json
[2/6] Deduplicating functions (MD5 over normalized code)...
  Total: 330,492, Unique: 326,907, Duplicates: 3,585 (rate=1.08%)
[3/6] PrimeVul-style labeling (OneFunc + NVDCheck)...
  Attempting to reconstruct func_before from Git diff...
  Reconstructing func_before: 100%|██████████| 326907/326907 [07:40<00:00, 709.26it/s]  
  Successfully reconstructed 92/326907 func_before entries
  After labeling: 3,684 samples (3,684 vulnerable, 0 benign)
[4/6] Temporal-style split (synthetic commit ordering)...
  Fetching commit timestamps from Git...
  Reading commit times: 100%|██████████| 129/129 [00:01<00:00, 106.36it/s]
  Successfully fetched 129/129 commit times from Git
  Train: 3,266  Dev: 62  Test: 356
[5/6] Building paired vulnerable/benign functions...
  Paired functions: 0
[6/6] Saving CSV files to output directory...
  Saved:
    - /home/m1hu/pre-data/data/output/diversevul_all.csv
    - /home/m1hu/pre-data/data/output/diversevul_train.csv
    - /home/m1hu/pre-data/data/output/diversevul_dev.csv
    - /home/m1hu/pre-data/data/output/diversevul_test.csv
    - /home/m1hu/pre-data/data/output/diversevul_paired.csv
Done.
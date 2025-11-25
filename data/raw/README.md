# 示例数据集说明

本目录包含用于测试和演示的示例数据文件。

## 数据源

请将以下数据文件放置在此目录：

### 必需文件

1. **bigvul.csv** - BigVul 数据集
   - 包含大规模的 C/C++ 漏洞数据
   - 格式: commit_id, func_before, func_after, is_vulnerable, cve_id, commit_time, file_path, func_name

2. **crossvul.csv** - CrossVul 数据集
   - 跨项目漏洞数据
   - 格式同上

3. **cve_fixes.csv** - CVE Fixes 数据集
   - 从 CVE 数据库收集的修复
   - 格式同上

4. **diversevul.csv** - DiverseVul 数据集
   - 多样化的漏洞样本
   - 格式同上

### 可选文件

5. **nvd_cve_descriptions.json** - NVD CVE 描述数据
   - NVD (National Vulnerability Database) 中的 CVE 描述
   - 格式:
   ```json
   {
     "CVE-2021-1234": {
       "description": "A vulnerability in the foo function..."
     }
   }
   ```

## 数据格式规范

### CSV 文件列说明

- `commit_id`: 唯一的 commit 标识符
- `func_before`: 修改前的函数代码（完整的函数体）
- `func_after`: 修改后的函数代码（完整的函数体）
- `is_vulnerable`: 布尔值，表示是否为漏洞相关
- `is_security_related`: 布尔值，表示是否为安全相关的 commit
- `cve_id`: CVE 编号（如果有）
- `commit_time`: Commit 时间戳（格式: YYYY-MM-DD HH:MM:SS 或 ISO 8601）
- `file_path`: 文件路径
- `func_name`: 函数名（可选，如果为空将自动提取）

### 示例 CSV 记录

```csv
commit_id,func_before,func_after,is_security_related,cve_id,commit_time,file_path,func_name
abc123,"int foo() { return 1; }","int foo() { return 2; }",true,CVE-2021-1234,2021-01-15 10:30:00,src/foo.c,foo
```

## 数据获取

原始数据可以从以下来源获取：

- **BigVul**: https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset
- **CrossVul**: [链接待补充]
- **CVE/fixes**: https://cve.mitre.org/
- **DiverseVul**: [链接待补充]
- **NVD**: https://nvd.nist.gov/

## 注意事项

1. 数据文件应使用 UTF-8 编码
2. CSV 文件应包含表头
3. 代码字段中的特殊字符应正确转义
4. 时间戳应保持一致的格式
5. 确保 commit_id 在各数据源中的唯一性

## 测试数据

如果您只是想测试代码功能，可以运行：

```bash
python examples/quick_start.py
```

这将自动生成一些示例数据并运行完整流程。

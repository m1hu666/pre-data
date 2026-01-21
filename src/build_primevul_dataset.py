"""
REEF to PrimeVul Dataset Builder
将REEF数据集按照PrimeVul的构建方法进行处理

主要流程：
1. 从URL获取filename和file status (modified/added/deleted)
2. 使用patch反打补丁获取修复前源文件
3. 使用TreeSitter提取函数对
4. OneFunc标记：只有一个变更函数对时标记
5. NVDCheck：使用NVD描述进行验证标记
6. 输出函数数据集和漏洞函数对数据集
"""

import json
import sys
import os
import re
import subprocess
import tempfile
import requests
import warnings
import hashlib
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set
from collections import defaultdict
import pandas as pd
import yaml
from tqdm import tqdm

# 抑制tree-sitter的FutureWarning
warnings.filterwarnings('ignore', category=FutureWarning, module='tree_sitter')
# 添加项目根目录到路径
current_file = Path(__file__)
absolute_path = current_file.resolve()
directory_name = absolute_path.parent
root_dir = directory_name.parent
sys.path.append(str(directory_name))

from tree_sitter_parse import TreeSitterParse


class REEFDatasetBuilder:
    """REEF数据集构建器"""
    
    def __init__(self, config_path: Path):
        """初始化数据集构建器"""
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = yaml.load(f, Loader=yaml.FullLoader)
        
        self.root_dir = root_dir
        self.data_dir = self.root_dir / 'data'
        self.raw_dir = self.data_dir / 'raw' / 'TJU-REEF-SCRIPT'  # 修改为新的数据目录
        self.output_dir = self.data_dir / 'output_tju'  # 使用新的输出目录
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 获取GitHub Token（如果存在）
        self.github_token = os.environ.get('GITHUB_TOKEN', '')
        if self.github_token:
            print(f"使用GitHub Token进行认证（提高API速率限制）")
        else:
            print(f"未设置GitHub Token，API速率限制为60次/小时")
            print(f"建议设置环境变量: export GITHUB_TOKEN='your_token'")
        
        # 加载NVD CVE描述数据（如果存在）
        self.nvd_data = self.load_nvd_data()
        
        # 统计信息
        self.stats = {
            'total_samples': 0,
            'successful_patch': 0,
            'failed_patch': 0,
            'onefunc_labeled': 0,
            'nvdcheck_labeled': 0,
            'discarded_multi_func': 0
        }
    
    @staticmethod
    def normalize_code(code: str) -> str:
        """
        PrimeVul去重方法：规范化代码
        去除空格、制表符、换行符、回车符等字符
        """
        if not code:
            return ""
        # 去除所有空白字符（空格、制表符、换行符、回车符等）
        normalized = re.sub(r'\s+', '', code)
        return normalized
    
    @staticmethod
    def compute_md5(code: str) -> str:
        """计算代码的MD5哈希值"""
        normalized = REEFDatasetBuilder.normalize_code(code)
        return hashlib.md5(normalized.encode('utf-8')).hexdigest()
    
    @staticmethod
    def is_function_changed(func_before: str, func_after: str) -> bool:
        """
        PrimeVul去重方法：判断函数是否真正发生变化
        通过比较规范化后的MD5哈希值来判断
        如果哈希值相同，说明函数没有实际变化
        """
        hash_before = REEFDatasetBuilder.compute_md5(func_before)
        hash_after = REEFDatasetBuilder.compute_md5(func_after)
        return hash_before != hash_after
    
    def load_nvd_data(self) -> Dict:
        """加载NVD CVE描述数据
        
        遍历 NVD 目录下的所有 JSON 文件，构建 CVE ID 到描述的映射
        返回格式: {cve_id: {'description': '...', 'cvss': '...', ...}}
        
        使用缓存机制加速：首次加载后保存到 cveid_description/nvd_cve_cache.json
        """
        # 检查缓存文件
        cache_dir = self.data_dir / 'raw' / 'cveid_description'
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / 'nvd_cve_cache.json'
        
        # 如果缓存存在，直接加载
        if cache_file.exists():
            print(f"从缓存加载NVD数据: {cache_file}")
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cve_dict = json.load(f)
                print(f"NVD数据加载完成，共 {len(cve_dict)} 条CVE")
                return cve_dict
            except Exception as e:
                print(f"加载缓存失败: {e}，将重新构建")
        
        # 缓存不存在，从原始NVD文件加载
        nvd_dir = self.data_dir / 'raw' / 'NVD'
        if not nvd_dir.exists():
            print(f"NVD目录不存在: {nvd_dir}")
            return {}
        
        print(f"正在加载NVD数据: {nvd_dir}")
        cve_dict = {}
        
        # 查找所有 nvdcve-*.json 文件
        json_files = sorted(nvd_dir.glob('nvdcve-*.json'))
        
        if not json_files:
            print(f"未找到NVD JSON文件")
            return {}
        
        print(f"找到 {len(json_files)} 个NVD文件")
        
        for json_file in json_files:
            try:
                print(f"  加载 {json_file.name}...", end='', flush=True)
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # 处理 vulnerabilities 字段 (NVD 2.0 格式)
                vulnerabilities = data.get('vulnerabilities', [])
                
                for item in vulnerabilities:
                    cve = item.get('cve', {})
                    cve_id = cve.get('id', '')
                    
                    if not cve_id:
                        continue
                    
                    # 提取英文描述
                    descriptions = cve.get('descriptions', [])
                    description = ''
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break
                    
                    # 提取 CVSS 分数
                    cvss_score = None
                    metrics = cve.get('metrics', {})
                    cvss_v31 = metrics.get('cvssMetricV31', [])
                    cvss_v30 = metrics.get('cvssMetricV30', [])
                    cvss_v2 = metrics.get('cvssMetricV2', [])
                    
                    if cvss_v31:
                        cvss_score = cvss_v31[0].get('cvssData', {}).get('baseScore')
                    elif cvss_v30:
                        cvss_score = cvss_v30[0].get('cvssData', {}).get('baseScore')
                    elif cvss_v2:
                        cvss_score = cvss_v2[0].get('cvssData', {}).get('baseScore')
                    
                    cve_dict[cve_id] = {
                        'description': description,
                        'cvss': cvss_score,
                        'published': cve.get('published', ''),
                        'lastModified': cve.get('lastModified', '')
                    }
                
                print(f" 完成 ({len(vulnerabilities)} 条CVE)")
                
            except Exception as e:
                print(f"\n  加载 {json_file.name} 失败: {e}")
                continue
        
        print(f"NVD数据加载完成，共 {len(cve_dict)} 条CVE")
        
        # 保存到缓存文件
        try:
            print(f"正在保存NVD数据到缓存: {cache_file}")
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(cve_dict, f, indent=2)
            print(f"缓存保存成功")
        except Exception as e:
            print(f"保存缓存失败: {e}")
        
        return cve_dict
    
    def get_file_extension(self, filename: str) -> str:
        """获取文件扩展名"""
        return Path(filename).suffix.lstrip('.')
    
    def determine_language(self, filename: str) -> Optional[str]:
        """根据文件名确定编程语言"""
        ext = self.get_file_extension(filename)
        
        lang_map = {
            'c': 'C',
            'cpp': 'C++', 'cc': 'C++', 'cxx': 'C++', 'c++': 'C++',
            'py': 'Python',
            'java': 'Java',
            'js': 'JS',
            'go': 'GO',
            'cs': 'C#'
        }
        
        return lang_map.get(ext.lower())
    
    def _extract_function_name(self, func_code: str) -> str:
        """从函数代码中提取函数名"""
        # 简单的正则表达式提取函数名
        # 支持多种语言的函数定义格式
        patterns = [
            r'def\s+(\w+)\s*\(',  # Python
            r'function\s+(\w+)\s*\(',  # JavaScript
            r'func\s+(\w+)\s*\(',  # Go
            r'(\w+)\s*\([^)]*\)\s*{',  # C/C++/Java/C#
        ]
        
        for pattern in patterns:
            match = re.search(pattern, func_code)
            if match:
                return match.group(1)
        
        # 如果都不匹配，返回默认名称
        return "unknown_function"
        
    def extract_commit_date(self, commit_info: Dict) -> Optional[str]:
        """从commit信息中提取日期"""
        try:
            # GitHub API返回的commit信息中包含日期
            commit_date = commit_info.get('commit', {}).get('author', {}).get('date')
            if not commit_date:
                commit_date = commit_info.get('commit', {}).get('committer', {}).get('date')
            return commit_date
        except Exception:
            return None
    
    def fetch_commit_info(self, url: str) -> Optional[Dict]:
        """从GitHub API获取commit信息"""
        try:
            # 添加缓存机制，避免重复请求
            cache_dir = self.data_dir / 'cache' / 'commit_info'
            cache_dir.mkdir(parents=True, exist_ok=True)
            
            # 从URL提取commit hash作为缓存键
            commit_hash = url.split('/')[-1]
            cache_file = cache_dir / f"{commit_hash}.json"
            
            if cache_file.exists():
                with open(cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            
            # 构建请求头（使用GitHub Token进行认证）
            headers = {
                'Accept': 'application/vnd.github.v3+json'
            }
            if self.github_token:
                headers['Authorization'] = f'token {self.github_token}'
            
            # 请求GitHub API
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                # 保存到缓存
                with open(cache_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
                return data
            else:
                # 记录失败原因但不打印详细信息
                self.stats.setdefault('api_failures', {})[response.status_code] = \
                    self.stats.get('api_failures', {}).get(response.status_code, 0) + 1
                return None
        except Exception as e:
            # 记录异常但不打印详细信息
            self.stats['api_exceptions'] = self.stats.get('api_exceptions', 0) + 1
            return None
    
    def apply_reverse_patch(self, source_code: str, patch: str, language: str) -> Optional[str]:
        """使用patch反打补丁获取修复前的代码"""
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_path = Path(tmp_dir)
                
                # 确定文件扩展名
                lang_config = self.config['data_preprocess'].get(language, {})
                post_fix = lang_config.get('post_fix', 'txt')
                
                # 写入修复后的源文件
                after_file = tmp_path / f'after.{post_fix}'
                with open(after_file, 'w', encoding='utf-8') as f:
                    f.write(source_code)
                
                # 写入patch文件
                patch_file = tmp_path / 'fix.patch'
                with open(patch_file, 'w', encoding='utf-8') as f:
                    f.write(patch)
                
                # 反向应用patch (使用-R参数)
                before_file = tmp_path / f'before.{post_fix}'
                
                # 复制after文件到before文件
                subprocess.run(['cp', str(after_file), str(before_file)], check=True)
                
                # 应用反向patch
                cmd = ['patch', '-R', '-s', str(before_file), str(patch_file)]
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                
                if result.returncode == 0:
                    # 读取修复前的代码
                    with open(before_file, 'r', encoding='utf-8') as f:
                        before_code = f.read()
                    return before_code
                else:
                    # 记录patch失败但不打印详细信息
                    return None
                    
        except Exception as e:
            # 记录异常但不打印详细信息
            return None
    
    def extract_function_pairs(
        self, 
        code_before: str, 
        code_after: str, 
        language: str
    ) -> List[Tuple[str, str, str]]:
        """
        使用TreeSitter提取函数对
        返回: [(func_name, func_before, func_after), ...]
        """
        try:
            lang_config = self.config['data_preprocess'].get(language)
            if not lang_config:
                # 静默跳过不支持的语言
                return [], {}
            
            parser = TreeSitterParse(lang_config)
            
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_path = Path(tmp_dir)
                post_fix = lang_config['post_fix']
                
                # 写入临时文件
                before_file = tmp_path / f'before.{post_fix}'
                after_file = tmp_path / f'after.{post_fix}'
                
                with open(before_file, 'w', encoding='utf-8') as f:
                    f.write(code_before)
                with open(after_file, 'w', encoding='utf-8') as f:
                    f.write(code_after)
                
                # 解析代码
                tree_before = parser.parse_code(code_before)
                tree_after = parser.parse_code(code_after)
                
                # 获取函数对
                changed_functions = parser.compare_functions(tree_before, tree_after)
                
                # 提取所有函数（包括未变更的）
                all_funcs_before = parser.get_functions(tree_before)
                all_funcs_after = parser.get_functions(tree_after)
                
                # 构建函数对列表
                func_pairs = []
                changed_func_names = set()
                
                # 添加变更的函数对
                # compare_functions返回: [code_before, code_after, func_name]
                for changed_func in changed_functions:
                    # 获取函数名
                    try:
                        code_before = changed_func[0]
                        code_after = changed_func[1]
                        func_name = changed_func[2]
                        func_pairs.append((func_name, code_before, code_after))
                        changed_func_names.add(func_name)
                    except Exception as e:
                        # 静默跳过失败的函数对
                        continue
                
                # 添加未变更的函数（前后一致）
                unchanged_funcs = {}
                for func_info in all_funcs_after:
                    func_name = func_info[0]
                    func_node = func_info[1]
                    if func_name not in changed_func_names:
                        func_code = func_node.text.decode('utf-8')
                        unchanged_funcs[func_name] = func_code
                
                return func_pairs, unchanged_funcs
                
        except Exception as e:
            # 静默处理异常
            return [], {}
     
    def onefunc_labeling(
        self, 
        func_pairs: List[Tuple[str, str, str]], 
        unchanged_funcs: Dict[str, str]
    ) -> List[Dict]:
        """
        OneFunc标记策略
        - 如果只有一个函数对变更：修复前函数标记为vulnerable，修复后函数和其他函数标记为benign
        - 如果多个函数对变更：返回None（丢弃该数据）
        """
        if len(func_pairs) == 0:
            return None  # 没有变更，丢弃
        
        if len(func_pairs) > 1:
            return None  # 多个变更，丢弃
        
        # 只有一个函数对变更
        labeled_data = []
        
        func_name, func_before, func_after = func_pairs[0]
        
        # 修复前函数标记为vulnerable
        labeled_data.append({
            'func_name': func_name,
            'func_code': func_before,
            'label': 'vulnerable',
            'source': 'onefunc'
        })
        
        # 修复后函数标记为benign
        labeled_data.append({
            'func_name': func_name,
            'func_code': func_after,
            'label': 'benign',
            'source': 'onefunc'
        })
        
        # 其他未变更函数标记为benign
        for func_name, func_code in unchanged_funcs.items():
            labeled_data.append({
                'func_name': func_name,
                'func_code': func_code,
                'label': 'benign',
                'source': 'onefunc_unchanged'
            })
        
        return labeled_data
    
    def nvdcheck_labeling(
        self, 
        cve_id: str, 
        func_pairs: List[Tuple[str, str, str]], 
        unchanged_funcs: Dict[str, str],
        filenames: List[str]
    ) -> Tuple[List[Dict], List[Tuple[str, str, str]]]:
        """
        NVDCheck标记策略
        - 使用CVE-ID查找NVD描述
        - 如果函数名被提及，标记为vulnerable，并返回对应的函数对
        - 如果filename被提及，检查该文件变更函数是否只有一个，按onefunc方法标记
        
        返回: (labeled_data, mentioned_func_pairs)
        """
        if not cve_id or cve_id not in self.nvd_data:
            return [], []
        
        labeled_data = []
        mentioned_func_pairs = []
        description = self.nvd_data[cve_id].get('description', '').lower()
        
        if not description:
            return [], []
        
        # 检查函数名是否被提及
        mentioned_funcs = set()
        for func_name, func_before, func_after in func_pairs:
            # 提取简单函数名（去掉命名空间等）
            simple_name = func_name.split('::')[-1].split('.')[-1]
            if simple_name.lower() in description:
                mentioned_funcs.add(func_name)
                # 标记为vulnerable
                labeled_data.append({
                    'func_name': func_name,
                    'func_code': func_before,
                    'label': 'vulnerable',
                    'source': 'nvdcheck_func_mention'
                })
                # 添加到函数对列表
                mentioned_func_pairs.append((func_name, func_before, func_after))
        
        # 检查filename是否被提及
        for filename in filenames:
            simple_filename = Path(filename).name.lower()
            if simple_filename in description:
                # 如果该文件只有一个变更函数，按onefunc方法标记
                if len(func_pairs) == 1:
                    func_name, func_before, func_after = func_pairs[0]
                    if func_name not in mentioned_funcs:
                        labeled_data.append({
                            'func_name': func_name,
                            'func_code': func_before,
                            'label': 'vulnerable',
                            'source': 'nvdcheck_file_mention'
                        })
                        # 添加到函数对列表
                        mentioned_func_pairs.append((func_name, func_before, func_after))
        
        return labeled_data, mentioned_func_pairs
    
    def process_reef_sample(self, sample: Dict) -> Optional[Dict]:
        """处理单个REEF样本
        
        OneFunc策略：统计整个commit中所有文件的函数变化总数
        - 如果整个commit只有1个函数变化，标记为vulnerable（PrimeVul思路）
        - 如果有多个函数变化，不使用OneFunc标记
        
        NVDCheck策略：在每个文件中独立判断
        - 检查CVE描述是否提及函数名或文件名
        """
        cve_id = sample.get('cve_id', '')
        url = sample.get('url', '')
        details = sample.get('details', [])
        
        if not details:
            return None
        
        # 获取commit信息
        commit_info = self.fetch_commit_info(url)
        if not commit_info or 'files' not in commit_info:
            return None
        
        # 提取commit日期
        commit_date = self.extract_commit_date(commit_info)
        
        # 第一遍遍历：收集所有文件的函数对和未变更函数
        all_file_data = []  # 存储每个文件的处理结果
        total_func_pairs = []  # 整个commit的所有函数对
        
        for detail in details:
            raw_code = detail.get('raw_code', '')
            patch = detail.get('patch', '')
            raw_url = detail.get('raw_url', '')
            
            if not raw_code or not patch:
                continue
            
            # 从raw_url提取filename
            try:
                from urllib.parse import unquote
                filepath = unquote(raw_url.split('/raw/')[-1].split('/', 1)[-1])
            except:
                continue
            
            # 确定语言
            language = self.determine_language(filepath)
            if not language:
                continue
            
            # 从commit_info中找到对应文件的status
            file_info = None
            for f in commit_info.get('files', []):
                if f.get('filename') == filepath or f.get('filename') in filepath:
                    file_info = f
                    break
            
            if not file_info:
                continue
            
            file_status = file_info.get('status', 'modified')
            
            # 对于added文件，没有before版本，跳过
            if file_status == 'added':
                continue
            
            # 应用反向patch获取修复前代码
            code_before = self.apply_reverse_patch(raw_code, patch, language)
            if not code_before:
                self.stats['failed_patch'] += 1
                continue
            
            self.stats['successful_patch'] += 1
            
            # 提取函数对
            func_pairs, unchanged_funcs = self.extract_function_pairs(
                code_before, raw_code, language
            )
            
            # 保存这个文件的处理结果
            file_data = {
                'filepath': filepath,
                'language': language,
                'file_status': file_status,
                'func_pairs': func_pairs,
                'unchanged_funcs': unchanged_funcs,
                'code_before': code_before,
                'code_after': raw_code
            }
            all_file_data.append(file_data)
            
            # 累计所有函数对（用于判断整个commit的函数变化总数）
            total_func_pairs.extend(func_pairs)
        
        # 如果没有成功处理任何文件，返回None
        if not all_file_data:
            return None
        
        # 第二遍遍历：应用标记策略
        all_labeled_data = []
        all_func_pairs = []
        added_func_pairs = set()  # 记录已添加的函数对（避免OneFunc和NVDCheck重复）
        
        # OneFunc标记：判断整个commit是否只有1个函数变化
        onefunc_applied = False
        if len(total_func_pairs) == 1:
            # 整个commit只有1个函数变化，应用OneFunc标记
            onefunc_applied = True
            self.stats['onefunc_labeled'] += 1
            
            # 找到这个唯一的函数对所在的文件
            for file_data in all_file_data:
                if len(file_data['func_pairs']) == 1:
                    func_name, func_before, func_after = file_data['func_pairs'][0]
                    
                    # 标记修复前函数为vulnerable（保存func_after用于后续生成函数对）
                    all_labeled_data.append({
                        'func_name': func_name,
                        'func_code': func_before,
                        'func_code_after': func_after,  # 保存修复后版本
                        'label': 'vulnerable',
                        'source': 'onefunc',
                        'cve_id': cve_id,
                        'language': file_data['language'],
                        'filename': file_data['filepath'],
                        'file_status': file_data['file_status'],
                        'project_language': sample.get('language', ''),
                        'cvss': sample.get('cvss', ''),
                        'cwe': sample.get('CWEs', [])[0] if sample.get('CWEs') else '',
                        'commit_date': commit_date
                    })
                    
                    # 标记修复后函数为benign
                    all_labeled_data.append({
                        'func_name': func_name,
                        'func_code': func_after,
                        'label': 'benign',
                        'source': 'onefunc',
                        'cve_id': cve_id,
                        'language': file_data['language'],
                        'filename': file_data['filepath'],
                        'file_status': file_data['file_status'],
                        'project_language': sample.get('language', ''),
                        'cvss': sample.get('cvss', ''),
                        'cwe': sample.get('CWEs', [])[0] if sample.get('CWEs') else '',
                        'commit_date': commit_date
                    })
                
                # 标记该文件的所有未变更函数为benign
                for func_name, func_code in file_data['unchanged_funcs'].items():
                    all_labeled_data.append({
                        'func_name': func_name,
                        'func_code': func_code,
                        'label': 'benign',
                        'source': 'onefunc_unchanged',
                        'cve_id': cve_id,
                        'language': file_data['language'],
                        'filename': file_data['filepath'],
                        'file_status': file_data['file_status'],
                        'project_language': sample.get('language', ''),
                        'cvss': sample.get('cvss', ''),
                        'cwe': sample.get('CWEs', [])[0] if sample.get('CWEs') else '',
                        'commit_date': commit_date
                    })
        elif len(total_func_pairs) > 1:
            # 多个函数变化，记录但不用OneFunc标记
            self.stats['discarded_multi_func'] += 1
        
        # NVDCheck标记：对每个文件独立判断
        for file_data in all_file_data:
            nvd_labels, nvd_func_pairs = self.nvdcheck_labeling(
                cve_id, 
                file_data['func_pairs'], 
                file_data['unchanged_funcs'], 
                [file_data['filepath']]
            )
            
            if nvd_labels:
                self.stats['nvdcheck_labeled'] += len(nvd_labels)
                
                # 添加元信息并保存func_after用于后续生成函数对
                for label_data in nvd_labels:
                    # 找到对应的func_after
                    func_after = None
                    for func_name, func_before, func_after_candidate in file_data['func_pairs']:
                        if func_name == label_data['func_name'] and self.compute_md5(func_before) == self.compute_md5(label_data['func_code']):
                            func_after = func_after_candidate
                            break
                    
                    label_data.update({
                        'func_code_after': func_after,  # 保存修复后版本
                        'cve_id': cve_id,
                        'language': file_data['language'],
                        'filename': file_data['filepath'],
                        'file_status': file_data['file_status'],
                        'project_language': sample.get('language', ''),
                        'cvss': sample.get('cvss', ''),
                        'cwe': sample.get('CWEs', [])[0] if sample.get('CWEs') else '',
                        'commit_date': commit_date
                    })
                
                all_labeled_data.extend(nvd_labels)
        
        return {
            'labeled_functions': all_labeled_data,
            'function_pairs': []  # 不在这里生成函数对，后续从vulnerable函数中提取
        }
    
    def build_dataset(self, jsonl_file: Path, max_samples: int = None):
        """构建完整数据集
        
        Args:
            jsonl_file: JSONL数据文件路径
            max_samples: 最大处理样本数（None表示处理全部）
        """
        print(f"开始处理REEF数据集: {jsonl_file}")
        
        # 读取JSONL文件
        samples = []
        with open(jsonl_file, 'r', encoding='utf-8') as f:
            for line in f:
                samples.append(json.loads(line))
                if max_samples and len(samples) >= max_samples:
                    break
        
        self.stats['total_samples'] = len(samples)
        print(f"总样本数: {len(samples)}")
        
        # 处理每个样本
        all_labeled_functions = []
        all_function_pairs = []
        
        for sample in tqdm(samples, desc="处理样本"):
            result = self.process_reef_sample(sample)
            if result:
                all_labeled_functions.extend(result['labeled_functions'])
                all_function_pairs.extend(result['function_pairs'])
        
        # 保存结果
        print("\n保存数据集...")
        
        # 1. 函数数据集（带标签）
        if all_labeled_functions:
            df_functions = pd.DataFrame(all_labeled_functions)
            
            # 去重：根据函数代码内容去重（保留第一次出现的）
            original_count = len(df_functions)
            df_functions = df_functions.drop_duplicates(subset=['func_code'], keep='first')
            dedup_count = len(df_functions)
            
            output_path = self.output_dir / 'reef_labeled_functions.csv'
            df_functions.to_csv(output_path, index=False)
            print(f"函数数据集已保存: {output_path}")
            print(f"原始函数数: {original_count}, 去重后: {dedup_count} (移除 {original_count - dedup_count} 个重复)")
            print(f"标签分布:\n{df_functions['label'].value_counts()}")
        
        # 2. 漏洞函数对数据集
        if all_function_pairs:
            df_pairs = pd.DataFrame(all_function_pairs)
            
            # 去重：根据修复前函数代码去重（同一个漏洞函数只保留一次）
            original_count = len(df_pairs)
            df_pairs = df_pairs.drop_duplicates(subset=['func_before'], keep='first')
            dedup_count = len(df_pairs)
            
            output_path = self.output_dir / 'reef_vulnerability_pairs.csv'
            df_pairs.to_csv(output_path, index=False)
            print(f"\n漏洞函数对数据集已保存: {output_path}")
            print(f"原始函数对数: {original_count}, 去重后: {dedup_count} (移除 {original_count - dedup_count} 个重复)")
        
        # 打印统计信息
        print("\n" + "="*50)
        print("处理统计:")
        for key, value in self.stats.items():
            if key == 'api_failures' and isinstance(value, dict):
                print(f"GitHub API失败:")
                for status_code, count in value.items():
                    print(f"  状态码 {status_code}: {count} 次")
            else:
                print(f"{key}: {value}")
        print("="*50)

    def build_dataset_multi(self, jsonl_files: List[Path], max_samples: int = None):
        """遍历多个JSONL文件，汇总构建数据集并输出为JSONL

        保留原有单文件构建逻辑不变，只在此方法中做多文件聚合和JSONL输出。
        """
        # 打开日志文件
        log_file = self.root_dir / 'result_tju.log'  # 使用新的日志文件名
        log_f = open(log_file, 'w', encoding='utf-8')
        
        def log_print(msg):
            """同时打印到控制台和日志文件"""
            print(msg)
            log_f.write(msg + '\n')
            log_f.flush()
        
        log_print("开始处理TJU-REEF-SCRIPT数据集（多文件聚合）")
        log_print(f"{'='*70}\n")

        # 按文件处理并记录每个文件的统计信息
        all_labeled_functions: List[Dict] = []
        all_function_pairs: List[Dict] = []
        total_samples_count = 0
        file_stats = []

        for jsonl_file in jsonl_files:
            log_print(f"\n正在处理文件: {jsonl_file.name}")
            log_print("-" * 70)
            
            # 读取该文件的样本
            file_samples = []
            with open(jsonl_file, 'r', encoding='utf-8') as f:
                for line in f:
                    file_samples.append(json.loads(line))
                    if max_samples and (total_samples_count + len(file_samples)) >= max_samples:
                        break
            
            file_sample_count = len(file_samples)
            total_samples_count += file_sample_count
            log_print(f"该文件样本数: {file_sample_count}")
            
            # 处理该文件的样本
            file_labeled_functions = []
            file_function_pairs = []
            onefunc_count = 0
            nvdcheck_count = 0
            
            for sample in tqdm(file_samples, desc=f"  处理 {jsonl_file.name}"):
                result = self.process_reef_sample(sample)
                if result:
                    # 统计该样本的OneFunc和NVDCheck数量
                    for func in result['labeled_functions']:
                        if func.get('source') in ['onefunc', 'onefunc_unchanged']:
                            onefunc_count += 1
                        elif func.get('source', '').startswith('nvdcheck'):
                            nvdcheck_count += 1
                    
                    file_labeled_functions.extend(result['labeled_functions'])
            
            # 汇总到全局
            all_labeled_functions.extend(file_labeled_functions)
            
            # 计算该文件的vulnerable数量（去重前）
            vulnerable_count = sum(1 for f in file_labeled_functions if f.get('label') == 'vulnerable')
            # 计算该文件的函数对数量（有func_code_after的vulnerable函数）
            file_function_pairs_count = sum(1 for f in file_labeled_functions 
                                           if f.get('label') == 'vulnerable' and f.get('func_code_after'))
            
            # 记录该文件统计
            file_stat = {
                'file': jsonl_file.name,
                'samples': file_sample_count,
                'onefunc_labeled': onefunc_count,
                'nvdcheck_labeled': nvdcheck_count,
                'total_functions': len(file_labeled_functions),
                'vulnerable_functions': vulnerable_count,
                'function_pairs': file_function_pairs_count
            }
            file_stats.append(file_stat)
            
            log_print(f"  OneFunc标记: {onefunc_count} 条")
            log_print(f"  NVDCheck标记: {nvdcheck_count} 条")
            log_print(f"  总函数数: {len(file_labeled_functions)} (vulnerable: {vulnerable_count}, benign: {len(file_labeled_functions)-vulnerable_count})")
            log_print(f"  函数对数: {file_function_pairs_count}")
            
            if max_samples and total_samples_count >= max_samples:
                log_print(f"\n已达到最大样本数 {max_samples}，停止处理")
                break

        self.stats['total_samples'] = total_samples_count
        log_print(f"\n{'='*70}")
        log_print(f"所有文件处理完成，总样本数: {total_samples_count}")
        log_print(f"{'='*70}\n")

        # 保存结果（JSONL聚合输出）
        log_print("\n保存聚合数据集 (JSONL)...")

        # 1. 函数数据集（带标签）
        if all_labeled_functions:
            df_functions = pd.DataFrame(all_labeled_functions)
            
            # PrimeVul去重方法：计算每个函数的MD5哈希值
            log_print("应用PrimeVul去重方法（规范化+MD5哈希）...")
            df_functions['func_code_md5'] = df_functions['func_code'].apply(
                lambda x: self.compute_md5(x) if pd.notna(x) else ''
            )

            # 去重策略：同一代码如果有多个标签，优先保留vulnerable
            # 原因：如果某代码在任何上下文中被标记为vulnerable，说明它可能存在漏洞
            # 这样保证数据集的一致性，避免训练时的标签冲突
            original_count = len(df_functions)
            
            # 按MD5分组，检查是否有标签冲突
            grouped = df_functions.groupby('func_code_md5')
            conflicts = []
            for md5_hash, group in grouped:
                if len(group['label'].unique()) > 1:
                    conflicts.append((md5_hash, len(group)))
            
            if conflicts:
                log_print(f"发现 {len(conflicts)} 个代码同时有vulnerable和benign标签")
                log_print(f"  采用策略: 优先保留vulnerable标签")
            
            # 排序：vulnerable优先（在前），然后按MD5去重保留第一个
            df_functions['label_priority'] = df_functions['label'].map({'vulnerable': 0, 'benign': 1})
            df_functions = df_functions.sort_values('label_priority')
            df_functions = df_functions.drop_duplicates(subset=['func_code_md5'], keep='first')
            df_functions = df_functions.drop(columns=['label_priority'])
            
            dedup_count = len(df_functions)
            
            # 统计标签分布
            label_counts = df_functions['label'].value_counts()
            vulnerable_count = label_counts.get('vulnerable', 0)
            benign_count = label_counts.get('benign', 0)
            
            # 移除临时的MD5列
            df_functions = df_functions.drop(columns=['func_code_md5'])

            jsonl_path = self.output_dir / 'tju_reef_labeled_functions.jsonl'  # 新的输出文件名
            df_functions.to_json(jsonl_path, orient='records', lines=True, force_ascii=False)
            log_print(f"函数JSONL数据集已保存: {jsonl_path}")
            log_print(f"原始函数数: {original_count}, 去重后: {dedup_count} (移除 {original_count - dedup_count} 个重复)")
            log_print(f"  去重策略: 同一代码优先保留vulnerable标签")
            
            log_print(f"标签分布:")
            log_print(f"  vulnerable: {vulnerable_count}")
            log_print(f"  benign: {benign_count}")

        # 2. 漏洞函数对数据集 - 从标记为vulnerable的函数中提取
        log_print("\n从vulnerable函数中提取漏洞函数对...")
        if all_labeled_functions:
            # 筛选出所有vulnerable函数（且有func_code_after字段）
            vulnerable_funcs = [f for f in all_labeled_functions 
                               if f.get('label') == 'vulnerable' and f.get('func_code_after')]
            
            log_print(f"  找到 {len(vulnerable_funcs)} 个vulnerable函数有对应的修复版本")
            
            # 构建函数对
            all_function_pairs = []
            for func in vulnerable_funcs:
                func_pair = {
                    'func_name': func['func_name'],
                    'func_before': func['func_code'],
                    'func_after': func['func_code_after'],
                    'cve_id': func.get('cve_id', ''),
                    'language': func.get('language', ''),
                    'filename': func.get('filename', ''),
                    'cwe': func.get('cwe', ''),
                    'cvss': func.get('cvss', ''),
                    'project_language': func.get('project_language', ''),
                    'commit_date': func.get('commit_date', ''),
                    'source': func.get('source', '')
                }
                all_function_pairs.append(func_pair)
            
            log_print(f"  生成了 {len(all_function_pairs)} 个初始函数对")
        
        # 应用PrimeVul去重
        if all_function_pairs:
            df_pairs = pd.DataFrame(all_function_pairs)
            
            # PrimeVul去重方法：
            # 1. 首先过滤掉before和after没有实际变化的函数对
            log_print("应用PrimeVul去重方法...")
            log_print("  步骤1: 过滤未实际变化的函数对（MD5相同）...")
            original_count = len(df_pairs)
            
            # 计算before和after的MD5
            df_pairs['md5_before'] = df_pairs['func_before'].apply(
                lambda x: self.compute_md5(x) if pd.notna(x) else ''
            )
            df_pairs['md5_after'] = df_pairs['func_after'].apply(
                lambda x: self.compute_md5(x) if pd.notna(x) else ''
            )
            
            # 分析未变化的函数对来源
            unchanged_pairs = df_pairs[df_pairs['md5_before'] == df_pairs['md5_after']]
            if len(unchanged_pairs) > 0:
                onefunc_unchanged = len(unchanged_pairs[unchanged_pairs['source'] == 'onefunc'])
                nvdcheck_unchanged = len(unchanged_pairs[unchanged_pairs['source'].str.startswith('nvdcheck')])
                log_print(f"    发现 {len(unchanged_pairs)} 个未实际变化的函数对:")
                log_print(f"      - OneFunc: {onefunc_unchanged} 个（TreeSitter提取问题/Patch仅改注释空白）")
                log_print(f"      - NVDCheck: {nvdcheck_unchanged} 个（CVE描述提到但未实际修改的函数）")
                
                # 显示source字段的实际分布（用于调试）
                if len(unchanged_pairs) != onefunc_unchanged + nvdcheck_unchanged:
                    other_sources = unchanged_pairs[~unchanged_pairs['source'].isin(['onefunc']) & 
                                                     ~unchanged_pairs['source'].str.startswith('nvdcheck')]
                    if len(other_sources) > 0:
                        log_print(f"      - 其他来源: {len(other_sources)} 个")
                        log_print(f"        来源详情: {other_sources['source'].value_counts().to_dict()}")
            
            # 过滤MD5相同的（即没有实际变化的）
            df_pairs = df_pairs[df_pairs['md5_before'] != df_pairs['md5_after']]
            unchanged_removed = original_count - len(df_pairs)
            log_print(f"    共移除 {unchanged_removed} 个未实际变化的函数对")
            
            # 2. 然后按照修复前函数的MD5去重
            log_print("  步骤2: 按修复前函数MD5去重...")
            before_dedup_count = len(df_pairs)
            
            # 统计unique的before函数数量（在去重前）
            unique_before_count = df_pairs['md5_before'].nunique()
            
            # 分析重复的原因
            if before_dedup_count > unique_before_count:
                duplicate_count = before_dedup_count - unique_before_count
                log_print(f"    发现 {duplicate_count} 个漏洞函数有多个修复版本")
                
                # 分析是否真的是"多个修复版本"还是"完全相同的函数对"
                duplicates_analysis = df_pairs.groupby('md5_before').agg({
                    'md5_after': lambda x: x.nunique(),
                    'func_name': 'count'
                }).reset_index()
                duplicates_analysis.columns = ['md5_before', 'unique_after_count', 'total_count']
                duplicates_with_same_after = duplicates_analysis[
                    (duplicates_analysis['total_count'] > 1) & 
                    (duplicates_analysis['unique_after_count'] == 1)
                ]
                duplicates_with_diff_after = duplicates_analysis[
                    (duplicates_analysis['total_count'] > 1) & 
                    (duplicates_analysis['unique_after_count'] > 1)
                ]
                
                same_pair_count = duplicates_with_same_after['total_count'].sum() - len(duplicates_with_same_after)
                diff_after_count = len(duplicates_with_diff_after)
                
                log_print(f"      - 完全相同的函数对重复: {same_pair_count} 个")
                log_print(f"        原因: REEF数据集中同一CVE的多个commit修改了相同函数")
                log_print(f"      - 同一漏洞函数有不同修复: {diff_after_count} 个")
                log_print(f"        原因: 渐进式修复，同一函数在不同commit中被多次改进")
            
            df_pairs = df_pairs.drop_duplicates(subset=['md5_before'], keep='first')
            dedup_count = len(df_pairs)
            duplicate_removed = before_dedup_count - dedup_count
            log_print(f"    共移除 {duplicate_removed} 个重复项（保留首次出现）")
            
            # 移除临时的MD5列
            df_pairs = df_pairs.drop(columns=['md5_before', 'md5_after'])

            jsonl_path = self.output_dir / 'tju_reef_vulnerability_pairs.jsonl'  # 新的输出文件名
            df_pairs.to_json(jsonl_path, orient='records', lines=True, force_ascii=False)
            log_print(f"\n漏洞函数对JSONL数据集已保存: {jsonl_path}")
            log_print(f"原始函数对数: {original_count}")
            log_print(f"  - 移除未实际变化: {unchanged_removed}")
            log_print(f"  - 移除重复项: {duplicate_removed}")
            log_print(f"  - 最终保留: {dedup_count}")
            
            # 统计函数对来源
            if 'source' in df_pairs.columns:
                onefunc_pairs = len(df_pairs[df_pairs['source'] == 'onefunc'])
                nvdcheck_pairs = len(df_pairs[df_pairs['source'].str.startswith('nvdcheck')])
                log_print(f"  函数对来源:")
                log_print(f"    - OneFunc: {onefunc_pairs}")
                log_print(f"    - NVDCheck: {nvdcheck_pairs}")
            
            # 显示unique的before函数数量
            log_print(f"  唯一的漏洞函数(before): {unique_before_count}")
            if duplicate_removed > 0:
                log_print(f"  注: 这 {duplicate_removed} 个重复项中包含:")
                log_print(f"      * 完全相同的函数对（数据集重复）")
                log_print(f"      * 同一漏洞的渐进式修复（多次迭代）")

        # 打印汇总统计
        log_print(f"\n{'='*70}")
        log_print("【最终数据统计】")
        log_print(f"{'='*70}")
        log_print(f"总样本数: {total_samples_count}")
        log_print(f"最终函数条目数: {len(df_functions) if all_labeled_functions else 0}")
        if all_labeled_functions:
            log_print(f"  - vulnerable: {vulnerable_count}")
            log_print(f"  - benign: {benign_count}")
        log_print(f"最终漏洞函数对条目数: {len(df_pairs) if all_function_pairs else 0}")
        
        # 解释数量差异
        if all_labeled_functions and all_function_pairs and vulnerable_count < len(df_pairs):
            log_print(f"\n  注: 函数对数({len(df_pairs)}) > vulnerable数({vulnerable_count})")
            log_print(f"      合理原因: 同一漏洞函数可能在不同CVE/commit中有不同的修复方式")
            log_print(f"      函数数据集按代码去重，函数对数据集保留所有before-after配对")
            log_print(f"  - benign: {benign_count}")
        log_print(f"最终漏洞函数对条目数: {len(df_pairs) if all_function_pairs else 0}")
        log_print(f"{'='*70}")

        # 打印详细统计信息
        log_print(f"\n{'='*70}")
        log_print("【详细处理统计】")
        log_print(f"{'='*70}")
        for key, value in self.stats.items():
            if key == 'api_failures' and isinstance(value, dict):
                log_print(f"GitHub API失败:")
                for status_code, count in value.items():
                    log_print(f"  状态码 {status_code}: {count} 次")
            else:
                log_print(f"{key}: {value}")
        
        # 打印各文件统计表格
        if file_stats:
            log_print(f"\n{'='*70}")
            log_print("【各文件详细统计】")
            log_print(f"{'='*70}")
            log_print(f"{'文件名':<30} {'样本':<8} {'OneFunc':<10} {'NVDCheck':<10} {'函数对':<8}")
            log_print("-" * 70)
            for stat in file_stats:
                log_print(f"{stat['file']:<30} {stat['samples']:<8} {stat['onefunc_labeled']:<10} "
                      f"{stat['nvdcheck_labeled']:<10} {stat['function_pairs']:<8}")
        log_print(f"{'='*70}\n")
        
        # 打印日志保存位置并关闭文件
        print(f"详细统计已保存到: {log_file}")
        log_f.close()


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='构建REEF到PrimeVul格式的数据集')
    parser.add_argument('--max-samples', type=int, default=None, 
                      help='最大处理样本数（默认处理全部）')
    args = parser.parse_args()
    
    # 配置文件路径
    config_path = directory_name / 'data_preprocess.yaml'
    
    # 创建构建器
    builder = REEFDatasetBuilder(config_path)

    # 查找所有JSONL文件
    jsonl_files = sorted(builder.raw_dir.glob('*.jsonl'))

    if not jsonl_files:
        print(f"错误: 未在 {builder.raw_dir} 找到任何 .jsonl 文件")
        return

    print(f"找到 {len(jsonl_files)} 个JSONL文件:")
    for f in jsonl_files:
        print(f"  - {f.name}")
    print()

    # 多文件聚合构建数据集（JSONL输出）
    builder.build_dataset_multi(jsonl_files, max_samples=args.max_samples)


if __name__ == '__main__':
    main()

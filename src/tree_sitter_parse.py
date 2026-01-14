import codecs
import copy
import pathlib
import re
import tokenize
from io import StringIO
from typing import Generator
import difflib
import Levenshtein
import unidiff.errors
import yaml
from tqdm import tqdm
from tree_sitter import Language, Parser, Tree, Node
from pathlib import Path

from unidiff import PatchSet


class TreeSitterParse:
    def __init__(self, config):
        self.config = config
        # 移除调试输出: print(config)
        self.language = self.config['language'].lower()
        self.parser = self.get_parser(self.language)
        self.comment_types = self.config['comment_types']
        self.function_types = self.config['function_types']
        self.string_types = self.config['string_types']
        self.post_fix = self.config['post_fix']
        if self.language in ['python']:
            self.indent = self.config['indent_token']

    def get_parser(self, language):
        tree_sitter_dir = Path(__file__).parent.parent / 'tools'
        language = language.lower()
        if language == 'c_sharp':
            dir_name = 'c-sharp'
        else:
            dir_name = language
        so_path = tree_sitter_dir / 'build' / f'libtree-sitter-{dir_name}.so'
        Language.build_library(
            # so文件保存位置
            str(so_path),
            # vendor文件下git clone的仓库
            [
                str(tree_sitter_dir / f'tree-sitter-{dir_name}')
            ]
        )
        _language = Language(str(so_path), language)
        parser = Parser()
        parser.set_language(_language)
        return parser

    def parse_code(self, code: str):
        tree = self.parser.parse(bytes(code, "utf-8"))
        return tree

    def remove_comments(self, source, tree):
        if self.language != 'python':
            clean_source = bytearray(source, 'utf8')
            offset = 0
            stack = [tree.root_node]
            while stack:
                node = stack.pop()
                if node.type in self.comment_types:
                    start = node.start_byte - offset
                    end = node.end_byte - offset
                    del clean_source[start:end]
                    offset += (end - start)
                else:
                    stack.extend(reversed(node.children))

            return bytes(clean_source).decode('utf8')
        else:
            """
            Tree-sitter并不能完美去除comment，
            参考：https://stackoverflow.com/questions/1769332/script-to-remove-python-comments-docstrings
            Returns 'source' minus comments and docstrings.
            """
            io_obj = StringIO(source)
            out = ""
            prev_toktype = tokenize.INDENT
            last_lineno = -1
            last_col = 0
            for tok in tokenize.generate_tokens(io_obj.readline):
                token_type = tok[0]
                token_string = tok[1]
                start_line, start_col = tok[2]
                end_line, end_col = tok[3]
                ltext = tok[4]
                if start_line > last_lineno:
                    last_col = 0
                if start_col > last_col:
                    out += (" " * (start_col - last_col))
                if token_type == tokenize.COMMENT:
                    pass
                elif token_type == tokenize.STRING:
                    if prev_toktype != tokenize.INDENT:
                        if prev_toktype != tokenize.NEWLINE:
                            if start_col > 0:
                                out += token_string
                else:
                    out += token_string
                prev_toktype = token_type
                last_col = end_col
                last_lineno = end_line
            return out

    def get_func_identifier(self, tree):
        cursor = tree.walk()
        visited_children = False
        find_identifier = False
        while True:
            if not visited_children:
                if cursor.node.type == 'identifier':
                    yield cursor.node.text.decode('utf-8')
                    find_identifier = True
                    break
                if not cursor.goto_first_child():
                    visited_children = True
            elif cursor.goto_next_sibling():
                visited_children = False
            elif not cursor.goto_parent():
                break

        if find_identifier:
            return
        # 考虑使用其他的identifier作为identifier
        cursor = tree.walk()
        visited_children = False
        while True:
            if not visited_children:
                if 'identifier' in str(cursor.node.type):
                    yield cursor.node.text.decode('utf-8')
                    break
                if not cursor.goto_first_child():
                    visited_children = True
            elif cursor.goto_next_sibling():
                visited_children = False
            elif not cursor.goto_parent():
                break

    def recursive_get_func(self, tree):
        cursor = tree.walk()
        visited_children = False
        while True:
            if not visited_children:
                if cursor.node.type in self.function_types:
                    yield cursor.node
                if not cursor.goto_first_child():
                    visited_children = True
            elif cursor.goto_next_sibling():
                visited_children = False
            elif not cursor.goto_parent():
                break

    def get_functions(self, tree):
        func_list = []
        func_nodes = list(map(lambda node: node, self.recursive_get_func(tree)))
        for n in func_nodes:
            node_names = []
            selected_node = None
            if self.language in ['c', 'cpp']:
                for i in n.children:
                    if i.type == 'function_declarator':
                        selected_node = i
                        break
                if selected_node is None:
                    if n.children[-1].type == "compound_statement":
                        if len(n.children) > 2:
                            if n.children[-2].type != 'ERROR':
                                selected_node = n.children[-2]
                            else:
                                selected_node = n.children[-3]
                    # 找不到的话先序遍历找一个identifier
                if selected_node is None:
                    selected_node = n
                node_names = list(map(lambda node: node, self.get_func_identifier(selected_node)))

            elif self.language in ['java', 'c_sharp']:
                if n.type in self.function_types:
                    for i in n.children:
                        if i.type == 'identifier':
                            selected_node = i
                            break
                    # 找不到的话先序遍历找一个identifier
                if selected_node is None:
                    selected_node = n
                    node_names = list(map(lambda node: node, self.get_func_identifier(selected_node)))
                else:
                    node_names = [selected_node.text.decode('utf-8')]
            elif self.language in ['javascript']:
                if n.type in self.function_types:
                    # 增加对匿名函数的处理, 将函数体前的内容都作为函数名以减少重复的函数名导致的函数匹配过长问题
                    if n.type == 'function_expression' and n.children[0].type != 'identifier':
                        # 对于匿名函数，手动加上函数关键字
                        func_name = 'function'
                        for i in n.children:
                            if i.type != 'statement_block':
                                func_name += i.text.decode('utf-8')
                        node_names = [func_name]
                    # 对这类型结点特殊处理
                    elif n.type == 'method_definition':
                        selected_node = None
                        for i in n.children:
                            if i.type in ['computed_property_name', 'property_identifier', 'string']:
                                selected_node = i
                                break
                        if selected_node is None:
                            selected_node = n
                            node_names = list(map(lambda node: node, self.get_func_identifier(selected_node)))
                        else:
                            node_names = [selected_node.text.decode('utf-8')]
                    else:
                        for i in n.children:
                            if i.type == 'identifier':
                                selected_node = i
                                break
                        if selected_node is None:
                            selected_node = n
                            node_names = list(map(lambda node: node, self.get_func_identifier(selected_node)))
                        else:
                            node_names = [selected_node.text.decode('utf-8')]
            elif self.language in ['go']:
                if n.type in self.function_types:
                    # 增加对匿名函数的处理, 将非函数体部分均作为函数名
                    if n.type == 'func_literal':
                        # 手动加上函数关键字
                        func_name = 'func'
                        for i in n.children:
                            if i.type != 'block':
                                func_name += i.text.decode('utf-8')
                        node_names = [func_name]
                    # 对这类型结点特殊处理
                    elif n.type in ['method_declaration']:
                        for i in n.children:
                            if i.type == 'field_identifier':
                                selected_node = i
                                break
                        if selected_node is None:
                            selected_node = n
                            node_names = list(map(lambda node: node, self.get_func_identifier(selected_node)))
                        else:
                            node_names = [selected_node.text.decode('utf-8')]
                    else:
                        for i in n.children:
                            if i.type == 'identifier':
                                selected_node = i
                                break
                        if selected_node is None:
                            selected_node = n
                            node_names = list(map(lambda node: node, self.get_func_identifier(selected_node)))
                        else:
                            node_names = [selected_node.text.decode('utf-8')]
            elif self.language in ['python']:
                selected_node = None
                for i in n.children:
                    if i.type in ['identifier']:
                        selected_node = i
                        break
                if selected_node is None:
                    selected_node = n
                    node_names = list(map(lambda node: node, self.get_func_identifier(selected_node)))
                else:
                    node_names = [selected_node.text.decode('utf-8')]
            if len(node_names) == 0:
                # TODO: no identifier
                print('no identifier')
                print(n.text.decode('utf-8'))
                continue
            func_name = node_names[0]
            func_list.append([func_name, n])
        return func_list

    def compare_functions(self, tree_before, tree_after):
        functions_before = self.get_functions(tree_before)
        functions_after = self.get_functions(tree_after)
        changed_functions = []

        # TODO:新增的函数找不到修改前function，这是合理的，完全删减的函数有可能误匹配函数，这是后续可能需要改进的
        for func_before_list in functions_before:
            func_name = func_before_list[0]
            func_before = func_before_list[1]
            func_candidates = [f[1] for f in functions_after if f[0] == func_name]
            code_before = func_before.text.decode('utf-8')
            if len(func_candidates) == 0:
                continue
            if len(func_candidates) == 1:
                func_after = func_candidates[0]
            else:
                # if there are multiple functions with the same name, we need to find the best match
                # consider each function edit distance, the function with the smallest edit distance is the best match
                edit_distances = []
                for i in range(len(func_candidates)):
                    func = func_candidates[i]
                    code_after = func.text.decode('utf-8')
                    edit_distance = Levenshtein.distance(code_before, code_after)
                    edit_distances.append(edit_distance)
                min_edit_distance = min(edit_distances)
                min_edit_index = edit_distances.index(min_edit_distance)
                func_after = func_candidates[min_edit_index]
                func_name += '_' + str(func_before.start_point[0])
            code_after = func_after.text.decode('utf-8')
            if code_before != code_after:
                changed_functions.append([code_before, code_after, func_name])
        return changed_functions

    def get_string_literals(self, tree: Tree):
        # TODO: for different language, the string type may be different, use dict to store
        cursor = tree.walk()
        visited_children = False
        while True:
            if not visited_children:
                if cursor.node.type in self.string_types:
                    yield cursor.node
                    visited_children = True
                    continue
                if not cursor.goto_first_child():
                    visited_children = True
            elif cursor.goto_next_sibling():
                visited_children = False
            elif not cursor.goto_parent():
                break

    def format_func_name(self, func_name):
        # TODO: for different language, the function name may be different, more design needed
        if self.language in ['c']:
            new_name = func_name.split('(')[0].strip().replace('\n', '_').replace(' ', '_')
        else:
            new_name = func_name.strip().replace('\n', '_').replace(' ', '_')
        # limit func_name length
        limit_len = 114
        length = min(len(new_name), limit_len)
        new_name = new_name[:length]
        return new_name

    def get_func_tokens(self, tree: Tree) -> Generator[Node, None, None]:
        cursor = tree.walk()
        visited_children = False

        if self.language in ['c']:
            while True:
                if not visited_children:
                    # debug
                    # node_text = cursor.node.text.decode('utf-8')
                    if cursor.node.type == 'string_literal':
                        literal = ''
                        for child in cursor.node.children:
                            literal += child.text.decode('utf-8')
                        # add special handling for escape character \\*
                        # 写的什么东西
                        # 目前是将三个\\\* 换成 \\*
                        if '\\\\\\"' in literal:
                            pattern = r'(?<!\\)\\\\\\"'
                            # 将匹配到的单个 \ 替换为 \\
                            literal = re.sub(pattern, r'\\\\"', literal)
                            # literal = literal.replace('\\\\\\"', '\\\\\"')

                        yield literal
                        visited_children = True
                        continue

                    if cursor.node.type == 'char_literal':
                        literal = ''
                        for child in cursor.node.children:
                            literal += child.text.decode('utf-8')
                        if literal == "'" + '"' + "'":
                            literal = "\\'\"\\'"
                        elif literal == "'" + '\\\\"' + "'":
                            literal = "\\'\\\\\"\\'"
                        elif literal == "'" + "\\" + "'" + "'":
                            literal = "'\\\\''"
                        yield literal
                        visited_children = True
                        continue

                    if cursor.node.type == 'number_literal':
                        number = cursor.node.text.decode('utf-8')
                        if number[0] == '-':
                            yield number[0]
                            yield number[1:]
                        else:
                            yield number
                        visited_children = True
                        continue
                    if cursor.node.type in ['#define', 'preproc_directive', '#ifdef', '#else', '#endif', '#ifndef',
                                            '#if']:
                        text = cursor.node.text.decode('utf-8')
                        yield text[0:1]
                        yield text[1:]
                        visited_children = True
                        continue

                    if cursor.node.type == 'preproc_arg':
                        n = cursor.node.text.decode('utf-8')
                        sub_tree = self.parse_code(n)
                        node_names = list(map(lambda node: node, self.get_func_tokens(sub_tree)))
                        for i in node_names:
                            if i == '':
                                continue
                            yield i
                        visited_children = True
                        continue

                    if not cursor.goto_first_child():
                        s = cursor.node.text.decode('utf-8')
                        yield s
                        visited_children = True
                elif cursor.goto_next_sibling():
                    visited_children = False
                elif not cursor.goto_parent():
                    break
        elif self.language in ['cpp', 'java', 'c_sharp', 'javascript', 'go', 'python']:
            while True:
                if not visited_children:
                    if cursor.node.type in self.string_types:
                        s = cursor.node.text.decode('utf-8')
                        yield s
                        visited_children = True
                        continue

                    if not cursor.goto_first_child():
                        s = cursor.node.text.decode('utf-8')
                        yield s
                        visited_children = True
                elif cursor.goto_next_sibling():
                    visited_children = False
                elif not cursor.goto_parent():
                    break
        return

    def replace_string_blank(self, source_code, indent_lists=None):
        # TODO: for python, consider indent
        tree = self.parse_code(source_code)
        node_names = list(map(lambda node: node, self.get_func_tokens(tree)))
        func = ''
        if self.language in ['python']:
            row_count = 0
            indent_token = self.indent
            for idx, node in enumerate(list(node_names)):
                if node == '':
                    continue
                if node == '\n' or node == ' ':
                    continue
                # try to strip the node
                node = node.strip()
                if node != '#<S2SV>':
                    func += node.replace(' ', '<S2SV_blank>') + ' '
                else:
                    func += node.replace(' ', '<S2SV_blank>') + ' '
                    row_count += 1
                    if idx != len(node_names) - 1 and row_count < len(indent_lists):
                        indent_count = indent_lists[row_count]
                        for _ in range(indent_count):
                            func += indent_token + ' '
        else:
            for node in list(node_names):
                if node == '':
                    continue
                if node == '\n' or node == ' ':
                    continue
                # try to strip the node
                node = node.strip()
                func += node.replace(' ', '<S2SV_blank>') + ' '
        return func

    def replace_newline_char(self, source_code):
        tree = self.parse_code(source_code)
        node_names = list(map(lambda node: node.text.decode('utf-8'), self.get_string_literals(tree)))
        change_dict = {}
        if self.language in ['c']:
            for node in node_names:
                sign = ''
                if node.startswith('"') and node.endswith('"') or node.startswith("'") and node.endswith("'"):
                    if node.startswith('"'):
                        sign = '"'
                        node = node[1:-1]
                    elif node.startswith("'"):
                        sign = "'"
                        node = node[1:-1]
                new_node = node
                if '\\\\' in node:
                    new_node = new_node.replace('\\\\', '\\\\\\\\')
                if '\\"' in node:
                    new_node = new_node.replace('\\"', '\\\\\"')
                if '\\t' in node:
                    new_node = new_node.replace('\\t', '\\\\t')
                if '\\b' in node:
                    new_node = new_node.replace('\\b', '\\\\b')
                if '\\r' in node:
                    new_node = new_node.replace('\\r', '\\\\r')
                if '\\v' in node:
                    new_node = new_node.replace('\\v', '\\\\v')
                if '\\f' in node:
                    new_node = new_node.replace('\\f', '\\\\f')
                if '\\a' in node:
                    new_node = new_node.replace('\\a', '\\\\a')
                if '\\0' in node:
                    new_node = new_node.replace('\\0', '\\\\0')
                if "\\\\'" in new_node:
                    new_node = re.sub(r"(?<!\\)\\\\'", r"\\\\\\'", new_node)
                if "'" in node:
                    new_node = re.sub(r"(?<!\\)'", r"\\'", new_node)
                    # new_node = new_node.replace("'", "\\\'")
                if '\\e' in node:
                    new_node = re.sub(r'(?<!\\)\\e', r'\\\\e', new_node)
                if '\\n' in node:
                    new_node = re.sub(r'(?<!\\)\\n', r'\\\\n', new_node)
                # 使用正则表达式进行替换
                # (?<!\\) 是一个负向后瞻断言，确保前面不是反斜杠
                # \\ 匹配一个反斜杠
                # \d{2,} 匹配两个或更多数字
                new_node = re.sub(r'(?<!\\)\\(\d{2,})', r'\\\\\1', new_node)
                # pattern = r'(?<!\\)\\(?!\\)'
                # # 将匹配到的单个 \ 替换为 \\
                # new_node = re.sub(pattern, r'\\\\', new_node)
                # 对 \\' 则会中符号替换

                node = sign + node + sign
                new_node = sign + new_node + sign
                change_dict[node] = new_node
        elif self.language in ['cpp', 'java', 'c_sharp', 'javascript', 'go', 'python']:
            for node in node_names:
                # 只对换行符处理
                new_node = node
                # 字符串中的 \n 字符 -> \\n
                if '\\n' in node:
                    new_node = re.sub(r'(?<!\\)\\n', r'\\\\n', new_node)
                # 字符串中的换行符 -> \n
                if '\n' in node:
                    new_node = re.sub(r'(?<!\\)\n', r'\\n', new_node)
                change_dict[node] = new_node

        for key, value in change_dict.items():
            source_code = source_code.replace(key, value)
        return source_code

    def replace_new_line_char_with_special_token(self, input_str):
        # Comments have been removed so add comment tokens for line delimiters
        if self.language != 'python':
            special_char = ' //<S2SV>\n '
        else:
            special_char = ' #<S2SV>\n '
        pattern = r'(?<!\\)\n'
        result = re.sub(pattern, special_char, input_str)
        return result

    def calculate_indent(self, str_lines):
        indent_lists = [str_line[:len(str_line) - len(str_line.lstrip())] for str_line in str_lines]
        # 将indent_lists中的最小的非零空格数作为indent的最小单位，制表符算一个indent
        indent_counts = []
        for indent in indent_lists:
            blank_space = 0
            tab_space = 0
            for i in indent:
                if i == ' ':
                    blank_space += 1
                elif i == '\t':
                    tab_space += 1
            indent_counts.append([blank_space, tab_space])
        min_indent = 114514
        for indent in indent_counts:
            if indent[0] != 0:
                min_indent = min(min_indent, indent[0])

        indent_count_lists = []
        for indent in indent_counts:
            indent_count = indent[0] // min_indent + indent[1]
            indent_count_lists.append(indent_count)
        return indent_count_lists

    def format_diff(self, func_before, func_after, func_name, file_path, tmp_dir):
        # func_before = func_before.strip()
        # func_after = func_after.strip()
        func_before = self.replace_newline_char(func_before)
        func_after = self.replace_newline_char(func_after)
        if not func_before.endswith('\n'):
            func_before += '\n'
        if not func_after.endswith('\n'):
            func_after += '\n'
        with open(tmp_dir / f'test_func_before.{self.post_fix}', 'w', encoding='utf-8') as f:
            f.write(func_before)
        with open(tmp_dir / f'test_func_before.{self.post_fix}', 'r', encoding='utf-8') as f:
            func_before_lines = f.readlines()
        with open(tmp_dir / f'test_func_after.{self.post_fix}', 'w', encoding='utf-8') as f:
            f.write(func_after)
        with open(tmp_dir / f'test_func_after.{self.post_fix}', 'r', encoding='utf-8') as f:
            func_after_lines = f.readlines()
        try:

            diff = list(difflib.unified_diff(func_before_lines, func_after_lines,
                                             fromfile='func_before.function',
                                             tofile='func_after.function', n=1000000))
            if diff:
                with codecs.open(tmp_dir / 'S2SV_func.diff', 'w', 'utf-8') as f:
                    f.write(''.join(diff))
                patch = PatchSet.from_filename(tmp_dir / 'S2SV_func.diff', encoding='utf-8')
                pre_version_function = [line[1:] for line in patch[0][0].source]
                post_version_function = [line[1:] for line in patch[0][0].target]
                # for python indent
                if self.language in ['python']:
                    # 去掉空白行
                    new_pre_version_function = []
                    for line in pre_version_function:
                        new_line = line.strip()
                        if new_line == '':
                            continue
                        new_pre_version_function.append(line)
                    pre_version_function = new_pre_version_function
                    new_post_version_function = []
                    for line in post_version_function:
                        new_line = line.strip()
                        if new_line == '':
                            continue
                        new_post_version_function.append(line)
                    post_version_function = new_post_version_function
                    pre_indent_count = self.calculate_indent(pre_version_function)
                    post_indent_count = self.calculate_indent(post_version_function)
                pre_version_function = [line.lstrip() for line in pre_version_function]
                post_version_function = [line.lstrip() for line in post_version_function]
                pre_version_function_str = ''.join(pre_version_function)
                post_version_function_str = ''.join(post_version_function)

                if ''.join(pre_version_function_str) == ''.join(post_version_function_str):
                    return

                # Comments have been removed so add comment tokens for line delimiters
                pre_version_function_str = self.replace_new_line_char_with_special_token(pre_version_function_str)
                post_version_function_str = self.replace_new_line_char_with_special_token(post_version_function_str)
                if self.language in ['python']:
                    pre_version_function_str = self.replace_string_blank(pre_version_function_str, pre_indent_count)
                    post_version_function_str = self.replace_string_blank(post_version_function_str, post_indent_count)
                else:
                    pre_version_function_str = self.replace_string_blank(pre_version_function_str)
                    post_version_function_str = self.replace_string_blank(post_version_function_str)

                file_dir = file_path.parent
                if self.language in ['c']:
                    # prevent too long file name error for VRepair dataset
                    file_name = str(file_path.name).split('@')[-1].strip()
                else:
                    file_name = str(file_path.name).strip()
                file_post_fix = f'.token{self.post_fix}'
                file_path = file_dir / str(file_name + '_' + func_name + file_post_fix)
                func_before_path = file_path
                func_after_path = Path(str(file_path).replace('pre_version', 'post_version'))
                with open(func_before_path, 'w', encoding='utf-8') as f:
                    f.write(pre_version_function_str)
                with open(func_after_path, 'w', encoding='utf-8') as f:
                    f.write(post_version_function_str)
                return True
        except unidiff.errors.UnidiffParseError as e:
            print('UnidiffParseError: ', e)
            print(file_path)
            return False

    def get_func_pair_diff(self, file_path_before, file_path_after, tmp_dir):
        with open(file_path_before, 'r', encoding='utf-8') as f:
            source_before = f.read()
        with open(file_path_after, 'r', encoding='utf-8') as f:
            source_after = f.read()
        tree_before = self.parse_code(source_before)
        tree_after = self.parse_code(source_after)

        try:
            source_before = self.remove_comments(source_before, tree_before)
            source_after = self.remove_comments(source_after, tree_after)
        except RecursionError as e:
            print('===========')
            print(e)
            print(file_path_before)
            return 0
        # rebuild tree after removing comments
        tree_before = self.parse_code(source_before)
        tree_after = self.parse_code(source_after)
        try:
            changes = self.compare_functions(tree_before, tree_after)
        except IndexError as e:
            print(e)
            print(file_path_before)
            exit(-1)

        diff_func_count = 0
        for change in changes:
            func_name = self.format_func_name(change[2])
            flag = self.format_diff(change[0], change[1], func_name, file_path_before, tmp_dir)
            if flag:
                diff_func_count += 1
        return diff_func_count

    def get_detection_func_pair(self, file_path_before, file_path_after, tmp_dir):
        with open(file_path_before, 'r', encoding='utf-8') as f:
            source_before = f.read()
        with open(file_path_after, 'r', encoding='utf-8') as f:
            source_after = f.read()
        tree_before = self.parse_code(source_before)
        tree_after = self.parse_code(source_after)

        try:
            source_before = self.remove_comments(source_before, tree_before)
            source_after = self.remove_comments(source_after, tree_after)
        except RecursionError as e:
            print('===========')
            print(e)
            print(file_path_before)
            return 0
        # rebuild tree after removing comments
        tree_before = self.parse_code(source_before)
        tree_after = self.parse_code(source_after)
        try:
            changes = self.compare_functions(tree_before, tree_after)
        except IndexError as e:
            print(e)
            print(file_path_before)
            exit(-1)

        return changes

    def find_identical_functions(self, tree_before, tree_after):
        functions_before = self.get_functions(tree_before)
        functions_after = self.get_functions(tree_after)
        identical_functions = []

        # TODO:新增的函数找不到修改前function，这是合理的，完全删减的函数有可能误匹配函数，这是后续可能需要改进的
        for func_before_list in functions_before:
            func_name = func_before_list[0]
            func_before = func_before_list[1]
            func_candidates = [f[1] for f in functions_after if f[0] == func_name]
            code_before = func_before.text.decode('utf-8')
            if len(func_candidates) == 0:
                continue
            if len(func_candidates) == 1:
                func_after = func_candidates[0]
            else:
                # if there are multiple functions with the same name, we need to find the best match
                # consider each function edit distance, the function with the smallest edit distance is the best match
                edit_distances = []
                for i in range(len(func_candidates)):
                    func = func_candidates[i]
                    code_after = func.text.decode('utf-8')
                    edit_distance = Levenshtein.distance(code_before, code_after)
                    edit_distances.append(edit_distance)
                min_edit_distance = min(edit_distances)
                min_edit_index = edit_distances.index(min_edit_distance)
                func_after = func_candidates[min_edit_index]
                func_name += '_' + str(func_before.start_point[0])
            code_after = func_after.text.decode('utf-8')
            if code_before == code_after:
                identical_functions.append([code_before, code_after, func_name])
        return identical_functions
    
    def get_detection_identical_funcs(self, file_path_before, file_path_after, tmp_dir):
        with open(file_path_before, 'r', encoding='utf-8') as f:
            source_before = f.read()
        with open(file_path_after, 'r', encoding='utf-8') as f:
            source_after = f.read()
        tree_before = self.parse_code(source_before)
        tree_after = self.parse_code(source_after)

        try:
            source_before = self.remove_comments(source_before, tree_before)
            source_after = self.remove_comments(source_after, tree_after)
        except RecursionError as e:
            print('===========')
            print(e)
            print(file_path_before)
            return 0
        # rebuild tree after removing comments
        tree_before = self.parse_code(source_before)
        tree_after = self.parse_code(source_after)
        try:
            changes = self.find_identical_functions(tree_before, tree_after)
        except IndexError as e:
            print(e)
            print(file_path_before)
            exit(-1)

        return changes


if __name__ == '__main__':
    config = yaml.load(open('./data_preprocess.yaml'), Loader=yaml.FullLoader)
    specific_config = config['data_preprocess']['Python']
    parser = TreeSitterParse(specific_config)
    before_path = pathlib.Path(
        r'/home/yjj/data/datasets/data/REEF/multi_post_fix_data/C++/4129/pre_version/code0.py')
    after_path = Path(str(before_path).replace('pre_version', 'post_version'))
    parser.get_func_pair_diff(before_path, after_path, Path('./tmp'))
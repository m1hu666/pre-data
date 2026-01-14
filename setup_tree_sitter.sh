#!/bin/bash
# 设置 Tree-sitter 语言解析器

set -e

TOOLS_DIR="/home/m1hu/pre-data/tools"
cd "$TOOLS_DIR"

echo "正在克隆 Tree-sitter 语言解析器..."

# C
if [ ! -d "tree-sitter-c" ]; then
    echo "克隆 tree-sitter-c..."
    git clone https://github.com/tree-sitter/tree-sitter-c.git --depth 1
fi

# C++
if [ ! -d "tree-sitter-cpp" ]; then
    echo "克隆 tree-sitter-cpp..."
    git clone https://github.com/tree-sitter/tree-sitter-cpp.git --depth 1
fi

# Python
if [ ! -d "tree-sitter-python" ]; then
    echo "克隆 tree-sitter-python..."
    git clone https://github.com/tree-sitter/tree-sitter-python.git --depth 1
fi

# Java
if [ ! -d "tree-sitter-java" ]; then
    echo "克隆 tree-sitter-java..."
    git clone https://github.com/tree-sitter/tree-sitter-java.git --depth 1
fi

# JavaScript
if [ ! -d "tree-sitter-javascript" ]; then
    echo "克隆 tree-sitter-javascript..."
    git clone https://github.com/tree-sitter/tree-sitter-javascript.git --depth 1
fi

# Go
if [ ! -d "tree-sitter-go" ]; then
    echo "克隆 tree-sitter-go..."
    git clone https://github.com/tree-sitter/tree-sitter-go.git --depth 1
fi

# C#
if [ ! -d "tree-sitter-c-sharp" ]; then
    echo "克隆 tree-sitter-c-sharp..."
    git clone https://github.com/tree-sitter/tree-sitter-c-sharp.git --depth 1
fi

echo "Tree-sitter 语言解析器设置完成！"
ls -l

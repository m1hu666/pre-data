#!/bin/bash
# 修复TreeSitter版本不兼容问题
# 将语言库回退到tree-sitter 0.21.3兼容的版本（ABI 14）

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR/tools"
BUILD_DIR="$TOOLS_DIR/build"

echo "==================================================================="
echo "TreeSitter版本兼容性修复脚本"
echo "==================================================================="
echo "问题: Python、C、Go、JS、C# 的语言库版本为15，不兼容tree-sitter 0.21.3（需要13-14）"
echo "解决: 将语言库回退到兼容版本"
echo ""

# 定义需要回退的语言及其兼容版本/commit
# 这些版本使用ABI 14，兼容tree-sitter 0.21.x
declare -A COMPATIBLE_VERSIONS=(
    ["tree-sitter-python"]="v0.20.4"  # 2023年版本，使用ABI 14
    ["tree-sitter-c"]="v0.20.6"        # 2023年版本
    ["tree-sitter-go"]="v0.20.0"       # 2023年版本
    ["tree-sitter-javascript"]="v0.20.4"  # 2023年版本
    ["tree-sitter-c-sharp"]="v0.20.0"  # 2023年版本
)

# Java和C++已经工作，不需要修改
echo "跳过已正常工作的语言: Java, C++"
echo ""

cd "$TOOLS_DIR"

for LANG_DIR in "${!COMPATIBLE_VERSIONS[@]}"; do
    VERSION="${COMPATIBLE_VERSIONS[$LANG_DIR]}"
    echo "-------------------------------------------------------------------"
    echo "处理: $LANG_DIR → $VERSION"
    echo "-------------------------------------------------------------------"
    
    if [ ! -d "$LANG_DIR" ]; then
        echo "❌ 目录不存在: $LANG_DIR"
        continue
    fi
    
    cd "$LANG_DIR"
    
    # 获取当前状态
    CURRENT_COMMIT=$(git rev-parse --short HEAD)
    echo "当前commit: $CURRENT_COMMIT"
    
    # 检查版本是否存在
    if ! git rev-parse "$VERSION" >/dev/null 2>&1; then
        echo "❌ 版本 $VERSION 不存在，尝试获取..."
        git fetch --tags
    fi
    
    # 回退到兼容版本
    echo "切换到: $VERSION"
    if git checkout "$VERSION" 2>/dev/null; then
        echo "✓ 成功切换到 $VERSION"
    else
        echo "❌ 切换失败，尝试使用最近的兼容commit..."
        # 如果标签不存在，尝试找到2023年的commit
        git log --before="2024-01-01" --format="%h %s" -n 1
        FALLBACK_COMMIT=$(git log --before="2024-01-01" --format="%h" -n 1)
        git checkout "$FALLBACK_COMMIT"
    fi
    
    cd "$TOOLS_DIR"
    echo ""
done

echo "==================================================================="
echo "重新编译语言库"
echo "==================================================================="

# 清理旧的编译文件
rm -f "$BUILD_DIR"/libtree-sitter-python.so
rm -f "$BUILD_DIR"/libtree-sitter-c.so
rm -f "$BUILD_DIR"/libtree-sitter-go.so
rm -f "$BUILD_DIR"/libtree-sitter-javascript.so
rm -f "$BUILD_DIR"/libtree-sitter-c-sharp.so

# 重新编译（使用Python脚本测试，自动触发编译）
echo "将在首次使用时自动编译..."
echo ""

echo "==================================================================="
echo "修复完成！"
echo "==================================================================="
echo "下一步: 运行测试脚本验证"
echo "  cd /home/m1hu/pre-data"
echo "  source venv/bin/activate"
echo "  python src/test_treesitter.py"
echo ""

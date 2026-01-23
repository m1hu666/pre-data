#!/usr/bin/env python3
"""测试超时机制是否正常工作"""

import signal
import time

class TimeoutError(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutError("处理超时")

def slow_function():
    """模拟耗时操作"""
    print("开始慢速操作...")
    time.sleep(5)
    print("慢速操作完成")

def main():
    timeout = 2  # 2秒超时
    
    print(f"测试超时机制（超时限制: {timeout}秒）")
    
    try:
        # 设置超时
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)
        
        slow_function()
        
        # 取消超时
        signal.alarm(0)
        print("✓ 操作在超时前完成")
        
    except TimeoutError as e:
        # 超时，取消alarm并跳过
        signal.alarm(0)
        print(f"✗ 操作超时: {e}")
    except Exception as e:
        # 其他异常，也取消alarm
        signal.alarm(0)
        print(f"✗ 其他错误: {e}")
    
    print("\n测试快速操作...")
    
    def fast_function():
        print("快速操作完成")
    
    try:
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)
        fast_function()
        signal.alarm(0)
        print("✓ 快速操作正常完成")
    except TimeoutError:
        signal.alarm(0)
        print("✗ 快速操作超时（不应该发生）")
    
    print("\n超时机制测试完成")

if __name__ == '__main__':
    main()

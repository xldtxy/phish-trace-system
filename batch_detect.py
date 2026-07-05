#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量邮件检测脚本
用法：python batch_detect.py <邮件目录> [输出文件]
示例：python batch_detect.py test_email_dataset/danger batch_result.csv
"""

import os
import sys
import json
import csv
from datetime import datetime

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.preprocess import parse_email
from modules.detector import detect_phish
from modules.tracer import trace_email


def batch_detect(email_dir, output_file=None):
    """
    批量检测邮件目录中的所有eml文件
    
    Args:
        email_dir: 邮件目录路径
        output_file: 输出CSV文件路径（可选）
    """
    # 获取所有eml文件
    eml_files = []
    for root, dirs, files in os.walk(email_dir):
        for f in files:
            if f.lower().endswith('.eml'):
                eml_files.append(os.path.join(root, f))
    
    if not eml_files:
        print(f"[!] 在 {email_dir} 中未找到 .eml 文件")
        return
    
    print(f"[*] 找到 {len(eml_files)} 封邮件，开始批量检测...")
    print("=" * 80)
    
    results = []
    success_count = 0
    phish_count = 0
    
    for i, file_path in enumerate(eml_files, 1):
        filename = os.path.basename(file_path)
        print(f"[{i}/{len(eml_files)}] 检测: {filename}", end=" ")
        
        try:
            # 解析邮件
            email_data = parse_email(file_path)
            
            # 检测钓鱼
            detection = detect_phish(email_data)
            
            # 溯源
            trace = trace_email(email_data)
            
            # 统计
            if detection.get('is_phish'):
                phish_count += 1
                status = "🚨 钓鱼"
            else:
                status = "✅ 正常"
            
            success_count += 1
            
            # 保存结果
            results.append({
                'file': filename,
                'path': file_path,
                'from': email_data.get('from', ''),
                'subject': email_data.get('subject', ''),
                'is_phish': detection.get('is_phish', False),
                'risk_level': detection.get('risk_level', '未知'),
                'confidence': detection.get('confidence', 0),
                'reason': detection.get('reason', ''),
                'ip_count': len(trace.get('ips', [])),
                'domain_count': len(trace.get('domains', [])),
            })
            
            print(f"{status} (风险: {detection.get('risk_level', '未知')}, 置信度: {detection.get('confidence', 0):.0%})")
            
        except Exception as e:
            print(f"❌ 失败: {e}")
            results.append({
                'file': filename,
                'path': file_path,
                'from': '',
                'subject': '',
                'is_phish': False,
                'risk_level': '检测失败',
                'confidence': 0,
                'reason': str(e),
                'ip_count': 0,
                'domain_count': 0,
            })
    
    print("=" * 80)
    print(f"\n[✓] 检测完成！")
    print(f"    总计: {len(eml_files)} 封")
    print(f"    成功: {success_count} 封")
    print(f"    钓鱼邮件: {phish_count} 封")
    print(f"    正常邮件: {success_count - phish_count} 封")
    if success_count > 0:
        print(f"    钓鱼占比: {phish_count/success_count:.1%}")
    
    # 输出CSV
    if output_file:
        with open(output_file, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'file', 'from', 'subject', 'is_phish', 'risk_level', 
                'confidence', 'reason', 'ip_count', 'domain_count', 'path'
            ])
            writer.writeheader()
            writer.writerows(results)
        print(f"\n[✓] 结果已保存到: {output_file}")
    
    # 输出JSON
    json_file = output_file.replace('.csv', '.json') if output_file else 'batch_result.json'
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump({
            'total': len(eml_files),
            'success': success_count,
            'phish_count': phish_count,
            'normal_count': success_count - phish_count,
            'timestamp': datetime.now().isoformat(),
            'results': results
        }, f, ensure_ascii=False, indent=2)
    print(f"[✓] 详细结果已保存到: {json_file}")
    
    return results


def main():
    if len(sys.argv) < 2:
        print("用法: python batch_detect.py <邮件目录> [输出CSV文件]")
        print("示例:")
        print("  python batch_detect.py test_email_dataset/danger")
        print("  python batch_detect.py test_email_dataset/danger result.csv")
        print()
        print("如果不指定输出文件，默认输出到 batch_result.csv 和 batch_result.json")
        return
    
    email_dir = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'batch_result.csv'
    
    if not os.path.exists(email_dir):
        print(f"[!] 目录不存在: {email_dir}")
        return
    
    batch_detect(email_dir, output_file)


if __name__ == '__main__':
    main()

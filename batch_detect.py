"""
批量邮件在线检测脚本，检测结果同步写入detections.json，前端页面统计自动更新
用法: python batch_detect.py <邮件目录> [输出文件]
示例: python batch_detect.py test_email_dataset/danger batch_result.csv
"""
import sys
import os
import json
import csv
from datetime import datetime

# 添加项目根目录路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from modules.preprocess import parse_email
from modules.detector import detect_phish
from modules.tracer import trace_email

# 全局检测记录文件（和网页上传共用存储）
DETECTION_RECORD_FILE = "detections.json"

def load_global_records():
    """加载全局检测记录，不存在则返回空列表"""
    if not os.path.exists(DETECTION_RECORD_FILE):
        return []
    try:
        with open(DETECTION_RECORD_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_global_record(record):
    """单条检测记录写入全局文件，同步给前端统计接口"""
    records = load_global_records()
    records.append(record)
    with open(DETECTION_RECORD_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)

def batch_detect(email_dir, output_file=None):
    # 遍历目录所有eml邮件
    eml_files = []
    for root, _, files in os.walk(email_dir):
        for fname in files:
            if fname.lower().endswith(".eml"):
                eml_files.append(os.path.join(root, fname))
    if not eml_files:
        print(f"目录 {email_dir} 未找到任何.eml邮件文件")
        return

    all_result = []
    print(f"共找到 {len(eml_files)} 封邮件，开始批量检测...")

    for idx, file_path in enumerate(eml_files, 1):
        print(f"\n[{idx}/{len(eml_files)}] 正在检测: {os.path.basename(file_path)}")
        try:
            # 解析邮件
            mail_data = parse_email(file_path)
            # AI在线检测
            detect_res = detect_phish(mail_data)
            # 溯源信息
            trace_res = trace_email(mail_data)

            # 组装统一格式记录（和网页上传数据格式完全一致）
            single_record = {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "filename": os.path.basename(file_path),
                "sender": mail_data.get("from", ""),
                "subject": mail_data.get("subject", ""),
                "is_phish": detect_res.get("is_phish", False),
                "risk_level": detect_res.get("risk_level", "低风险"),
                "confidence": detect_res.get("confidence", 0.0),
                "reason": detect_res.get("reason", ""),
                "trace_info": trace_res
            }

            # 同步写入全局记录，前端可读取
            save_global_record(single_record)
            all_result.append(single_record)
            print(f"完成：风险等级 {single_record['risk_level']}")
        except Exception as e:
            err_msg = f"文件 {file_path} 检测失败：{str(e)}"
            print(err_msg)
            all_result.append({
                "filename": os.path.basename(file_path),
                "error": err_msg
            })

    # 导出本地CSV、JSON结果（原有逻辑保留）
    base_name = output_file if output_file else "batch_result"
    csv_path = f"{base_name}.csv"
    json_path = f"{base_name}.json"

    # CSV导出
    csv_header = ["文件名", "发件人", "主题", "是否钓鱼", "风险等级", "置信度", "判定理由", "检测时间"]
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=csv_header)
        writer.writeheader()
        for item in all_result:
            writer.writerow({
                "文件名": item.get("filename", ""),
                "发件人": item.get("sender", ""),
                "主题": item.get("subject", ""),
                "是否钓鱼": item.get("is_phish", ""),
                "风险等级": item.get("risk_level", ""),
                "置信度": item.get("confidence", ""),
                "判定理由": item.get("reason", ""),
                "检测时间": item.get("time", "")
            })
    # JSON导出
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(all_result, f, ensure_ascii=False, indent=2)

    print(f"\n批量检测全部完成！")
    print(f"本地报告已保存：{csv_path} / {json_path}")
    print(f"检测数据已同步至全局记录 {DETECTION_RECORD_FILE}，刷新前端页面即可看到更新统计")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python batch_detect.py <邮件目录> [输出CSV文件名]")
        print("示例:")
        print("  python batch_detect.py test_email_dataset/danger")
        print("  python batch_detect.py test_email_dataset/danger result.csv")
        sys.exit(0)
    mail_dir = sys.argv[1]
    out_file = sys.argv[2] if len(sys.argv) >=3 else None
    batch_detect(mail_dir, out_file)
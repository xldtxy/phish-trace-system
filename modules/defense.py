import sqlite3
import os
import shutil
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
import config

# ========== 黑名单管理 ==========
def init_db():
    """初始化黑名单数据库"""
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            value TEXT UNIQUE,
            risk_level TEXT,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


def add_to_blacklist(type_str, value, risk_level='高'):
    """添加条目到黑名单（IP/域名/邮箱）"""
    if not value:
        return False
    init_db()
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT OR IGNORE INTO blacklist (type, value, risk_level) VALUES (?, ?, ?)',
            (type_str, value, risk_level)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"[-] 黑名单写入失败: {e}")
        return False
    finally:
        conn.close()


def is_blacklisted(value):
    """查询条目是否在黑名单中，返回风险等级"""
    if not value:
        return None
    init_db()
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT risk_level FROM blacklist WHERE value = ?', (value,))
    res = cursor.fetchone()
    conn.close()
    return res[0] if res else None


# ========== 可疑邮件归档 ==========
def archive_suspicious_email(file_path, reason):
    """将可疑邮件带标记归档到本地目录"""
    archive_dir = 'suspicious_archive'
    if not os.path.exists(archive_dir):
        os.makedirs(archive_dir)

    if not os.path.exists(file_path):
        return None

    filename = os.path.basename(file_path)
    name, ext = os.path.splitext(filename)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    new_filename = f"{timestamp}_{name}_FLAGGED_{reason}{ext}"
    dest_path = os.path.join(archive_dir, new_filename)

    try:
        shutil.copy(file_path, dest_path)
        return dest_path
    except Exception as e:
        print(f"[-] 归档失败: {e}")
        return None


# ========== 蜜罐自动回复 ==========
def send_honeypot_reply(to_email, subject):
    """模拟正常员工回复，诱导攻击者暴露身份"""
    if not config.SMTP_USER or not config.SMTP_PASSWORD:
        return False, "未配置SMTP邮箱信息"

    reply_content = f"""
您好：

您发送的主题为「{subject}」的邮件已收到，相关事宜我们正在核实处理。
如需进一步沟通，请直接回复本邮件。

此致
行政部
"""

    msg = MIMEText(reply_content, "plain", "utf-8")
    msg["From"] = config.SMTP_USER
    msg["To"] = to_email
    msg["Subject"] = "Re: " + subject

    try:
        server = smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT)
        server.starttls()
        server.login(config.SMTP_USER, config.SMTP_PASSWORD)
        server.sendmail(config.SMTP_USER, to_email, msg.as_string())
        server.quit()
        return True, "蜜罐回复已发送"
    except Exception as e:
        return False, str(e)
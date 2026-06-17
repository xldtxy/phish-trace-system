import os
import re
import email
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
import config


def allowed_file(filename):
    """检查文件是否为.eml格式（核心校验）"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in config.ALLOWED_EXTENSIONS


def parse_email(file_path):
    """
    基础版邮件解析：只提取核心字段，无图片/二维码/附件处理
    输出：发件人、收件人、主题、日期、正文、链接、Received头（溯源用）
    """
    result = {
        'headers': {},
        'text': '',
        'html': '',
        'links': []
    }

    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        # 1. 提取核心邮件头（检测+溯源必须）
        result['headers']['from'] = str(msg.get('From', ''))
        result['headers']['to'] = str(msg.get('To', ''))
        result['headers']['subject'] = str(msg.get('Subject', ''))
        result['headers']['date'] = str(msg.get('Date', ''))
        result['headers']['received'] = [str(h) for h in msg.get_all('Received', [])]

        # 2. 提取邮件正文（纯文本+HTML）
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))

                # 跳过所有附件和内嵌资源
                if 'attachment' in content_disposition:
                    continue

                # 提取纯文本正文
                if content_type == 'text/plain':
                    try:
                        result['text'] = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        result['text'] = part.get_payload(decode=True).decode('gbk', errors='ignore')

                # 提取HTML正文
                elif content_type == 'text/html':
                    try:
                        result['html'] = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        result['html'] = part.get_payload(decode=True).decode('gbk', errors='ignore')
        else:
            # 非多部分邮件直接提取正文
            if msg.get_content_type() == 'text/plain':
                try:
                    result['text'] = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                except:
                    result['text'] = msg.get_payload(decode=True).decode('gbk', errors='ignore')

        # 3. 从HTML和纯文本中提取所有链接（检测必须）
        # 从HTML提取链接
        if result['html']:
            soup = BeautifulSoup(result['html'], 'html.parser')
            for a in soup.find_all('a', href=True):
                if a['href'].startswith(('http://', 'https://')):
                    result['links'].append(a['href'])

        # 从纯文本提取链接
        if result['text']:
            text_links = re.findall(r'https?://[^\s<>"\']+', result['text'])
            result['links'].extend(text_links)

        # 链接去重
        result['links'] = list(set(result['links']))

        return result

    except Exception as e:
        raise Exception(f"邮件解析失败: {str(e)}")


# 兼容旧版函数名
parse_email_simple = parse_email
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import uuid
import re
import email
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup

# 导入检测和溯源模块
from modules.detector import detect_phish
from modules.tracer import trace_email

# 初始化Flask应用
app = Flask(__name__)
CORS(app)
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'eml'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 最大16MB

# 自动创建上传文件夹
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


# 检查文件格式
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# 极简邮件解析（只保留核心字段）
def parse_email_simple(file_path):
    result = {
        'from': '',
        'to': '',
        'subject': '',
        'text': '',
        'links': [],
        'headers': {}  # 保留headers给溯源模块用
    }
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        # 提取核心头信息
        result['from'] = str(msg.get('From', '未知'))
        result['to'] = str(msg.get('To', '未知'))
        result['subject'] = str(msg.get('Subject', '无主题'))
        # 保留Received头给溯源模块
        result['headers']['received'] = [str(h) for h in msg.get_all('Received', [])]

        # 提取纯文本正文
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get('Content-Disposition', ''))
                if part.get_content_type() == 'text/plain' and 'attachment' not in content_disposition:
                    try:
                        result['text'] = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        result['text'] = part.get_payload(decode=True).decode('gbk', errors='ignore')
                    break
        else:
            if msg.get_content_type() == 'text/plain':
                try:
                    result['text'] = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                except:
                    result['text'] = msg.get_payload(decode=True).decode('gbk', errors='ignore')

        # 提取所有链接并去重
        result['links'] = list(set(re.findall(r'https?://[^\s<>"\']+', result['text'])))
        return result

    except Exception as e:
        raise Exception(f"邮件解析失败: {str(e)}")


# 静态文件路由：访问前端页面
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


# 核心接口：上传邮件 → 解析 → 检测 → 溯源
@app.route('/api/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': '未上传文件'}), 400

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'success': False, 'error': '仅支持上传.eml格式的邮件文件'}), 400

    # 生成唯一文件名保存临时文件
    filename = f"{uuid.uuid4()}.eml"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    try:
        # 1. 解析邮件
        email_data = parse_email_simple(file_path)
        # 2. 钓鱼邮件检测
        detect_result = detect_phish(email_data)
        # 3. IP溯源分析
        trace_result = trace_email(email_data)

        # 删除临时文件
        os.remove(file_path)

        # 返回完整结果
        return jsonify({
            'success': True,
            'email': email_data,
            'detection': detect_result,
            'trace': trace_result
        })

    except Exception as e:
        # 出错时也删除临时文件
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
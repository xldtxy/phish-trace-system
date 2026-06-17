from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import uuid
import config


from modules.preprocess import allowed_file
from modules.preprocess import parse_email_simple
from modules.detector import detect_phish
from modules.tracer import trace_email
from modules.defense import add_to_blacklist, archive_suspicious_email, send_honeypot_reply

# 初始化Flask应用
app = Flask(__name__)
CORS(app)
app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH

# 自动创建上传目录
if not os.path.exists(config.UPLOAD_FOLDER):
    os.makedirs(config.UPLOAD_FOLDER)

# ========== 页面路由 ==========
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload')
def upload_page():
    return render_template('upload.html')


@app.route('/result')
def result_page():
    return render_template('result.html')


# ========== 核心检测API ==========
@app.route('/api/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': '未上传文件'}), 400

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'success': False, 'error': '仅支持.eml格式'}), 400

    filename = f"{uuid.uuid4()}.eml"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    try:
        # 1. 解析邮件
        email_data = parse_email_simple(file_path)
        # 2. 大模型检测
        detect_result = detect_phish(email_data)
        # 3. IP+域名溯源
        trace_result = trace_email(email_data)

        # 删除临时文件
        os.remove(file_path)
        return jsonify({
            'success': True,
            'email': email_data,
            'detection': detect_result,
            'trace': trace_result
        })

    except Exception as e:
        # 出错也清理临时文件
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({'success': False, 'error': str(e)}), 500


# ========== 反制功能API ==========
@app.route('/api/blacklist/add', methods=['POST'])
def blacklist_add():
    data = request.json
    ok = add_to_blacklist(
        data.get('type'),
        data.get('value'),
        data.get('risk_level', '高')
    )
    return jsonify({'success': ok})


@app.route('/api/archive', methods=['POST'])
def archive_email():
    data = request.json
    file_path = data.get('file_path', '')
    reason = data.get('reason', '可疑邮件')
    result = archive_suspicious_email(file_path, reason)
    return jsonify({'success': result is not None, 'path': result})


@app.route('/api/honeypot/reply', methods=['POST'])
def honeypot_reply():
    data = request.json
    ok, msg = send_honeypot_reply(
        data.get('to', ''),
        data.get('subject', '')
    )
    return jsonify({'success': ok, 'message': msg})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=config.FLASK_PORT)
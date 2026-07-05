from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import uuid
import json
import datetime
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

# 检测记录存储文件
DETECTIONS_FILE = "detections.json"

# 自动创建上传目录
if not os.path.exists(config.UPLOAD_FOLDER):
    os.makedirs(config.UPLOAD_FOLDER)


# ========== 数据持久化工具函数 ==========
def _load_detections():
    """加载所有检测记录"""
    if not os.path.exists(DETECTIONS_FILE):
        return []
    try:
        with open(DETECTIONS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return []


def _save_detection(record):
    """保存一条检测记录"""
    detections = _load_detections()
    detections.append(record)
    with open(DETECTIONS_FILE, 'w', encoding='utf-8') as f:
        json.dump(detections, f, ensure_ascii=False, indent=2)


def _get_stats():
    """获取统计数据"""
    detections = _load_detections()
    total = len(detections)
    phish_count = sum(1 for d in detections if d.get('detection', {}).get('is_phish', False))
    traced_count = sum(1 for d in detections if d.get('trace', {}).get('ips') and len(d['trace']['ips']) > 0)
    # 反制数量用黑名单记录数
    defense_count = 0
    if os.path.exists(config.DB_PATH):
        try:
            import sqlite3
            conn = sqlite3.connect(config.DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM blacklist")
            defense_count = cursor.fetchone()[0]
            conn.close()
        except:
            defense_count = 0
    return {
        'total': total,
        'phish': phish_count,
        'traced': traced_count,
        'defense': defense_count
    }


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


# ========== 统计API ==========
@app.route('/api/stats', methods=['GET'])
def get_stats():
    """获取检测统计数据"""
    stats = _get_stats()
    return jsonify({
        'success': True,
        'stats': stats
    })


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

        # 保存检测记录
        record = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.datetime.now().isoformat(),
            'email': {
                'from': email_data.get('headers', {}).get('from', ''),
                'subject': email_data.get('headers', {}).get('subject', ''),
                'to': email_data.get('headers', {}).get('to', ''),
                'date': email_data.get('headers', {}).get('date', ''),
                'text': email_data.get('text', '')[:500]  # 只存前500字
            },
            'detection': detect_result,
            'trace': trace_result
        }
        _save_detection(record)

        # 删除临时文件
        os.remove(file_path)

        return jsonify({
            'success': True,
            'record_id': record['id'],
            'email': {
                'from': email_data.get('headers', {}).get('from', ''),
                'subject': email_data.get('headers', {}).get('subject', ''),
                'to': email_data.get('headers', {}).get('to', ''),
                'date': email_data.get('headers', {}).get('date', ''),
                'text': email_data.get('text', '')
            },
            'detection': detect_result,
            'trace': trace_result
        })
    except Exception as e:
        # 出错也清理临时文件
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({'success': False, 'error': str(e)}), 500


# ========== 单条溯源API（用于一键溯源） ==========
@app.route('/api/trace', methods=['POST'])
def trace_single():
    """单独对邮件进行溯源（支持重新上传或指定记录ID）"""
    # 方式1：通过记录ID获取已检测邮件进行溯源
    record_id = request.json.get('record_id') if request.is_json else None
    if record_id:
        detections = _load_detections()
        for d in detections:
            if d.get('id') == record_id:
                # 如果已有溯源结果直接返回
                if d.get('trace'):
                    return jsonify({
                        'success': True,
                        'trace': d['trace'],
                        'email': d.get('email', {})
                    })
        return jsonify({'success': False, 'error': '未找到该检测记录'}), 404

    # 方式2：重新上传邮件进行溯源
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': '请上传.eml邮件文件或提供record_id'}), 400

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'success': False, 'error': '仅支持.eml格式'}), 400

    filename = f"{uuid.uuid4()}.eml"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    try:
        email_data = parse_email_simple(file_path)
        trace_result = trace_email(email_data)
        os.remove(file_path)

        return jsonify({
            'success': True,
            'email': {
                'from': email_data.get('headers', {}).get('from', ''),
                'subject': email_data.get('headers', {}).get('subject', ''),
                'to': email_data.get('headers', {}).get('to', ''),
                'date': email_data.get('headers', {}).get('date', '')
            },
            'trace': trace_result
        })
    except Exception as e:
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

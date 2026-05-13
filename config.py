import os
from dotenv import load_dotenv

# 加载.env文件
load_dotenv()

# 基础路径配置
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
ALLOWED_EXTENSIONS = {'eml'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 限制上传文件最大16MB

# 大模型配置
OLLAMA_BASE_URL = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434/api')
TEXT_MODEL = os.getenv('TEXT_MODEL', 'qwen2:7b-instruct')
MULTIMODAL_MODEL = os.getenv('MULTIMODAL_MODEL', 'qwen2-vl:7b-instruct')

# 第三方API配置
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
WHOISXML_API_KEY = os.getenv('WHOISXML_API_KEY')

# SMTP邮箱配置（蜜罐回复）
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.qq.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USER = os.getenv('SMTP_USER')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')

# 初始化上传文件夹
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
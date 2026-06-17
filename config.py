import os
from dotenv import load_dotenv

load_dotenv()

# ========== 服务基础配置 ==========
UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "uploads")
MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", 16 * 1024 * 1024))
ALLOWED_EXTENSIONS = {"eml"}
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))

# ========== 大模型配置 ==========
# 通义千问在线API
DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY", "")
QWEN_MODEL = os.getenv("QWEN_MODEL", "qwen-turbo")
API_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
REQUEST_TIMEOUT = 60

# Ollama本地大模型（备用）
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/api")
TEXT_MODEL = os.getenv("TEXT_MODEL", "qwen2:7b-instruct")

# ========== 威胁情报 ==========
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
WHOISXML_API_KEY = os.getenv("WHOISXML_API_KEY", "")

# ========== IP溯源 ==========
IP_API_URL = "http://ip-api.com/json/"

# ========== SMTP蜜罐配置 ==========
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.qq.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")

# ========== 黑名单数据库 ==========
DB_PATH = "blacklist.db"
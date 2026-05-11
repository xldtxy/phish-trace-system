import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
ALLOWED_EXTENSIONS = {'eml'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

OLLAMA_BASE_URL = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434/api')
TEXT_MODEL = os.getenv('TEXT_MODEL', 'qwen2:7b-instruct')
MULTIMODAL_MODEL = os.getenv('MULTIMODAL_MODEL', 'qwen2-vl:7b-instruct')
from flask import Flask
from flask_cors import CORS
import config

app = Flask(__name__)
app.config.from_object(config)
CORS(app)

@app.route('/')
def index():
    return "Phish Trace System - 项目已启动"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
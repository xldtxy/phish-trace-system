基于大模型的钓鱼邮件智能溯源与反制系统
 
全国大学生信息安全竞赛参赛项目
 
Flask
 
 
 
📖 项目简介
 
针对传统钓鱼邮件检测工具只能检测文本特征、无法识别图片钓鱼、缺乏主动反制能力的三大痛点，本系统采用大模型+多模态+主动防御的技术路线，构建了集智能检测、全链路溯源、一键反制于一体的钓鱼邮件防御系统。
 
系统完全基于开源技术栈实现，可100%本地化部署，无需依赖任何闭源云服务。在保证90%以上检测准确率的同时，具备主动反制能力，能有效遏制钓鱼邮件攻击的传播。
 
 
 
✨ 核心功能与实现原理
 
1. 邮件智能解析模块
 
- 实现方法：基于Python标准库 email 和 BeautifulSoup4 深度解析 .eml 格式邮件
- 提取内容：- 邮件头：发件人、收件人、主题、SPF/DKIM/DMARC验证结果、Received路由信息
- 邮件体：纯文本正文、HTML正文、所有超链接
- 附件：内嵌图片、文件附件
- 特色功能：集成 pyzbar 自动识别图片中的二维码内容，提前拦截钓鱼二维码攻击
 
2. 大模型多模态检测引擎
 
- 文本钓鱼检测- 基础模型：通义千问2（Qwen2:7b-instruct）
- 实现方式：结构化提示词工程+输出格式强制约束
- 检测维度：紧急催促话术、官方机构伪装、可疑链接特征、个人信息索取
- 输出格式：严格JSON格式，包含 is_phish 、 risk_level 、 reason 、 suspicious_points 
- 图片钓鱼检测- 基础模型：通义千问2多模态（Qwen2-VL:7b-instruct）
- 检测能力：识别图片内嵌钓鱼话术、伪造官方Logo、钓鱼二维码
- 解决痛点：传统工具无法检测的"纯图片钓鱼邮件"
- 双校验机制- 大模型智能检测 + 规则引擎兜底
- 集成Virustotal权威威胁情报，对邮件链接进行第三方恶意扫描
 
3. 全链路攻击溯源模块
 
- IP地理位置溯源：从邮件 Received 头提取公网IP，调用IP-API获取国家、城市、运营商、经纬度信息
- 域名WHOIS溯源：调用阿里云WHOIS API，查询恶意域名的注册时间、注册人、注册商
- 路由分析：还原邮件完整发送链路，定位真实攻击源IP
 
4. 主动反制系统
 
- 一键举报：对接工信部12321网络不良与垃圾信息举报受理中心，一键举报恶意域名、邮箱、IP
- 防火墙黑名单生成：自动生成可直接导入防火墙的黑名单文件，包含恶意IP、域名、邮箱
- 蜜罐自动回复：自动发送虚假身份信息回复邮件，迷惑攻击者并收集其行为特征
 
 
 
🛠️ 技术栈
 
类别 技术选型 版本 
后端框架 Flask 2.3.3 
跨域处理 Flask-Cors 4.0.0 
大模型运行平台 Ollama 0.1.30 
大模型 Qwen2:7b-instruct / Qwen2-VL:7b-instruct 最新 
前端 HTML5 + Tailwind CSS + 原生JavaScript - 
邮件解析 email + BeautifulSoup4 4.12.2 
二维码识别 pyzbar + Pillow 0.1.9 / 10.1.0 
第三方API IP-API、阿里云WHOIS、Virustotal、12321 - 
 
 
 
🚀 快速开始
 
1. 环境要求
 
- Python 3.10 及以上版本
- 内存：16GB及以上（推荐32GB，运行7B大模型）
- 显卡：NVIDIA GTX 1660 6GB及以上（可选，大幅提升推理速度）
- 硬盘：至少50GB空闲空间（存放大模型文件）
 
2. 安装步骤
 
bash
  
# 1. 克隆仓库
git clone https://github.com/你的GitHub用户名/phish-trace-system.git
cd phish-trace-system

# 2. 创建并激活虚拟环境
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

# 3. 安装依赖
pip install -r requirements.txt
 
 
3. 安装大模型
 
bash
  
# 安装Ollama（官网：https://ollama.com/）
# 下载文本检测模型
ollama pull qwen2:7b-instruct
# 下载多模态图片检测模型
ollama pull qwen2-vl:7b-instruct
 
 
4. 配置环境变量
 
复制项目根目录下的 .env.example 文件，重命名为 .env ，填入你的API密钥：
 
env
  
# Virustotal API密钥
VIRUSTOTAL_API_KEY=你的Virustotal_API_KEY
# 阿里云WHOIS API AppCode
ALIYUN_APPCODE=你的阿里云AppCode
# QQ邮箱SMTP配置（用于蜜罐回复）
SMTP_USER=你的QQ邮箱@qq.com
SMTP_PASSWORD=你的QQ邮箱SMTP授权码
 
 
5. 运行系统
 
bash
  
python app.py
 
 
打开浏览器访问  http://localhost:5000  即可使用系统。
 
 
 
📁 项目结构
 
plaintext
  
phish-trace-system/
├── README.md           # 项目说明文档
├── .gitignore          # Git忽略文件配置
├── .env.example        # 环境变量模板
├── requirements.txt    # Python依赖清单
├── app.py              # Flask应用主入口
├── config.py           # 全局配置文件
├── modules/            # 核心模块
│   ├── __init__.py
│   ├── preprocess.py   # 邮件预处理与解析模块
│   ├── detector.py     # 大模型检测引擎
│   ├── virustotal.py   # Virustotal链接扫描模块
│   ├── tracer.py       # 攻击溯源模块
│   ├── counter.py      # 主动反制模块
│   └── honeypot.py     # 蜜罐自动回复模块
└── static/             # 前端静态资源
    └── index.html      # 系统主页面
 
 
 
 
👥 团队分工
 
角色 负责内容 
大模型与检测负责人 大模型检测、多模态检测、Virustotal集成、准确率优化 
后端与安全负责人 系统架构、邮件解析、溯源模块、反制模块、攻防测试 
前端与文档负责人 前端界面开发、演示视频录制、PPT制作、技术文档撰写 
 
 
 
📊 性能指标
 
- 文本钓鱼检测准确率：≥92%
- 图片钓鱼检测准确率：≥88%
- 正常邮件误报率：≤5%
- 单封邮件平均处理时间：≤10秒（GPU加速）
- 支持并发数：5
 
 
 
⚠️ 免责声明
 
本系统仅用于学习和研究目的，禁止用于任何非法用途。使用本系统进行的任何操作，均由使用者自行承担相应责任。
 
 
 
📄 许可证
 
本项目采用 MIT 许可证 开源。

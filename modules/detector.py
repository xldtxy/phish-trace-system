import requests
import json

# ========== 配置项 - 请修改这里 ==========
DASHSCOPE_API_KEY = "sk-bc468f740d0d40c4b421e68ca996d707"  # 替换成你自己的DashScope密钥
MODEL_NAME = "qwen-turbo"                    # 可选: qwen-turbo / qwen-plus / qwen-max
REQUEST_TIMEOUT = 60                         # 请求超时时间（秒）

# 钓鱼敏感关键词（兜底规则用）
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "password", "bank",
    "验证", "登录", "账户", "密码", "冻结", "解封", "补贴", "工资",
    "紧急", "立即", "点击", "领取", "中奖", "退款"
]


def _rule_based_detect(email_data):
    """
    兜底：规则-based 简易检测
    当大模型API调用失败时自动降级，保证系统不崩溃
    """
    is_phish = False
    risk_level = "低"
    confidence = 0.5
    reason = "规则初筛：未检测到明显钓鱼特征"
    malicious_links = []

    # 检查链接中的敏感关键词
    for link in email_data.get("links", []):
        link_lower = link.lower()
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in link_lower:
                is_phish = True
                risk_level = "中"
                confidence = 0.6
                reason = f"规则初筛：链接包含敏感关键词「{kw}」，存在钓鱼嫌疑"
                malicious_links.append(link)
                break
        if is_phish:
            break

    # 检查正文紧急诱导话术
    text = email_data.get("text", "")
    urgency_words = ["立即", "紧急", "24小时", "尽快", "否则"]
    for word in urgency_words:
        if word in text and is_phish:
            risk_level = "高"
            confidence = 0.75
            reason += "；正文存在紧急诱导话术"
            break

    return {
        "is_phish": is_phish,
        "risk_level": risk_level,
        "confidence": confidence,
        "reason": reason,
        "malicious_links": malicious_links
    }


def detect_phish(email_data):
    """
    核心函数：钓鱼邮件智能检测（通义千问在线API版）
    输入：后端解析后的结构化邮件数据 email_data
    输出：标准化检测结果（严格对齐后端接口）
    """
    # 提取邮件核心信息
    sender = email_data.get("from", "未知发件人")
    subject = email_data.get("subject", "无主题")
    body = email_data.get("text", "")
    links = email_data.get("links", [])

    # 正文过长截断，避免token超限
    if len(body) > 3000:
        body = body[:3000] + "\n[内容过长已截断]"

    # 构造对话消息
    messages = [
        {
            "role": "system",
            "content": "你是专业的钓鱼邮件安全分析师，擅长识别伪造发件人、诱导链接、诈骗话术等钓鱼邮件特征。你必须严格按照指定的JSON格式返回结果，不得输出任何多余文字。"
        },
        {
            "role": "user",
            "content": f"""
请分析以下邮件是否为钓鱼邮件，从【发件人可信度、正文话术、链接安全性、诱导行为】四个维度综合判断。

=== 邮件信息 ===
发件人：{sender}
主题：{subject}
正文内容：
{body}

包含的链接列表：
{json.dumps(links, ensure_ascii=False)}

=== 输出要求 ===
必须严格返回标准JSON格式，字段如下：
{{
    "is_phish": true/false,
    "risk_level": "高/中/低",
    "confidence": 0.xx,
    "reason": "用中文详细说明判断理由，不超过100字",
    "malicious_links": ["识别出的恶意链接列表，没有则为空数组"]
}}

要求：
1. is_phish 为布尔值，true表示是钓鱼邮件
2. risk_level 只能是 高、中、低 三个值之一
3. confidence 为0到1之间的浮点数，表示置信度
4. malicious_links 只放你确认有恶意的链接，不确定就放空
"""
        }
    ]

    try:
        # 调用通义千问兼容OpenAI格式接口
        response = requests.post(
            "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {DASHSCOPE_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": MODEL_NAME,
                "messages": messages,
                "temperature": 0.1,  # 调低温度，输出更稳定
                "response_format": {"type": "json_object"}  # 强制返回JSON
            },
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        result = response.json()

        # 解析模型返回的内容
        ai_response = result["choices"][0]["message"]["content"]
        ai_result = json.loads(ai_response)

        # 字段校验与格式化，确保输出稳定
        return {
            "is_phish": bool(ai_result.get("is_phish", False)),
            "risk_level": ai_result.get("risk_level", "低"),
            "confidence": float(ai_result.get("confidence", 0.5)),
            "reason": str(ai_result.get("reason", "大模型分析完成")),
            "malicious_links": list(ai_result.get("malicious_links", []))
        }

    except Exception as e:
        # API调用失败，自动降级到规则检测
        rule_result = _rule_based_detect(email_data)
        rule_result["reason"] = f"[降级模式] {rule_result['reason']}（API调用失败：{str(e)[:30]}）"
        return rule_result
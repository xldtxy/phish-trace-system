import requests
import json
import hashlib
import config

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "password", "bank",
    "验证", "登录", "账户", "密码", "冻结", "解封", "补贴", "工资",
    "紧急", "立即", "点击", "领取", "中奖", "退款"
]


def _rule_based_detect(email_data):
    """规则兜底检测"""
    is_phish = False
    risk_level = "低"
    confidence = 0.5
    reason = "规则初筛：未检测到明显钓鱼特征"
    malicious_links = []

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


def _virustotal_check(links):
    """VirusTotal链接威胁情报检测"""
    if not config.VIRUSTOTAL_API_KEY or not links:
        return [], 0

    malicious = []
    total_malicious = 0
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}

    for link in links[:5]:  # 限制检测数量，避免超限
        try:
            # 提交URL扫描
            res = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": link},
                timeout=10
            )
            if res.status_code != 200:
                continue

            # 获取分析ID
            analysis_id = res.json()["data"]["id"]

            # 查询结果
            res_report = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=10
            )
            stats = res_report.json()["data"]["attributes"]["stats"]
            if stats["malicious"] > 0:
                malicious.append(link)
                total_malicious += stats["malicious"]
        except:
            continue

    return malicious, total_malicious


def detect_phish(email_data):
    """核心：三重引擎钓鱼邮件检测"""
    sender = email_data.get("from", "未知发件人")
    subject = email_data.get("subject", "无主题")
    body = email_data.get("text", "")
    links = email_data.get("links", [])

    if len(body) > 3000:
        body = body[:3000] + "\n[内容过长已截断]"

    # 先执行威胁情报检测
    vt_malicious, vt_count = _virustotal_check(links)

    messages = [
        {
            "role": "system",
            "content": "你是专业的钓鱼邮件安全分析师，结合威胁情报结果综合判断。必须严格返回JSON，禁止输出多余文字。"
        },
        {
            "role": "user",
            "content": f"""
请从发件人可信度、正文话术、链接安全性、诱导行为四个维度分析。
威胁情报提示：VirusTotal检测到{len(vt_malicious)}个恶意链接，恶意引擎命中数{vt_count}。

发件人：{sender}
主题：{subject}
正文：
{body}

链接列表：
{json.dumps(links, ensure_ascii=False)}
恶意链接：
{json.dumps(vt_malicious, ensure_ascii=False)}

返回格式：
{{
    "is_phish": true/false,
    "risk_level": "高/中/低",
    "confidence": 0.xx,
    "reason": "中文理由，不超过100字",
    "malicious_links": ["恶意链接列表"]
}}
"""
        }
    ]

    try:
        response = requests.post(
            config.API_BASE_URL,
            headers={
                "Authorization": f"Bearer {config.DASHSCOPE_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": config.QWEN_MODEL,
                "messages": messages,
                "temperature": 0.1,
                "response_format": {"type": "json_object"}
            },
            timeout=config.REQUEST_TIMEOUT
        )
        response.raise_for_status()
        result = response.json()

        ai_result = json.loads(result["choices"][0]["message"]["content"])
        return {
            "is_phish": bool(ai_result.get("is_phish", False)),
            "risk_level": ai_result.get("risk_level", "低"),
            "confidence": float(ai_result.get("confidence", 0.5)),
            "reason": str(ai_result.get("reason", "分析完成")),
            "malicious_links": list(ai_result.get("malicious_links", [])),
            "virustotal_hits": vt_count
        }

    except Exception as e:
        rule_result = _rule_based_detect(email_data)
        rule_result["reason"] = f"[降级模式] {rule_result['reason']}（API异常：{str(e)[:30]}）"
        return rule_result
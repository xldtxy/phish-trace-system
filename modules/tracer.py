import re
import requests
from urllib.parse import urlparse
import config


def extract_public_ips(received_headers):
    """提取公网IP，过滤内网地址"""
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ips = []

    for header in received_headers:
        ips.extend(re.findall(ip_pattern, header))

    public_ips = []
    for ip in ips:
        o = list(map(int, ip.split('.')))
        is_private = (
                o[0] == 10 or
                (o[0] == 172 and 16 <= o[1] <= 31) or
                (o[0] == 192 and o[1] == 168) or
                ip == '127.0.0.1'
        )
        if not is_private:
            public_ips.append(ip)

    return list(set(public_ips))


def trace_ip(ip):
    """IP地理位置溯源"""
    try:
        res = requests.get(f"{config.IP_API_URL}{ip}", timeout=10)
        data = res.json()
        if data['status'] == 'success':
            return {
                'ip': ip,
                'country': data.get('country', '未知'),
                'region': data.get('regionName', '未知'),
                'city': data.get('city', '未知'),
                'isp': data.get('isp', '未知'),
                'status': 'success'
            }
        return {'ip': ip, 'status': 'fail', 'error': '查询失败'}
    except Exception as e:
        return {'ip': ip, 'status': 'fail', 'error': str(e)}


def extract_domains(links):
    """从链接中提取根域名"""
    domains = set()
    for link in links:
        try:
            parsed = urlparse(link)
            domain = parsed.netloc.replace("www.", "")
            if domain:
                domains.add(domain)
        except:
            continue
    return list(domains)


def trace_domain(domain):
    """域名WHOIS溯源（基于WHOISXML API）"""
    if not config.WHOISXML_API_KEY:
        return {'domain': domain, 'status': 'fail', 'error': '未配置WHOIS API'}

    try:
        res = requests.get(
            "https://www.whoisxmlapi.com/whoisserver/WhoisService",
            params={
                "apiKey": config.WHOISXML_API_KEY,
                "domainName": domain,
                "outputFormat": "JSON"
            },
            timeout=15
        )
        data = res.json()
        whois = data.get("WhoisRecord", {})
        registry = whois.get("registryData", {})

        return {
            'domain': domain,
            'registrar': registry.get("registrarName", "未知"),
            'created_date': registry.get("createdDateNormalized", "未知"),
            'expires_date': registry.get("expiresDateNormalized", "未知"),
            'registrant': registry.get("registrant", {}).get("organization", "未知"),
            'status': 'success'
        }
    except Exception as e:
        return {'domain': domain, 'status': 'fail', 'error': str(e)}


def trace_email(email_data):
    """全链路溯源入口：IP + 域名"""
    received = email_data.get('headers', {}).get('received', [])
    links = email_data.get('links', [])

    ips = extract_public_ips(received)
    domains = extract_domains(links)

    return {
        'ips': [trace_ip(ip) for ip in ips],
        'domains': [trace_domain(d) for d in domains[:3]]  # 限制数量避免超限
    }
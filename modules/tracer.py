import re
import requests


def extract_public_ips(received_headers):
    """从邮件Received头中提取公网IP，过滤内网IP"""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = []
    for header in received_headers:
        found_ips = re.findall(ip_pattern, header)
        ips.extend(found_ips)

    # 过滤内网IP和回环地址
    public_ips = []
    for ip in ips:
        if not (ip.startswith(('10.', '172.16.', '192.168.')) or ip == '127.0.0.1'):
            public_ips.append(ip)
    return list(set(public_ips))


def trace_ip(ip):
    """
    基础版IP溯源：使用免费的ip-api.com接口
    无需申请API密钥，直接就能用
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        data = response.json()
        if data['status'] == 'success':
            return {
                'ip': ip,
                'country': data.get('country', '未知'),
                'region': data.get('regionName', '未知'),
                'city': data.get('city', '未知'),
                'isp': data.get('isp', '未知'),
                'status': 'success'
            }
        else:
            return {'ip': ip, 'status': 'fail', 'error': '查询失败'}
    except Exception as e:
        return {'ip': ip, 'status': 'fail', 'error': str(e)}


def trace_email(email_data):
    """邮件全链路IP溯源"""
    # 从邮件头提取Received信息
    received_headers = email_data.get('headers', {}).get('received', [])
    # 提取公网IP
    ips = extract_public_ips(received_headers)
    # 逐个溯源
    ip_results = [trace_ip(ip) for ip in ips]
    return {'ips': ip_results}
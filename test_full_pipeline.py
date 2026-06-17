"""
钓鱼邮件检测系统 - 全流程离线测试脚本
覆盖：邮件解析、大模型检测、IP/域名溯源、黑名单反制
无需启动Web服务，直接运行即可验证所有模块
"""
import os
from modules.preprocess import parse_email_simple
from modules.detector import detect_phish
from modules.tracer import trace_email
from modules.defense import init_db, add_to_blacklist, is_blacklisted

# 测试样本文件
TEST_EML = "test.eml"


def print_divider(title=""):
    print("\n" + "=" * 60)
    if title:
        print(f"  {title}")
        print("=" * 60)


def test_parse():
    """测试1：邮件解析模块"""
    print_divider("[1/4] 邮件解析模块测试")
    if not os.path.exists(TEST_EML):
        print(f" 测试失败：未找到测试文件 {TEST_EML}")
        return None

    try:
        email_data = parse_email_simple(TEST_EML)

        # 关键字段校验
        required_fields = ["from", "subject", "text", "links", "headers"]
        missing = [f for f in required_fields if f not in email_data]
        if missing:
            print(f" 字段缺失：{missing}")
            return None

        # 输出统计信息
        print(f" 解析成功")
        print(f"   发件人：{email_data['from']}")
        print(f"   主题：{email_data['subject']}")
        print(f"   正文长度：{len(email_data['text'])} 字符")
        print(f"   提取链接：{len(email_data['links'])} 个")
        print(f"   Received头：{len(email_data['headers'].get('received', []))} 条")
        return email_data

    except Exception as e:
        print(f" 解析异常：{str(e)}")
        return None


def test_detect(email_data):
    """测试2：大模型检测模块"""
    print_divider("[2/4] 智能检测模块测试")
    if not email_data:
        print(" 跳过：上游解析失败")
        return None

    try:
        result = detect_phish(email_data)

        required_fields = ["is_phish", "risk_level", "confidence", "reason", "malicious_links"]
        missing = [f for f in required_fields if f not in result]
        if missing:
            print(f" 返回字段缺失：{missing}")
            return None

        # 输出检测结果
        print(f"   检测完成")
        print(f"   是否钓鱼：{result['is_phish']}")
        print(f"   风险等级：{result['risk_level']}")
        print(f"   置信度：{result['confidence']:.2f}")
        print(f"   判定理由：{result['reason']}")
        print(f"   恶意链接：{len(result['malicious_links'])} 个")

        # 提示降级状态
        if "[降级模式]" in result["reason"]:
            print("当前为规则兜底模式（大模型API未响应）")
        return result

    except Exception as e:
        print(f"检测异常：{str(e)}")
        return None


def test_trace(email_data):
    """测试3：全链路溯源模块"""
    print_divider("[3/4] 全链路溯源模块测试")
    if not email_data:
        print("跳过：上游解析失败")
        return None

    try:
        result = trace_email(email_data)
        ip_list = result.get("ips", [])
        domain_list = result.get("domains", [])

        print(f"溯源完成")
        print(f"提取公网IP：{len(ip_list)} 个")
        for ip_info in ip_list:
            if ip_info["status"] == "success":
                print(f"     {ip_info['ip']} → {ip_info['country']} {ip_info['city']} / {ip_info['isp']}")
            else:
                print(f"     {ip_info['ip']} → 查询失败")

        print(f"域名WHOIS溯源：{len(domain_list)} 个")
        for d_info in domain_list:
            if d_info["status"] == "success":
                print(f"     {d_info['domain']} → 注册商：{d_info['registrar']}")
            else:
                print(f"     {d_info['domain']} → {d_info.get('error', '查询失败')}")

        return result

    except Exception as e:
        print(f"溯源异常：{str(e)}")
        return None


def test_defense():
    """测试4：反制模块（黑名单）"""
    print_divider("[4/4] 反制模块测试")
    try:
        init_db()
        test_ip = "198.51.100.74"

        # 添加测试
        add_ok = add_to_blacklist("ip", test_ip, "高")
        print(f"黑名单添加：{'成功' if add_ok else '失败/已存在'}")

        # 查询测试
        risk = is_blacklisted(test_ip)
        if risk:
            print(f"黑名单查询：命中，风险等级 = {risk}")
        else:
            print(f"黑名单查询：未命中")

        return True

    except Exception as e:
        print(f"反制模块异常：{str(e)}")
        return False


if __name__ == "__main__":
    print("\n" + "=" * 30)
    print("        钓鱼邮件智能检测与溯源系统 - 全流程测试")
    print("=" * 30)

    # 按依赖顺序执行
    email_data = test_parse()
    detect_result = test_detect(email_data)
    trace_result = test_trace(email_data)
    defense_ok = test_defense()

    # 最终汇总
    print_divider("测试汇总")
    all_pass = all([email_data, detect_result, trace_result, defense_ok])
    if all_pass:
        print("全部模块测试通过，系统运行正常")
        print("可执行 python app.py 启动Web服务")
    else:
        print("部分模块测试失败，请根据上方错误信息排查")
    print("=" * 60 + "\n")
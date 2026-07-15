# ImaRead SQL Injection PoC

一个用于检测 `imaRead.make.php` 页面中 `feeItem[]` 参数存在报错注入（SQL Injection）漏洞的批量检测脚本。支持单目标检测与多线程/多进程批量扫描，并自动保存结果。

> **Warning**
> **免责声明：** 本工具仅用于合法的安全审计、漏洞自查与教学研究。请勿用于非法扫描或攻击。因使用本工具带来的任何直接或间接后果，均由使用者本人承担。

---

## 🛠️ 功能特性

* **双模式支持**：支持单个 URL 深度检测，或通过文本文件进行批量扫描。
* **高并发扫描**：基于 Python `multiprocessing` 多进程编写，内置文件写锁（Lock），确保在大批量扫描时数据完整、不冲突。
* **智能识别**：通过匹配特定 MD5 哈希（`12345678` 对应的 XPATH 错误回显）精确判断漏洞是否存在。
* **自动输出**：扫描结果实时打印，并自动保存至本地 `vuln.txt`。

---

## 🚀 快速开始

### 1. 克隆项目与安装依赖

首先克隆仓库到本地，并确保安装了 `requests` 库：

```bash
git clone [https://github.com/你的用户名/你的仓库名.git](https://github.com/你的用户名/你的仓库名.git)
cd 你的仓库名
pip install requests

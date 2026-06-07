# WebVulnScanner

AI-Powered Web Vulnerability Scanner - Python实现的自动化Web漏洞扫描器，集成LLM进行智能payload生成和漏洞分析。

## Features

### 漏洞检测模块
| Module | Description | Severity |
|--------|-------------|----------|
| SQL Injection | Error-based, Boolean-based, Time-based SQLi检测 | Critical |
| XSS | 反射型XSS检测，支持多种绕过payload | High |
| Command Injection | OS命令注入检测（盲注+回显） | Critical |
| File Inclusion | LFI/RFI本地/远程文件包含检测 | Critical |
| Directory Scan | 目录和文件暴力枚举发现 | Low-Medium |
| Sensitive Files | 敏感文件检测(.git, .env, backup等) | Critical |
| Info Leak | 信息泄露检测(内部IP、密钥、栈跟踪) | Medium-High |

### AI集成 (核心亮点)
- **智能Payload生成**: 基于目标技术栈，LLM自动生成针对性攻击payload
- **漏洞分析**: AI自动分析漏洞成因、影响范围和修复建议
- **技术指纹识别**: AI辅助识别Web技术栈(WAF/框架/中间件)
- **报告摘要**: AI自动生成漏洞评估执行摘要

### 架构特点
- 模块化设计，易于扩展新的检测模块
- 多线程并发扫描
- User-Agent轮换
- 自动重试机制
- HTML/JSON双格式报告
- 支持代理配置

## Quick Start

### 安装

```bash
git clone https://github.com/wulongovo/web-vuln-scanner.git
cd web-vuln-scanner
pip install -r requirements.txt
```

### 基本用法

```bash
# 基本扫描
python main.py -u http://example.com

# 指定模块
python main.py -u http://example.com --modules sqli,xss

# 启用AI分析
python main.py -u http://example.com --ai

# 完整参数
python main.py -u http://example.com --ai --depth 3 --threads 20 --report html
```

### AI配置

设置环境变量:

```bash
# OpenAI
export AI_PROVIDER=openai
export AI_API_KEY=sk-your-key
export AI_MODEL=gpt-4o-mini

# Ollama (本地)
export AI_PROVIDER=ollama
export AI_MODEL=qwen2.5

# 自定义API
export AI_PROVIDER=custom
export AI_BASE_URL=https://your-api.com/v1
export AI_API_KEY=your-key
export AI_MODEL=your-model
```

## CLI Options

```
-u, --url         Target URL (required)
-m, --modules     Comma-separated modules: sqli,xss,cmd_injection,file_include,dirscan,sensitive_files,info_leak
--ai              Enable AI-powered payload generation and analysis
--depth           Crawl depth (default: 3)
--max-pages       Max pages to crawl (default: 200)
-t, --threads     Number of threads (default: 10)
-r, --report      Report format: json, html, both (default: both)
-o, --output      Custom output directory
--crawl-only      Only crawl, skip vulnerability scanning
--proxy           Proxy URL (e.g., http://127.0.0.1:8080)
-v, --verbose     Verbose output
--timeout         HTTP timeout in seconds (default: 10)
```

## Project Structure

```
web-vuln-scanner/
├── main.py                 # CLI entry point
├── config.py               # Global configuration
├── requirements.txt
├── core/
│   ├── crawler.py          # Web crawler (URL/form discovery)
│   ├── scanner.py          # Main scan engine
│   └── report.py           # HTML/JSON report generator
├── modules/
│   ├── base.py             # Base module class
│   ├── sqli.py             # SQL injection detection
│   ├── xss.py              # XSS detection
│   ├── cmd_injection.py    # Command injection detection
│   ├── file_include.py     # LFI/RFI detection
│   ├── dirscan.py          # Directory discovery
│   ├── sensitive_files.py  # Sensitive file detection
│   └── info_leak.py        # Information leakage detection
├── ai/
│   └── ai_payload.py       # LLM payload generation & analysis
├── lib/
│   ├── http_client.py      # HTTP client with retries
│   ├── logger.py           # Logging utility
│   └── utils.py            # Common utilities
├── dicts/
│   ├── dirs.txt            # Directory wordlist
│   └── subdomains.txt      # Subdomain wordlist
├── output/                 # Scan output data
└── reports/                # Generated reports
```

## Extending

Add a new module by creating a file in `modules/`:

```python
from modules.base import BaseModule

class MyModule(BaseModule):
    name = "my_module"
    description = "My custom vulnerability check"

    def run(self, param_urls, forms):
        for url in param_urls:
            # Your detection logic
            self.add_finding("my_vuln", url, "param", "medium", "evidence")
        return self.findings
```

Then register it in `config.py` ENABLED_MODULES and `core/scanner.py` module_map.

## Disclaimer

This tool is for authorized security testing and educational purposes only.
Unauthorized access to computer systems is illegal. Always obtain proper authorization before scanning.

## License

MIT License

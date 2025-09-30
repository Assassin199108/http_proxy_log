# HTTP Proxy Log

基于 mitmproxy 的 HTTP 代理日志记录工具，专门用于监控和记录 API 请求/响应，特别适用于 AI 模型 API 的调用分析。

## 功能特性

- 🔍 **请求监控**: 拦截并记录 HTTP/HTTPS 请求详情
- 📊 **响应分析**: 解析 API 响应，提取使用统计信息
- 🔒 **安全脱敏**: 自动隐藏 Authorization 头中的敏感信息
- 📝 **文件日志**: 日志统一保存在 `logs/` 目录，按日期归档
- 🗂️ **自动清理**: 自动删除超过 7 天的日志文件
- 🎯 **AI API 优化**: 专门针对 OpenAI 等 AI 模型 API 进行优化

## 安装

### 使用虚拟环境

```bash
# 创建虚拟环境
python3 -m venv venv

# 激活虚拟环境
source venv/bin/activate  # Linux/Mac
# 或 venv\Scripts\activate  # Windows

# 安装依赖
pip install -e .
```

### 使用 uv

```bash
# 创建虚拟环境
uv venv

# 激活虚拟环境
source .venv/bin/activate

# 安装依赖
uv pip install -e .
```

## 使用方法

### 启动代理

```bash
# 使用 mitmdump 启动
mitmproxy --mode reverse:{具体代理的url} -p 8080 -s main.py

# 或者直接运行主程序
python main.py
```

### 代理配置

将你的应用或浏览器配置为使用 `http://localhost:8080` 作为 HTTP/HTTPS 代理。

## 日志文件

- **存储位置**: `logs/` 目录
- **文件格式**: `proxy_YYYYMMDD.log`
- **日志内容**: 包含时间戳、请求方法、URL、响应状态、数据大小等信息
- **自动清理**: 超过 7 天的日志文件会自动删除

## 日志示例

```
2025-09-30 14:30:25,123 - > POST https://api.openai.com/v1/chat/completions
2025-09-30 14:30:25,124 -   req.json keys=['model', 'messages', 'temperature'] model=gpt-3.5-turbo
2025-09-30 14:30:26,456 - < 200 https://api.openai.com/v1/chat/completions len=512
2025-09-30 14:30:26,457 -   data={'id': 'chat-123', 'object': 'chat.completion', 'usage': {'prompt_tokens': 25, 'completion_tokens': 50, 'total_tokens': 75}}
```

## 安全特性

- Authorization 头自动替换为 `Bearer ***`
- 日志文件不会包含真实的 API 密钥
- 支持中文和其他 Unicode 字符

## 依赖

- Python 3.11+
- mitmproxy >= 10.0.0

## 许可证

[MIT](LICENSE)

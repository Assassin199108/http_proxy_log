from mitmproxy import http
import json
import logging
import os
import glob
from datetime import datetime, timedelta

# 清理超过7天的日志文件
def _cleanup_old_logs():
    log_dir = "logs"
    if not os.path.exists(log_dir):
        return

    # 获取7天前的日期
    cutoff_date = datetime.now() - timedelta(days=7)

    # 匹配所有 proxy_YYYYMMDD.log 格式的文件
    log_pattern = os.path.join(log_dir, "proxy_*.log")
    log_files = glob.glob(log_pattern)

    deleted_count = 0
    for log_file in log_files:
        try:
            # 从文件名提取日期 (proxy_20250930.log -> 20250930)
            filename = os.path.basename(log_file)
            date_str = filename.replace("proxy_", "").replace(".log", "")

            if len(date_str) == 8:  # YYYYMMDD格式
                file_date = datetime.strptime(date_str, "%Y%m%d")

                # 如果文件日期早于7天前，则删除
                if file_date < cutoff_date:
                    os.remove(log_file)
                    deleted_count += 1
        except (ValueError, OSError):
            # 如果解析日期失败或删除文件失败，跳过该文件
            continue

    if deleted_count > 0:
        print(f"已清理 {deleted_count} 个超过7天的日志文件")

# 配置日志文件
def _setup_logging():
    # 创建统一的日志文件夹
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # 清理超过7天的日志文件
    _cleanup_old_logs()

    # 每日一个文件，使用追加模式
    log_file = os.path.join(log_dir, f'proxy_{datetime.now().strftime("%Y%m%d")}.log')

    # 创建专用的logger，避免使用basicConfig
    logger = logging.getLogger('proxy_logger')

    # 清除已存在的handlers，避免重复配置
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # 设置logger级别
    logger.setLevel(logging.INFO)

    # 创建文件处理器
    file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    file_handler.setLevel(logging.INFO)

    # 创建格式器
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    file_handler.setFormatter(formatter)

    # 添加处理器到logger
    logger.addHandler(file_handler)

    # 防止日志传播到根logger
    logger.propagate = False

    return logger

logger = _setup_logging()

def _mask_auth(headers):
    # 脱敏 Authorization
    auth = headers.get("Authorization") or headers.get("authorization")
    if auth:
        headers["Authorization"] = "Bearer ***"

def request(flow: http.HTTPFlow):
    _mask_auth(flow.request.headers)
    logger.info(f"> {flow.request.method} {flow.request.pretty_url}")
    ct = flow.request.headers.get("content-type", "")
    if "application/json" in ct:
        try:
            body = json.loads(flow.request.get_text() or "{}")
            #model = body.get("model")
            # logger.info(f"  req.json keys={list(body.keys())} model={model}")
            # 如需完整提示词，谨慎记录：
            logger.info(json.dumps(body, ensure_ascii=False))
        except Exception:
            pass

def response(flow: http.HTTPFlow):
    _mask_auth(flow.response.headers)
    size = len(flow.response.raw_content or b"")
    logger.info(f"< {flow.response.status_code} {flow.request.pretty_url} len={size}")
    ct = flow.response.headers.get("content-type", "")
    if ct.startswith("application/json"):
        try:
            data = json.loads(flow.response.get_text() or "{}")
            logger.info(f"  data={data}")
        except Exception:
            pass


def main():
    print("Hello from http-proxy-log!")
    # 测试日志记录功能
    logger.info("测试日志记录功能 - 这条消息应该出现在日志文件中")
    logger.info("Current time for testing: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


if __name__ == "__main__":
    main()

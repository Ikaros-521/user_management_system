import json
import sys, traceback
import chardet
from loguru import logger

local_config = None
CONFIG_PATH = "config.json"

def load_config():
    global local_config
    
    try:
        detected_encoding = chardet.detect(open(CONFIG_PATH, 'rb').read())['encoding']
        with open(CONFIG_PATH, 'r', encoding=detected_encoding) as file:
            local_config = json.loads(file.read())
        
        if local_config["日志"]["日志等级"] and local_config["日志"]["最大文件大小"]:
            if local_config["日志"]["日志等级"].lower() == "info":
                logger.configure(handlers=[
                    {
                        "sink": sys.stderr,
                        "format": "{time:YYYY-MM-DD HH:mm:ss.SSS} | <lvl>{level:8}</>| <lvl>{message}</>",
                        "colorize": True
                    },
                ])
            logger.add("log.txt", level=local_config["日志"]["日志等级"], rotation=local_config["日志"]["最大文件大小"])
        else:
            logger.add("log.txt", level="INFO", rotation="100 MB")
            
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error(f"配置文件加载失败: {e}")
        sys.exit(1)


def get_config():
    global local_config
    
    return local_config

def set_config(data: dict):
    global local_config
    
    local_config = data
    
def save_config():
    global local_config
    try:
        detected_encoding = chardet.detect(open("config.json", 'rb').read())['encoding']
        with open("config.json", 'w', encoding=detected_encoding) as file:
            json.dump(local_config, file, indent=4, ensure_ascii=False)
        logger.info("配置文件保存成功.")
    except Exception as e:
        logger.error(f"保存配置文件失败: {e}")

def set_qr_code_config(data: dict):
    """
    更新二维码配置，更新完后保存到本地
    """
    global local_config
    
    def update_existing_keys(original_dict, update_dict):
        for key, value in update_dict.items():
            if key in original_dict:
                original_dict[key] = value
        return original_dict

    try:
        # 更新
        update_existing_keys(local_config["二维码"], data)
        
        detected_encoding = chardet.detect(open("config.json", 'rb').read())['encoding']
        with open("config.json", 'w', encoding=detected_encoding) as file:
            json.dump(local_config, file, indent=4, ensure_ascii=False)
        logger.info("配置文件保存成功.")
    except Exception as e:
        logger.error(f"保存配置文件失败: {e}")
        
def get_qr_code_config():
    """
    获取二维码配置
    """
    global local_config
    
    return local_config["二维码"]


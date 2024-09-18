# 递归函数，用于将字典中的所有值转换为字符串
def convert_values_to_str(d):
    for key, value in d.items():
        if isinstance(value, dict):
            # 如果值是字典，递归调用 convert_values_to_str
            convert_values_to_str(value)
        else:
            # 将值转换为字符串
            d[key] = str(value)

# 格式化datetime时间  
def format_datetime(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def get_current_datetime():
    from datetime import datetime
    
    now = datetime.now()
    
    # 获取年份并只保留最后两位
    year = now.strftime("%y")
    # 获取月份，并补充0使其总是两位数
    month = now.strftime("%m")
    # 获取日期，并补充0使其总是两位数
    day = now.strftime("%d")
    # 获取小时，并补充0使其总是两位数
    hours = now.strftime("%H")
    # 获取分钟，并补充0使其总是两位数
    minutes = now.strftime("%M")
    # 获取秒，并补充0使其总是两位数
    seconds = now.strftime("%S")
    # 获取星期几，1表示星期一，7表示星期天
    weekday = (now.weekday() + 1) % 7 + 1

    # 将结果存储在字典中
    datetime_dict = {
        "年": year,
        "月": month,
        "日": day,
        "时": hours,
        "分": minutes,
        "秒": seconds,
        "星期": weekday
    }

    return datetime_dict

def dict_to_string(data):
    """将dict转换为字符串，格式为key: value, key: value, ...

    Args:
        data (dict): 待转换的数据

    Returns:
        str: 拼接后的字符串
    """
    if not data:
        return "无数据"
    return ', '.join([f"{key}: {value}" for key, value in data.items()])

def move_and_replace(src: str, dest: str):
    """
    将文件从 src 移动到 dest，如果 dest 处已有文件，则进行覆盖。
    
    Args:
        src (str): 源文件路径
        dest (str): 目标文件路径

    Returns:
        dict: 移动结果
    """
    try:
        import os, shutil
        from loguru import logger
        from utils.models import CommonResult
        
        # 如果目标路径存在文件，则删除
        if os.path.exists(dest):
            os.remove(dest)
        
        # 移动文件
        shutil.move(src, dest)
        msg = f"文件{src}已成功移动到 {dest}"
        logger.info(msg)
        return CommonResult(code=0, success=True, data={"msg": msg})

    except FileNotFoundError:
        msg = f"源文件 {src} 未找到"
        logger.error(msg)
        return CommonResult(code=404, success=False, data={"msg": msg})
    except PermissionError:
        msg = f"权限错误：无法访问 {src} 或 {dest}"
        logger.error(msg)
        return CommonResult(code=403, success=False, data={"msg": msg})
    except Exception as e:
        msg = f"发生错误：{e}"
        logger.error(msg)
        return CommonResult(code=500, success=False, data={"msg": msg})

# 角色字符串转换
def role_name_converter(role: str, type: int=0):
    if type == 0:
        if role == 'admin':
            return '管理员'
        # 其他角色转换规则
        elif role == 'user':
            return '普通用户'
        elif role == 'super_admin':
            return '超级管理员'
        # 默认情况
        else:
            return '普通用户'
    elif type == 1:
        if role == '管理员':
            return 'admin'
        # 其他角色转换规则
        elif role == '普通用户':
            return 'user'
        elif role == '超级管理员':
            return 'super_admin'
        # 默认情况
        else:
            return 'user'
    elif type == 2:
        if role in ['user', 'admin', 'super_admin']:
            return role
        else:
            return 'user'
            

                  
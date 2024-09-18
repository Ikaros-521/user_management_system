from sqlalchemy import select, update, and_
from datetime import datetime, timedelta
from loguru import logger
import traceback
from fastapi import HTTPException

from utils.database import database, users_table, logs_table, transaction_manager

# 检测当前用户是否为超级管理员，不是则抛出异常
async def check_super_admin_role(current_user):
    resp_json = await get_user_roles(current_user["username"])
    if resp_json['code'] != 200:
        raise HTTPException(status_code=403, detail="获取当前用户权限失败，请检查数据库是否正常！")
    
    is_super_admin = False
    roles = resp_json['data']['roles']
    for role in roles:
        # 如果当前用户是超级管理员，则可以添加用户
        if role == "super_admin":
            is_super_admin = True

    if not is_super_admin:
        raise HTTPException(status_code=403, detail="当前用户无权限添加用户")

async def insert_msg_to_logs_table(current_user: dict, msg: str) -> dict:
    """将消息插入到日志表中

    Args:
        current_user (dict): 当前用户信息
        msg (str): 待插入的消息

    Returns:
        dict: 插入结果
    """
    try:
        # 查询users表，获取当前用户信息
        query = users_table.select().where(users_table.c.username == current_user['username'])
        user = await database.fetch_one(query)
        if user is None:
            logger.error(f"用户 {current_user['username']} 不存在")
            return {"code": 404, "message": "用户不存在"}
        
        # 保存发送和接收的消息到数据库
        query = logs_table.insert().values(
            user_id=user['id'],
            username=user['username'],
            nickname=user['nickname'],
            message=msg,
            update_ts=datetime.utcnow()
        )
        rows_affected = await transaction_manager.execute(query)

        # 判断插入是否成功
        if rows_affected > 0:
            return {"code": 200, "success": True, "data": {"msg": f"插入日志成功"}}
        else:
            return {"code": 200, "success": False, "data": {"msg": f"插入日志失败"}}
    except Exception as e:
        logger.error(traceback.format_exc())
        return {"code": 500, "success": False, "data": {"msg": f"插入日志失败: {e}"}}

# 获取当前用户角色列表
async def get_user_roles(username: str):
    try:
        # 获取当前用户的角色信息
        query = select(users_table).where(users_table.c.username == username)
        user = await database.fetch_one(query)
        # logger.debug(user)

        # 是否超级管理员
        is_super_admin = False
        roles = user["roles"].split(",")
    
        return {"code": 200, "success": True, "data": {"roles": roles}}
    except Exception as e:
        logger.error(traceback.format_exc()) 
        return {"code": 500, "success": False, "data": {"roles": None}}
        
# 检测当前用户是否为管理员及以上，不是则抛出异常
async def check_admin_role(current_user):
    from fastapi import HTTPException
    
    resp_json = await get_user_roles(current_user["username"])
    if resp_json['code'] != 200:
        raise HTTPException(status_code=403, detail="获取当前用户权限失败，请检查数据库是否正常！")
    
    is_admin = False
    roles = resp_json['data']['roles']
    for role in roles:
        # 如果当前用户是超级管理员，则可以添加用户
        if role in ["super_admin", "admin"]:
            is_admin = True

    if not is_admin:
        raise HTTPException(status_code=403, detail="当前用户无权限添加用户") 
         
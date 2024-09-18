from fastapi import APIRouter, HTTPException, status, Depends, Request
from sqlalchemy import select, update, delete, func
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timedelta
from loguru import logger
import asyncio, json

from utils.database import database, users_table, logs_table, transaction_manager
from utils.models import GetLogMessage, DelLogMessage, LogListData, LogListResult
from utils.models import LogListData, LogListResult
from utils.config import get_config 
from utils.common import format_datetime
from utils.db_common import check_admin_role, check_super_admin_role
from routes.auth import get_current_active_user
from utils.models import CommonResult

router = APIRouter()

@router.post("/log/del_log")
async def del_log(msg: DelLogMessage, current_user: dict = Depends(get_current_active_user)):
    try:
        await check_super_admin_role(current_user)

        query = select(logs_table).where(logs_table.c.id == msg.id)
        device = await database.fetch_one(query)
        if not device:
            raise HTTPException(status_code=404, detail=f"ID：{msg.id} 不存在")

        
        query = (
            delete(logs_table)
            .where(logs_table.c.id == msg.id)
        )
        rows_affected = await transaction_manager.execute(query)
        
        return CommonResult(code=0, success=True, data={"msg": f"删除日志 ID：{msg.id} 成功"})
    except Exception as e:
        logger.error(f"删除日志失败： {e}")
        raise HTTPException(status_code=500, detail=str(e))

# 删除所有日志
@router.post("/log/del_all_logs")
async def del_projects(current_user: dict = Depends(get_current_active_user)):
    try:
        await check_super_admin_role(current_user)

        delete_query = delete(logs_table)
        rows_affected = await transaction_manager.execute(delete_query)

        # 返回结果
        return CommonResult(
            code=0,
            success=True,
            data={
                "msg": "清空日志完成"
            }
        )
    except SQLAlchemyError as e:
        logger.error(f"清空日志失败： {e}")
        raise HTTPException(status_code=500, detail="数据库操作失败")
    except Exception as e:
        logger.error(f"清空日志失败： {e}")
        raise HTTPException(status_code=500, detail=str(e))
 
    
@router.post("/log/get_log_list")
async def get_log_list(msg: GetLogMessage, current_user: dict = Depends(get_current_active_user)):
    try:
        await check_super_admin_role(current_user)

        search_params = msg.search_params
        page = msg.page
        limit = msg.limit
        
        nickname = None
        message = None
        username = None
        
        # 解析搜索参数
        if search_params:
            try:
                search_dict = json.loads(search_params)
                if 'username' in search_dict:
                    username = search_dict.get('username')
                if 'nickname' in search_dict:
                    nickname = search_dict.get('nickname')
                if 'message' in search_dict:
                    message = search_dict.get('message')
                # 可以处理更多的搜索参数
            except json.JSONDecodeError:
                return HTTPException(status_code=400, detail="search_params的参数非JSON格式字符串，解析失败")

        # 构建基本查询
        query = select(logs_table)

        # 根据是否有搜索参数添加过滤条件
        if search_params:
            if nickname:
                nickname_pattern = f"%{nickname}%"
                query = query.where(logs_table.c.nickname.ilike(nickname_pattern))

            # Check if 'sn' is in search_params and perform substring search
            if username:
                username_pattern = f"%{username}%"
                query = query.where(logs_table.c.username.ilike(username_pattern))

            if message:
                message_pattern = f"%{message}%"
                query = query.where(logs_table.c.message.ilike(message_pattern))

            if nickname == '' and username == '' and message == '':
                total_query = select(func.count()).select_from(logs_table)
                total_count = await database.fetch_val(total_query)
            else:
                # 查询数据总数
                total_query = query.with_only_columns(func.count()).order_by(None)
                total_count = await database.fetch_val(total_query)
        else:
            total_query = select(func.count()).select_from(logs_table)
            total_count = await database.fetch_val(total_query)

        # 根据数据量决定是返回全部还是分页
        if total_count <= limit * (page - 1):
            results = await database.fetch_all(query.order_by(logs_table.c.id))
        else:
            offset = (page - 1) * limit
            results = await database.fetch_all(query.order_by(logs_table.c.id).offset(offset).limit(limit))

        if results:
            logs = [
                LogListData(
                    id=result["id"],
                    user_id=result["user_id"],
                    username=result["username"],
                    nickname=result["nickname"],
                    message=result["message"],
                    update_ts=format_datetime(result["update_ts"])
                ) for result in results
            ]

            logger.info(f"查询logs_table表成功")
            
            return LogListResult(code=0, success=True, count=total_count, data=logs, other={"total_count": total_count})
        else:
            logger.info(f"查询logs_table表 无数据")
            return LogListResult(code=0, success=True, count=0, data=[], other={"total_count": 0})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))    

@router.post("/log/get_operate_log_list")
async def get_operate_log_list(msg: GetLogMessage, current_user: dict = Depends(get_current_active_user)):
    try:
        search_params = msg.search_params
        page = msg.page
        limit = msg.limit
        
        user_id = None
        nickname = None
        message = None
        
        # 解析搜索参数
        if search_params:
            try:
                search_dict = json.loads(search_params)
                if 'user_id' in search_dict:
                    user_id = search_dict.get('user_id')
                if 'nickname' in search_dict:
                    nickname = search_dict.get('nickname')
                if 'message' in search_dict:
                    message = search_dict.get('message')
                # 可以处理更多的搜索参数
            except json.JSONDecodeError:
                return HTTPException(status_code=400, detail="search_params的参数非JSON格式字符串，解析失败")

        # 构建基本查询
        query = select(logs_table)

        # 根据是否有搜索参数添加过滤条件
        if search_params:
            if user_id:
                user_id_pattern = f"%{user_id}%"
                query = query.where(logs_table.c.user_id.ilike(user_id_pattern))

            # Check if 'sn' is in search_params and perform substring search
            if nickname:
                nickname_pattern = f"%{nickname}%"
                query = query.where(logs_table.c.nickname.ilike(nickname_pattern))

            if message:
                message_pattern = f"%{message}%"
                query = query.where(logs_table.c.message.ilike(message_pattern))

            if user_id is None and nickname == '' and message == '':
                total_query = select(func.count()).select_from(logs_table)
                total_count = await database.fetch_val(total_query)
            else:
                # 查询数据总数
                total_query = query.with_only_columns(func.count()).order_by(None)
                total_count = await database.fetch_val(total_query)
        else:
            total_query = select(func.count()).select_from(logs_table)
            total_count = await database.fetch_val(total_query)

        # 根据数据量决定是返回全部还是分页
        if total_count <= limit * (page - 1):
            results = await database.fetch_all(query.order_by(logs_table.c.id))
        else:
            offset = (page - 1) * limit
            results = await database.fetch_all(query.order_by(logs_table.c.id).offset(offset).limit(limit))

        if results:
            logs = [
                LogListData(
                    id=result["id"],
                    user_id=result["user_id"],
                    nickname=str(result["nickname"]),
                    message=result["message"],
                    update_ts=format_datetime(result["update_ts"])
                ) for result in results
            ]

            logger.info(f"查询logs_table表成功")
            
            return LogListResult(code=0, success=True, count=total_count, data=logs, other={"total_count": total_count})
        else:
            logger.info(f"查询logs_table表 无数据")
            return LogListResult(code=0, success=True, count=0, data=[], other={"total_count": 0})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))   

    
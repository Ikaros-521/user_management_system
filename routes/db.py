from fastapi import APIRouter, HTTPException, status, Depends, Request, UploadFile, File, Form
from fastapi.responses import FileResponse
from sqlalchemy import select, update, delete, text, create_engine
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timedelta
from loguru import logger
import asyncio, json, traceback
from typing import Optional
import os
import hashlib


from utils.database import DATABASE_TYPE, TABLE_LIST, close_db, restart_db
from utils.models import CommonResult
from utils.config import get_config
from utils.common import move_and_replace
from routes.auth import get_current_active_user


router = APIRouter()

@router.post("/db/download_db")
async def download_db(current_user: dict = Depends(get_current_active_user)):
    # 获取当前工作目录
    current_working_directory = os.getcwd()
    logger.debug(f"当前工作目录: {current_working_directory}")
    
    # 设置数据库文件路径
    DB_FILE_PATH = "data/data.db"

    if os.path.exists(DB_FILE_PATH):
        return FileResponse(path=DB_FILE_PATH, filename="data.db", media_type='application/octet-stream')
    else:
        raise HTTPException(status_code=404, detail="数据库文件不存在")

@router.post("/db/upload_db")
async def upload_db(
    file: UploadFile = File(...),
    md5: str = Form(...),
    current_user: dict = Depends(get_current_active_user)
):
    try:
        # 数据库为sqlite下的操作
        if DATABASE_TYPE == "sqlite":
            from utils.database import DATABASE_PATH, DATABASE_NAME
            logger.debug(f"上传文件: {file.filename}")
            logger.debug(f"上传文件的MD5: {md5}")
            
            if file.filename != DATABASE_NAME:
                raise HTTPException(status_code=400, detail="数据文件名不正确")
        
            # 计算文件的MD5值
            hash_md5 = hashlib.md5()
            content = await file.read()
            hash_md5.update(content)
            computed_md5 = hash_md5.hexdigest()

            if computed_md5 != md5:
                raise HTTPException(status_code=400, detail="MD5值不匹配")

            # 存储文件到本地
            file_location = f"{file.filename}"
            with open(file_location, "wb") as buffer:
                buffer.write(content)
            
            # 检测db文件是否能够正常被打开，并且相关表是否存在
            try:
                engine = create_engine(f"sqlite:///{file_location}")
                with engine.connect() as connection:
                    for table in TABLE_LIST:
                        result = connection.execute(text(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}';"))
                        if not result.fetchone():
                            raise HTTPException(status_code=400, detail=f"表 {table} 不存在")
            except SQLAlchemyError as db_error:
                logger.error(f"数据库文件检查失败： {db_error}")
                raise HTTPException(status_code=400, detail="数据库文件无效或无法打开")
            
            logger.info("关闭数据库连接")
            await close_db()
            
            if DATABASE_TYPE == "sqlite":
                logger.info("替换数据库文件")
                move_resp = move_and_replace(file_location, DATABASE_PATH)
            
            restart_resp = await restart_db()
            
            if move_resp.code == 0:
                if restart_resp.code == 0:
                    return CommonResult(code=0, success=True, data={"msg":"上传成功"})
                
            if restart_resp.code == 0:
                return CommonResult(code=0, success=False, data={"msg": move_resp.data["msg"]})
            else:
                return CommonResult(code=0, success=False, data={"msg": restart_resp.data["msg"]})
        else:
            raise HTTPException(status_code=400, detail=f"当前数据库不支持上传导入")
    except HTTPException as e:
        logger.error(traceback.format_exc())
        logger.error(f"上传数据库失败： {e.detail}")
        raise e
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error(f"上传数据库失败： {e}")
        raise HTTPException(status_code=500, detail=str(e))


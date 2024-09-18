import asyncio
import uvicorn
import sys, traceback
import json
from loguru import logger
from fastapi import FastAPI, HTTPException, Depends, Request, Form, status
from fastapi.middleware.cors import CORSMiddleware
from starlette.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse
from routes import auth, log, db

from utils.config import get_config, load_config
from utils.database import database, metadata, engine, init_db


app = FastAPI()

app.mount("/ums", StaticFiles(directory="ums"), name="ums")

# 允许跨域
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 加载API路由接口
app.include_router(auth.router)
app.include_router(log.router)
app.include_router(db.router)

@app.on_event("startup")
async def startup():
    await database.connect()
    await init_db()  # 初始化数据库

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

if __name__ == "__main__":
    try:
        load_config()
        loop = asyncio.get_event_loop()
        local_config = get_config()

        config = uvicorn.Config(app, host=local_config["HTTP"]["IP"], port=local_config["HTTP"]["端口"], loop="asyncio")
        server = uvicorn.Server(config)
        loop.run_until_complete(server.serve())
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error(f"配置文件加载失败！{str(e)}")
        logger.info("按任意键退出...")
        input()  # 暂停程序直到用户输入并按回车键

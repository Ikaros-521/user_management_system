from sqlalchemy import MetaData, Table, Column, String, Integer, DateTime, Text, ForeignKey
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from databases import Database
from datetime import datetime, timedelta
from loguru import logger

from utils.models import CommonResult

DATABASE_TYPE = "sqlite"
DATABASE_PATH = "./data/data.db"
DATABASE_NAME = "data.db"
DATABASE_URL = f"sqlite+aiosqlite:///{DATABASE_PATH}"
database = Database(DATABASE_URL)
engine = create_async_engine(DATABASE_URL, echo=True)
metadata = MetaData()
TABLE_LIST = ["users", "logs"]


"""
初始超管账号： admin   密码：admin123
INSERT INTO users (avatar, username, nickname, roles, hashed_password, email, phone, expiration_ts, create_ts, last_login_ts, disabled)
VALUES ('https://avatar.vercel.sh/rauchg.svg?text=Admin', 'admin', 'admin', 'super_admin', '$2b$12$1NY9PGi/X8FsMDW9VxyueeHNU/bFP4ggKk0Jr26DofqA2edVlkUze', 'user@example.com', '1234567890', '3000-01-01 00:00:00', '2024-06-05 15:00:00', '2024-06-05 15:00:00', 0);
"""
users_table = Table(
    "users", metadata,
    Column("id", Integer, primary_key=True),
    Column("avatar", Text),
    Column("username", String, unique=True, index=True),
    Column("nickname", String),
    Column("roles", Text),
    Column("hashed_password", String),
    Column("email", String),
    Column("phone", String),
    Column("expiration_ts", DateTime, default=datetime.utcnow),
    Column("create_ts", DateTime, default=datetime.utcnow),
    Column("last_login_ts", DateTime, default=datetime.utcnow),
    Column("disabled", Integer, default=0),
)

logs_table = Table(
    "logs", metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("username", String, ForeignKey("users.username")),
    Column("nickname", String, ForeignKey("users.nickname")),
    Column("message", Text),
    Column("update_ts", DateTime, default=datetime.utcnow),
)


# SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 创建异步会话
async_session = sessionmaker(
    bind=engine, 
    class_=AsyncSession,
    expire_on_commit=False
)


# 初始化数据库
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)

# 关闭数据库连接
async def close_db():
    try:
        await database.disconnect()
        await engine.dispose()
        
        return CommonResult(code=0, success=True, data={"msg": "关闭数据库连接成功"}) 
    except Exception as e:
        msg = f"关闭数据库失败: {e}"
        logger.error(msg)
        return CommonResult(code=500, success=False, data={"msg": msg}) 

# 重启数据库连接
async def restart_db(new_database_url=None):
    global engine, async_session, database
    
    try:
        await close_db()  # 先关闭现有连接

        if new_database_url:
            global DATABASE_URL
            DATABASE_URL = new_database_url

        database = Database(DATABASE_URL)
        engine = create_async_engine(DATABASE_URL, echo=True)
        async_session = sessionmaker(
            bind=engine, 
            class_=AsyncSession,
            expire_on_commit=False
        )
        return CommonResult(code=0, success=True, data={"msg": "重启数据库连接成功"}) 
    except Exception as e:
        msg = f"重启数据库连接失败: {e}"
        logger.error(msg)
        return CommonResult(code=500, success=False, data={"msg": msg}) 
    
    
# 通用事务管理器
class TransactionManager:
    def __init__(self, session_factory):
        self.session_factory = session_factory

    async def execute(self, query):
        async with self.session_factory() as session:
            async with session.begin():
                try:
                    result = await session.execute(query)
                    await session.commit()
                    return result.rowcount  # 返回受影响的行数
                except Exception as e:
                    await session.rollback()
                    raise e

# 创建事务管理器实例
transaction_manager = TransactionManager(async_session)

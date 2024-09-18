from pydantic import BaseModel, Field
from datetime import datetime
from typing import List, Dict, Any, Optional
    

"""
登录
"""
class Login(BaseModel):
    username: str
    password: str

class UserResultData(BaseModel):
    avatar: str
    username: str
    nickname: str
    roles: List[str]
    accessToken: str
    refreshToken: str
    expiration_ts: datetime
    expires: datetime

class UserResult(BaseModel):
    code: int
    success: bool
    data: UserResultData

class UpdatePasswordMessage(BaseModel):
    username: str
    old_password: str
    new_password: str

class UpdateUserInfoMessage(BaseModel):
    username: str
    new_username: str
    phone: str
    email: str

class TokenData(BaseModel):
    accessToken: str
    refreshToken: str
    expires: datetime

class TokenResponse(BaseModel):
    code: int
    success: bool
    data: TokenData


class RefreshTokenRequest(BaseModel):
    refreshToken: str
  
"""
用户管理
""" 
class GetUserMessage(BaseModel):
    # 页数
    page: int
    # 记录数上限
    limit: int
    # 搜索参数json字符串
    search_params: Optional[str] = Field(None)
    
class UserListData(BaseModel):
    id: int
    avatar: str
    username: str
    nickname: str
    roles: List[str]
    email: str
    phone: str
    expiration_ts: str
    create_ts: str
    last_login_ts: str
    disabled: str

class UserListResult(BaseModel):
    code: int
    success: bool
    count: int
    data: List[UserListData] 
    other: Optional[Dict[str, Any]] = None

class AddUserMessage(BaseModel):
    avatar: str
    username: str
    nickname: str
    roles: str
    password: str
    email: str
    phone: str
    expiration_ts: str
    disabled: int

class DelUserMessage(BaseModel):
    id: int
    
class DelUsersMessage(BaseModel):
    ids: List[DelUserMessage]
    
class UpdateUserMessage(BaseModel):
    id: int
    username: str
    ori_username: str
    nickname: str
    roles: str
    email: str
    phone: str
    expiration_ts: str
    disabled: int


"""
通用
""" 
class CommonResult(BaseModel):
    code: int
    success: bool
    data: Dict[str, Any]
    other: Optional[Dict[str, Any]] = None


"""
日志管理
"""   
class DelLogMessage(BaseModel):
    id: int

class GetLogMessage(BaseModel):
    # 页数
    page: int
    # 记录数上限
    limit: int
    # 搜索参数json字符串
    search_params: Optional[str] = Field(None)

class LogListData(BaseModel):
    id: int
    user_id: int
    username: str
    nickname: str
    message: str
    update_ts: str

class LogListResult(BaseModel):
    code: int
    success: bool
    count: int
    data: List[LogListData] 
    other: Optional[Dict[str, Any]] = None

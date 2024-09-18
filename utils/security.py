from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import re


# 初始化密码加密上下文，使用bcrypt算法
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "mysecretkey"  # 用于JWT编码的秘密密钥
ALGORITHM = "HS256"  # JWT使用的编码算法

def verify_password(plain_password, hashed_password):
    """
    验证明文密码是否与哈希密码匹配

    参数:
    plain_password (str): 明文密码
    hashed_password (str): 哈希后的密码

    返回:
    bool: 如果匹配返回True，否则返回False
    """
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    """
    创建一个JWT访问令牌

    参数:
    data (dict): 需要编码的数据
    expires_delta (timedelta, optional): 令牌的过期时间，默认为15分钟

    返回:
    str: 编码后的JWT令牌
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def hash_password(password: str) -> str:
    """
    生成密码的哈希值

    参数:
    password (str): 明文密码

    返回:
    str: 哈希后的密码
    """
    return pwd_context.hash(password)


def validate_username(username):
    if not re.match(r"^[a-zA-Z0-9_\u4e00-\u9fa5\s·]+$", username):
        return {'ret': False, 'msg': '用户名不能有特殊字符'}
    if re.match(r"(^_)|(__)|(_+$)", username):
        return {'ret': False, 'msg': '用户名首尾不能出现下划线'}
    if re.match(r"^\d+$", username):
        return {'ret': False, 'msg': '用户名不能全为数字'}
    return {'ret': True, 'msg': '用户名验证通过'}

def validate_phone(phone):
    if not re.match(r"^1[3-9]\d{9}$", phone):
        return {'ret': False, 'msg': '请输入正确的手机号'}
    return {'ret': True, 'msg': '手机号验证通过'}

def validate_email(email):
    if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
        return {'ret': False, 'msg': '请输入正确的邮箱'}
    return {'ret': True, 'msg': '邮箱验证通过'}

def validate_password(password):
    if not re.match(r"^[\S]{8,20}$", password):
        return {'ret': False, 'msg': '密码必须为8到20位的非空字符'}
    if re.match(r"^\d+$", password):
        return {'ret': False, 'msg': '密码不能全为数字'}
    if not ((re.search(r"[a-z]", password) and re.search(r"[A-Z]", password)) or 
            (re.search(r"[a-z]", password) and re.search(r"\d", password)) or 
            (re.search(r"[a-z]", password) and re.search(r"[^\w\s]", password)) or 
            (re.search(r"[A-Z]", password) and re.search(r"\d", password)) or 
            (re.search(r"[A-Z]", password) and re.search(r"[^\w\s]", password)) or 
            (re.search(r"\d", password) and re.search(r"[^\w\s]", password))):
        return {'ret': False, 'msg': '密码必须包含大小写字母、数字和特殊符号中的两种及以上'}
    return {'ret': True, 'msg': '密码验证通过'}

if __name__ == '__main__':
    print(hash_password('admin123'))

    # 示例用法：
    username_error = validate_username('example_username')
    username_error2 = validate_username('serna')
    username_error3 = validate_username('serasd!$na')
    phone_error = validate_phone('13800138000')
    phone_error2 = validate_phone('23800138000')
    phone_error3 = validate_phone('13a00138000')
    phone_error4 = validate_phone('138001380001')
    phone_error5 = validate_phone('1380013800')
    email_error = validate_email('example@example.com')
    email_error2 = validate_email('1@1.com')
    email_error3 = validate_email('1@1com')
    email_error4 = validate_email('11com')
    email_error5 = validate_email('11.com')
    password_error = validate_password('Password123!')
    password_error2 = validate_password('Password123')
    password_error3 = validate_password('password123')
    password_error4 = validate_password('pass123')

    print(username_error)  # {"ret": True, "msg": "用户名验证通过"}
    print(username_error2)
    print(username_error3)
    print(phone_error)     # {"ret": True, "msg": "手机号验证通过"}
    print(phone_error2)
    print(phone_error3)
    print(phone_error4)
    print(phone_error5)
    print(email_error)
    print(email_error2)
    print(email_error3)
    print(email_error4)
    print(email_error5)     # {"ret": True, "msg": "邮箱验证通过"}
    print(password_error)  # {"ret": True, "msg": "密码验证通过"}
    print(password_error2)
    print(password_error3)
    print(password_error4)
    
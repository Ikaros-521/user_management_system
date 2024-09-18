# 前言

用户管理系统，提供简易的用户管理功能，提供API接口，提供用户登录服务，可以通过系统设置用户过期时间，实现个简易的计费统计。  

# 环境

python: 3.10  
数据库：SQLite3  
操作系统：Windows 10 / Linux

# 安装

`pip install -r requirements.txt`  

# 运行

`python main.py`

浏览器打开：`http://127.0.0.1:1119/ums/login.html`，即可访问登录页面。  

API文档：`http://127.0.0.1:1119/docs`  

# 数据库添加默认数据

## 插入超级管理员账号

初始超管账号：admin   密码：admin123  
参考SQL语句：  
```
INSERT INTO users (avatar, username, nickname, roles, hashed_password, email, phone, expiration_ts, create_ts, last_login_ts, disabled)
VALUES ('https://avatar.vercel.sh/rauchg.svg?text=Admin', 'admin', 'admin', 'super_admin', '$2b$12$1NY9PGi/X8FsMDW9VxyueeHNU/bFP4ggKk0Jr26DofqA2edVlkUze', 'user@example.com', '1234567890', '3000-01-01 00:00:00', '2024-06-05 15:00:00', '2024-06-05 15:00:00', 0);
```

# 更新日志

- 2024-09-19
    - 初版demo发布
    
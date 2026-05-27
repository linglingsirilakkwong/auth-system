import sqlite3
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Request, Form, Depends, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="授权管理中心")
DB_FILE = "users.db"


# ================= 数据库初始化 =================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            mac_address TEXT,
            status TEXT DEFAULT 'pending',
            expires_at DATETIME
        )
    ''')
    conn.commit()
    conn.close()


init_db()


# ================= 数据模型 =================
class UserAuth(BaseModel):
    username: str
    password: str
    mac_address: str


class RunCheck(BaseModel):
    username: str
    mac_address: str


# ================= 🌐 首页使用说明 (路径修改为 /secure) =================
@app.get("/secure", response_class=HTMLResponse)
@app.get("/secure/", response_class=HTMLResponse)  # 兼容带有斜杠的访问
def index_page():
    html_content = """
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>软件授权管理系统</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f0f2f5; color: #333; line-height: 1.6; margin: 0; padding: 40px 20px; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }
            h1 { color: #1a73e8; text-align: center; margin-bottom: 30px; border-bottom: 2px solid #f0f2f5; padding-bottom: 20px; }
            h2 { color: #202124; margin-top: 30px; display: flex; align-items: center; }
            h2 span { font-size: 24px; margin-right: 10px; }
            .user-guide { background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #34a853; margin-bottom: 30px; }
            .user-guide ol { padding-left: 20px; margin: 0; }
            .user-guide li { margin-bottom: 12px; }
            .admin-section { background: #e8f0fe; padding: 25px; border-radius: 8px; border-left: 4px solid #1a73e8; text-align: center; }
            .btn { display: inline-block; background: #1a73e8; color: white; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-weight: bold; margin-top: 15px; transition: background 0.3s; }
            .btn:hover { background: #1557b0; }
            code { background: #e8eaed; padding: 2px 6px; border-radius: 4px; font-family: monospace; color: #d93025; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ 专属软件授权验证系统</h1>

            <div class="user-guide">
                <h2><span>🧑‍💻</span> 普通用户使用指南</h2>
                <ol>
                    <li><b>获取软件：</b> 请确保您已经从管理员处获取了最新的客户端程序。</li>
                    <li><b>注册账号：</b> 首次打开软件时，选择注册新账号。系统将自动绑定您的当前电脑设备。</li>
                    <li><b>等待审批：</b> 注册完成后，系统会提示进入待审批状态。请等待管理员分配授权。</li>
                    <li><b>启动运行：</b> 管理员审批通过后，重新打开软件登录即可使用。</li>
                    <li><b>免密登录：</b> 成功登录一次后，软件下次将自动校验并秒进程序。</li>
                </ol>
            </div>

            <div class="admin-section">
                <h2 style="justify-content: center;"><span>👑</span> 管理员控制台</h2>
                <p style="color: #5f6368; margin-bottom: 20px;">审查注册请求、分配时长、收回权限或彻底清理废弃账号。</p>
                <a href="/secure/admin" class="btn">进入管理员后台 ➔</a>
            </div>
        </div>
    </body>
    </html>
    """
    return html_content


# ================= API 接口 (修改前缀为 /secure/api/) =================

@app.post("/secure/api/register")
def register_user(user: UserAuth):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password, mac_address, status) VALUES (?, ?, ?, 'pending')",
                  (user.username, user.password, user.mac_address))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return {"status": "error", "message": "该账号已被注册！"}
    conn.close()
    return {"status": "success", "message": "注册成功！已提交授权请求，请等待管理员审批。"}


@app.post("/secure/api/login")
def login_user(user: UserAuth):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT password, mac_address, status, expires_at FROM users WHERE username=?", (user.username,))
    row = c.fetchone()
    conn.close()

    if not row:
        return {"status": "error", "message": "账号不存在，请先注册"}

    db_pwd, db_mac, status, expires_str = row

    if db_pwd != user.password:
        return {"status": "error", "message": "密码错误！"}

    if db_mac != user.mac_address:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("UPDATE users SET mac_address=?, status='pending' WHERE username=?",
                  (user.mac_address, user.username))
        conn.commit()
        conn.close()
        return {"status": "error", "message": "检测到更换设备！已重新提交审批请求。"}

    if status == 'pending':
        return {"status": "error", "message": "账号正在等待管理员审批。"}
    elif status == 'rejected':
        return {"status": "error", "message": "您的授权已被管理员拒绝。"}

    if datetime.now() > datetime.fromisoformat(expires_str):
        return {"status": "error", "message": "您的授权已过期。"}

    return {"status": "success", "message": "登录成功", "expires_at": expires_str}


@app.post("/secure/api/verify_run")
def verify_run(req: RunCheck):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT mac_address, status, expires_at FROM users WHERE username=?", (req.username,))
    row = c.fetchone()
    conn.close()

    if not row:
        return {"status": "error", "message": "账号已被彻底注销"}

    db_mac, status, expires_str = row

    if db_mac != req.mac_address:
        return {"status": "error", "message": "设备码不匹配"}

    if status != 'approved':
        return {"status": "error", "message": "管理员已收回您的使用权限！"}

    if datetime.now() > datetime.fromisoformat(expires_str):
        return {"status": "error", "message": "授权已过期！"}

    return {"status": "success", "message": "权限有效", "expires_at": expires_str}


# ================= 可视化管理员后台 (修改前缀为 /secure/admin) =================

ADMIN_USER = "admin"
ADMIN_PWD = "admin888"
SESSION_TOKEN = "secret_admin_token_2026"


def get_login_page(error_msg=""):
    return f"""
    <html><head><title>管理员登录</title></head>
    <body style="font-family: Arial; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f4f4f9; margin: 0;">
        <div style="background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 300px; text-align: center;">
            <h2 style="margin-top:0; color: #1a73e8;">🔐 管理员后台</h2>
            <p style="color: red; font-size: 14px; min-height: 20px;">{error_msg}</p>
            <form action="/secure/admin/login" method="post" style="display: flex; flex-direction: column; gap: 15px;">
                <input type="text" name="username" placeholder="管理员账号" required style="padding: 10px; border: 1px solid #ccc; border-radius: 4px;">
                <input type="password" name="password" placeholder="管理密码" required style="padding: 10px; border: 1px solid #ccc; border-radius: 4px;">
                <button type="submit" style="padding: 10px; background: #1a73e8; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px;">安全登录</button>
            </form>
            <div style="margin-top: 20px; font-size: 13px;">
                <a href="/secure" style="color: #666; text-decoration: none;">← 返回首页</a>
            </div>
        </div>
    </body></html>
    """


@app.post("/secure/admin/login")
def admin_login(username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USER and password == ADMIN_PWD:
        # 修改：重定向到 /secure/admin
        response = RedirectResponse(url="/secure/admin", status_code=303)
        response.set_cookie(key="admin_session", value=SESSION_TOKEN, max_age=7200, httponly=True)
        return response
    else:
        return HTMLResponse(get_login_page("账号或密码错误！"))


@app.get("/secure/admin/logout")
def admin_logout():
    # 修改：重定向回首页
    response = RedirectResponse(url="/secure", status_code=303)
    response.delete_cookie(key="admin_session")
    return response


def check_admin_auth(request: Request):
    session = request.cookies.get("admin_session")
    if not session or session != SESSION_TOKEN:
        raise HTTPException(status_code=401, detail="未授权访问")
    return True


@app.get("/secure/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request):
    session = request.cookies.get("admin_session")
    if not session or session != SESSION_TOKEN:
        return HTMLResponse(get_login_page())

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT username, mac_address, status, expires_at FROM users ORDER BY status DESC")
    users = c.fetchall()
    conn.close()

    rows_html = ""
    for u in users:
        uname, mac, status, exp = u
        exp_text = exp[:16] if exp else "无"
        status_color = "orange" if status == 'pending' else "green" if status == 'approved' else "red"

        # 修改：表单 action 为 /secure/admin/action
        rows_html += f"""
        <tr onmouseover="this.style.backgroundColor='#f1f3f4'" onmouseout="this.style.backgroundColor='transparent'">
            <td>{uname}</td><td style='font-family: monospace; color: #555; font-size: 12px;'>{mac}</td>
            <td style='color:{status_color}; font-weight:bold;'>{status}</td><td>{exp_text}</td>
            <td>
                <form action="/secure/admin/action" method="post" style="display:flex; align-items:center; gap:5px; margin:0;">
                    <input type="hidden" name="target_user" value="{uname}">
                    <input type="number" name="days" value="30" style="width:50px; padding: 4px; border:1px solid #ccc; border-radius:3px;" title="授权天数">
                    <span style="font-size:12px; color:#666;">天</span>
                    <button type="submit" name="action" value="approve" style="background:#34a853; color:white; border:none; padding:5px 10px; cursor:pointer; border-radius:3px;">通过</button>
                    <button type="submit" name="action" value="reject" style="background:#ea4335; color:white; border:none; padding:5px 10px; cursor:pointer; border-radius:3px;">拒绝</button>
                    <button type="submit" name="action" value="delete" style="background:#5f6368; color:white; border:none; padding:5px 10px; cursor:pointer; border-radius:3px; margin-left:10px;" onclick="return confirm('⚠️ 危险操作：确定要彻底删除用户【{uname}】吗？数据不可恢复！');">删除</button>
                </form>
            </td>
        </tr>
        """

    html_content = f"""
    <html><head><title>授权管理中心</title></head>
    <body style="font-family: Arial, sans-serif; padding: 20px; background: #f0f2f5;">
        <div style="max-width: 1050px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); border-radius: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #eee; padding-bottom: 15px; margin-bottom: 25px;">
                <h2 style="margin: 0; color: #1a73e8;">🔐 管理员控制台</h2>
                <div>
                    <a href="/secure" style="color: #666; text-decoration: none; margin-right: 20px; font-size: 14px;">返回首页</a>
                    <a href="/secure/admin/logout" style="background: #f1f3f4; color: #3c4043; text-decoration: none; padding: 8px 15px; border-radius: 4px; font-size: 14px; font-weight: bold;">退出登录</a>
                </div>
            </div>

            <table border="1" cellpadding="12" cellspacing="0" style="width: 100%; text-align: left; border-collapse: collapse; border-color: #e0e0e0;">
                <tr style="background:#f8f9fa;">
                    <th>客户端账号</th><th>设备机器码 (MAC)</th><th>当前状态</th><th>到期时间</th><th>操作面板</th>
                </tr>
                {rows_html}
            </table>
        </div>
    </body></html>
    """
    return html_content


@app.post("/secure/admin/action")
def admin_action(target_user: str = Form(...), action: str = Form(...), days: int = Form(30),
                 _=Depends(check_admin_auth)):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    if action == "approve":
        expires_at = (datetime.now() + timedelta(days=days)).isoformat()
        c.execute("UPDATE users SET status='approved', expires_at=? WHERE username=?", (expires_at, target_user))
    elif action == "reject":
        c.execute("UPDATE users SET status='rejected' WHERE username=?", (target_user,))
    elif action == "delete":
        c.execute("DELETE FROM users WHERE username=?", (target_user,))

    conn.commit()
    conn.close()

    # 修改：操作完毕后重定向回管理员面板
    return RedirectResponse(url="/secure/admin", status_code=303)


if __name__ == "__main__":
    import os
    # 自动获取云服务器分配的端口，找不到则默认 14283
    port = int(os.environ.get("PORT", 14283))
    print("启动服务器中...")
    uvicorn.run(app, host="0.0.0.0", port=port)

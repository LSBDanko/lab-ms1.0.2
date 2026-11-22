# 实验室管理系统 · LAB MS

五邑大学实验室管理系统：试剂台账、耗材记录、仪器使用、负责人管理、全流程溯源、实时通知、预约、附件与危化品双人复核。

## 项目结构

```text
lab-ms/
├─ index.html              # GitHub Pages 入口，跳转到 frontend/index.html
├─ frontend/
│  ├─ index.html           # 单页前端
│  ├─ config.js            # 后端 API 地址配置
│  └─ assets/              # 校园图片、实验室图片、Logo
├─ backend/
│  ├─ main.py              # FastAPI + SQLite
│  ├─ requirements.txt
│  └─ lab.db               # 本地数据，不提交到 Git
├─ Dockerfile              # 不绑卡 Docker 部署（Hugging Face Spaces 等）
├─ deploy/
│  └─ huggingface/         # Hugging Face Space 的 README 模板
├─ render.yaml             # Render 后端部署示例
└─ README.md
```

## 本地运行

### 1. 启动后端

Windows PowerShell：

```powershell
cd backend
py -3.11 -m venv .venv
.\.venv\Scripts\pip.exe install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

macOS / Linux：

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

后端默认地址：

```text
http://127.0.0.1:8000
```

接口文档：

```text
http://127.0.0.1:8000/docs
```

### 2. 打开前端

直接打开：

```text
frontend/index.html
```

或使用根目录入口：

```text
index.html
```

也可以直接打开后端根地址：

```text
http://127.0.0.1:8000/
```

后端会自动托管 `frontend/`，此时前端和 API 同源，不需要额外配置 `config.js`。

`frontend/config.js` 默认留空，直接打开 `frontend/index.html` 时会访问本机 `8000` 端口。

## 同一 WiFi 下让手机 / 平板访问

不需要 GitHub Pages，也不需要云服务器或银行卡。后端现在会直接托管前端页面。

1. 确保电脑和后端服务正在运行
2. 在电脑上执行：

```powershell
ipconfig
```

找到当前 WiFi 的 IPv4 地址，例如：

```text
192.168.1.23
```

3. 手机/平板连接同一个 WiFi，打开：

```text
http://192.168.1.23:8000/
```

就能直接打开完整系统，前端和 API 同源，不需要改 `config.js`。

如果手机打不开，通常是 Windows 防火墙拦截了 8000 端口。可以在管理员 PowerShell 中执行：

```powershell
netsh advfirewall firewall add rule name="Lab MS 8000" dir=in action=allow protocol=TCP localport=8000
```

> 这种方式只在同一局域网内有效，电脑关机或休眠后无法访问。

## GitHub Pages 部署

### 1. 开启 Pages

仓库 → **Settings** → **Pages**：

```text
Source: Deploy from a branch
Branch: main
Folder: / (root)
```

保存后等待 1～3 分钟。

访问：

```text
https://你的用户名.github.io/仓库名/
```

根目录的 `index.html` 会自动跳转到：

```text
https://你的用户名.github.io/仓库名/frontend/index.html
```

### 2. 如果仍然 404

按顺序检查：

1. 仓库是 Public，或当前账号套餐支持私有仓库 Pages
2. Pages 设置的分支和目录是否正确
3. Actions 中 Pages 部署是否成功
4. 文件名必须是 `index.html`，不是 `Index.html`
5. 网址是否包含正确的仓库名
6. 是否刚部署完还没生效，等待 1～3 分钟并强制刷新

## 重要：GitHub Pages 不能运行后端

GitHub Pages 只能托管 HTML/CSS/JS，不能运行 FastAPI、Python 或 SQLite。

所以正确架构是：

```text
GitHub Pages  →  frontend/index.html
CloudBase Run / Render / 云服务器  →  backend/main.py
```

### 1. 部署后端

#### 腾讯云 CloudBase Run（国内推荐）

CloudBase 云托管支持直接部署 FastAPI Docker 容器，地域目前为上海。

1. 注册/登录腾讯云，开通 CloudBase 环境
2. 安装 CloudBase CLI：

```bash
npm install -g @cloudbase/cli
tcb login
```

3. 在项目根目录部署：

```bash
tcb cloudrun deploy \
  -e 你的环境ID \
  -s lab-ms \
  --port 80 \
  --source . \
  --env-params '{"PORT":"80","LAB_SECRET":"你的随机长字符串","LAB_DB":"/tmp/lab.db","TZ":"Asia/Shanghai"}' \
  --force --yes --wait
```

4. 查看公网地址：

```bash
tcb cloudrun detail -e 你的环境ID -s lab-ms
```

`DefaultDomainName` 就是公网 HTTPS 地址。

注意：

- 容器端口必须是 `80`
- SQLite 位于 `/tmp/lab.db`，容器重启后可能重置
- 长期保存数据需要改用 CloudBase PostgreSQL 或腾讯云数据库
- 体验版环境有有效期，到期/超出额度后以控制台账单为准

#### 不绑卡方案：Hugging Face Spaces

如果 Render 要求绑定银行卡，可以使用 Hugging Face Spaces 的免费 Docker Space，不需要信用卡。

1. 注册/登录 [Hugging Face](https://huggingface.co/)
2. 打开 [新建 Space](https://huggingface.co/new-space)
3. 填写名称，SDK 选择 **Docker**，硬件选择 **CPU basic · FREE**
4. 可见性选择 **Public**
5. 创建后，把下面这些内容放到 Space 根目录：

```text
Dockerfile
backend/
frontend/
```

推荐直接用 Space 页面上的 **Files → Upload files** 上传，避免覆盖 Space 自动生成的 `README.md`。

如果使用 Git 推送整个仓库，请保留 Space 根目录的 `README.md`，或者使用 [deploy/huggingface/README.md](deploy/huggingface/README.md) 作为 Space 的 README，不要直接使用项目根目录的 README 覆盖它。

6. 在 Space 的 **Settings → Variables and secrets** 添加：

```text
LAB_SECRET=一串足够长的随机字符串
```

7. 等待构建完成，地址通常是：

```text
https://你的用户名-你的Space名.hf.space
```

后端会自动托管前端，直接打开这个地址就能使用完整系统，不需要额外配置 GitHub Pages 的 `config.js`。

8. 测试健康检查：

```text
https://你的用户名-你的Space名.hf.space/api/health
```

返回 `{"ok": true, ...}` 就说明后端已上线。

9. 打开接口文档：

```text
https://你的用户名-你的Space名.hf.space/docs
```

10. 如果你仍然想用 GitHub Pages 作为前端入口，再把地址填入 `frontend/config.js`：

```js
window.LAB_API_BASE = 'https://你的用户名-你的Space名.hf.space';
```

**注意：** 免费 Space 的 `/tmp` 数据在重启或重新构建后可能被清空，适合演示；要长期保存台账，需要持久化磁盘或 PostgreSQL。Dockerfile 已将数据库路径设置为 `/tmp/lab.db`。

#### Render 方案（可能需要绑卡）

可以直接使用根目录的 `render.yaml` 在 Render 创建 Blueprint，也可以手动配置：

```text
Root Directory: backend
Build Command: pip install -r requirements.txt
Start Command: uvicorn main:app --host 0.0.0.0 --port $PORT
```

建议设置环境变量：

```text
LAB_SECRET=一串足够长的随机字符串
```

后端已允许跨域，前端和后端可以分开部署。

### 2. 配置前端 API 地址

部署好后端后，编辑 `frontend/config.js`：

```js
window.LAB_API_BASE = 'https://你的后端域名';
```

提交后等待 GitHub Pages 重新部署。

### 3. SQLite 数据持久化

免费平台的文件系统通常是临时的，重新部署后 `lab.db` 可能被重置。

如果需要长期保存数据，建议：

- 使用带持久化磁盘的云服务器，或
- 将 SQLite 换成 PostgreSQL

## 后续更新

当前 `D:\unity games\lab-ms` 已经是连接 `LSBDanko/lab-ms1.0.2` 的 Git 仓库。

修改代码后，直接双击：

```text
publish.bat
```

或者在 PowerShell 中运行：

```powershell
.\publish.ps1
```

脚本会：

1. 提交当前修改
2. 推送到 GitHub
3. 让 GitHub Pages 自动重新发布
4. 询问是否同时重新部署 CloudBase

只改前端且只用 GitHub Pages 时，CloudBase 可以选择 `N`。  
如果手机使用的是 CloudBase 直连地址，则选 `y`。

如果只想提交 GitHub、不部署 CloudBase：

```powershell
.\publish.ps1 -SkipCloudBase
```

手动流程：

```powershell
git add -A
git commit -m "update"
git push origin main

tcb cloudrun deploy `
  -e gastric-skunk-d1gn1l6iv2cfab3e2 `
  -s lab-ms `
  --port 80 `
  --source . `
  --force --yes --wait
```

注意：CloudBase 容器重启/重新部署后，`/tmp/lab.db` 可能重置。

## 安全提醒

不要把以下文件提交到公开仓库：

```text
backend/.venv/
backend/lab.db
backend/lab.db.bak-*
backend/__pycache__/
```

`.gitignore` 已经包含这些规则。

如果数据库已经被提交过，需要从 Git 索引中移除：

```bash
git rm --cached backend/lab.db
git rm -r --cached backend/.venv
git commit -m "chore: stop tracking local database and venv"
```

如果数据库里包含真实账号或敏感数据，建议更换测试账号密码，必要时重写 Git 历史。

## 启动后的演示账号

```text
admin / 123456
liyan / 123456
wangbo / 123456
```

首次部署后请立即修改密码。

## 配置优先级

前端 API 地址按以下顺序读取：

```text
URL 参数 ?api=...
→ frontend/config.js 中的 window.LAB_API_BASE
→ localStorage.lab_api_base
→ http://127.0.0.1:8000
```

例如临时测试：

```text
https://你的用户名.github.io/lab-ms/?api=https://lab-ms-api.onrender.com
```

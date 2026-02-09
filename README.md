# Server Monitor — Multi-Server GPU Monitoring Dashboard

**[中文文档 / Chinese Documentation](#中文文档)**

A lightweight server monitoring system designed for multi-GPU server clusters. Built with Python + Flask + SQLite — ready to use with minimal setup.

## Features

- **Deep GPU Monitoring** — Real-time display of each GPU's utilization, VRAM, temperature, power draw, and running processes (PID, process name, VRAM usage)
- **System Resource Monitoring** — CPU, memory, disk usage, and network I/O
- **Password Protection** — Admin password loaded only from config file; never exposed through the web interface
- **Login Rate Limiting** — Max 5 attempts per 5 minutes to prevent brute-force attacks
- **SQLite Storage** — Zero-config database, all data stored in a single `monitor.db` file
- **Agent Token Auth** — Agents must carry a Bearer token to report data, preventing unauthorized writes
- **Auto Refresh** — Dashboard pulls latest data every 30 seconds automatically
- **Auto Data Cleanup** — Historical metrics older than the retention period are automatically purged
- **Dark / Light Theme** — Toggle between dark and light themes, preference saved in browser
- **Server Overview Panel** — At-a-glance summary showing each server's GPU model, count, and active status
- **Per-User GPU Usage** — Displays which user and LXC/Incus container owns each GPU process

## Project Structure

```
server-moniter/
├── config.yaml            # Main server config (password, token, etc.)
│                          # 主服务器配置（密码、token 等）
├── agent_config.yaml      # Agent config template (copy to each server)
│                          # Agent 配置模板（复制到各服务器）
├── app.py                 # Main server (Flask Web + SQLite + API)
│                          # 主服务端（Flask Web + SQLite + API）
├── agent.py               # Monitoring agent (deploy to monitored servers)
│                          # 监控 Agent（部署到被监控服务器）
├── requirements.txt       # Python dependencies / Python 依赖
├── Dockerfile             # Docker image for the server / 主服务端 Docker 镜像
├── docker-compose.yml     # Docker Compose deployment / Docker Compose 部署
├── scripts/
│   ├── install_server.sh  # One-click server deploy / 主服务端一键部署
│   ├── install_agent.sh   # One-click agent deploy / Agent 一键部署
│   ├── upgrade.sh         # One-click upgrade / 一键升级
│   └── uninstall.sh       # Uninstall script / 卸载脚本
└── templates/
    ├── login.html         # Login page / 登录页面
    ├── register.html      # Invite registration page / 邀请注册页面
    ├── admin.html         # Admin panel / 管理员面板
    └── dashboard.html     # Monitoring dashboard / 监控面板
```

## One-Click Deployment

### Option A: Shell Scripts (Recommended for GPU servers)

**Deploy the main server** (on the monitoring host):

```bash
# Recommended: save first, then run (enables admin/password prompts)
curl -sSL https://raw.githubusercontent.com/tangshunpu/Server-Monitor/main/scripts/install_server.sh -o install.sh && sudo bash install.sh

# Or piped (uses defaults: admin/admin123, port 5100)
curl -sSL https://raw.githubusercontent.com/tangshunpu/Server-Monitor/main/scripts/install_server.sh | sudo bash
```

**Deploy agents** (on each monitored server — run one command per server):

```bash
curl -sSL https://raw.githubusercontent.com/tangshunpu/Server-Monitor/main/scripts/install_agent.sh | sudo bash -s -- \
  --url http://MONITOR_SERVER_IP:5100 \
  --token YOUR_AGENT_TOKEN
```

The scripts will automatically install dependencies, generate configs, and create systemd services.

### Option B: Docker Compose (Server only)

```bash
git clone https://github.com/tangshunpu/Server-Monitor.git
cd Server-Monitor
# Edit config.yaml first! / 先编辑 config.yaml！
docker-compose up -d
```

> **Note**: Docker is only recommended for the server side. Agents should run natively on the host for direct access to `nvidia-smi` and system metrics.
>
> **注意**：Docker 仅推荐用于主服务端。Agent 应直接在宿主机运行以访问 `nvidia-smi` 和系统指标。

### Upgrade

Upgrade server and/or agent to the latest version (config files are preserved):

```bash
# Auto-detect and upgrade all installed components
# 自动检测并升级所有已安装组件
curl -sSL https://raw.githubusercontent.com/tangshunpu/Server-Monitor/main/scripts/upgrade.sh | sudo bash

# Or specify: server | agent | all
# 或指定: server | agent | all
curl -sSL https://raw.githubusercontent.com/tangshunpu/Server-Monitor/main/scripts/upgrade.sh | sudo bash -s -- agent
```

### Uninstall

```bash
curl -sSL https://raw.githubusercontent.com/tangshunpu/Server-Monitor/main/scripts/uninstall.sh | sudo bash -s -- all
```

---

## Manual Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure the Main Server

Edit `config.yaml` and update the following key fields:

```yaml
server:
  port: 5100                                        # Web server port / Web 服务端口
  secret_key: "replace-with-a-random-string"        # Flask session secret / Flask session 密钥

auth:
  password: "replace-with-your-admin-password"      # Login password / 登录密码

agent:
  token: "replace-with-a-secure-token"              # Agent auth token / Agent 认证令牌
```

> **Security Note**: `config.yaml` contains sensitive information. Set file permissions accordingly: `chmod 600 config.yaml`.
>
> **安全提示**：`config.yaml` 包含敏感信息，请设置文件权限 `chmod 600 config.yaml`。

### 3. Start the Main Server

```bash
python app.py
```

Once started, open `http://YOUR_IP:5100` in your browser and enter the admin password to access the dashboard.

### 4. Deploy Agents to Monitored Servers

Copy `agent.py` and `agent_config.yaml` to each server you want to monitor.

Edit `agent_config.yaml`:

```yaml
server_url: "http://MONITOR_SERVER_IP:5100"    # Monitor server URL / 监控主服务器地址
token: "must-match-agent-token-in-config-yaml" # Must match config.yaml agent.token / 必须与主服务器一致
interval: 30                                   # Reporting interval in seconds / 上报间隔（秒）
```

Install agent dependencies and start:

```bash
pip install psutil requests pyyaml
python agent.py -c agent_config.yaml
```

## Agent CLI Arguments

```
python agent.py [-c CONFIG] [-i INTERVAL]

Options:
  -c, --config    Config file path (default: agent_config.yaml)
                  配置文件路径（默认: agent_config.yaml）
  -i, --interval  Reporting interval in seconds (overrides config file)
                  上报间隔秒数（覆盖配置文件中的值）
```

## Running the Agent as a Service

It is recommended to use `systemd` to manage the agent process for auto-start on boot and automatic restart on failure.

Create `/etc/systemd/system/server-monitor-agent.service`:

```ini
[Unit]
Description=Server Monitor Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/server-monitor
ExecStart=/usr/bin/python3 /opt/server-monitor/agent.py -c /opt/server-monitor/agent_config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable server-monitor-agent
sudo systemctl start server-monitor-agent
```

## API Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/login` | POST | Form password | Admin login / 管理员登录 |
| `/logout` | GET | — | Logout / 退出登录 |
| `/api/report` | POST | Bearer token | Agent reports metrics / Agent 上报指标数据 |
| `/api/servers` | GET | Session | Get all servers' latest status / 获取所有服务器最新状态 |
| `/api/servers/<id>/history` | GET | Session | Get server history (`?hours=24`) / 获取历史数据 |
| `/api/servers/<id>` | DELETE | Session | Delete server and its data / 删除服务器及其数据 |

## GPU Monitoring Details

The agent collects GPU information by calling the `nvidia-smi` command — no additional Python GPU libraries required. The NVIDIA driver must be installed on each monitored server.

Collected GPU metrics include:

- GPU compute utilization / GPU 计算利用率
- VRAM used / total / 显存使用量 / 总量
- GPU temperature / GPU 温度
- Power draw / power limit / 功耗 / 功耗上限
- Process list on GPU (PID, process name, VRAM usage) / GPU 进程列表（PID、进程名、显存占用）

If a server has no NVIDIA GPU, the agent will automatically skip GPU collection; all other metrics are reported normally.

## Security Notes

- Admin password is **only** stored in `config.yaml` — never written to the database, never returned by any API
- Login uses `hmac.compare_digest` for timing-safe comparison to prevent timing attacks
- Login failures are rate-limited to prevent brute-force attacks
- Agent reporting uses a separate Bearer token for authentication
- For production, it is recommended to use an Nginx reverse proxy with HTTPS enabled

## Tech Stack

- **Backend**: Python 3 / Flask
- **Database**: SQLite
- **Frontend**: Vanilla HTML / CSS / JavaScript (no external framework dependencies)
- **Agent**: psutil + nvidia-smi

---

## 中文文档

### 简介

轻量级服务器监控系统，专为多 GPU 服务器集群设计。基于 Python + Flask + SQLite 实现，开箱即用，无需复杂安装。

### 功能特性

- **GPU 深度监控** — 实时显示每块 GPU 的利用率、显存、温度、功耗，以及 GPU 上运行的进程（PID、进程名、显存占用）
- **系统资源监控** — CPU、内存、磁盘使用率，网络收发流量
- **密码保护** — 管理员密码仅从配置文件加载，Web 界面不暴露任何密码信息
- **登录速率限制** — 5 分钟内最多 5 次尝试，防止暴力破解
- **SQLite 存储** — 零配置数据库，数据存储在单个 `monitor.db` 文件中
- **Agent Token 认证** — Agent 上报数据需携带 Bearer token，防止未授权写入
- **自动刷新** — Dashboard 每 30 秒自动拉取最新数据，无需手动刷新
- **数据自动清理** — 超过保留天数的历史指标自动删除
- **明暗主题切换** — 支持深色 / 浅色主题，偏好保存在浏览器
- **服务器总览面板** — 一目了然显示每台服务器的 GPU 型号、数量和活跃状态
- **用户级 GPU 占用** — 显示每个 GPU 进程的用户名和 LXC/Incus 容器归属

### 一键部署

**方案 A：Shell 脚本（推荐用于 GPU 服务器）**

部署主服务端（在监控主机上执行）：

```bash
# 推荐：先保存再运行（可交互设置管理员账号和密码）
curl -sSL https://raw.githubusercontent.com/tangshunpu/Server-Monitor/main/scripts/install_server.sh -o install.sh && sudo bash install.sh

# 或管道方式（使用默认值：admin/admin123，端口 5100）
curl -sSL https://raw.githubusercontent.com/tangshunpu/Server-Monitor/main/scripts/install_server.sh | sudo bash
```

部署 Agent（在每台被监控服务器上执行）：

```bash
curl -sSL https://raw.githubusercontent.com/tangshunpu/Server-Monitor/main/scripts/install_agent.sh | sudo bash -s -- \
  --url http://监控主服务器IP:5100 \
  --token 你的Agent令牌
```

脚本会自动安装依赖、生成配置、创建 systemd 服务。

**方案 B：Docker Compose（仅主服务端）**

```bash
git clone https://github.com/tangshunpu/Server-Monitor.git
cd Server-Monitor
# 先编辑 config.yaml！
docker-compose up -d
```

> **注意**：Docker 仅推荐用于主服务端。Agent 应直接在宿主机运行以访问 `nvidia-smi` 和系统指标。

**一键升级**

```bash
# 自动检测并升级所有已安装组件（配置文件不会被修改）
curl -sSL https://raw.githubusercontent.com/tangshunpu/Server-Monitor/main/scripts/upgrade.sh | sudo bash

# 或指定升级: server | agent | all
curl -sSL https://raw.githubusercontent.com/tangshunpu/Server-Monitor/main/scripts/upgrade.sh | sudo bash -s -- agent
```

**卸载**

```bash
curl -sSL https://raw.githubusercontent.com/tangshunpu/Server-Monitor/main/scripts/uninstall.sh | sudo bash -s -- all
```

---

### 手动部署

#### 1. 安装依赖

```bash
pip install -r requirements.txt
```

#### 2. 配置主服务器

编辑 `config.yaml`，修改以下关键项：

```yaml
server:
  port: 5100                                    # Web 服务端口
  secret_key: "替换为一段随机字符串"               # Flask session 密钥

auth:
  password: "替换为你的管理员密码"                  # 登录密码

agent:
  token: "替换为一段安全令牌"                      # Agent 认证 token
```

> **安全提示**：`config.yaml` 包含敏感信息，请设置文件权限 `chmod 600 config.yaml`。

#### 3. 启动主服务器

```bash
python app.py
```

服务启动后，浏览器访问 `http://YOUR_IP:5100`，输入管理员密码即可进入监控面板。

#### 4. 部署 Agent 到被监控服务器

将 `agent.py` 和 `agent_config.yaml` 复制到每台需要监控的服务器上。

编辑 `agent_config.yaml`：

```yaml
server_url: "http://主服务器IP:5100"     # 监控主服务器地址
token: "与主服务器config.yaml中的agent.token一致"
interval: 30                             # 上报间隔（秒）
```

安装 Agent 依赖并启动：

```bash
pip install psutil requests pyyaml
python agent.py -c agent_config.yaml
```

#### 后台运行 Agent

推荐使用 `systemd` 管理 Agent 进程，实现开机自启和崩溃重启。详见上方英文部分的 systemd 配置示例。

### GPU 监控说明

Agent 通过调用 `nvidia-smi` 命令采集 GPU 信息，无需额外安装 Python GPU 库。要求被监控服务器已安装 NVIDIA 驱动。如果服务器没有 NVIDIA GPU，Agent 会自动跳过 GPU 采集，其他指标正常上报。

### 安全说明
- 登录使用 `hmac.compare_digest` 进行时间安全比较，防止计时攻击
- 登录失败有速率限制，防止暴力破解
- Agent 上报使用独立的 Bearer token 认证
- 建议在生产环境中使用 Nginx 反向代理并启用 HTTPS

## License

MIT

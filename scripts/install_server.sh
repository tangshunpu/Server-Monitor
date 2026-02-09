#!/usr/bin/env bash
# ============================================================
# Server Monitor — One-click server deployment script
# 服务器监控 — 主服务端一键部署脚本
# ============================================================
# Usage / 用法:
#   curl -sSL https://raw.githubusercontent.com/tangshunpu/Server-Monitor/main/scripts/install_server.sh -o install.sh && sudo bash install.sh
#   (Recommended: save first, then run - so prompts work correctly)
#   OR / 或者: curl -sSL ... | sudo bash  (uses defaults, no prompts)
# ============================================================

set -e

INSTALL_DIR="/opt/server-monitor"
SERVICE_NAME="server-monitor"
REPO_URL="https://raw.githubusercontent.com/tangshunpu/Server-Monitor/main"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

find_preferred_conda_base_python() {
    local conda_bin=""
    local conda_base=""
    if command -v conda &>/dev/null; then
        conda_bin="$(command -v conda)"
        conda_base="$("$conda_bin" info --base 2>/dev/null || true)"
        if [ -n "$conda_base" ] && [ -x "$conda_base/bin/python" ]; then
            echo "$conda_base/bin/python|conda"
            return 0
        fi
    fi

    local candidates=(
        "/opt/conda/bin/python|conda"
        "/root/miniconda3/bin/python|miniconda"
        "/root/anaconda3/bin/python|anaconda"
        "/usr/local/miniconda3/bin/python|miniconda"
        "/usr/local/anaconda3/bin/python|anaconda"
    )
    local item path dist
    for item in "${candidates[@]}"; do
        path="${item%%|*}"
        dist="${item##*|}"
        if [ -x "$path" ]; then
            echo "$path|$dist"
            return 0
        fi
    done
    return 1
}

detect_python_runtime() {
    local conda_meta
    conda_meta="$(find_preferred_conda_base_python || true)"
    if [ -n "$conda_meta" ]; then
        PYTHON_BIN="${conda_meta%%|*}"
        CONDA_DIST="${conda_meta##*|}"
        PY_RUNTIME="conda"
        CONDA_ENV_NAME="base"
    elif command -v python3 &>/dev/null; then
        PYTHON_BIN="$(command -v python3)"
        PY_RUNTIME="system"
    else
        error "Python3/Conda not found. Please install Python 3.8+ or Conda first.\n未找到 Python3/Conda，请先安装 Python 3.8+ 或 Conda。"
    fi

    PYTHON_VERSION="$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    PYTHON_PREFIX="$("$PYTHON_BIN" -c 'import sys; print(sys.prefix)')"

    if [ "$PY_RUNTIME" = "conda" ]; then
        info "Using Conda base Python $PYTHON_VERSION (${CONDA_DIST}, ${PYTHON_BIN}) / 使用 Conda base Python $PYTHON_VERSION (${CONDA_DIST})"
    else
        info "Detected system Python $PYTHON_VERSION (${PYTHON_BIN}) / 检测到系统 Python $PYTHON_VERSION"
    fi

    if ! "$PYTHON_BIN" -m pip --version &>/dev/null; then
        error "pip is not available for ${PYTHON_BIN}. Please install pip first.\n${PYTHON_BIN} 缺少 pip，请先安装。"
    fi
}

# --- Check root / 检查 root 权限 ---
if [ "$EUID" -ne 0 ]; then
    error "Please run as root (sudo) / 请使用 root 权限运行 (sudo)"
fi

# --- Check Python runtime / 检查 Python 运行时 ---
detect_python_runtime

# --- Create install directory / 创建安装目录 ---
info "Installing to $INSTALL_DIR / 安装到 $INSTALL_DIR"
mkdir -p "$INSTALL_DIR/templates"

# --- Download files / 下载文件 ---
info "Downloading files / 正在下载文件..."

download_file() {
    local url="$1"
    local dest="$2"
    if command -v curl &>/dev/null; then
        curl -sSL "$url" -o "$dest"
    elif command -v wget &>/dev/null; then
        wget -q "$url" -O "$dest"
    else
        error "Neither curl nor wget found / 未找到 curl 或 wget"
    fi
}

download_file "$REPO_URL/app.py"                   "$INSTALL_DIR/app.py"
download_file "$REPO_URL/requirements.txt"         "$INSTALL_DIR/requirements.txt"
download_file "$REPO_URL/templates/login.html"     "$INSTALL_DIR/templates/login.html"
download_file "$REPO_URL/templates/dashboard.html" "$INSTALL_DIR/templates/dashboard.html"
download_file "$REPO_URL/templates/admin.html"     "$INSTALL_DIR/templates/admin.html"
download_file "$REPO_URL/templates/register.html"  "$INSTALL_DIR/templates/register.html"
download_file "$REPO_URL/templates/user.html"      "$INSTALL_DIR/templates/user.html"

# --- Generate config if not exists / 如果配置不存在则生成 ---
if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
    info "Generating config.yaml / 正在生成 config.yaml..."

    # Generate random secret key and token
    # 生成随机密钥和令牌
    SECRET_KEY=$("$PYTHON_BIN" -c "import secrets; print(secrets.token_hex(32))")
    AGENT_TOKEN=$("$PYTHON_BIN" -c "import secrets; print(secrets.token_hex(24))")

    # Prompt for admin credentials / 提示输入管理员凭据
    # Use /dev/tty when piped (curl | bash) so read doesn't consume the script from stdin
    echo ""
    if [ -t 0 ]; then
        read -p "Admin username (default: admin) / 管理员用户名 (默认: admin): " ADMIN_USER
        read -sp "Admin password / 管理员密码: " ADMIN_PASS
        echo ""
        read -p "Web port (default 5100) / Web 端口 (默认 5100): " WEB_PORT
    else
        warn "Running non-interactively (e.g. piped), using defaults. Use: curl -o install.sh && bash install.sh for prompts."
        ADMIN_USER="admin"
        ADMIN_PASS="admin123"
        WEB_PORT="5100"
    fi
    ADMIN_USER=${ADMIN_USER:-admin}
    if [ -z "$ADMIN_PASS" ]; then
        ADMIN_PASS="admin123"
        warn "Empty password, using default: admin123 / 密码为空，使用默认: admin123"
    fi
    WEB_PORT=${WEB_PORT:-5100}

    cat > "$INSTALL_DIR/config.yaml" <<YAML
server:
  host: "0.0.0.0"
  port: ${WEB_PORT}
  secret_key: "${SECRET_KEY}"
  debug: false

auth:
  username: "${ADMIN_USER}"
  password: "${ADMIN_PASS}"

agent:
  token: "${AGENT_TOKEN}"

data:
  retention_days: 30
YAML

    chmod 600 "$INSTALL_DIR/config.yaml"
    info "config.yaml created (permissions: 600) / config.yaml 已创建（权限: 600）"
    echo ""
    echo -e "${GREEN}====================================${NC}"
    echo -e "  Agent Token: ${YELLOW}${AGENT_TOKEN}${NC}"
    echo -e "  Web Port:    ${YELLOW}${WEB_PORT}${NC}"
    echo -e "${GREEN}====================================${NC}"
    echo -e "  Save the Agent Token above! You will need it when deploying agents."
    echo -e "  请保存上面的 Agent Token！部署 Agent 时需要使用。"
    echo -e "${GREEN}====================================${NC}"
    echo ""
else
    info "config.yaml already exists, skipping / config.yaml 已存在，跳过"
fi

# --- Read actual port from config / 从配置文件读取实际端口 ---
ACTUAL_PORT=$(grep -E '^[[:space:]]*port:' "$INSTALL_DIR/config.yaml" 2>/dev/null | head -1 | sed 's/.*port:[[:space:]]*//' | tr -d ' "' || echo "5100")
ACTUAL_PORT=${ACTUAL_PORT:-5100}

# --- Install Python dependencies / 安装 Python 依赖 ---
info "Installing Python dependencies with ${PYTHON_BIN} / 使用 ${PYTHON_BIN} 安装 Python 依赖..."
"$PYTHON_BIN" -m pip install -q flask pyyaml

# --- Create systemd service / 创建 systemd 服务 ---
info "Creating systemd service / 正在创建 systemd 服务..."

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<SERVICE
[Unit]
Description=Server Monitor Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${PYTHON_BIN} ${INSTALL_DIR}/app.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
Environment=PYTHON_RUNTIME=${PY_RUNTIME}

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

# --- Done / 完成 ---
echo ""
info "============================================"
info "  Server Monitor installed successfully!"
info "  服务器监控安装完成！"
info "============================================"
info "  Dashboard: http://$(hostname -I | awk '{print $1}'):${ACTUAL_PORT}"
info "  Service:   systemctl status $SERVICE_NAME"
info "  Logs:      journalctl -u $SERVICE_NAME -f"
info "============================================"

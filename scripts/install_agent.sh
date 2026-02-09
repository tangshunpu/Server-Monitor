#!/usr/bin/env bash
# ============================================================
# Server Monitor — One-click agent deployment script
# 服务器监控 — Agent 一键部署脚本
# ============================================================
# Usage / 用法:
#   curl -sSL https://raw.githubusercontent.com/tangshunpu/Server-Monitor/main/scripts/install_agent.sh | bash
#   OR with arguments / 或者带参数:
#   bash scripts/install_agent.sh --url http://SERVER_IP:5100 --token YOUR_TOKEN
# ============================================================

set -e

INSTALL_DIR="/opt/server-monitor"
SERVICE_NAME="server-monitor-agent"
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

    # Try common per-user conda locations when running via sudo.
    # 在 sudo 场景下尝试调用发起用户 home 下的 conda。
    local sudo_home=""
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        sudo_home="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)"
        [ -z "$sudo_home" ] && sudo_home="/home/$SUDO_USER"
        local conda_bins=(
            "$sudo_home/miniconda3/bin/conda"
            "$sudo_home/anaconda3/bin/conda"
            "$sudo_home/conda/bin/conda"
        )
        local cb
        for cb in "${conda_bins[@]}"; do
            if [ -x "$cb" ]; then
                conda_base="$("$cb" info --base 2>/dev/null || true)"
                if [ -n "$conda_base" ] && [ -x "$conda_base/bin/python" ]; then
                    echo "$conda_base/bin/python|conda"
                    return 0
                fi
            fi
        done
    fi

    local candidates=(
        "/opt/conda/bin/python|conda"
        "/root/miniconda3/bin/python|miniconda"
        "/root/anaconda3/bin/python|anaconda"
        "/usr/local/miniconda3/bin/python|miniconda"
        "/usr/local/anaconda3/bin/python|anaconda"
    )
    if [ -n "$sudo_home" ]; then
        candidates+=(
            "$sudo_home/miniconda3/bin/python|miniconda"
            "$sudo_home/anaconda3/bin/python|anaconda"
            "$sudo_home/conda/bin/python|conda"
        )
    fi
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

# --- Parse arguments / 解析参数 ---
SERVER_URL=""
AGENT_TOKEN=""
INTERVAL=30

while [[ $# -gt 0 ]]; do
    case $1 in
        --url)      SERVER_URL="$2";   shift 2 ;;
        --token)    AGENT_TOKEN="$2";  shift 2 ;;
        --interval) INTERVAL="$2";     shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--url SERVER_URL] [--token AGENT_TOKEN] [--interval SECONDS]"
            echo "用法:  $0 [--url 服务器地址]   [--token Agent令牌]    [--interval 上报间隔秒数]"
            exit 0 ;;
        *) error "Unknown option: $1" ;;
    esac
done

# --- Check root / 检查 root 权限 ---
if [ "$EUID" -ne 0 ]; then
    error "Please run as root (sudo) / 请使用 root 权限运行 (sudo)"
fi

# --- Check Python runtime / 检查 Python 运行时 ---
detect_python_runtime

# --- Check nvidia-smi / 检查 nvidia-smi ---
if command -v nvidia-smi &>/dev/null; then
    GPU_COUNT=$(nvidia-smi --query-gpu=count --format=csv,noheader,nounits 2>/dev/null | head -1 || echo "0")
    info "Found nvidia-smi, $GPU_COUNT GPU(s) detected / 检测到 nvidia-smi, $GPU_COUNT 块 GPU"
else
    warn "nvidia-smi not found — GPU monitoring will be skipped / nvidia-smi 未找到 — 将跳过 GPU 监控"
fi

# --- Prompt for config if not provided / 未提供参数时交互式输入 ---
if [ -z "$SERVER_URL" ]; then
    echo ""
    read -p "Monitor server URL (e.g. http://192.168.1.100:5100) / 监控服务器地址: " SERVER_URL
    [ -z "$SERVER_URL" ] && error "Server URL is required / 服务器地址不能为空"
fi

if [ -z "$AGENT_TOKEN" ]; then
    read -p "Agent token (from server's config.yaml) / Agent 令牌: " AGENT_TOKEN
    [ -z "$AGENT_TOKEN" ] && error "Agent token is required / Agent 令牌不能为空"
fi

# --- Create install directory / 创建安装目录 ---
info "Installing to $INSTALL_DIR / 安装到 $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# --- Download agent.py / 下载 agent.py ---
info "Downloading agent.py / 正在下载 agent.py..."

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

download_file "$REPO_URL/agent.py" "$INSTALL_DIR/agent.py"

# --- Generate agent config / 生成 Agent 配置 ---
info "Generating agent_config.yaml / 正在生成 agent_config.yaml..."

cat > "$INSTALL_DIR/agent_config.yaml" <<YAML
# Auto-generated by install_agent.sh
# 由 install_agent.sh 自动生成

server_url: "${SERVER_URL}"
token: "${AGENT_TOKEN}"
interval: ${INTERVAL}
YAML

chmod 600 "$INSTALL_DIR/agent_config.yaml"

# --- Install Python dependencies / 安装 Python 依赖 ---
info "Installing Python dependencies with ${PYTHON_BIN} / 使用 ${PYTHON_BIN} 安装 Python 依赖..."
"$PYTHON_BIN" -m pip install -q psutil requests pyyaml

# --- Create systemd service / 创建 systemd 服务 ---
info "Creating systemd service / 正在创建 systemd 服务..."

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<SERVICE
[Unit]
Description=Server Monitor Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${PYTHON_BIN} ${INSTALL_DIR}/agent.py -c ${INSTALL_DIR}/agent_config.yaml
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1
Environment=PYTHON_RUNTIME=${PY_RUNTIME}

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

# --- Verify connection / 验证连接 ---
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    STATUS="${GREEN}running${NC}"
else
    STATUS="${RED}failed${NC}"
fi

# --- Done / 完成 ---
echo ""
info "============================================"
info "  Agent installed successfully!"
info "  Agent 安装完成！"
info "============================================"
info "  Server:   $SERVER_URL"
info "  Hostname: $(hostname)"
info "  Status:   $STATUS"
info "  Service:  systemctl status $SERVICE_NAME"
info "  Logs:     journalctl -u $SERVICE_NAME -f"
info "============================================"

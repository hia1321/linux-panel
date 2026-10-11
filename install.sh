#!/usr/bin/env bash
# =============================================================================
#  Linux-Panel 一键安装脚本
#  适用于 Debian/Ubuntu 系裸机环境
# =============================================================================
set -euo pipefail

# ----------------------------- 基本配置 -------------------------------------
REPO_URL="https://github.com/hia1321/linux-panel.git"
INSTALL_DIR="/opt/linux-panel"
SERVICE_NAME="linux-panel"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PYTHON_BIN="/usr/bin/python3"
VENV_DIR="${INSTALL_DIR}/venv"
PANEL_PORT="${PANEL_PORT:-8888}"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

# ----------------------------- 权限检查 -------------------------------------
if [[ $EUID -ne 0 ]]; then
    err "请使用 root 权限运行：sudo bash $0"
    exit 1
fi

# ----------------------------- 系统检测 -------------------------------------
if ! command -v apt-get >/dev/null 2>&1; then
    err "本脚本目前仅支持 Debian/Ubuntu 系系统。"
    exit 1
fi

# ----------------------------- 交互式安装依赖 --------------------------------
install_pkg_if_missing() {
    local cmd="$1"
    local pkg="${2:-$1}"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        warn "未检测到 ${cmd}。"
        read -rp "是否安装 ${pkg}？[Y/n] " ans
        if [[ ! "$ans" =~ ^[Nn]$ ]]; then
            apt-get update -qq
            apt-get install -y "$pkg"
            log "已安装 ${pkg}"
        else
            err "缺少 ${cmd}，无法继续。"
            exit 1
        fi
    else
        log "已存在 ${cmd}"
    fi
}

log "检查系统依赖..."
install_pkg_if_missing git git
install_pkg_if_missing python3 python3
install_pkg_if_missing pip3 python3-pip

# 确保 venv 模块可用（Ubuntu 通常需要单独装 python3-venv）
if ! "$PYTHON_BIN" -c "import venv" >/dev/null 2>&1; then
    warn "python3-venv 模块不可用。"
    read -rp "是否安装 python3-venv？[Y/n] " ans
    if [[ ! "$ans" =~ ^[Nn]$ ]]; then
        apt-get update -qq
        apt-get install -y python3-venv
        log "已安装 python3-venv"
    else
        err "缺少 python3-venv，无法创建虚拟环境。"
        exit 1
    fi
fi

# ----------------------------- 克隆仓库 -------------------------------------
if [[ -d "$INSTALL_DIR" ]]; then
    warn "目录 ${INSTALL_DIR} 已存在，尝试更新..."
    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        git -C "$INSTALL_DIR" pull --ff-only || {
            err "git pull 失败，请检查网络或手动处理冲突。"
            exit 1
        }
    else
        err "${INSTALL_DIR} 存在但不是 git 仓库，请手动处理。"
        exit 1
    fi
else
    log "克隆仓库到 ${INSTALL_DIR} ..."
    git clone "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# ----------------------------- 创建虚拟环境 ----------------------------------
if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    log "创建 Python 虚拟环境..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
else
    log "虚拟环境已存在，跳过创建。"
fi

VENV_PY="${VENV_DIR}/bin/python"
VENV_PIP="${VENV_DIR}/bin/pip"

# ----------------------------- 安装依赖 -------------------------------------
if [[ -f requirements.txt ]]; then
    read -rp "是否安装/更新 requirements.txt 中的 Python 依赖？[Y/n] " ans
    if [[ ! "$ans" =~ ^[Nn]$ ]]; then
        log "安装 Python 依赖..."
        "$VENV_PIP" install --upgrade pip
        "$VENV_PIP" install -r requirements.txt
        log "Python 依赖安装完成。"
    fi
else
    warn "未找到 requirements.txt，跳过依赖安装。"
fi

# ----------------------------- 创建 systemd 服务 -----------------------------
log "创建 systemd 服务文件..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Linux Web Panel
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
Environment=PANEL_HOST=0.0.0.0
Environment=PANEL_PORT=${PANEL_PORT}
Environment=PANEL_FILE_ROOT=/
ExecStart=${VENV_PY} ${INSTALL_DIR}/app.py
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# ----------------------------- 创建快捷管理命令 -------------------------------
log "创建快捷管理命令 linux-panel ..."
cat > /usr/local/bin/linux-panel <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
SERVICE="linux-panel"

if [[ $EUID -ne 0 ]]; then
    echo "请用 sudo：sudo linux-panel $*" >&2
    exit 1
fi

case "${1:-}" in
    start)
        systemctl start "$SERVICE"
        systemctl status "$SERVICE" --no-pager -l
        ;;
    stop)
        systemctl stop "$SERVICE"
        echo "已停止"
        ;;
    restart)
        systemctl restart "$SERVICE"
        systemctl status "$SERVICE" --no-pager -l
        ;;
    status)
        systemctl status "$SERVICE" --no-pager -l
        ;;
    logs)
        journalctl -u "$SERVICE" -f -n 100
        ;;
    enable)
        systemctl enable --now "$SERVICE"
        ;;
    disable)
        systemctl disable --now "$SERVICE"
        ;;
    *)
        echo "用法: sudo linux-panel {start|stop|restart|status|logs|enable|disable}"
        ;;
esac
EOF
chmod +x /usr/local/bin/linux-panel

# ----------------------------- 启动服务 -------------------------------------
systemctl daemon-reload
systemctl enable --now "$SERVICE"

# ----------------------------- 完成提示 -------------------------------------
echo
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Linux-Panel 安装完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "  访问地址 : ${GREEN}http://<服务器IP>:${PANEL_PORT}${NC}"
echo -e "  安装目录 : ${INSTALL_DIR}"
echo -e "  管理命令 : ${YELLOW}sudo linux-panel start|stop|restart|status|logs${NC}"
echo
echo -e "  首次登录密码请查看日志："
echo -e "  ${YELLOW}sudo journalctl -u linux-panel -n 100 --no-pager${NC}"
echo -e "${GREEN}========================================${NC}"

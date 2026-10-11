#!/usr/bin/env bash
# =============================================================================
#  Linux-Panel 一键安装脚本
#  强制以 root 身份安装和运行
#  默认端口：33972
#  适用系统：Debian / Ubuntu 系
#  仓库地址：https://github.com/hia1321/linux-panel
# =============================================================================

# ----------------------------- 基本配置 -------------------------------------
REPO_URL="https://github.com/hia1321/linux-panel.git"
REPO_PATH="hia1321/linux-panel"          # 供 CDN 镜像使用
REPO_BRANCH="main"
INSTALL_DIR="/opt/linux-panel"
SERVICE_NAME="linux-panel"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PYTHON_BIN="/usr/bin/python3"
VENV_DIR="${INSTALL_DIR}/venv"
PANEL_PORT="${PANEL_PORT:-33972}"

# ----------------------------- 颜色输出 -------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $*"; }
info() { echo -e "${BLUE}[i]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

# =============================================================================
#  0. GitHub 镜像回退克隆（国内服务器必备）
# =============================================================================
clone_repo() {
    local target="$1"
    local urls=(
        "https://github.com/${REPO_PATH}.git"
        "https://ghfast.top/https://github.com/${REPO_PATH}.git"
        "https://ghproxy.net/https://github.com/${REPO_PATH}.git"
        "https://hub.gitmirror.com/https://github.com/${REPO_PATH}.git"
        "https://gitclone.com/github.com/${REPO_PATH}.git"
    )
    for url in "${urls[@]}"; do
        info "尝试克隆：$url"
        if timeout 180 git clone --depth 1 -b "$REPO_BRANCH" "$url" "$target" 2>/dev/null; then
            log "克隆成功：$url"
            return 0
        fi
        warn "失败：$url"
        rm -rf "$target"
    done
    return 1
}

# =============================================================================
#  1. 权限检查：必须以 root 身份运行
# =============================================================================
if [[ $EUID -ne 0 ]]; then
    err "本安装脚本必须以 root 身份运行。"
    err "推荐流程（避开终端 /dev/fd 兼容问题和 GitHub 直连问题）："
    err "  curl -fsSL https://cdn.jsdelivr.net/gh/${REPO_PATH}@${REPO_BRANCH}/install.sh -o /tmp/install.sh"
    err "  sudo bash /tmp/install.sh"
    exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
    err "检测到当前有效用户不是 root，拒绝继续。"
    exit 1
fi

log "已确认以 root 身份运行，继续安装..."

# =============================================================================
#  2. 系统检测
# =============================================================================
if ! command -v apt-get >/dev/null 2>&1; then
    err "本脚本目前仅支持 Debian / Ubuntu 系系统。"
    exit 1
fi

if [[ ! -d /run/systemd/system ]]; then
    err "未检测到 systemd，本脚本依赖 systemd 管理服务。"
    exit 1
fi

# =============================================================================
#  3. 交互式安装系统依赖
# =============================================================================
install_pkg_if_missing() {
    local cmd="$1"
    local pkg="${2:-$1}"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        warn "未检测到 ${cmd}。"
        read -rp "是否安装 ${pkg}？[Y/n] " ans
        if [[ ! "${ans:-Y}" =~ ^[Nn]$ ]]; then
            apt-get update -qq
            apt-get install -y "$pkg" || true
            log "已尝试安装 ${pkg}"
        else
            err "缺少 ${cmd}，无法继续。"
            exit 1
        fi
    else
        log "已存在 ${cmd}"
    fi
}

info "检查系统依赖..."
install_pkg_if_missing git git
install_pkg_if_missing python3 python3
install_pkg_if_missing pip3 python3-pip

# =============================================================================
#  3.1 确保 python3-venv 可用（精简安装，不装 python3-full）
# =============================================================================
if ! "$PYTHON_BIN" -m venv --help >/dev/null 2>&1 || ! "$PYTHON_BIN" -m ensurepip --version >/dev/null 2>&1; then
    warn "检测到 python3-venv 或 ensurepip 缺失（Ubuntu/Debian 常见问题）。"
    read -rp "是否自动安装 python3-venv？[Y/n] " ans
    if [[ ! "${ans:-Y}" =~ ^[Nn]$ ]]; then
        apt-get update -qq
        PY_VER=$("$PYTHON_BIN" -c 'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")')
        apt-get install -y "${PY_VER}-venv" || apt-get install -y python3-venv || true
        log "已尝试安装 python3-venv 相关包。"
    else
        err "缺少 python3-venv，无法创建虚拟环境。"
        exit 1
    fi
fi

# 二次确认 venv 是否真正可用
if ! "$PYTHON_BIN" -m venv --help >/dev/null 2>&1; then
    err "python3-venv 仍不可用，请手动执行：sudo apt install python3-venv"
    exit 1
fi

# 检测可选命令（不阻塞安装）
for opt in ssh-keygen ufw sshd; do
    if ! command -v "$opt" >/dev/null 2>&1; then
        warn "未检测到 ${opt}，面板对应功能可能不可用。"
    fi
done

# =============================================================================
#  4. 克隆 / 更新仓库到 /opt/linux-panel
# =============================================================================
if [[ -d "$INSTALL_DIR" ]]; then
    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        info "目录 ${INSTALL_DIR} 已存在，执行 git pull 更新..."
        git -C "$INSTALL_DIR" pull --ff-only || warn "git pull 失败，跳过更新，继续安装。"
    else
        err "${INSTALL_DIR} 已存在，但不是 git 仓库。"
        err "请手动删除后再运行本脚本：sudo rm -rf ${INSTALL_DIR}"
        exit 1
    fi
else
    info "克隆仓库到 ${INSTALL_DIR} ..."
    if ! clone_repo "$INSTALL_DIR"; then
        err "所有 GitHub 官方源与镜像源均克隆失败，请检查网络。"
        exit 1
    fi
    log "仓库克隆完成。"
fi

cd "$INSTALL_DIR" || exit 1

# =============================================================================
#  5. 创建虚拟环境
# =============================================================================
if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    info "创建 Python 虚拟环境 ${VENV_DIR} ..."
    rm -rf "$VENV_DIR"
    if ! "$PYTHON_BIN" -m venv "$VENV_DIR"; then
        err "创建虚拟环境失败，请检查 python3-venv 是否安装正确。"
        exit 1
    fi
    log "虚拟环境创建完成。"
else
    log "虚拟环境已存在，跳过创建。"
fi

VENV_PY="${VENV_DIR}/bin/python"
VENV_PIP="${VENV_DIR}/bin/pip"

# =============================================================================
#  6. 安装 Python 依赖
# =============================================================================
if [[ -f requirements.txt ]]; then
    read -rp "是否安装/更新 requirements.txt 中的 Python 依赖？[Y/n] " ans
    if [[ ! "${ans:-Y}" =~ ^[Nn]$ ]]; then
        info "安装 Python 依赖..."
        "$VENV_PIP" install --upgrade pip || warn "pip 升级失败，使用现有版本。"
        "$VENV_PIP" install -r requirements.txt || warn "部分依赖安装失败，服务可能无法启动。"
        log "Python 依赖处理完成。"
    else
        warn "已跳过依赖安装。"
    fi
else
    warn "未找到 requirements.txt，跳过依赖安装。"
fi

# =============================================================================
#  7. 目录权限收紧
# =============================================================================
info "设置安装目录权限为 root:root 700 ..."
chown -R root:root "$INSTALL_DIR" || true
chmod 700 "$INSTALL_DIR" || true
if [[ -d "${INSTALL_DIR}/data" ]]; then
    chmod 700 "${INSTALL_DIR}/data" || true
fi
if [[ -f "${INSTALL_DIR}/data/secret.key" ]]; then
    chmod 600 "${INSTALL_DIR}/data/secret.key" || true
fi
if [[ -f "${INSTALL_DIR}/data/panel.db" ]]; then
    chmod 600 "${INSTALL_DIR}/data/panel.db" || true
fi
log "目录权限已收紧。"

# =============================================================================
#  8. 写入 systemd 服务
# =============================================================================
info "创建 systemd 服务：${SERVICE_FILE}"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Linux Web Panel (root-only)
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
Environment="PANEL_HOST=0.0.0.0"
Environment="PANEL_PORT=${PANEL_PORT}"
Environment="PANEL_FILE_ROOT=/"
ExecStart=${VENV_PY} ${INSTALL_DIR}/app.py
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
log "systemd 服务文件已创建。"

# =============================================================================
#  9. 写入快捷管理命令 linux-panel
# =============================================================================
info "创建快捷管理命令：/usr/local/bin/linux-panel"
cat > /usr/local/bin/linux-panel <<'EOF'
#!/usr/bin/env bash
SERVICE="linux-panel"

if [[ $EUID -ne 0 ]]; then
    echo "错误：linux-panel 必须以 root 身份运行。" >&2
    echo "请使用：sudo linux-panel $*" >&2
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
        mkdir -p /etc/systemd/system/multi-user.target.wants
        ln -sf /etc/systemd/system/${SERVICE}.service /etc/systemd/system/multi-user.target.wants/${SERVICE}.service
        echo "已设置开机自启"
        ;;
    disable)
        rm -f /etc/systemd/system/multi-user.target.wants/${SERVICE}.service
        echo "已取消开机自启"
        ;;
    uninstall)
        read -rp "确定要卸载 linux-panel 吗？[y/N] " ans
        if [[ ! "$ans" =~ ^[Yy]$ ]]; then
            echo "已取消"
            exit 0
        fi
        systemctl stop "$SERVICE" 2>/dev/null || true
        rm -f /etc/systemd/system/multi-user.target.wants/${SERVICE}.service
        rm -f /etc/systemd/system/${SERVICE}.service
        systemctl daemon-reload
        rm -f /usr/local/bin/linux-panel
        echo "服务已卸载。"
        echo "安装目录 /opt/linux-panel 未删除，如需删除请手动执行："
        echo "  sudo rm -rf /opt/linux-panel"
        ;;
    *)
        echo "用法: sudo linux-panel {start|stop|restart|status|logs|enable|disable|uninstall}"
        ;;
esac
EOF
chmod 755 /usr/local/bin/linux-panel
log "快捷管理命令已创建。"

# =============================================================================
#  10. 设置开机自启 + 启动服务（用软链接避开 systemd 老版本报错）
# =============================================================================
info "重新加载 systemd 并启动服务..."
systemctl daemon-reload || true

# 手动创建开机自启软链接（兼容性比 systemctl enable 更好）
mkdir -p /etc/systemd/system/multi-user.target.wants
ln -sf "$SERVICE_FILE" "/etc/systemd/system/multi-user.target.wants/${SERVICE_NAME}.service"
log "已设置开机自启。"

# 启动服务
systemctl start "$SERVICE" || warn "服务启动失败，请使用 'sudo linux-panel logs' 查看日志排查。"

# =============================================================================
#  11. 完成提示（一定会输出）
# =============================================================================
echo
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Linux-Panel 安装完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "  运行身份 : ${YELLOW}root${NC}（强制）"
echo -e "  安装目录 : ${INSTALL_DIR}"
echo -e "  访问地址 : ${GREEN}http://<服务器IP>:${PANEL_PORT}${NC}"
echo -e "  管理命令 : ${YELLOW}sudo linux-panel {start|stop|restart|status|logs|uninstall}${NC}"
echo
echo -e "  首次登录密码请查看日志："
echo -e "  ${YELLOW}sudo journalctl -u linux-panel -n 50 --no-pager${NC}"
echo
echo -e "  如果启用了 UFW，请放行面板端口："
echo -e "  ${YELLOW}sudo ufw allow ${PANEL_PORT}/tcp${NC}"
echo -e "${GREEN}========================================${NC}"

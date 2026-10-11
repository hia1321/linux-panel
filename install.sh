#!/usr/bin/env bash
# =============================================================================
#  Linux-Panel 一键安装脚本
#  强制以 root 身份安装和运行
#  默认端口：33972
#  适用系统：Debian / Ubuntu 系
# =============================================================================

REPO_PATH="hia1321/linux-panel"
REPO_BRANCH="main"
INSTALL_DIR="/opt/linux-panel"
SERVICE_NAME="linux-panel"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PYTHON_BIN="/usr/bin/python3"
VENV_DIR="${INSTALL_DIR}/venv"
PANEL_PORT="${PANEL_PORT:-33972}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
info() { echo -e "${BLUE}[i]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

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
            log "克隆成功：$url"; return 0
        fi
        warn "失败：$url"; rm -rf "$target"
    done
    return 1
}

# ---------- 权限 ----------
if [[ $EUID -ne 0 ]]; then
    err "必须以 root 身份运行。推荐流程："
    err "  curl -fsSL \"https://cdn.jsdelivr.net/gh/${REPO_PATH}@${REPO_BRANCH}/install.sh?t=\$(date +%s)\" -o /tmp/install.sh"
    err "  sudo bash /tmp/install.sh"
    exit 1
fi
log "已确认以 root 身份运行，继续安装..."

# ---------- 系统检测 ----------
command -v apt-get >/dev/null 2>&1 || { err "仅支持 Debian / Ubuntu 系"; exit 1; }
[[ -d /run/systemd/system ]] || { err "未检测到 systemd"; exit 1; }

# ---------- 系统依赖 ----------
install_pkg_if_missing() {
    local cmd="$1" pkg="${2:-$1}"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        warn "未检测到 ${cmd}。"; read -rp "是否安装 ${pkg}？[Y/n] " ans
        if [[ ! "${ans:-Y}" =~ ^[Nn]$ ]]; then
            apt-get update -qq; apt-get install -y "$pkg" || true; log "已尝试安装 ${pkg}"
        else err "缺少 ${cmd}"; exit 1; fi
    else log "已存在 ${cmd}"; fi
}
info "检查系统依赖..."
install_pkg_if_missing git git
install_pkg_if_missing python3 python3
install_pkg_if_missing pip3 python3-pip

# ---------- python3-venv ----------
if ! "$PYTHON_BIN" -m venv --help >/dev/null 2>&1 || ! "$PYTHON_BIN" -m ensurepip --version >/dev/null 2>&1; then
    warn "python3-venv / ensurepip 缺失。"
    read -rp "是否自动安装 python3-venv？[Y/n] " ans
    if [[ ! "${ans:-Y}" =~ ^[Nn]$ ]]; then
        apt-get update -qq
        PY_VER=$("$PYTHON_BIN" -c 'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")')
        apt-get install -y "${PY_VER}-venv" || apt-get install -y python3-venv || true
    else err "缺少 python3-venv"; exit 1; fi
fi

# ---------- 克隆 ----------
if [[ -d "$INSTALL_DIR" ]]; then
    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        info "目录已存在，git pull 更新..."
        git -C "$INSTALL_DIR" pull --ff-only || warn "更新失败，继续使用现有代码"
    else
        err "${INSTALL_DIR} 存在但不是 git 仓库，请先 sudo rm -rf ${INSTALL_DIR}"; exit 1
    fi
else
    info "克隆仓库到 ${INSTALL_DIR} ..."
    clone_repo "$INSTALL_DIR" || { err "克隆失败"; exit 1; }
    log "仓库克隆完成。"
fi

cd "$INSTALL_DIR" || exit 1

# ---------- venv ----------
if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    info "创建虚拟环境 ..."
    rm -rf "$VENV_DIR"
    "$PYTHON_BIN" -m venv "$VENV_DIR" || { err "创建 venv 失败"; exit 1; }
    log "虚拟环境创建完成。"
else
    log "虚拟环境已存在。"
fi
VENV_PY="${VENV_DIR}/bin/python"
VENV_PIP="${VENV_DIR}/bin/pip"

# ---------- 依赖 ----------
if [[ -f requirements.txt ]]; then
    read -rp "是否安装/更新 Python 依赖？[Y/n] " ans
    if [[ ! "${ans:-Y}" =~ ^[Nn]$ ]]; then
        info "安装依赖..."
        "$VENV_PIP" install --upgrade pip || warn "pip 升级失败"
        "$VENV_PIP" install -r requirements.txt || warn "部分依赖失败"
        log "依赖处理完成。"
    fi
fi

# ---------- 权限 ----------
chown -R root:root "$INSTALL_DIR" || true
chmod 700 "$INSTALL_DIR" || true
[[ -d "${INSTALL_DIR}/data" ]] && chmod 700 "${INSTALL_DIR}/data" || true
[[ -f "${INSTALL_DIR}/data/secret.key" ]] && chmod 600 "${INSTALL_DIR}/data/secret.key" || true
[[ -f "${INSTALL_DIR}/data/panel.db" ]] && chmod 600 "${INSTALL_DIR}/data/panel.db" || true

# ---------- .env（关键！）----------
info "写入环境变量文件：${INSTALL_DIR}/.env"
cat > "${INSTALL_DIR}/.env" <<EOF
PANEL_HOST=0.0.0.0
PANEL_PORT=${PANEL_PORT}
PANEL_FILE_ROOT=/
EOF
chmod 600 "${INSTALL_DIR}/.env"
log "环境变量文件已写入。"

# ---------- systemd 服务（关键！EnvironmentFile 写法）----------
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
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${VENV_PY} ${INSTALL_DIR}/app.py
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
log "systemd 服务文件已创建。"

# ---------- linux-panel 命令 ----------
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
    start)   systemctl start "$SERVICE"; systemctl status "$SERVICE" --no-pager -l ;;
    stop)    systemctl stop "$SERVICE"; echo "已停止" ;;
    restart) systemctl restart "$SERVICE"; systemctl status "$SERVICE" --no-pager -l ;;
    status)  systemctl status "$SERVICE" --no-pager -l ;;
    logs)    journalctl -u "$SERVICE" -f -n 100 ;;
    pass)    journalctl -u "$SERVICE" -n 300 --no-pager | grep -A 6 "面板已初始化" ;;
    enable)
        mkdir -p /etc/systemd/system/multi-user.target.wants
        ln -sf /etc/systemd/system/${SERVICE}.service /etc/systemd/system/multi-user.target.wants/${SERVICE}.service
        echo "已设置开机自启" ;;
    disable)
        rm -f /etc/systemd/system/multi-user.target.wants/${SERVICE}.service
        echo "已取消开机自启" ;;
    uninstall)
        read -rp "确定要卸载 linux-panel 吗？[y/N] " ans
        [[ ! "$ans" =~ ^[Yy]$ ]] && { echo "已取消"; exit 0; }
        systemctl stop "$SERVICE" 2>/dev/null || true
        rm -f /etc/systemd/system/multi-user.target.wants/${SERVICE}.service
        rm -f /etc/systemd/system/${SERVICE}.service
        systemctl daemon-reload
        rm -f /usr/local/bin/linux-panel
        echo "服务已卸载。安装目录未删除，如需删除请手动执行："
        echo "  sudo rm -rf /opt/linux-panel" ;;
    *) echo "用法: sudo linux-panel {start|stop|restart|status|logs|pass|enable|disable|uninstall}" ;;
esac
EOF
chmod 755 /usr/local/bin/linux-panel
log "快捷管理命令已创建。"

# ---------- 加载 + 开机自启 + 启动 ----------
info "重新加载 systemd ..."
systemctl daemon-reload || true
sleep 1

mkdir -p /etc/systemd/system/multi-user.target.wants
ln -sf "$SERVICE_FILE" "/etc/systemd/system/multi-user.target.wants/${SERVICE_NAME}.service"
log "已设置开机自启。"

START_TIME=$(date '+%Y-%m-%d %H:%M:%S')
STARTED=0
for i in 1 2 3; do
    info "启动服务（第 ${i} 次尝试）..."
    systemctl start "$SERVICE_NAME" 2>/dev/null || true
    sleep 4
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        STARTED=1
        log "服务已成功启动并运行中！"
        break
    fi
    warn "第 ${i} 次启动未成功，继续重试..."
done

if [[ $STARTED -ne 1 ]]; then
    err "服务启动失败，以下是最近 50 行日志："
    echo "------------------------------------------------------------"
    journalctl -u "$SERVICE_NAME" -n 50 --no-pager 2>/dev/null || true
    echo "------------------------------------------------------------"
else
    sleep 2
fi

# ---------- 完成提示 ----------
echo
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Linux-Panel 安装完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "  运行身份 : ${YELLOW}root${NC}（强制）"
echo -e "  安装目录 : ${INSTALL_DIR}"
echo -e "  访问地址 : ${GREEN}http://<服务器IP>:${PANEL_PORT}${NC}"
echo -e "  管理命令 : ${YELLOW}sudo linux-panel {start|stop|restart|status|logs|pass|uninstall}${NC}"
echo

INIT_LOG=$(journalctl -u "$SERVICE_NAME" --since "$START_TIME" --no-pager 2>/dev/null | grep -A 6 "面板已初始化" || true)
if [[ -n "$INIT_LOG" ]]; then
    echo -e "${YELLOW}  ─── 面板初始化信息 ───${NC}"
    echo "$INIT_LOG" | sed 's/^.*python\[[0-9]*\]: //'
    echo
    echo -e "  ${YELLOW}请登录后立即修改密码！${NC}"
else
    warn "本次启动日志中没有“面板已初始化”信息。"
    warn "如忘记密码，请执行：sudo linux-panel pass"
fi

echo
echo -e "  如果启用了 UFW，请放行面板端口："
echo -e "  ${YELLOW}sudo ufw allow ${PANEL_PORT}/tcp${NC}"
echo -e "${GREEN}========================================${NC}"

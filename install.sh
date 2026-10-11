#!/usr/bin/env bash
# =============================================================================
# Linux-Panel 一键安装 / 修复脚本
# Debian / Ubuntu + systemd；服务以 root 身份运行；默认端口 33972
# 可重复执行：尽量保留现有 .env 与 data 数据
# 推荐：先下载为文件，再运行 sudo bash install.sh（不要使用 curl | bash）
# =============================================================================
set -Eeuo pipefail

REPO_PATH="hia1321/linux-panel"
REPO_BRANCH="main"
INSTALL_DIR="/opt/linux-panel"
SERVICE_NAME="linux-panel"
SERVICE_UNIT="${SERVICE_NAME}.service"
SERVICE_FILE="/etc/systemd/system/${SERVICE_UNIT}"
COMMAND_FILE="/usr/local/bin/linux-panel"
PYTHON_BIN="/usr/bin/python3"
VENV_DIR="${INSTALL_DIR}/venv"
ENV_FILE="${INSTALL_DIR}/.env"
PANEL_PORT="${PANEL_PORT:-33972}"
APT_UPDATED=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
info() { echo -e "${BLUE}[i]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*" >&2; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }
die()  { err "$*"; exit 1; }

on_error() {
    local rc=$?
    err "脚本在第 ${BASH_LINENO[0]:-未知} 行执行失败（退出码 ${rc}）。"
    exit "$rc"
}
trap on_error ERR

if [[ ${EUID} -ne 0 ]]; then
    die "请以 root 身份运行：sudo bash /path/to/install.sh"
fi

if ! command -v apt-get >/dev/null 2>&1; then
    die "本脚本仅支持 Debian / Ubuntu 系统。"
fi
if [[ ! -d /run/systemd/system ]]; then
    die "未检测到正在运行的 systemd。"
fi
if [[ ! "$PANEL_PORT" =~ ^[0-9]+$ ]] || (( PANEL_PORT < 1 || PANEL_PORT > 65535 )); then
    die "PANEL_PORT 必须是 1 到 65535 之间的端口号。"
fi

apt_update_once() {
    if (( APT_UPDATED == 0 )); then
        info "更新 apt 软件包索引..."
        # 一些系统仍残留 file:/cdrom 安装介质源；索引更新失败时先给出警告，
        # 再尝试使用已有索引安装，避免非关键源阻断整个安装流程。
        if apt-get update; then
            APT_UPDATED=1
        else
            warn "apt-get update 返回错误。请检查 /etc/apt/sources.list*，尤其是 file:/cdrom 源；继续尝试安装依赖。"
            APT_UPDATED=1
        fi
    fi
}

install_packages() {
    apt_update_once
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
}

ensure_command() {
    local cmd="$1" pkg="$2"
    if command -v "$cmd" >/dev/null 2>&1; then
        log "已存在 ${cmd}"
        return 0
    fi
    warn "未检测到 ${cmd}，尝试安装软件包 ${pkg}..."
    install_packages "$pkg" || die "安装 ${pkg} 失败。请先修复 apt 软件源后重试。"
    command -v "$cmd" >/dev/null 2>&1 || die "安装后仍找不到命令：${cmd}"
    log "${cmd} 已安装"
}

info "检查系统依赖..."
ensure_command git git
ensure_command timeout coreutils
if [[ ! -x "$PYTHON_BIN" ]]; then
    install_packages python3 || die "安装 python3 失败。"
fi
[[ -x "$PYTHON_BIN" ]] || die "找不到 ${PYTHON_BIN}。"
log "已存在 python3：$($PYTHON_BIN --version 2>&1)"

# 不要求系统全局安装 pip3；应用依赖安装在独立 venv 中。
if ! "$PYTHON_BIN" -m venv --help >/dev/null 2>&1; then
    warn "未检测到 venv 模块，尝试安装 python3-venv..."
    install_packages python3-venv || true
fi

# ---------- 克隆或更新代码 ----------
clone_repo() {
    local target="$1" url
    local urls=(
        "https://github.com/${REPO_PATH}.git"
        "https://ghfast.top/https://github.com/${REPO_PATH}.git"
        "https://ghproxy.net/https://github.com/${REPO_PATH}.git"
        "https://gitclone.com/github.com/${REPO_PATH}.git"
    )
    for url in "${urls[@]}"; do
        info "尝试克隆：${url}"
        if timeout 180 git clone --depth 1 -b "$REPO_BRANCH" "$url" "$target"; then
            log "克隆成功：${url}"
            return 0
        fi
        warn "该地址克隆失败，尝试下一个镜像。"
        rm -rf -- "$target"
    done
    return 1
}

if [[ -d "$INSTALL_DIR" ]]; then
    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        info "检测到已有仓库，尝试更新代码..."
        if git -C "$INSTALL_DIR" pull --ff-only; then
            log "代码已更新。"
        else
            warn "git pull 失败，将继续使用当前已安装代码。"
        fi
    else
        die "${INSTALL_DIR} 已存在但不是 Git 仓库。为避免误删数据，脚本不会自动删除它。请先备份并检查该目录。"
    fi
else
    info "克隆仓库到 ${INSTALL_DIR}..."
    clone_repo "$INSTALL_DIR" || die "所有 Git 克隆地址均失败，请检查网络后重试。"
fi

[[ -f "${INSTALL_DIR}/app.py" ]] || die "安装目录中没有 app.py，仓库内容不完整。"
cd "$INSTALL_DIR"

# ---------- 创建虚拟环境 ----------
if [[ ! -x "${VENV_DIR}/bin/python" ]] || ! "${VENV_DIR}/bin/python" -m pip --version >/dev/null 2>&1; then
    info "创建 Python 虚拟环境：${VENV_DIR}..."
    rm -rf -- "$VENV_DIR"
    if ! "$PYTHON_BIN" -m venv "$VENV_DIR"; then
        warn "创建虚拟环境失败，尝试安装对应版本的 venv 软件包..."
        PY_VER=$("$PYTHON_BIN" -c 'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")')
        install_packages "${PY_VER}-venv" python3-venv || die "安装 venv 依赖失败。"
        "$PYTHON_BIN" -m venv "$VENV_DIR" || die "创建 Python 虚拟环境失败。"
    fi
    log "Python 虚拟环境已创建。"
else
    log "Python 虚拟环境已存在。"
fi

VENV_PY="${VENV_DIR}/bin/python"
VENV_PIP="${VENV_DIR}/bin/pip"
[[ -x "$VENV_PIP" ]] || die "虚拟环境中没有 pip：${VENV_PIP}"

# ---------- 安装 Python 依赖 ----------
if [[ -f "${INSTALL_DIR}/requirements.txt" ]]; then
    info "安装 / 更新 Python 依赖..."
    "$VENV_PY" -m pip install --upgrade pip || die "升级虚拟环境 pip 失败。"
    "$VENV_PIP" install -r "${INSTALL_DIR}/requirements.txt" || die "Python 依赖安装失败，请检查网络与 requirements.txt。"
    log "Python 依赖已安装。"
else
    warn "没有找到 requirements.txt，跳过依赖安装。"
fi

# ---------- 权限及环境配置 ----------
chown -R root:root "$INSTALL_DIR"
chmod 700 "$INSTALL_DIR"
mkdir -p "${INSTALL_DIR}/data"
chmod 700 "${INSTALL_DIR}/data"
[[ -f "${INSTALL_DIR}/data/secret.key" ]] && chmod 600 "${INSTALL_DIR}/data/secret.key" || true
[[ -f "${INSTALL_DIR}/data/panel.db" ]] && chmod 600 "${INSTALL_DIR}/data/panel.db" || true

# 首次安装才创建 .env；重新运行安装脚本时保留用户已有配置，仅补缺失项。
if [[ ! -f "$ENV_FILE" ]]; then
    cat > "$ENV_FILE" <<EOF_ENV
PANEL_HOST=0.0.0.0
PANEL_PORT=${PANEL_PORT}
PANEL_FILE_ROOT=/
EOF_ENV
    log "已创建环境变量文件：${ENV_FILE}"
else
    info "保留现有环境变量文件：${ENV_FILE}"
    grep -q '^PANEL_HOST=' "$ENV_FILE" || echo 'PANEL_HOST=0.0.0.0' >> "$ENV_FILE"
    grep -q '^PANEL_PORT=' "$ENV_FILE" || echo "PANEL_PORT=${PANEL_PORT}" >> "$ENV_FILE"
    grep -q '^PANEL_FILE_ROOT=' "$ENV_FILE" || echo 'PANEL_FILE_ROOT=/' >> "$ENV_FILE"
fi
chmod 600 "$ENV_FILE"

# ---------- 写入 systemd 服务 ----------
info "创建 systemd 服务文件：${SERVICE_FILE}..."
cat > "$SERVICE_FILE" <<EOF_SERVICE
[Unit]
Description=Linux Web Panel (root-only)
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_PY} ${INSTALL_DIR}/app.py
Restart=on-failure
RestartSec=3
TimeoutStartSec=60
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF_SERVICE
chmod 644 "$SERVICE_FILE"
log "systemd 服务文件已写入。"

# ---------- 写入管理命令 ----------
info "创建管理命令：${COMMAND_FILE}..."
cat > "$COMMAND_FILE" <<'EOF_COMMAND'
#!/usr/bin/env bash
set -u
SERVICE="linux-panel.service"
if [[ ${EUID} -ne 0 ]]; then
    echo "错误：linux-panel 必须以 root 身份运行。" >&2
    echo "请使用：sudo linux-panel ${*}" >&2
    exit 1
fi
case "${1:-}" in
    start)
        systemctl start "$SERVICE"
        systemctl status "$SERVICE" --no-pager -l
        ;;
    stop)
        systemctl stop "$SERVICE"
        echo "服务已停止。"
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
    log-tail)
        journalctl -u "$SERVICE" -n 100 --no-pager
        ;;
    pass)
        journalctl -u "$SERVICE" -n 300 --no-pager | grep -A 6 '面板已初始化' || true
        ;;
    enable)
        systemctl enable "$SERVICE"
        ;;
    disable)
        systemctl disable "$SERVICE"
        ;;
    uninstall)
        echo "这将停止并移除 systemd 服务与管理命令，但保留 /opt/linux-panel 中的程序和数据。"
        read -r -p "确定卸载吗？[y/N] " ans
        [[ "$ans" =~ ^[Yy]$ ]] || { echo "已取消。"; exit 0; }
        systemctl disable --now "$SERVICE" 2>/dev/null || true
        rm -f /etc/systemd/system/"$SERVICE"
        systemctl daemon-reload
        rm -f /usr/local/bin/linux-panel
        echo "服务和管理命令已卸载；程序及数据仍保留在 /opt/linux-panel。"
        ;;
    *)
        echo "用法：sudo linux-panel {start|stop|restart|status|logs|log-tail|pass|enable|disable|uninstall}"
        exit 2
        ;;
esac
EOF_COMMAND
chmod 755 "$COMMAND_FILE"

# ---------- 重新加载、开机自启并立即启动 ----------
info "重新加载 systemd 配置..."
systemctl daemon-reload
info "启用开机自启并立即启动服务..."
START_TIME=$(date '+%Y-%m-%d %H:%M:%S')
if systemctl enable --now "$SERVICE_UNIT"; then
    sleep 2
fi

if systemctl is-active --quiet "$SERVICE_UNIT"; then
    log "服务已成功启动，且已设置开机自启。"
    START_OK=1
else
    START_OK=0
    err "服务未能启动。systemd 状态和日志如下："
    echo '---------------- systemctl status ----------------'
    systemctl status "$SERVICE_UNIT" --no-pager -l || true
    echo '---------------- journalctl ----------------------'
    journalctl -u "$SERVICE_UNIT" -n 100 --no-pager || true
    echo '--------------------------------------------------'
fi

# ---------- 安装结果 ----------
echo
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Linux-Panel 安装 / 修复流程已完成${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "  运行身份 : ${YELLOW}root${NC}"
echo -e "  安装目录 : ${INSTALL_DIR}"
echo -e "  访问地址 : ${GREEN}http://<服务器IP>:${PANEL_PORT}${NC}（实际端口以 .env 中 PANEL_PORT 为准）"
echo -e "  管理命令 : ${YELLOW}sudo linux-panel {start|stop|restart|status|logs|log-tail|pass}${NC}"
echo

if (( START_OK == 1 )); then
    INIT_LOG=$(journalctl -u "$SERVICE_UNIT" --since "$START_TIME" --no-pager 2>/dev/null | grep -A 6 '面板已初始化' || true)
    if [[ -n "$INIT_LOG" ]]; then
        echo -e "${YELLOW}── 首次初始化信息 ──${NC}"
        echo "$INIT_LOG" | sed 's/^.*python\[[0-9]*\]: //'
        echo
        echo -e "${YELLOW}请登录后立即修改初始密码。${NC}"
    fi
    echo "如果启用了 UFW，请按需放行端口：sudo ufw allow ${PANEL_PORT}/tcp"
    echo -e "${GREEN}========================================${NC}"
else
    echo -e "${RED}服务仍未运行。请检查上方日志，或运行：sudo linux-panel log-tail${NC}"
    echo -e "${GREEN}========================================${NC}"
    exit 1
fi

#!/usr/bin/env bash
# If invoked as `sh install.sh`, switch to Bash before Bash-specific syntax.
if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi
# =============================================================================
# Linux-Panel 一键安装脚本
# 运行身份：root；系统：Debian / Ubuntu（systemd）
# 默认端口：33972
# =============================================================================
set -Eeuo pipefail

REPO_PATH="hia1321/linux-panel"
REPO_BRANCH="main"
INSTALL_DIR="/opt/linux-panel"
SERVICE_NAME="linux-panel"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PYTHON_BIN="$(command -v python3 2>/dev/null || true)"
VENV_DIR="${INSTALL_DIR}/venv"
PANEL_PORT="33972"
APT_UPDATED=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
info() { echo -e "${BLUE}[i]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

confirm() {
    local prompt="$1" ans=""
    # 没有交互终端时默认继续，支持自动化安装。
    if [[ ! -t 0 ]]; then return 0; fi
    read -r -p "${prompt} [Y/n] " ans || true
    [[ ! "${ans:-Y}" =~ ^[Nn]$ ]]
}

apt_update_once() {
    if [[ "$APT_UPDATED" -eq 0 ]]; then
        info "更新 APT 软件索引..."
        # 部分服务器配置了失效的 CD-ROM 软件源。即使 update 返回非零，
        # 仍尝试安装所需软件包；若安装确实失败，会在后续明确报错退出。
        if apt-get update -qq; then
            log "APT 软件索引已更新。"
        else
            warn "apt-get update 返回错误；继续尝试安装所需软件包。若安装失败，请检查 /etc/apt/sources.list 及 sources.list.d 中的软件源。"
        fi
        APT_UPDATED=1
    fi
}

apt_install() {
    apt_update_once
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

install_pkg_if_missing() {
    local cmd="$1" pkg="${2:-$1}"
    if command -v "$cmd" >/dev/null 2>&1; then
        log "已存在 ${cmd}。"
        return 0
    fi

    warn "未检测到 ${cmd}。"
    if ! confirm "是否自动安装 ${pkg}？"; then
        err "缺少必需命令 ${cmd}，安装终止。"
        exit 1
    fi
    if ! apt_install "$pkg"; then
        err "安装系统软件包 ${pkg} 失败。请先修复 APT 软件源后重试。"
        exit 1
    fi
    if ! command -v "$cmd" >/dev/null 2>&1; then
        err "软件包 ${pkg} 安装后仍未找到命令 ${cmd}。"
        exit 1
    fi
    log "已安装 ${pkg}。"
}

clone_repo() {
    local target="$1"
    local urls=(
        "https://github.com/${REPO_PATH}.git"
        "https://ghfast.top/https://github.com/${REPO_PATH}.git"
        "https://ghproxy.net/https://github.com/${REPO_PATH}.git"
        "https://hub.gitmirror.com/https://github.com/${REPO_PATH}.git"
        "https://gitclone.com/github.com/${REPO_PATH}.git"
    )
    local url
    for url in "${urls[@]}"; do
        info "尝试克隆：${url}"
        if timeout 180 git clone --depth 1 -b "$REPO_BRANCH" "$url" "$target"; then
            log "克隆成功：${url}"
            return 0
        fi
        warn "克隆失败：${url}"
        rm -rf "$target"
    done
    return 1
}

# ---------- 权限与系统检测 ----------
if [[ "$EUID" -ne 0 ]]; then
    err "必须以 root 身份运行。推荐流程："
    err "  curl -fsSL \"https://cdn.jsdelivr.net/gh/${REPO_PATH}@${REPO_BRANCH}/install.sh?t=\$(date +%s)\" -o /tmp/install.sh"
    err "  sudo bash /tmp/install.sh"
    exit 1
fi
log "已确认以 root 身份运行。"

command -v apt-get >/dev/null 2>&1 || { err "仅支持 Debian / Ubuntu 系（需要 apt-get）。"; exit 1; }
[[ -d /run/systemd/system ]] || { err "未检测到 systemd，无法安装系统服务。"; exit 1; }
[[ -n "$PYTHON_BIN" ]] || PYTHON_BIN="/usr/bin/python3"

if ! [[ "$PANEL_PORT" =~ ^[0-9]+$ ]] || (( PANEL_PORT < 1 || PANEL_PORT > 65535 )); then
    err "PANEL_PORT 必须是 1 到 65535 之间的端口号。"
    exit 1
fi

info "检查系统依赖..."
install_pkg_if_missing git git
install_pkg_if_missing python3 python3
# 不再强制安装系统级 pip3：Python 依赖全部安装在项目 venv 内。

# ---------- 获取 / 更新代码 ----------
if [[ -d "$INSTALL_DIR" ]]; then
    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        info "目录已存在，尝试更新代码..."
        if git -C "$INSTALL_DIR" pull --ff-only; then
            log "代码已更新。"
        else
            warn "git pull 更新失败，将继续使用安装目录中的现有代码。"
        fi
    else
        # 支持从 ZIP 手动部署的项目目录（这种方式本来就没有 .git）。
        # 只有检测到完整的模块化项目结构时才继续；不会覆盖或删除现有代码与数据。
        if [[ -f "${INSTALL_DIR}/app.py" && -f "${INSTALL_DIR}/requirements.txt" && -d "${INSTALL_DIR}/linux_panel" ]]; then
            warn "${INSTALL_DIR} 不是 Git 仓库，但检测到完整模块化项目。"
            warn "跳过 git pull，继续使用当前目录中的代码安装依赖并配置服务。若需更新代码，请先将新版本文件上传到该目录。"
        else
            err "${INSTALL_DIR} 不是 Git 仓库，且缺少完整项目文件（app.py、requirements.txt 或 linux_panel/）。为保护现有数据，安装已停止。"
            err "请先备份 /opt/linux-panel/data、SSL 证书配置及当前代码，再补齐项目文件。"
            exit 1
        fi
    fi
else
    info "克隆仓库到 ${INSTALL_DIR}..."
    clone_repo "$INSTALL_DIR" || { err "所有 Git 克隆地址均失败，请检查网络后重试。"; exit 1; }
fi

cd "$INSTALL_DIR"
[[ -f app.py ]] || { err "安装目录中找不到 app.py。"; exit 1; }
[[ -f requirements.txt ]] || { err "安装目录中找不到 requirements.txt。"; exit 1; }

# ---------- 创建 / 检查虚拟环境 ----------
VENV_PY="${VENV_DIR}/bin/python"
if [[ -x "$VENV_PY" ]] && "$VENV_PY" -m pip --version >/dev/null 2>&1; then
    log "现有 Python 虚拟环境可用。"
else
    info "创建或修复 Python 虚拟环境..."
    rm -rf "$VENV_DIR"
    if ! "$PYTHON_BIN" -m venv "$VENV_DIR"; then
        warn "创建虚拟环境失败，尝试安装与当前 Python 版本匹配的 venv 系统包。"
        PY_VER=$("$PYTHON_BIN" -c 'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")')
        if ! apt_install "${PY_VER}-venv"; then
            if ! apt_install python3-venv; then
                err "无法安装 Python venv 组件。请修复 APT 软件源后执行安装脚本。"
                exit 1
            fi
        fi
        rm -rf "$VENV_DIR"
        "$PYTHON_BIN" -m venv "$VENV_DIR" || { err "虚拟环境创建失败。"; exit 1; }
    fi
    log "Python 虚拟环境已创建。"
fi

# 避免只检查系统 pip3；直接通过虚拟环境 Python 调用 pip。
if ! "$VENV_PY" -m pip --version >/dev/null 2>&1; then
    "$VENV_PY" -m ensurepip --upgrade || { err "虚拟环境中没有可用的 pip。"; exit 1; }
fi

# ---------- 安装项目依赖 ----------
info "安装 / 更新 requirements.txt 中的全部 Python 依赖..."
if ! "$VENV_PY" -m pip install --disable-pip-version-check --upgrade pip; then
    warn "pip 自身升级失败，将继续尝试安装项目依赖。"
fi
if ! "$VENV_PY" -m pip install --disable-pip-version-check --retries 3 --timeout 30 -r requirements.txt; then
    err "Python 依赖安装失败，已中止后续服务部署。请检查网络或 pip 软件源后重试。"
    exit 1
fi

# 预检最新版 app.py 使用的第三方模块，防止依赖缺失后仍启动服务。
info "检查关键 Python 模块..."
if ! "$VENV_PY" - <<'PY'
from flask import Flask
from flask_socketio import SocketIO
from cryptography.fernet import Fernet
import requests
from aliyunsdkcore.client import AcsClient
from aliyunsdkalidns.request.v20150109.DescribeDomainsRequest import DescribeDomainsRequest
from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.dnspod.v20210323 import dnspod_client, models
from linux_panel.ssl_service import inspect_certificate, load_ssl_config
from linux_panel.routes.ssl import bp as ssl_blueprint
print("关键 Python 模块导入正常。")
PY
then
    err "关键模块导入失败，请检查 requirements.txt 和 Python 环境。"
    exit 1
fi

if ! "$VENV_PY" -m compileall -q app.py linux_panel; then
    err "Python 模块语法检查失败，未继续启动服务。"
    exit 1
fi
log "依赖安装、模块导入及 Python 语法检查均已通过。"

# ---------- 权限 ----------
chown -R root:root "$INSTALL_DIR"
chmod 700 "$INSTALL_DIR"
[[ -d "${INSTALL_DIR}/data" ]] && chmod 700 "${INSTALL_DIR}/data" || true
[[ -f "${INSTALL_DIR}/data/secret.key" ]] && chmod 600 "${INSTALL_DIR}/data/secret.key" || true
[[ -f "${INSTALL_DIR}/data/panel.db" ]] && chmod 600 "${INSTALL_DIR}/data/panel.db" || true

# ---------- 移除旧版独立 HTTPS 服务（原来默认监听 443） ----------
# 新版由 linux-panel.service 在同一个外部端口分流 HTTP/TLS：HTTP 只返回 HTTPS 跳转，
# TLS 代理到本机回环地址的内侧监听器。关闭旧的独立 443 服务，避免残留监听。
info "清理旧版独立 HTTPS 服务（如果存在）..."
systemctl disable --now linux-panel-https.service >/dev/null 2>&1 || true
if systemctl is-active --quiet linux-panel-https.service 2>/dev/null; then
    err "旧版 linux-panel-https.service 仍在运行，无法安全迁移。请先执行：systemctl stop linux-panel-https.service"
    exit 1
fi
rm -f /etc/systemd/system/linux-panel-https.service \
      /etc/systemd/system/multi-user.target.wants/linux-panel-https.service
systemctl daemon-reload || true

# ---------- 安装时准备 HTTPS 证书 ----------
info "检查并准备 HTTPS 证书（默认端口 ${PANEL_PORT}）..."
if ! PANEL_PORT="$PANEL_PORT" "$VENV_PY" - <<'PY_SSL_BOOTSTRAP'
import os
from linux_panel.ssl_service import bootstrap_self_signed_certificate
port = int(os.environ.get("PANEL_PORT", "33972"))
info, message = bootstrap_self_signed_certificate(port)
print(message)
print("证书有效期至：", info.get("expires_at_display") or info.get("expires_at"))
PY_SSL_BOOTSTRAP
then
    err "准备 HTTPS 证书失败，未继续配置服务。"
    exit 1
fi

# ---------- 环境变量 ----------
info "写入环境变量文件：${INSTALL_DIR}/.env"
cat > "${INSTALL_DIR}/.env" <<EOF_ENV
PANEL_HOST=0.0.0.0
PANEL_PORT=${PANEL_PORT}
PANEL_FILE_ROOT=/
PANEL_SSL_SERVER=1
PANEL_FORCE_HTTPS=1
EOF_ENV
chmod 600 "${INSTALL_DIR}/.env"

# ---------- HTTPS-only systemd 服务 ----------
info "创建 HTTPS-only systemd 服务：${SERVICE_FILE}"
cat > "$SERVICE_FILE" <<EOF_SERVICE
[Unit]
Description=Linux Web Panel (HTTPS-only, root-only)
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
Environment=PANEL_SSL_SERVER=1
Environment=PANEL_FORCE_HTTPS=1
Environment=PYTHONUNBUFFERED=1
ExecStart=${VENV_PY} ${INSTALL_DIR}/app.py
Restart=on-failure
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF_SERVICE

# ---------- 管理命令 ----------
info "创建管理命令：/usr/local/bin/linux-panel"
cat > /usr/local/bin/linux-panel <<'EOF_CMD'
#!/usr/bin/env bash
set -u
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
    pass)    journalctl -u "$SERVICE" -n 300 --no-pager | grep -A 6 "面板已初始化" || true ;;
    enable)  systemctl enable "$SERVICE"; echo "已设置开机自启" ;;
    disable) systemctl disable "$SERVICE"; echo "已取消开机自启；当前运行中的服务不会自动停止" ;;
    https-status) systemctl status "$SERVICE" --no-pager -l ;;
    https-logs) journalctl -u "$SERVICE" -n 200 --no-pager ;;
    uninstall)
        read -r -p "确定要卸载 linux-panel 吗？[y/N] " ans || true
        [[ "${ans:-}" =~ ^[Yy]$ ]] || { echo "已取消"; exit 0; }
        systemctl disable --now "$SERVICE" 2>/dev/null || true
        systemctl disable --now linux-panel-https.service 2>/dev/null || true
        rm -f "/etc/systemd/system/${SERVICE}.service" "/etc/systemd/system/linux-panel-https.service"
        systemctl daemon-reload
        rm -f /usr/local/bin/linux-panel
        echo "服务已卸载。安装目录及数据未删除；如需删除请手动备份后执行："
        echo "  sudo rm -rf /opt/linux-panel" ;;
    *) echo "用法: sudo linux-panel {start|stop|restart|status|logs|pass|enable|disable|https-status|https-logs|uninstall}" ;;
esac
EOF_CMD
chmod 755 /usr/local/bin/linux-panel

# ---------- 加载、开机自启并启动 ----------
info "重新加载 systemd 并设置开机自启..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
START_TIME=$(date '+%Y-%m-%d %H:%M:%S')
STARTED=0
for i in 1 2 3; do
    info "启动服务（第 ${i} 次尝试）..."
    if [[ "$i" -eq 1 ]]; then
        systemctl restart "$SERVICE_NAME" || true
    else
        systemctl start "$SERVICE_NAME" || true
    fi
    sleep 3
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        STARTED=1
        log "服务已成功启动并运行中。"
        break
    fi
    warn "第 ${i} 次启动未成功。"
done

if [[ "$STARTED" -ne 1 ]]; then
    err "服务启动失败。最近 80 行日志如下："
    echo "------------------------------------------------------------"
    journalctl -u "$SERVICE_NAME" -n 80 --no-pager 2>/dev/null || true
    echo "------------------------------------------------------------"
    err "可使用 sudo linux-panel logs 或 sudo linux-panel status 查看详情。"
fi

# ---------- 完成提示 ----------
echo
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Linux-Panel 安装流程结束${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "  运行身份 : ${YELLOW}root${NC}（强制）"
echo -e "  安装目录 : ${INSTALL_DIR}"
echo -e "  访问地址 : ${GREEN}https://<服务器IP>:${PANEL_PORT}${NC}"
echo -e "  管理命令 : ${YELLOW}sudo linux-panel {start|stop|restart|status|logs|pass|enable|disable|https-status|https-logs|uninstall}${NC}"
echo -e "  HTTPS 模式 : ${YELLOW}强制 HTTPS；HTTP 在同一端口自动跳转，外部不监听 TCP 443。${NC}"
echo -e "  HTTP 请求将保留原主机、端口、路径和查询参数，跳转到对应 HTTPS 地址。"
echo -e "  默认已生成自签名证书；浏览器首次访问可能提示证书不受信任，可在 SSL 管理中替换为正式证书。"
echo

INIT_LOG=$(journalctl -u "$SERVICE_NAME" --since "$START_TIME" --no-pager 2>/dev/null | grep -A 6 "面板已初始化" || true)
if [[ -n "$INIT_LOG" ]]; then
    echo -e "${YELLOW}  ─── 面板初始化信息 ───${NC}"
    echo "$INIT_LOG" | sed 's/^.*python\[[0-9]*\]: //'
    echo
    echo -e "  ${YELLOW}请登录后立即修改密码！${NC}"
else
    warn "本次启动日志中没有“面板已初始化”信息。已有数据库的面板通常不会重复输出初始化密码。"
    warn "如需查找首次启动时的密码，请执行：sudo linux-panel pass"
fi

echo
echo -e "  如果启用了 UFW，请放行面板 HTTPS 端口："
echo -e "  ${YELLOW}sudo ufw allow ${PANEL_PORT}/tcp${NC}"
echo -e "  申请 Let’s Encrypt 证书时还需临时由 Certbot 使用 TCP 80 进行 HTTP-01 验证，且该端口需要从公网可达："
echo -e "  ${YELLOW}sudo ufw allow 80/tcp${NC}"
echo -e "${GREEN}========================================${NC}"

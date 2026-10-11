# linux-panel



curl -fsSL "https://cdn.jsdelivr.net/gh/hia1321/linux-panel@main/install.sh?t=$(date +%s)" -o /tmp/linux-panel-install.sh && sudo bash /tmp/linux-panel-install.sh


sudo linux-panel start    # 启动



sudo linux-panel stop     # 停止



sudo linux-panel restart  # 重启



sudo linux-panel status   # 查看状态



sudo linux-panel logs     # 实时查看日志



sudo linux-panel enable   # 设置开机自启



sudo linux-panel disable  # 取消开机自启

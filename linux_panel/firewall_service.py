import re
import subprocess
from .common import PathError, check_port

# ============================================================================
# ufw
# ============================================================================
def run_cmd(args, timeout=15):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired: return -1, "", "命令超时"
    except FileNotFoundError: return -1, "", f"命令不存在：{args[0]}"

def ufw_available():
    return run_cmd(["which", "ufw"])[0] == 0

def _parse_ufw_rules():
    code, out, _ = run_cmd(["ufw", "status", "numbered"])
    if code != 0: return []
    rules = []
    for line in out.splitlines():
        m = re.match(r"^\[\s*(\d+)\]\s+(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT)\s+(.*?)\s*$", line)
        if not m: continue
        num, to, action, _d, src = m.groups()
        to_clean = re.sub(r"\s*\(v6\)\s*$", "", to).strip()
        pm = re.match(r"^(\d+(?:[:,\d]*)?)(?:/(\w+))?(?:\s|$)", to_clean)
        if not pm: continue
        port, proto = pm.group(1), (pm.group(2) or "any")
        source = "" if src.strip() in ("Anywhere", "Anywhere (v6)") else src.strip()
        rules.append({"num": int(num), "port": port, "proto": proto.lower(),
                      "action": action.lower(), "source": source})
    return rules

def ufw_status():
    code, out, err = run_cmd(["ufw", "status", "verbose"])
    if code != 0:
        return {"installed": ufw_available(), "active": False, "rules": [],
                "error": err.strip() or "无法获取 ufw 状态"}
    active = bool(re.search(r"^Status:\s*active", out, re.M))
    all_rules = _parse_ufw_rules()
    step1 = {}
    for r in all_rules:
        key = (r["port"], r["proto"], r["action"], r["source"])
        if key not in step1:
            step1[key] = dict(r); step1[key]["nums"] = [r["num"]]
        else: step1[key]["nums"].append(r["num"])
    step2 = {}
    for r in step1.values():
        key = (r["port"], r["action"], r["source"])
        if key not in step2:
            step2[key] = {"port": r["port"], "action": r["action"],
                          "source": r["source"], "protos": {r["proto"]},
                          "nums": list(r["nums"])}
        else:
            step2[key]["protos"].add(r["proto"])
            step2[key]["nums"].extend(r["nums"])
    rules = []
    for v in step2.values():
        protos = v["protos"]
        if "any" in protos or ("tcp" in protos and "udp" in protos): dp = "any"
        elif "tcp" in protos: dp = "tcp"
        elif "udp" in protos: dp = "udp"
        else: dp = "any"
        rules.append({"port": v["port"], "proto": dp, "action": v["action"],
                      "source": v["source"], "nums": sorted(set(v["nums"]))})
    rules.sort(key=lambda r: (int(re.match(r"\d+", r["port"]).group()) if re.match(r"\d+", r["port"]) else 0, r["proto"]))
    return {"installed": True, "active": active, "rules": rules}

def ufw_add(port, proto, source):
    port = check_port(port)
    proto = (proto or "any").lower()
    source = (source or "").strip()
    if source and not re.match(r"^[\d\./:a-fA-F]+$", source):
        return False, "来源地址格式不正确"
    st = ufw_status()
    existing = [r for r in st.get("rules", [])
                if r["port"] == port and r["source"] == source and r["action"] == "allow"]
    protos_existing = set(r["proto"] for r in existing)
    for r in existing:
        if r["proto"] == "any":
            return False, f"端口 {port} 已放行（ANY），无需重复添加"
        if r["proto"] == proto:
            return False, f"端口 {port} 已放行（{proto.upper()}），无需重复添加"
    upgrade = False
    if proto == "any" and protos_existing: upgrade = True
    elif proto == "tcp" and "udp" in protos_existing: upgrade = True
    elif proto == "udp" and "tcp" in protos_existing: upgrade = True
    if upgrade:
        nums_del = []
        for r in existing: nums_del.extend(r["nums"])
        for n in sorted(set(nums_del), reverse=True):
            run_cmd(["ufw", "--force", "delete", str(n)])
        if source: args = ["ufw", "allow", "from", source, "to", "any", "port", port]
        else: args = ["ufw", "allow", port]
        code, out, err = run_cmd(args)
        if code != 0: return False, (err.strip() or out.strip() or "ufw 执行失败")
        return True, f"端口 {port} 已合并升级为 ANY"
    if proto == "any":
        args = ["ufw", "allow", port] if not source else \
            ["ufw", "allow", "from", source, "to", "any", "port", port]
    else:
        args = ["ufw", "allow", f"{port}/{proto}"] if not source else \
            ["ufw", "allow", "from", source, "to", "any", "port", port, "proto", proto]
    code, out, err = run_cmd(args)
    if code != 0: return False, (err.strip() or out.strip() or "ufw 执行失败")
    return True, out.strip()

def ufw_delete_nums(nums):
    for n in sorted(set(int(n) for n in nums), reverse=True):
        code, out, err = run_cmd(["ufw", "--force", "delete", str(n)])
        if code != 0: return False, (err.strip() or f"删除规则 #{n} 失败")
    return True, "已删除"

def ufw_switch(enable):
    cmd = ["ufw", "--force", "enable" if enable else "disable"]
    code, out, err = run_cmd(cmd)
    if code != 0: return False, (err.strip() or out.strip() or "操作失败")
    return True, "ok"

__all__ = [name for name in globals() if not name.startswith("__")]

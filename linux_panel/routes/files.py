from flask import Blueprint
from ..core import *


bp = Blueprint("files", __name__)

@bp.route("/api/files")
@login_required
@api_guard
def api_files():
    rel = request.args.get("path", "")
    full = resolve(rel, must_exist=True)
    if not os.path.isdir(full): return jsonify(code=400, msg="不是目录")
    try: names = os.listdir(full)
    except PermissionError: return jsonify(code=403, msg="没有权限读取")
    # File listing must remain usable even if an old database is missing the
    # optional notes table. The directory contents are the primary data.
    try:
        notes = {r["path"]: r["note"] for r in db_all("SELECT path, note FROM file_notes")}
    except Exception as exc:
        log.warning("读取文件备注失败，仍继续列出文件：%s", exc)
        notes = {}
    entries = []
    for name in names:
        p = os.path.join(full, name)
        try: lst = os.lstat(p)
        except OSError: continue
        is_link = stat.S_ISLNK(lst.st_mode)
        try: st = os.stat(p) if is_link else lst
        except OSError: st = lst
        is_dir = stat.S_ISDIR(st.st_mode)
        rel_path = (rel.rstrip("/") + "/" + name).lstrip("/") if rel else name
        entries.append({
            "name": name, "path": rel_path,
            "dir": is_dir, "link": is_link,
            "size": 0 if is_dir else st.st_size,
            "mtime": st.st_mtime,
            "mode": oct(stat.S_IMODE(st.st_mode))[2:].zfill(4),
            "uid": st.st_uid, "gid": st.st_gid,
            "owner": uid_name(st.st_uid), "group": gid_name(st.st_gid),
            "note": notes.get(rel_path, ""),
        })
    entries.sort(key=lambda x: (not x["dir"], x["name"].lower()))
    try:
        du = shutil.disk_usage(full)
        disk = {"total": du.total, "used": du.used, "free": du.free}
    except OSError: disk = None
    return jsonify(code=0, data={"path": rel.strip("/"), "entries": entries, "disk": disk})

@bp.route("/api/files/mkdir", methods=["POST"])
@login_required
@api_guard
def api_mkdir():
    d = request.get_json() or {}
    parent = resolve(d.get("path", ""), must_exist=True)
    name = check_name(d.get("name"))
    target = os.path.join(parent, name)
    if os.path.exists(target): return jsonify(code=400, msg="已存在")
    os.makedirs(target, mode=0o755); return jsonify(code=0)

@bp.route("/api/files/touch", methods=["POST"])
@login_required
@api_guard
def api_touch():
    d = request.get_json() or {}
    parent = resolve(d.get("path", ""), must_exist=True)
    name = check_name(d.get("name"))
    target = os.path.join(parent, name)
    if os.path.exists(target): return jsonify(code=400, msg="已存在")
    open(target, "w").close(); os.chmod(target, 0o644)
    return jsonify(code=0)

@bp.route("/api/files/delete", methods=["POST"])
@login_required
@api_guard
def api_delete():
    d = request.get_json() or {}
    paths = d.get("paths") or []
    if not paths: return jsonify(code=400, msg="未选择文件")
    errors = []
    for rel in paths:
        full = resolve(rel)
        if full == FILE_ROOT: errors.append("不能删根目录"); continue
        if not os.path.lexists(full): continue
        try:
            if os.path.isdir(full) and not os.path.islink(full): shutil.rmtree(full)
            else: os.remove(full)
            db_exec("DELETE FROM file_notes WHERE path=?", (rel,))
        except OSError as e: errors.append(f"{os.path.basename(full)}: {e.strerror or e}")
    if errors: return jsonify(code=500, msg="部分失败：" + "; ".join(errors[:3]))
    return jsonify(code=0)

@bp.route("/api/files/rename", methods=["POST"])
@login_required
@api_guard
def api_rename():
    d = request.get_json() or {}
    src = resolve(d.get("path", ""), must_exist=True)
    old_rel = d.get("path", "").strip("/")
    name = check_name(d.get("name"))
    dst = os.path.join(os.path.dirname(src), name)
    if os.path.lexists(dst) and os.path.realpath(dst) != os.path.realpath(src):
        return jsonify(code=400, msg="目标已存在")
    os.rename(src, dst)
    new_rel = os.path.join(os.path.dirname(old_rel), name).replace(os.sep, "/").lstrip("/")
    db_exec("UPDATE file_notes SET path=? WHERE path=?", (new_rel, old_rel))
    return jsonify(code=0)

@bp.route("/api/files/copy", methods=["POST"])
@login_required
@api_guard
def api_copy():
    d = request.get_json() or {}
    paths = d.get("paths") or []
    target_dir = resolve(d.get("target", ""), must_exist=True)
    if not os.path.isdir(target_dir): return jsonify(code=400, msg="目标不是目录")
    errors, success = [], 0
    for rel in paths:
        src = resolve(rel, must_exist=True)
        name = os.path.basename(src)
        dst = os.path.join(target_dir, name)
        base, ext = os.path.splitext(name); i = 1
        while os.path.exists(dst):
            dst = os.path.join(target_dir, f"{base}_副本{i}{ext}"); i += 1
        try:
            if os.path.isdir(src) and not os.path.islink(src): shutil.copytree(src, dst)
            else: shutil.copy2(src, dst, follow_symlinks=False)
            success += 1
        except OSError as e: errors.append(f"{name}: {e.strerror or e}")
    if errors and not success: return jsonify(code=500, msg="复制失败：" + "; ".join(errors[:3]))
    return jsonify(code=0, msg=f"已复制 {success} 项")

@bp.route("/api/files/move", methods=["POST"])
@login_required
@api_guard
def api_move():
    d = request.get_json() or {}
    paths = d.get("paths") or []
    target_dir = resolve(d.get("target", ""), must_exist=True)
    if not os.path.isdir(target_dir): return jsonify(code=400, msg="目标不是目录")
    errors, success = [], 0
    for rel in paths:
        src = resolve(rel, must_exist=True)
        name = os.path.basename(src)
        dst = os.path.join(target_dir, name)
        if os.path.realpath(src) == os.path.realpath(dst): continue
        if os.path.exists(dst):
            base, ext = os.path.splitext(name); i = 1
            while os.path.exists(dst):
                dst = os.path.join(target_dir, f"{base}_副本{i}{ext}"); i += 1
        try:
            shutil.move(src, dst); success += 1
            db_exec("DELETE FROM file_notes WHERE path=?", (rel,))
        except OSError as e: errors.append(f"{name}: {e.strerror or e}")
    if errors and not success: return jsonify(code=500, msg="移动失败：" + "; ".join(errors[:3]))
    return jsonify(code=0, msg=f"已移动 {success} 项")

@bp.route("/api/files/chmod", methods=["POST"])
@login_required
@api_guard
def api_chmod():
    d = request.get_json() or {}
    paths = d.get("paths") or ([d["path"]] if d.get("path") else [])
    mode_str = (d.get("mode") or "").strip()
    recursive = bool(d.get("recursive"))
    if not re.match(r"^[0-7]{3,4}$", mode_str):
        return jsonify(code=400, msg="权限必须是 3~4 位八进制")
    mode = int(mode_str, 8)
    for rel in paths:
        full = resolve(rel, must_exist=True)
        os.chmod(full, mode)
        if recursive and os.path.isdir(full) and not os.path.islink(full):
            for root, dirs, files in os.walk(full):
                for n in dirs + files:
                    try: os.chmod(os.path.join(root, n), mode)
                    except OSError: pass
    return jsonify(code=0)

@bp.route("/api/files/chown", methods=["POST"])
@login_required
@api_guard
def api_chown():
    d = request.get_json() or {}
    paths = d.get("paths") or ([d["path"]] if d.get("path") else [])
    owner = (d.get("owner") or "").strip()
    group = (d.get("group") or "").strip()
    recursive = bool(d.get("recursive"))
    import pwd, grp
    uid = -1; gid = -1
    if owner:
        try: uid = pwd.getpwnam(owner).pw_uid
        except KeyError: return jsonify(code=400, msg=f"用户 {owner} 不存在")
    if group:
        try: gid = grp.getgrnam(group).gr_gid
        except KeyError: return jsonify(code=400, msg=f"组 {group} 不存在")
    for rel in paths:
        full = resolve(rel, must_exist=True)
        os.chown(full, uid, gid)
        if recursive and os.path.isdir(full) and not os.path.islink(full):
            for root, dirs, files in os.walk(full):
                for n in dirs + files:
                    try: os.chown(os.path.join(root, n), uid, gid)
                    except OSError: pass
    return jsonify(code=0)

@bp.route("/api/files/stat")
@login_required
@api_guard
def api_stat():
    full = resolve(request.args.get("path", ""), must_exist=True)
    st = os.lstat(full)
    rel = request.args.get("path", "").strip("/")
    note = db_one("SELECT note FROM file_notes WHERE path=?", (rel,))
    return jsonify(code=0, data={
        "name": os.path.basename(full), "path": full, "rel": rel,
        "size": st.st_size, "is_dir": stat.S_ISDIR(st.st_mode),
        "is_link": stat.S_ISLNK(st.st_mode),
        "mode": oct(stat.S_IMODE(st.st_mode))[2:].zfill(4),
        "uid": st.st_uid, "gid": st.st_gid,
        "owner": uid_name(st.st_uid), "group": gid_name(st.st_gid),
        "mtime": st.st_mtime, "atime": st.st_atime, "ctime": st.st_ctime,
        "note": note["note"] if note else "",
    })

@bp.route("/api/files/hash")
@login_required
@api_guard
def api_hash():
    full = resolve(request.args.get("path", ""), must_exist=True)
    if not os.path.isfile(full):
        return jsonify(code=400, msg="不是文件")
    algos = request.args.get("algos", "md5,sha1,sha256").split(",")
    algos = [a for a in algos if a in ("md5", "sha1", "sha256")]
    if not algos: algos = ["md5", "sha1", "sha256"]
    size = os.path.getsize(full)
    if size > 2 * 1024 * 1024 * 1024: algos = ["sha256"]
    hashers = {a: hashlib.new(a) for a in algos}
    try:
        with open(full, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk: break
                for h in hashers.values(): h.update(chunk)
    except OSError as e:
        return jsonify(code=500, msg=f"读取失败：{e.strerror or e}")
    result = {a: hashers[a].hexdigest() for a in algos}
    return jsonify(code=0, data={"hashes": result, "size": size})

@bp.route("/api/files/note", methods=["POST"])
@login_required
def api_note():
    d = request.get_json() or {}
    rel = (d.get("path") or "").strip("/")
    note = (d.get("note") or "").strip()
    if not rel: return jsonify(code=400, msg="缺少路径")
    try: resolve(rel, must_exist=True)
    except PathError as e: return jsonify(code=400, msg=str(e))
    if note:
        now = datetime.now().isoformat(timespec="seconds")
        c = get_db()
        try:
            c.execute("""INSERT INTO file_notes(path, note, updated_at) VALUES(?,?,?)
                         ON CONFLICT(path) DO UPDATE SET note=excluded.note, updated_at=excluded.updated_at""",
                      (rel, note, now))
            c.commit()
        finally: c.close()
    else:
        db_exec("DELETE FROM file_notes WHERE path=?", (rel,))
    return jsonify(code=0, msg="已保存")

@bp.route("/api/system/users_groups")
@login_required
def api_users_groups():
    import pwd, grp
    users, groups = [], []
    try:
        for p in pwd.getpwall(): users.append({"name": p.pw_name, "uid": p.pw_uid})
        users.sort(key=lambda x: x["uid"])
    except Exception: pass
    try:
        for g in grp.getgrall(): groups.append({"name": g.gr_name, "gid": g.gr_gid})
        groups.sort(key=lambda x: x["gid"])
    except Exception: pass
    return jsonify(code=0, data={"users": users, "groups": groups})

@bp.route("/api/files/read")
@login_required
@api_guard
def api_read():
    full = resolve(request.args.get("path", ""), must_exist=True)
    if not os.path.isfile(full): return jsonify(code=400, msg="不是文件")
    size = os.path.getsize(full)
    truncated = size > MAX_EDIT_SIZE
    try:
        with open(full, "r", encoding="utf-8") as f: content = f.read(MAX_EDIT_SIZE)
        enc = "utf-8"
    except UnicodeDecodeError:
        with open(full, "rb") as f: raw = f.read(MAX_EDIT_SIZE)
        content = raw.decode("latin-1"); enc = "latin-1"
    return jsonify(code=0, data={"content": content, "size": size, "encoding": enc, "truncated": truncated})

@bp.route("/api/files/write", methods=["POST"])
@login_required
@api_guard
def api_write():
    d = request.get_json() or {}
    full = resolve(d.get("path", ""))
    with open(full, "w", encoding="utf-8") as f: f.write(d.get("content", ""))
    return jsonify(code=0)

CHUNK_SIZE = 4 * 1024 * 1024

@bp.route("/api/files/upload_stream", methods=["POST"])
@login_required
def api_upload_stream():
    rel = request.args.get("path", "")
    name = request.args.get("name", "")
    overwrite = request.args.get("overwrite", "0") == "1"
    try: parent = resolve(rel, must_exist=True)
    except PathError as e: return jsonify(code=400, msg=str(e))
    if not os.path.isdir(parent): return jsonify(code=400, msg="目标不是目录")
    try: name = check_name(name)
    except PathError as e: return jsonify(code=400, msg=str(e))
    target = os.path.join(parent, name)

    if os.path.lexists(target):
        if os.path.isdir(target) and not os.path.islink(target):
            return jsonify(code=409, msg=f"同名目录已存在，无法用文件覆盖：{name}"), 409
        if not overwrite:
            return jsonify(code=409, msg=f"同名文件已存在：{name}。请确认是否覆盖。"), 409

    try: content_length = int(request.content_length or 0)
    except (TypeError, ValueError): content_length = 0
    try:
        du = shutil.disk_usage(parent); free = du.free
    except OSError: free = None
    if content_length and free is not None and content_length > free:
        return jsonify(code=507,
                       msg=f"磁盘空间不足：需要 {content_length//1024//1024} MB，"
                           f"剩余 {free//1024//1024} MB")

    written = 0
    temp_path = None
    try:
        fd, temp_path = tempfile.mkstemp(prefix=".linux-panel-upload-", dir=parent)
        with os.fdopen(fd, "wb") as f:
            stream = request.stream
            while True:
                chunk = stream.read(CHUNK_SIZE)
                if not chunk: break
                f.write(chunk); written += len(chunk)
            f.flush()
            os.fsync(f.fileno())
        try: os.chmod(temp_path, 0o644)
        except OSError: pass

        if overwrite:
            if os.path.isdir(target) and not os.path.islink(target):
                return jsonify(code=409, msg=f"同名目录已存在，无法用文件覆盖：{name}"), 409
            os.replace(temp_path, target)
            temp_path = None
        else:
            try:
                os.link(temp_path, target)
            except FileExistsError:
                return jsonify(code=409, msg=f"上传期间出现同名文件：{name}，请确认是否覆盖。"), 409
            os.unlink(temp_path)
            temp_path = None
        return jsonify(code=0, msg=f"上传成功（{human_size(written)}）", size=written)
    except OSError as e:
        if e.errno == errno.ENOSPC:
            return jsonify(code=507, msg=f"磁盘空间不足，已接收 {human_size(written)} 后中断")
        if e.errno == errno.EACCES:
            return jsonify(code=403, msg="权限不足，无法写入目标目录")
        if e.errno == errno.EROFS:
            return jsonify(code=400, msg="目标目录所在的文件系统为只读")
        return jsonify(code=500, msg=f"写入失败：{e.strerror or e}")
    except Exception as e:
        return jsonify(code=500, msg=f"上传异常：{e}")
    finally:
        if temp_path:
            try: os.unlink(temp_path)
            except OSError: pass

def human_size(n):
    if n is None: return "-"
    if n < 1024: return f"{n} B"
    units = ["KB", "MB", "GB", "TB", "PB"]; i = -1
    while n >= 1024 and i < len(units) - 1:
        n /= 1024; i += 1
    return f"{n:.2f} {units[i]}"

@bp.route("/api/files/upload", methods=["POST"])
@login_required
def api_upload():
    try:
        rel = request.form.get("path", "")
        parent = resolve(rel, must_exist=True)
        if not os.path.isdir(parent): return jsonify(code=400, msg="目标不是目录")
        files = request.files.getlist("files")
        if not files: return jsonify(code=400, msg="没有文件")
        saved, failed = [], []
        for f in files:
            name = os.path.basename(f.filename or "").strip()
            if not name: continue
            try: check_name(name)
            except PathError: failed.append(f"{name}: 非法名"); continue
            target = os.path.join(parent, name)
            temp_path = None
            try:
                if os.path.lexists(target):
                    failed.append(f"{name}: 同名文件已存在，已拒绝覆盖")
                    continue
                fd, temp_path = tempfile.mkstemp(prefix=".linux-panel-upload-", dir=parent)
                os.close(fd)
                f.save(temp_path)
                try: os.chmod(temp_path, 0o644)
                except OSError: pass
                os.link(temp_path, target)
                os.unlink(temp_path)
                temp_path = None
                saved.append(name)
            except OSError as e:
                if e.errno == errno.EEXIST:
                    failed.append(f"{name}: 同名文件已存在，已拒绝覆盖")
                elif e.errno == errno.ENOSPC: failed.append(f"{name}: 磁盘空间不足")
                else: failed.append(f"{name}: {e.strerror or e}")
            finally:
                if temp_path:
                    try: os.unlink(temp_path)
                    except OSError: pass
        if failed and not saved: return jsonify(code=500, msg="全部失败：" + "; ".join(failed[:3]))
        msg = f"成功 {len(saved)}"
        if failed: msg += f"，失败 {len(failed)}：" + "; ".join(failed[:3])
        return jsonify(code=0 if not failed else 200, msg=msg)
    except PathError as e: return jsonify(code=400, msg=str(e))
    except OSError as e:
        if e.errno == errno.ENOSPC: return jsonify(code=507, msg="磁盘空间不足")
        return jsonify(code=500, msg=str(e))

@bp.route("/api/files/download")
@login_required
@api_guard
def api_download():
    full = resolve(request.args.get("path", ""), must_exist=True)
    if os.path.isdir(full):
        buf = io.BytesIO()
        base = os.path.basename(full.rstrip("/")) or "root"
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(full):
                for fn in files:
                    fp = os.path.join(root, fn)
                    try: zf.write(fp, os.path.relpath(fp, os.path.dirname(full)))
                    except OSError: pass
        buf.seek(0)
        return send_file(buf, mimetype="application/zip", as_attachment=True,
                         download_name=f"{base}.zip")
    return send_file(full, as_attachment=True, download_name=os.path.basename(full))

@bp.route("/api/files/compress", methods=["POST"])
@login_required
@api_guard
def api_compress():
    d = request.get_json() or {}
    paths = d.get("paths") or []
    fmt = (d.get("format") or "zip").lower()
    archive_name = (d.get("archive_name") or "").strip()
    target_rel = d.get("target", "")
    if not paths: return jsonify(code=400, msg="未选择文件")
    target_dir = resolve(target_rel, must_exist=True)
    if not os.path.isdir(target_dir): return jsonify(code=400, msg="目标不是目录")
    if fmt == "zip": ext = ".zip"
    elif fmt in ("tar.gz", "tgz"): fmt = "tar.gz"; ext = ".tar.gz"
    elif fmt in ("tar.bz2", "tbz2"): fmt = "tar.bz2"; ext = ".tar.bz2"
    elif fmt == "tar": ext = ".tar"
    else: return jsonify(code=400, msg="不支持的压缩格式")
    if not archive_name:
        base = os.path.basename(paths[0].rstrip("/")) or "archive"
        archive_name = base + ext
    else:
        if not archive_name.lower().endswith((".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2")):
            archive_name += ext
        try: check_name(archive_name)
        except PathError as e: return jsonify(code=400, msg=str(e))
    archive_path = os.path.join(target_dir, archive_name)
    if os.path.lexists(archive_path):
        return jsonify(code=400, msg=f"压缩包 {archive_name} 已存在")
    try:
        if fmt == "zip":
            with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for rel in paths:
                    full = resolve(rel, must_exist=True)
                    if os.path.isdir(full) and not os.path.islink(full):
                        parent = os.path.dirname(full)
                        for root, dirs, files in os.walk(full):
                            arc_dir = os.path.relpath(root, parent)
                            if arc_dir and arc_dir != ".":
                                try: zf.write(root, arc_dir)
                                except OSError: pass
                            for fn in files:
                                fp = os.path.join(root, fn)
                                try: zf.write(fp, os.path.relpath(fp, parent))
                                except OSError: pass
                    else:
                        zf.write(full, os.path.basename(full))
        else:
            mode = "w:gz" if fmt == "tar.gz" else ("w:bz2" if fmt == "tar.bz2" else "w")
            with tarfile.open(archive_path, mode) as tf:
                for rel in paths:
                    full = resolve(rel, must_exist=True)
                    tf.add(full, arcname=os.path.basename(full))
    except OSError as e:
        try:
            if os.path.exists(archive_path): os.remove(archive_path)
        except OSError: pass
        if e.errno == errno.ENOSPC: return jsonify(code=507, msg="磁盘空间不足，压缩中断")
        return jsonify(code=500, msg=f"压缩失败：{e.strerror or e}")
    except Exception as e:
        try:
            if os.path.exists(archive_path): os.remove(archive_path)
        except OSError: pass
        return jsonify(code=500, msg=f"压缩失败：{e}")
    try: size = os.path.getsize(archive_path)
    except OSError: size = 0
    return jsonify(code=0, msg=f"已生成 {archive_name}（{human_size(size)}）", name=archive_name)

@bp.route("/api/files/extract", methods=["POST"])
@login_required
@api_guard
def api_extract():
    d = request.get_json() or {}
    path = d.get("path", "")
    target_rel = d.get("target", "")
    full = resolve(path, must_exist=True)
    if not os.path.isfile(full): return jsonify(code=400, msg="不是文件")
    if target_rel: target_dir = resolve(target_rel, must_exist=True)
    else: target_dir = os.path.dirname(full)
    if not os.path.isdir(target_dir): return jsonify(code=400, msg="目标不是目录")
    name = os.path.basename(full).lower()
    real_target = os.path.realpath(target_dir)
    def safe_join(member_name):
        target_path = os.path.realpath(os.path.join(real_target, member_name))
        if target_path != real_target and not target_path.startswith(real_target + os.sep):
            return None
        return target_path
    try:
        if name.endswith(".zip"):
            with zipfile.ZipFile(full, "r") as zf:
                for member in zf.namelist():
                    if safe_join(member) is None:
                        return jsonify(code=400, msg=f"压缩包含有非法路径：{member}")
                zf.extractall(real_target)
        elif name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar")):
            with tarfile.open(full, "r:*") as tf:
                for member in tf.getmembers():
                    if safe_join(member.name) is None:
                        return jsonify(code=400, msg=f"压缩包含有非法路径：{member.name}")
                    if os.path.isabs(member.name) or ".." in member.name.split("/"):
                        return jsonify(code=400, msg=f"压缩包含有非法路径：{member.name}")
                tf.extractall(real_target)
        else:
            return jsonify(code=400, msg="不支持的压缩格式（支持 .zip / .tar / .tar.gz / .tar.bz2 / .tar.xz）")
    except (zipfile.BadZipFile, tarfile.TarError) as e:
        return jsonify(code=500, msg=f"解压失败：{e}")
    except OSError as e:
        if e.errno == errno.ENOSPC: return jsonify(code=507, msg="磁盘空间不足，解压中断")
        return jsonify(code=500, msg=f"解压失败：{e.strerror or e}")
    except Exception as e:
        return jsonify(code=500, msg=f"解压失败：{e}")
    return jsonify(code=0, msg="解压完成")

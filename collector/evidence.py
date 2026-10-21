#!/usr/bin/env python3
"""B 段：采集运行中容器的运行时证据 + 宿主机内核信息。
用法: evidence.py <containers-inspect.json> <输出目录 evidence/>
只读取 /proc 和 docker top，不进入容器执行任何命令。
证据只代表采集这一刻：没看到加载 ≠ 永远不会加载。
"""
import glob
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

SO_RE = re.compile(r"\.so(\.|$)")  # libc.so.6 / libssl.so.3 / ld-linux-x86-64.so.2


def now():
    return datetime.now(timezone.utc).isoformat()


def norm(path):
    """/lib 在新版 Debian 是指向 usr/lib 的链接（实测），同一文件可能有两种写法。
    统一成 /usr/... 再比较，避免"加载了却对不上包"。"""
    for p in ("/lib/", "/lib64/", "/bin/", "/sbin/"):
        if path.startswith(p):
            return "/usr" + path
    return path


def dpkg_index(pid):
    """从宿主机经 /proc/<pid>/root 读容器里的 dpkg 文件清单：文件路径 → 包名"""
    idx = {}
    files = glob.glob(f"/proc/{pid}/root/var/lib/dpkg/info/*.list")
    for f in files:
        pkg = os.path.basename(f)[:-5].split(":", 1)[0]  # libc6:amd64.list → libc6
        try:
            with open(f, errors="replace") as fh:
                for line in fh:
                    idx[norm(line.rstrip("\n"))] = pkg
        except OSError:
            pass
    return idx, len(files)


def proc_info(pid, idx):
    info = {"pid": pid}
    try:
        info["exe"] = os.readlink(f"/proc/{pid}/exe")
    except OSError as e:
        info["exe"] = None
        info["error"] = f"读取失败（进程可能已退出）: {e.strerror}"
        return info
    info["exe_package"] = idx.get(norm(info["exe"]))
    libs = set()
    try:
        with open(f"/proc/{pid}/maps") as fh:
            for line in fh:
                parts = line.split(None, 5)
                if len(parts) == 6 and SO_RE.search(parts[5].strip()):
                    libs.add(parts[5].strip())
    except OSError as e:
        info["error"] = f"读取 maps 失败: {e.strerror}"
    info["libs"] = [{"path": p, "package": idx.get(norm(p))} for p in sorted(libs)]
    return info


def container_evidence(c):
    name = c["Name"].lstrip("/")
    main_pid = c["State"]["Pid"]
    idx, n_lists = dpkg_index(main_pid)
    top = subprocess.run(["docker", "top", c["Id"], "-eo", "pid,user,args"],
                         check=True, capture_output=True, text=True).stdout.splitlines()[1:]
    procs = []
    for line in top:
        pid, user, args = (line.split(None, 2) + [""])[:3]
        p = proc_info(int(pid), idx)
        p["user"] = user
        p["args"] = args
        procs.append(p)
    # 汇总：哪些包当前被哪些进程用着（可执行文件本身 + 加载的库）
    usage = {}
    for p in procs:
        hits = []
        if p.get("exe_package"):
            hits.append((p["exe_package"], "exe", p["exe"]))
        for lib in p.get("libs", []):
            if lib["package"]:
                hits.append((lib["package"], "lib", lib["path"]))
        for pkg, kind, path in hits:
            usage.setdefault(pkg, []).append({"pid": p["pid"], "args": p["args"], "via": kind, "path": path})
    unmatched = sorted({l["path"] for p in procs for l in p.get("libs", []) if not l["package"]})
    return {
        "collected_at": now(),
        "container": name,
        "container_id": c["Id"],
        "image_id": c["Image"],
        "config_user": (c.get("Config") or {}).get("User", ""),
        "dpkg_lists": n_lists,  # 0 = 容器里没有 dpkg，库无法对应到包
        "processes": procs,
        "package_usage": usage,
        "unmatched_libs": unmatched,  # 加载了但对不上任何包的库，研判时不能当作"没加载"
    }


def host_evidence():
    rr = "/var/run/reboot-required"
    pkgs_file = rr + ".pkgs"
    return {
        "collected_at": now(),
        "running_kernel": os.uname().release,
        "reboot_required": os.path.exists(rr),
        "reboot_required_pkgs": open(pkgs_file).read().split() if os.path.exists(pkgs_file) else [],
    }


def main():
    containers = json.load(open(sys.argv[1]))
    out = sys.argv[2]
    os.makedirs(out, exist_ok=True)
    for c in containers:
        ev = container_evidence(c)
        with open(os.path.join(out, f"container-{ev['container']}.json"), "w") as f:
            json.dump(ev, f, ensure_ascii=False, indent=2)
        print(f"  {ev['container']}: 进程 {len(ev['processes'])} 个，"
              f"正在使用的包 {len(ev['package_usage'])} 个，对不上包的库 {len(ev['unmatched_libs'])} 个")
    h = host_evidence()
    with open(os.path.join(out, "host.json"), "w") as f:
        json.dump(h, f, ensure_ascii=False, indent=2)
    print(f"  host: 内核 {h['running_kernel']}，需要重启 {h['reboot_required']}")


if __name__ == "__main__":
    main()

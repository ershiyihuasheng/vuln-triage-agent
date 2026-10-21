#!/usr/bin/env python3
"""第 6.5 步：每个镜像里，每个有漏洞的系统包装了哪些文件，并按路径分类。
用法: pkgfiles.py <快照目录>
做法: docker create（只创建、不启动）→ docker cp 取出 /var/lib/dpkg/info → docker rm。
      镜像里的程序不会被执行；运行中和没运行的镜像用同一种方法。
输出: <快照目录>/evidence/pkgfiles-<镜像短ID>.json
分类是白名单：只有全部文件都是 文档/头文件/静态库 时 inert=true（规则 R4 用）；
任何不认识的文件都让 inert=false，所以 R4 只会漏判、不会错判。
"""
import io
import json
import os
import re
import subprocess
import sys
import tarfile

DOC = ("/usr/share/doc/", "/usr/share/man/", "/usr/share/info/", "/usr/share/locale/",
       "/usr/share/lintian/", "/usr/share/bug/", "/usr/share/doc-base/")
EXEC_DIRS = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/games/", "/usr/local/bin/")
SO_RE = re.compile(r"\.so(\.|$)")
LIMIT = 50


def classify(path):
    name = os.path.basename(path)
    if name.endswith((".py", ".pl", ".sh", ".js", ".rb", ".lua")):
        return "script"       # 脚本也是会被执行的代码（例如 libc.so.6-gdb.py 不是共享库）
    if SO_RE.search(name):
        return "shared_lib"
    if path.startswith(EXEC_DIRS):
        return "executable"
    if path.startswith(DOC):
        return "doc"
    if path.startswith("/usr/include/") or name.endswith(".h"):
        return "header"
    if name.endswith(".a") or (name.endswith(".o") and path.startswith("/usr/lib/")):
        return "static"
    return "other"


def summarize(paths):
    paths = sorted(set(p for p in paths if p and p != "/."))
    # .list 里也记录目录：某一项是另一项的前缀 + "/"，它就是目录，不计入文件
    dirs = {os.path.dirname(p) for p in paths}
    files = [p for p in paths if p not in dirs]
    cls = {}
    for p in files:
        cls.setdefault(classify(p), []).append(p)
    counts = {k: len(v) for k, v in cls.items()}
    inert = bool(files) and set(cls) <= {"doc", "header", "static"}
    return {
        "files": len(files), "counts": counts, "inert": inert,
        "executables": cls.get("executable", [])[:LIMIT],
        "shared_libs": cls.get("shared_lib", [])[:LIMIT],
        "scripts": cls.get("script", [])[:LIMIT],
        "other_sample": cls.get("other", [])[:20],
    }


def read_lists(image_id):
    """返回 {包名: [文件路径]}；镜像里没有 dpkg 时返回 None"""
    cid = subprocess.run(["docker", "create", "--network", "none", "--entrypoint", "/nonexistent", image_id],
                         check=True, capture_output=True, text=True).stdout.strip()
    try:
        r = subprocess.run(["docker", "cp", f"{cid}:/var/lib/dpkg/info", "-"], capture_output=True)
        if r.returncode != 0:
            return None
        lists = {}
        with tarfile.open(fileobj=io.BytesIO(r.stdout)) as tf:
            for m in tf.getmembers():
                if m.isfile() and m.name.endswith(".list"):
                    pkg = os.path.basename(m.name)[:-5].split(":", 1)[0]   # libc6-dev:amd64.list → libc6-dev
                    data = tf.extractfile(m).read().decode("utf-8", "replace")
                    lists.setdefault(pkg, []).extend(data.splitlines())
        return lists
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True)


def main():
    snap = sys.argv[1]
    images = json.load(open(os.path.join(snap, "images.json")))
    pk = json.load(open(os.path.join(snap, "packages.json")))
    os.makedirs(os.path.join(snap, "evidence"), exist_ok=True)
    for t in pk["targets"]:
        wanted = {p["name"] for r in t["results"] if r.get("class") == "os-pkgs" for p in r["packages"]}
        img = next((i for i in images if i["short_id"] == t["short_id"]), None)
        if not wanted or img is None:
            continue
        lists = read_lists(img["id"])
        out = {"image_id": img["id"], "dpkg": lists is not None, "packages": {}}
        if lists is not None:
            for name in sorted(wanted):
                out["packages"][name] = summarize(lists[name]) if name in lists else {"missing_list": True}
        with open(os.path.join(snap, "evidence", f"pkgfiles-{t['short_id']}.json"), "w") as f:
            json.dump(out, f, ensure_ascii=False)
        n_inert = sum(1 for v in out["packages"].values() if v.get("inert"))
        print(f"  {t['short_id']}: dpkg={out['dpkg']} 有漏洞的系统包 {len(wanted)} 个，其中只含文档/头文件/静态库 {n_inert} 个")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""第 2 步准备：决定哪些包要交给 LLM。
上次已经研判过、且证据完全没变的包，直接沿用上次的结论（不再花 token）；其余的拆成批次。
缓存键 = 镜像ID + 包名 + 版本 + 路径/目标 + 漏洞集合 + usage + 是否只含文档类文件，任何一项变了都会重新研判。
用法: plan.py [--size 8]
读:  /work/pending.json  /work/cache.json（可没有）
写:  /work/batches/batch-000.json ...   /work/reused.json
"""
import argparse, glob, hashlib, json, os

OLD = {"正在使用": "受影响", "用不到": "不受影响", "证据不足": "待确认"}   # 旧版结论名 → 新名（兼容旧缓存）

ap = argparse.ArgumentParser()
ap.add_argument("--size", type=int, default=8)
ap.add_argument("--work", default="/work")
a = ap.parse_args()


def key(p):
    k = {"image": p["image"], "package": p["package"], "installed": p.get("installed", ""),
         "pkg_path": p.get("pkg_path", ""), "target": p.get("target", ""),
         "vulns": sorted(p.get("vulns", [])), "usage": p.get("usage", ""), "inert": p.get("inert", False)}
    return hashlib.sha256(json.dumps(k, sort_keys=True).encode()).hexdigest()


def legacy_key(p):
    """首次运行（2026-10-21）用的缓存键：没有区分同名包的路径。只对镜像里不重名的包使用，
    这样改了缓存键之后，已经研判过的 243 个结论不会全部失效、不用重跑"""
    k = {"image": p["image"], "package": p["package"], "installed": p.get("installed", ""),
         "vulns": sorted(p.get("vulns", [])), "usage": p.get("usage", ""), "inert": p.get("inert", False), "files": ""}
    return hashlib.sha256(json.dumps(k, sort_keys=True).encode()).hexdigest()


d = json.load(open(os.path.join(a.work, "pending.json")))
cache_path = os.path.join(a.work, "cache.json")
cache = json.load(open(cache_path)) if os.path.exists(cache_path) else {}

names_count = {}
for p in d["pending"]:
    names_count[(p["image"], p["package"])] = names_count.get((p["image"], p["package"]), 0) + 1
todo, reused = [], []
for p in d["pending"]:
    p["cache_key"] = key(p)
    c = cache.get(p["cache_key"])
    if c is None and names_count[(p["image"], p["package"])] == 1:
        c = cache.get(legacy_key(p))
    if c:
        c = dict(c, verdict=OLD.get(c["verdict"], c["verdict"]))
        reused.append({**p, **c, "source": "缓存（证据未变，沿用上次结论）"})
    else:
        todo.append(p)

bdir = os.path.join(a.work, "batches")
os.makedirs(bdir, exist_ok=True)
for f in glob.glob(os.path.join(bdir, "batch-[0-9]*.json")):
    os.remove(f)                       # 清掉上一次的批次，避免混进来
# 同一镜像里的同名包（如多份 node 依赖各带一份）不能放进同一批：校验按"镜像+包名"匹配 LLM 的结论，
# 同批出现两次就分不清哪条结论对应哪一份（首次运行有 4 个包因此被降级）
batches = []
for p in todo:
    k = (p["image"], p["package"])
    for b in batches:
        if len(b) < a.size and all((q["image"], q["package"]) != k for q in b):
            b.append(p); break
    else:
        batches.append([p])
names = []
for i, pkgs in enumerate(batches):
    name = f"{i:03d}"
    json.dump({"meta": d["meta"], "batch": name, "packages": pkgs},
              open(os.path.join(bdir, f"batch-{name}.json"), "w"), ensure_ascii=False)
    names.append(name)
json.dump(reused, open(os.path.join(a.work, "reused.json"), "w"), ensure_ascii=False)
print(json.dumps({"batches": names, "todo": len(todo), "reused": len(reused)}))

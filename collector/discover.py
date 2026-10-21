#!/usr/bin/env python3
"""把 docker inspect 的原始输出整理成镜像清单。
用法: discover.py <images-inspect.json> <containers-inspect.json> <输出 images.json> <输出 targets.txt>
"""
import json
import sys

images = json.load(open(sys.argv[1]))
containers = json.load(open(sys.argv[2]))

# 容器 inspect 里的 "Image" 是镜像 ID（sha256:...），用它把容器对应到镜像
running = {}
for c in containers:
    running.setdefault(c["Image"], []).append(c["Name"].lstrip("/"))

out = []
for im in images:
    cfg = im.get("Config") or {}  # 字段可能缺失（实测 User 就缺失），一律用 .get 取
    out.append({
        "id": im["Id"],
        "short_id": im["Id"].split(":", 1)[1][:12],
        "repo_tags": im.get("RepoTags") or [],
        "repo_digests": im.get("RepoDigests") or [],
        "entrypoint": cfg.get("Entrypoint"),
        "cmd": cfg.get("Cmd"),
        "user": cfg.get("User", ""),  # 空 = 未设置，Docker 默认以 root 运行
        "running_containers": running.get(im["Id"], []),
    })

with open(sys.argv[3], "w") as f:
    json.dump(out, f, ensure_ascii=False, indent=2)
with open(sys.argv[4], "w") as f:
    for o in out:
        f.write(o["short_id"] + "\n")
print(f"发现镜像 {len(out)} 个，其中正在运行 {sum(1 for o in out if o['running_containers'])} 个")

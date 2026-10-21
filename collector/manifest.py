#!/usr/bin/env python3
"""D 段：写 manifest.json —— 这份快照"是什么、用什么扫的、包含哪些文件"。
用法: manifest.py <快照目录> <快照ID>
写完 manifest 之后才由 collect.sh 创建 COMPLETE。
"""
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

snap, snap_id = sys.argv[1], sys.argv[2]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


tv = json.load(open(os.path.join(snap, "trivy-version.json")))
images = json.load(open(os.path.join(snap, "images.json")))
# 校验和覆盖 vulndata 要读的文件和证据文件；以后对比快照、排查"文件是否被改过"都用它
files = ["images.json", "packages.json", "cves.json"]
files += sorted(os.path.join("evidence", f) for f in os.listdir(os.path.join(snap, "evidence")))
manifest = {
    "snapshot_id": snap_id,
    "created_at": datetime.now(timezone.utc).isoformat(),
    "trivy_version": tv.get("Version"),
    "vuln_db_updated_at": (tv.get("VulnerabilityDB") or {}).get("UpdatedAt"),  # 漏洞库版本：结论变化时区分"库更新"还是"环境变化"
    "images": [{"short_id": i["short_id"], "id": i["id"], "repo_tags": i["repo_tags"],
                "repo_digests": i["repo_digests"], "running_containers": i["running_containers"]}
               for i in images],
    "files": {f: sha256(os.path.join(snap, f)) for f in files},
}
with open(os.path.join(snap, "manifest.json"), "w") as f:
    json.dump(manifest, f, ensure_ascii=False, indent=2)
print(f"  manifest: 镜像 {len(images)} 个，漏洞库 {manifest['vuln_db_updated_at']}，校验文件 {len(files)} 个")

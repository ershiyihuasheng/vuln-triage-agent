#!/usr/bin/env python3
"""C 段：把 Trivy 原始结果整理成两个小文件，供 vulndata 服务读取。
用法: normalize.py <快照目录>
  读:  <快照目录>/images.json, <快照目录>/raw/image-*.json
  写:  <快照目录>/packages.json  按 镜像 → 扫描目标 → 软件包 组织，每个包下列出漏洞
       <快照目录>/cves.json      每个 CVE 一条（去重），存描述等只和 CVE 有关的信息
原始结果 raw/ 保留不动：整理会丢字段，结论被质疑时以原始结果为准。
"""
import glob
import json
import os
import sys

snap = sys.argv[1]
images = {i["short_id"]: i for i in json.load(open(os.path.join(snap, "images.json")))}

targets = []
cves = {}
for path in sorted(glob.glob(os.path.join(snap, "raw", "image-*.json"))):
    sid = os.path.basename(path)[len("image-"):-len(".json")]
    raw = json.load(open(path))
    meta = raw.get("Metadata") or {}
    img = images.get(sid, {})
    results = []
    for r in raw.get("Results") or []:
        pkgs = {}
        for v in r.get("Vulnerabilities") or []:
            # 同一个包（同名、同路径、同版本）的多条漏洞归到一起
            key = (v.get("PkgName"), v.get("PkgPath", ""), v.get("InstalledVersion"))
            p = pkgs.setdefault(key, {
                "name": key[0], "pkg_path": key[1], "installed": key[2], "vulns": []})
            p["vulns"].append({
                "id": v.get("VulnerabilityID"),
                "fixed": v.get("FixedVersion", ""),   # 空 = 尚无修复版本
                "status": v.get("Status", ""),
                "severity": v.get("Severity", ""),
            })
            # 只和 CVE 有关的信息，每个 CVE 只存一份（实测宿主机同一批 CVE 被 8 个包重复记录）
            cid = v.get("VulnerabilityID")
            if cid and cid not in cves:
                cves[cid] = {
                    "title": v.get("Title", ""),
                    "description": v.get("Description", ""),
                    "cvss": v.get("CVSS") or {},
                    "cwe": v.get("CweIDs") or [],
                    "url": v.get("PrimaryURL", ""),
                    "published": v.get("PublishedDate", ""),
                }
        results.append({
            "target": r.get("Target"), "class": r.get("Class"), "type": r.get("Type"),
            "packages": sorted(pkgs.values(), key=lambda p: (p["name"] or "", p["pkg_path"])),
        })
    targets.append({
        "short_id": sid,
        "image_id": img.get("id"),
        "repo_tags": img.get("repo_tags", []),
        "os": meta.get("OS"),
        "running_containers": img.get("running_containers", []),
        "results": results,
    })

with open(os.path.join(snap, "packages.json"), "w") as f:
    json.dump({"targets": targets}, f, ensure_ascii=False)
with open(os.path.join(snap, "cves.json"), "w") as f:
    json.dump(cves, f, ensure_ascii=False)

for t in targets:
    recs = sum(len(p["vulns"]) for r in t["results"] for p in r["packages"])
    ids = {v["id"] for r in t["results"] for p in r["packages"] for v in p["vulns"]}
    npk = sum(len(r["packages"]) for r in t["results"])
    print(f"  {t['short_id']} {t['repo_tags']}: 漏洞记录 {recs} 条，不同 CVE {len(ids)} 个，有漏洞的包 {npk} 个")
for name in ("packages.json", "cves.json"):
    print(f"  {name}: {os.path.getsize(os.path.join(snap, name)) / 1e6:.1f} MB")
print(f"  CVE 去重后共 {len(cves)} 个")

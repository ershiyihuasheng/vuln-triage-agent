#!/usr/bin/env python3
"""第 2 步前半：为每一批待研判的包，由脚本经 OctoBus 取好证据，拼成一段给 LLM 的输入。
LLM 只负责判断，不再自己查询（agent 方式每查一次就重发全部上下文，实测每包 5～16 万 token）。
用法: build_prompts.py --batch test        → /work/prompts/batch-test.txt
      build_prompts.py --all               → 每个 /work/batches/batch-*.json 各一份
"""
import argparse
import glob
import json
import os
import subprocess
import sys

CAPSET = os.environ.get("VULNDATA_CAPSET", "internal/triage")
INSTANCE = os.environ.get("VULNDATA_INSTANCE", "vulndata-prod")
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4, "": 5}
CVE_DETAIL = 3        # 每个包附带详细描述的漏洞数（按严重程度挑）
CVE_TITLES = 15       # 每个包附带标题的漏洞数
DESC_CHARS = 700      # 描述截断长度


def call(method, req):
    cmd = ["grpcurl", "-plaintext", "-max-msg-sz", str(64 << 20),
           "-H", f"x-capability-sandbox-token: {os.environ['CAP_TOKEN']}",
           "-H", f"x-octobus-capset: {CAPSET}", "-H", f"x-octobus-instance: {INSTANCE}",
           "-d", json.dumps(req), os.environ["CAP_GRPC_TARGET"], f"vulndata.v1.VulndataService/{method}"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"调用 {method} 失败: {r.stderr.strip()}")
    return json.loads(r.stdout)


def evidence_for(snap, pkg, cve_cache):
    ev = call("GetPackageEvidence", {"snapshotId": snap, "imageShortId": pkg["image"], "package": pkg["package"]})
    # 同名包可能有多份（例如多个 node 依赖里各带一份），按 版本+路径+目标 挑出对应的那一份
    cands = ev.get("packages", [])
    match = [c for c in cands if c.get("installed", "") == pkg.get("installed", "")
             and c.get("pkgPath", "") == pkg.get("pkg_path", "") and c.get("target", "") == pkg.get("target", "")]
    pk = (match or cands or [{}])[0]
    vulns = list(pk.get("vulns", []))
    vulns.sort(key=lambda v: SEV_ORDER.get(v.get("severity", ""), 5))
    details = []
    for v in vulns[:CVE_TITLES]:
        vid = v.get("id")
        if vid not in cve_cache:
            c = call("GetCVE", {"snapshotId": snap, "cveId": vid})
            cve_cache[vid] = {"title": c.get("title", ""), "description": c.get("description", "")[:DESC_CHARS]}
        d = {"id": vid, "severity": v.get("severity", ""), "fixed": v.get("fixed", ""), "title": cve_cache[vid]["title"]}
        if len(details) < CVE_DETAIL:
            d["description"] = cve_cache[vid]["description"]
        details.append(d)
    return {
        "image": pkg["image"], "repo_tags": ev.get("repoTags", []), "package": pkg["package"],
        "installed": pk.get("installed", ""), "type": pk.get("type", ""), "target": pk.get("target", ""), "pkg_path": pk.get("pkgPath", ""),
        "usage": pk.get("usage", ""), "used_via": pk.get("usedVia", []),
        "files": pk.get("files", {}),
        "image_running_containers": ev.get("runningContainers", []), "image_user": ev.get("imageUser", ""),
        "image_entrypoint": ev.get("entrypoint", []), "image_cmd": ev.get("cmd", []),
        "vulns_total": ev.get("vulnsTotal", 0), "vulns": details,
    }


def build(batch_path, out_dir, instructions):
    b = json.load(open(batch_path))
    snap = b["meta"]["snapshot_id"]
    cache = {}
    items = [evidence_for(snap, p, cache) for p in b["packages"]]
    data = {"snapshot_id": snap, "batch": b["batch"], "host_kernel": b["meta"].get("host_kernel", ""),
            "drivers": b["meta"].get("drivers", []), "packages": items}
    text = instructions + "\n\n## 证据（JSON）\n\n" + json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    path = os.path.join(out_dir, f"batch-{b['batch']}.txt")
    open(path, "w").write(text)
    print(f"{path} 包 {len(items)} 个 字符 {len(text)}", file=sys.stderr)
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--batches", default="/work/batches")
    ap.add_argument("--out", default="/work/prompts")
    a = ap.parse_args()
    instructions = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "judge_prompt.md")).read()
    os.makedirs(a.out, exist_ok=True)
    paths = sorted(glob.glob(os.path.join(a.batches, "batch-[0-9]*.json"))) if a.all else [os.path.join(a.batches, f"batch-{a.batch}.json")]
    for p in paths:
        print(build(p, a.out, instructions))


if __name__ == "__main__":
    main()

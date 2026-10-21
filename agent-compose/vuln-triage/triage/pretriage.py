#!/usr/bin/env python3
"""第 1 步：确定性预研判。在沙箱里运行，经 OctoBus 调 vulndata 取数据，按 rules.yaml 套规则。
输出:
  <out>/pretriage.json  每个包的结论（规则命中的）或 "LLM"（待 LLM 研判）
  <out>/pending.json    只含待 LLM 研判的包，交给第 2 步
任何一次调用失败都以非零退出码退出（scheduler.shell 不会因非零退出抛异常，由 scheduler 脚本检查 success）。
"""
import argparse
import collections
import json
import os
import subprocess
import sys

import yaml

CAPSET = os.environ.get("VULNDATA_CAPSET", "internal/triage")
INSTANCE = os.environ.get("VULNDATA_INSTANCE", "vulndata-prod")


def call(method, req):
    """经 capproxy → OctoBus 网关 → vulndata 调用一个方法"""
    cmd = ["grpcurl", "-plaintext", "-max-msg-sz", str(64 << 20),
           "-H", f"x-capability-sandbox-token: {os.environ['CAP_TOKEN']}",
           "-H", f"x-octobus-capset: {CAPSET}",
           "-H", f"x-octobus-instance: {INSTANCE}",
           "-d", json.dumps(req), os.environ["CAP_GRPC_TARGET"],
           f"vulndata.v1.VulndataService/{method}"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"调用 {method} 失败: {r.stderr.strip()}")
    return json.loads(r.stdout)  # 注意：值为默认值的字段会被省略，读取一律用 .get


def matches(rule, pkg, ctx):
    m = rule.get("match", {})
    if "package" in m and pkg.get("name") not in m["package"]:
        return False
    if "usage" in m and pkg.get("usage", "") not in m["usage"]:
        return False
    if "inert" in m and bool(pkg.get("inert", False)) not in m["inert"]:   # false 会被 ProtoJSON 省略，默认 False
        return False
    return True


def precondition(rule, ctx):
    """返回 (是否满足, 说明)"""
    req = rule.get("require", {})
    if "all_agent_drivers_in" in req:
        if ctx["agents_error"]:
            return False, f"驱动类型未知（{ctx['agents_error']}）"
        if not ctx["drivers"]:
            return False, "没有任何 agent 记录，驱动类型无法确认"
        bad = [d for d in ctx["drivers"] if d not in req["all_agent_drivers_in"]]
        if bad:
            return False, f"存在驱动 {bad}"
    return True, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot-id", default="")
    ap.add_argument("--rules", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.yaml"))
    ap.add_argument("--out", default="/work")
    ap.add_argument("--images", default="", help="只研判这些镜像：逗号分隔，按镜像名包含或短 ID 匹配；为空 = 全部")
    a = ap.parse_args()

    conf = yaml.safe_load(open(a.rules))
    options = conf.get("options", {})

    summary = call("GetSummary", {"snapshotId": a.snapshot_id} if a.snapshot_id else {})
    snap = summary["snapshotId"]  # 之后所有调用都固定这份快照
    agents = summary.get("agents", [])
    ctx = {
        "host_kernel": summary.get("hostKernel", ""),
        "drivers": sorted({x.get("driver", "") for x in agents}),
        "agents_error": summary.get("agentsError", ""),
    }

    want = [x.strip() for x in a.images.split(",") if x.strip()]
    def selected(img):
        if not want:
            return True
        names = img.get("repoTags", []) + [img["shortId"]]
        return any(w in n for w in want for n in names)

    results, pending = [], []
    for img in summary.get("images", []):
        if not selected(img):
            continue
        lp = call("ListPackages", {"snapshotId": snap, "imageShortId": img["shortId"]})
        for p in lp.get("packages", []):
            rec = {
                "image": img["shortId"], "repo_tags": img.get("repoTags", []),
                "package": p.get("name", ""), "installed": p.get("installed", ""),
                "target": p.get("target", ""), "type": p.get("type", ""),
                "usage": p.get("usage", ""), "used_via": p.get("usedVia", []), "inert": p.get("inert", False),
                "pkg_path": p.get("pkgPath", ""), "class": p.get("class", ""),
                "vulns": [v.get("id") for v in p.get("vulns", [])],
                "vuln_details": [{"id": v.get("id"), "severity": v.get("severity", ""), "fixed": v.get("fixed", "")} for v in p.get("vulns", [])],
                "verdict": "LLM", "basis": "", "rule": "", "reason": "", "notes": [],
            }
            for rule in conf.get("rules", []):
                if not matches(rule, p, ctx):
                    continue
                ok, why = precondition(rule, ctx)
                if not ok:
                    rec["notes"].append(f"{rule['id']} 前提不满足：{why}")
                    continue
                verdict = rule["verdict"]
                if verdict.startswith("@"):
                    verdict = options[verdict[1:]]
                if verdict == "llm":
                    rec["notes"].append(f"{rule['id']} 配置为交给 LLM")
                    break
                rec.update(verdict=verdict, basis=rule.get("basis", ""), rule=rule["id"], reason=rule["reason"].format(
                    used_via="、".join(p.get("usedVia", [])) or "-",
                    host_kernel=ctx["host_kernel"] or "未知",
                    drivers=",".join(ctx["drivers"]) or "未知"))
                break
            results.append(rec)
            if rec["verdict"] == "LLM":
                pending.append(rec)

    os.makedirs(a.out, exist_ok=True)
    meta = {"snapshot_id": snap, "images_filter": want, "stale": summary.get("stale", False),
            "age_hours": summary.get("ageHours", 0), "host_kernel": ctx["host_kernel"],
            "drivers": ctx["drivers"], "agents_error": ctx["agents_error"], "options": options}
    json.dump({"meta": meta, "results": results}, open(os.path.join(a.out, "pretriage.json"), "w"), ensure_ascii=False, indent=1)
    json.dump({"meta": meta, "pending": pending}, open(os.path.join(a.out, "pending.json"), "w"), ensure_ascii=False, indent=1)

    # 摘要：每个镜像各结论多少个包；待 LLM 的包数和涉及的不同漏洞数（决定第 2 步的工作量）
    print(f"快照 {snap}  已过 {meta['age_hours']} 小时  过期: {meta['stale']}  驱动: {ctx['drivers']}")
    by = collections.defaultdict(collections.Counter)
    for r in results:
        by[(r["image"], tuple(r["repo_tags"]))][f"{r['verdict']}({r['rule']})" if r["rule"] else r["verdict"]] += 1
    for (sid, tags), c in by.items():
        print(f"  {sid} {list(tags)}: {dict(c)}")
    print(f"待 LLM 研判: {len(pending)} 个包，涉及不同漏洞 {len({v for r in pending for v in r['vulns']})} 个")
    print("待 LLM 的包按 usage 分:", dict(collections.Counter(r["usage"] for r in pending)))


if __name__ == "__main__":
    main()

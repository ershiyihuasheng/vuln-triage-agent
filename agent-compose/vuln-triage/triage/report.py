#!/usr/bin/env python3
"""输出报告：/work/report.md，并按快照存一份历史：/work/reports/<快照ID>.md
结论的主语是"这个包上报告的漏洞"：受影响 / 不受影响（附前提条件）/ 待确认。"""
import collections, json, os, sys

W = sys.argv[1] if len(sys.argv) > 1 else "/work"
d = json.load(open(f"{W}/final.json"))
m, s, rs = d["meta"], d["stats"], d["results"]
ORDER = {"受影响": 0, "待确认": 1, "不受影响": 2}
ADVICE = {"受影响": "优先修复", "待确认": "人工确认", "不受影响": "随正常周期升级"}
SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEV_CN = {"CRITICAL": "严重", "HIGH": "高", "MEDIUM": "中", "LOW": "低"}


def cell(x):
    return str(x).replace("|", "/").replace("\n", " ")


def cves(r):
    det = r.get("vuln_details") or [{"id": v, "severity": "", "fixed": ""} for v in r.get("vulns", [])]
    c = collections.Counter(v.get("severity", "") for v in det)
    counts = " ".join(f"{SEV_CN[k]}{c[k]}" for k in SEV if c[k]) or f"共{len(det)}"
    top = sorted(det, key=lambda v: SEV.get(v.get("severity", ""), 9))[:3]
    tops = "<br>".join(f"{v['id']}" + (f"（修复：{v['fixed']}）" if v.get("fixed") else "（暂无修复）") for v in top)
    more = f"<br>…另 {len(det) - 3} 个" if len(det) > 3 else ""
    return counts, tops + more


total = collections.Counter(r["verdict"] for r in rs)
L = ["# 镜像漏洞适用性研判报告", "",
     "结论的含义（主语是“这个包上报告的漏洞”）：**受影响** = 漏洞所在代码会被执行；"
     "**不受影响** = 当前环境下触发不了，附前提条件，条件变化即失效；**待确认** = 证据不足以判断。", "",
     f"- 快照：{m['snapshot_id']}（生成后 {m.get('age_hours', 0)} 小时，{'**已过期**' if m.get('stale') else '未过期'}）",
     f"- 宿主机内核：{m.get('host_kernel')}；沙箱驱动：{', '.join(m.get('drivers', []))}",
     f"- 研判范围：{', '.join(m.get('images_filter') or []) or '全部镜像'}",
     f"- 合计 {len(rs)} 个有漏洞的包：受影响 {total['受影响']}，待确认 {total['待确认']}，不受影响 {total['不受影响']}",
     f"- 结论来源：规则 {s['rule']}，沿用缓存 {s['cache']}，LLM {s['llm']}，LLM 结论被校验降级 {s['downgraded']}，LLM 失败批次 {s['llm_failed_batches']}",
     "- 依据类型标“（推断）”的，是从 LLM 理由文字推断的分类；规则结论的依据类型是确定的", ""]
by_img = collections.defaultdict(list)
for r in rs:
    by_img[(r["image"], tuple(r.get("repo_tags", [])))].append(r)
for (img, tags), items in by_img.items():
    c = collections.Counter(r["verdict"] for r in items)
    L += [f"## {', '.join(tags) or img}（{img}）", "",
          f"受影响 {c['受影响']} ｜ 待确认 {c['待确认']} ｜ 不受影响 {c['不受影响']}", "",
          "| 包 | 版本 | 漏洞数 | 主要 CVE | 结论 | 依据类型 | 说明 | 前提条件 | 建议 | 来源 |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for r in sorted(items, key=lambda r: (ORDER.get(r["verdict"], 9), r["package"])):
        counts, tops = cves(r)
        cond = "；".join(r.get("conditions") or []) or "—"
        L.append(f"| {cell(r['package'])} | {cell(r.get('installed', ''))} | {counts} | {tops} | **{r['verdict']}** | "
                 f"{cell(r.get('basis', ''))} | {cell(r.get('reason', ''))} | {cell(cond)} | {ADVICE.get(r['verdict'], '')} | {cell(r.get('source', ''))} |")
    L.append("")
text = "\n".join(L)
open(f"{W}/report.md", "w").write(text)
os.makedirs(f"{W}/reports", exist_ok=True)
open(f"{W}/reports/{m['snapshot_id']}.md", "w").write(text)
print(f"{W}/report.md 已生成：{len(rs)} 个包（历史：{W}/reports/{m['snapshot_id']}.md）")

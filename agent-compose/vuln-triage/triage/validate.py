#!/usr/bin/env python3
"""第 3 步：校验 LLM 的结论（不受 LLM 控制的确定性检查），合并规则结论和缓存，写出最终结果。
- 不合格的结论一律降级为"待确认"，并记录降级原因。
- 结论统一换成以"这个包上报告的漏洞"为主语的说法：受影响 / 不受影响 / 待确认。
  LLM 仍按已验证的提示词输出旧说法（正在使用/用不到/证据不足），在这里换名；
  依据类型：规则结论来自规则本身；LLM 结论从理由文字推断，并标注"（推断）"。
读:  /work/pretriage.json  /work/batches/*.json  /work/llm/<批次>.txt|.model  /work/reused.json
写:  /work/final.json   并把通过校验的 LLM 结论写进 /work/cache.json
"""
import glob, json, os, re, sys
from datetime import datetime, timezone

W = sys.argv[1] if len(sys.argv) > 1 else "/work"
NEW = {"正在使用": "受影响", "用不到": "不受影响", "证据不足": "待确认",
       "受影响": "受影响", "不受影响": "不受影响", "待确认": "待确认"}
RULE_BASIS = {"R2": "进程正在加载或运行", "R1": "包内无可执行代码", "R4": "包内无可执行代码", "R3": "组件仅特定驱动使用"}
STATIC_REFS = ("files", "description", "image_cmd", "image_entrypoint", "vulns[")
AFFECT_REFS = ("image_cmd", "image_entrypoint", "used_via", "files")


START = re.compile(r'\{\s*"(?:batch|results)"')


def parse(text, batch=None):
    """百炼不支持 JSON Schema 约束（实测），不同模型输出格式不同：
    kimi-k3 只输出 JSON；deepseek-v4.1-flash 先输出大段思考过程（其中也有 { 和草稿 JSON），最后才是结果。
    做法：找出所有以 {"batch" 或 {"results" 开头的位置，从最后一个往前逐个按 JSON 语法解析，
    取第一个含 results 列表、且 batch 字段（若有）与本批编号一致的对象。"""
    dec = json.JSONDecoder()
    for m in reversed(list(START.finditer(text))):
        try:
            obj, _ = dec.raw_decode(text, m.start())
        except ValueError:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("results"), list):
            if batch and obj.get("batch") not in (None, batch):
                continue
            return obj
    raise ValueError("输出里没有可解析的 results 对象")


def infer_basis(verdict, reason, evidence):
    t = reason + " " + " ".join(str(x) for x in evidence)
    if verdict == "受影响":
        return "启动命令直接运行（推断）" if any(k in t for k in ("image_cmd", "image_entrypoint", "启动命令")) else "会被运行（推断）"
    if verdict == "不受影响":
        if any(k in t for k in ("头文件", "无可执行", "没有可执行", "只含文档", "仅含文档", "纯编译期")):
            return "包内无可执行代码（推断）"
        if any(k in t for k in ("不在本包", "不在该包", "不在这个包", "不含", "没有", "只有", "仅有", "只提供", "仅提供", "不包含")):
            return "漏洞代码不在本包（推断）"
        return "触发条件不满足（推断）"
    return "证据不足"


def check(r):
    v = NEW.get(r.get("verdict"))
    ev = " ".join(str(x) for x in (r.get("evidence") or []))
    if v is None:
        return f"结论 {r.get('verdict')!r} 不在三种结论之内"
    if not r.get("reason"):
        return "没有写理由"
    if v == "不受影响":
        if not r.get("conditions"):
            return "判为不受影响但没有写前提条件"
        if not any(k in ev for k in STATIC_REFS):
            return "判为不受影响但没有引用静态证据（files/描述/启动命令），可能只是依据了'采集时没看到使用'"
    if v == "受影响" and not any(k in ev for k in AFFECT_REFS):
        return "判为受影响但没有引用启动命令/使用证据/文件清单"
    return ""


def base(p):
    return {k: p.get(k, d) for k, d in (("image", ""), ("repo_tags", []), ("package", ""), ("installed", ""),
                                         ("usage", ""), ("vulns", []), ("vuln_details", []))}


now = datetime.now(timezone.utc).isoformat()
pre = json.load(open(os.path.join(W, "pretriage.json")))
cache_path = os.path.join(W, "cache.json")
cache = json.load(open(cache_path)) if os.path.exists(cache_path) else {}
final, stats = [], {"rule": 0, "cache": 0, "llm": 0, "downgraded": 0, "llm_failed_batches": 0}

for r in pre["results"]:
    if r["verdict"] != "LLM":
        final.append({**base(r), "verdict": NEW.get(r["verdict"], r["verdict"]),
                      "basis": r.get("basis") or RULE_BASIS.get(r["rule"], ""), "reason": r["reason"],
                      "conditions": [], "source": f"规则 {r['rule']}"})
        stats["rule"] += 1

for r in json.load(open(os.path.join(W, "reused.json"))):
    v = NEW.get(r["verdict"], r["verdict"])
    final.append({**base(r), "verdict": v, "basis": r.get("basis") or infer_basis(v, r.get("reason", ""), r.get("evidence", [])),
                  "reason": r.get("reason", ""), "conditions": r.get("conditions", []), "evidence": r.get("evidence", []),
                  "model": r.get("model", ""), "source": r.get("source", "缓存")})
    stats["cache"] += 1

for bpath in sorted(glob.glob(os.path.join(W, "batches", "batch-[0-9]*.json"))):
    b = json.load(open(bpath)); name = b["batch"]
    mpath = os.path.join(W, "llm", f"{name}.model")
    model = open(mpath).read().strip() if os.path.exists(mpath) else ""
    try:
        results, err_all = parse(open(os.path.join(W, "llm", f"{name}.txt")).read(), name)["results"], ""
    except Exception as e:
        results, err_all = [], f"LLM 输出无法使用：{e}"
        stats["llm_failed_batches"] += 1
    by = {}
    for r in results:
        by.setdefault((r.get("image"), r.get("package")), []).append(r)
    for p in b["packages"]:
        got = by.get((p["image"], p["package"]), [])
        problem = err_all or ("没有对应的结论" if not got else "同一个包给了多条结论" if len(got) > 1 else check(got[0]))
        src = f"LLM（{model}）"
        if problem:
            final.append({**base(p), "verdict": "待确认", "basis": "证据不足", "reason": f"LLM 结论未通过校验：{problem}",
                          "llm_verdict": got[0].get("verdict") if got else "", "llm_reason": got[0].get("reason", "") if got else "",
                          "conditions": [], "evidence": [], "model": model, "source": src, "downgraded": True})
            stats["downgraded"] += 1
            continue
        r = got[0]
        v = NEW[r["verdict"]]
        rec = {**base(p), "verdict": v, "basis": infer_basis(v, r["reason"], r.get("evidence", [])), "reason": r["reason"],
               "evidence": r.get("evidence", []), "conditions": r.get("conditions", []),
               "missing_evidence": r.get("missing_evidence", []), "model": model, "source": src}
        final.append(rec); stats["llm"] += 1
        cache[p["cache_key"]] = {k: rec[k] for k in ("verdict", "basis", "reason", "evidence", "conditions", "missing_evidence", "model")} | \
            {"snapshot_id": pre["meta"]["snapshot_id"], "judged_at": now}

json.dump({"meta": pre["meta"] | {"generated_at": now}, "stats": stats, "results": final},
          open(os.path.join(W, "final.json"), "w"), ensure_ascii=False, indent=1)
json.dump(cache, open(cache_path, "w"), ensure_ascii=False)
print(json.dumps(stats, ensure_ascii=False))

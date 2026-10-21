// 读取快照的全部逻辑。只读、不研判；所有输入都当作不可信（调用参数可能来自 LLM）。
// 错误通过注入的 errors 抛出，便于脱离 SDK 单独测试。
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const SNAPSHOT_ID_RE = /^\d{8}T\d{6}$/;           // 采集脚本 date +%Y%m%dT%H%M%S 生成的格式
const IMAGE_ID_RE = /^[0-9a-f]{12}$/;              // discover.py 生成的 12 位短 ID
const VULN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$/;  // CVE-/GHSA-/DLA- 等
const MAX_PACKAGE_NAME = 256;
const MAX_VULNS_PER_EVIDENCE = 200;                // GetPackageEvidence 返回漏洞条数上限

export function createSnapshotReader(config, errors) {
  const dir = String(config.snapshotDir || "/snapshots");
  const maxAgeHours = Number(config.maxAgeHours ?? 26);

  // ---------- 选快照 ----------
  function resolveSnapshot(requested) {
    const id = String(requested ?? "");
    if (id !== "") {
      if (!SNAPSHOT_ID_RE.test(id)) throw errors.invalid("snapshotId 格式必须是 YYYYMMDDTHHMMSS");
      if (!fs.existsSync(path.join(dir, id, "COMPLETE"))) throw errors.notFound(`快照 ${id} 不存在或未完成`);
      return id;
    }
    const ids = fs.readdirSync(dir)
      .filter((n) => SNAPSHOT_ID_RE.test(n) && fs.existsSync(path.join(dir, n, "COMPLETE")))
      .sort();
    if (ids.length === 0) throw errors.notFound("没有任何完整快照");
    return ids[ids.length - 1];
  }

  // ---------- 读文件：先用 manifest 的 sha256 校验 ----------
  const cache = new Map();
  function readJson(snapId, rel) {
    const key = `${snapId}/${rel}`;
    if (cache.has(key)) return cache.get(key);
    const base = path.join(dir, snapId);
    const manifest = JSON.parse(fs.readFileSync(path.join(base, "manifest.json"), "utf8"));
    if (rel === "manifest.json") { cache.set(key, manifest); return manifest; }
    const expected = manifest.files?.[rel];
    if (!expected) throw errors.failed(`manifest 里没有 ${rel} 的校验和`);
    const buf = fs.readFileSync(path.join(base, rel));
    const actual = crypto.createHash("sha256").update(buf).digest("hex");
    if (actual !== expected) throw errors.failed(`${rel} 校验和与 manifest 不一致，数据可能被改过`);
    const value = JSON.parse(buf.toString("utf8"));
    cache.set(key, value);
    return value;
  }

  function evidenceFiles(snapId) {
    return Object.keys(readJson(snapId, "manifest.json").files || {}).filter((f) => f.startsWith("evidence/"));
  }

  function hostAndAgents(snapId) {
    const host = readJson(snapId, "evidence/host.json");
    const ag = readJson(snapId, "evidence/agents.json");
    const agents = (ag.agents || []).map((a) => ({ name: a.name || "", image: a.image || "", driver: a.driver || "" }));
    return { host, agents, agentsError: ag.error || "" };
  }

  function findImage(snapId, shortId) {
    const sid = String(shortId ?? "");
    if (!IMAGE_ID_RE.test(sid)) throw errors.invalid("imageShortId 必须是 12 位十六进制短 ID");
    const img = readJson(snapId, "images.json").find((i) => i.short_id === sid);
    if (!img) throw errors.notFound(`快照 ${snapId} 里没有镜像 ${sid}`);
    const target = readJson(snapId, "packages.json").targets.find((t) => t.short_id === sid) || { results: [] };
    return { img, target };
  }

  // 这个镜像正在运行的容器的证据
  function containerEvidence(snapId, img) {
    return (img.running_containers || [])
      .map((name) => `evidence/container-${name}.json`)
      .filter((rel) => evidenceFiles(snapId).includes(rel))
      .map((rel) => readJson(snapId, rel));
  }

  // 一个包的运行时使用情况
  function usageOf(pkg, result, evs, running) {
    const uses = [];
    if (result.class === "os-pkgs") {
      for (const ev of evs) for (const u of ev.package_usage?.[pkg.name] || [])
        uses.push({ container: ev.container, pid: u.pid, user: procUser(ev, u.pid), args: u.args, via: u.via, path: u.path });
    } else if (result.type === "gobinary") {
      // Go 程序把依赖编译进可执行文件（实测 octobus 主程序不加载任何 .so），只能看这个文件是否正被运行
      const exe = "/" + String(result.target || "").replace(/^\/+/, "");
      for (const ev of evs) for (const p of ev.processes || [])
        if (p.exe === exe) uses.push({ container: ev.container, pid: p.pid, user: p.user || "", args: p.args || "", via: "exe", path: exe });
    } else {
      return { usage: "not_tracked", uses };
    }
    if (!running) return { usage: "no_runtime_evidence", uses };
    return { usage: uses.length ? "in_use" : "not_observed", uses };
  }

  function procUser(ev, pid) {
    return (ev.processes || []).find((p) => p.pid === pid)?.user || "";
  }

  // 包文件清单（第 6.5 步采集）；快照里没有这项证据时返回 null
  function pkgFiles(snapId, shortId) {
    const rel = `evidence/pkgfiles-${shortId}.json`;
    return evidenceFiles(snapId).includes(rel) ? readJson(snapId, rel) : null;
  }

  function fileSummary(pf, pkg, result) {
    if (result.class !== "os-pkgs") return { note: "不是系统包，没有 dpkg 文件清单" };
    if (!pf) return { note: "快照里没有包文件清单" };
    if (!pf.dpkg) return { note: "镜像里没有 dpkg" };
    const f = pf.packages?.[pkg.name];
    if (!f || f.missing_list) return { note: "该包没有 dpkg 文件清单" };
    return { files: f.files || 0, counts: f.counts || {}, executables: strs(f.executables),
      sharedLibs: strs(f.shared_libs), scripts: strs(f.scripts), otherSample: strs(f.other_sample) };
  }

  function isInert(pf, pkg, result) {
    return result.class === "os-pkgs" && !!pf?.dpkg && pf.packages?.[pkg.name]?.inert === true;
  }

  function brief(pkg, result, usage, uses, vulns) {
    return {
      name: pkg.name || "", installed: pkg.installed || "", target: result.target || "",
      class: result.class || "", type: result.type || "", pkgPath: pkg.pkg_path || "",
      usage, usedVia: [...new Set(uses.map((u) => `${u.via}:${u.path}`))],
      vulns: vulns.map((v) => ({ id: v.id || "", severity: v.severity || "", fixed: v.fixed || "", status: v.status || "" })),
    };
  }

  const strs = (v) => (Array.isArray(v) ? v.map(String) : []);

  // ---------- 4 个方法 ----------
  function getSummary(req) {
    const snapId = resolveSnapshot(req.snapshotId);
    const m = readJson(snapId, "manifest.json");
    const images = readJson(snapId, "images.json");
    const pk = readJson(snapId, "packages.json");
    const { host, agents, agentsError } = hostAndAgents(snapId);
    const ageHours = (Date.now() - Date.parse(m.created_at)) / 3600e3;
    return {
      snapshotId: snapId, createdAt: m.created_at || "",
      ageHours: Math.round(ageHours * 100) / 100, stale: ageHours > maxAgeHours, maxAgeHours,
      trivyVersion: m.trivy_version || "", vulnDbUpdatedAt: m.vuln_db_updated_at || "",
      images: images.map((i) => {
        const t = pk.targets.find((x) => x.short_id === i.short_id) || { results: [] };
        const pkgs = t.results.flatMap((r) => r.packages);
        const vulns = pkgs.flatMap((p) => p.vulns);
        return {
          shortId: i.short_id, imageId: i.id, repoTags: strs(i.repo_tags), runningContainers: strs(i.running_containers),
          user: i.user || "", entrypoint: strs(i.entrypoint), cmd: strs(i.cmd),
          vulnerablePackages: pkgs.length, vulnRecords: vulns.length, uniqueVulns: new Set(vulns.map((v) => v.id)).size,
        };
      }),
      hostKernel: host.running_kernel || "", hostRebootRequired: !!host.reboot_required,
      agents, agentsError,
    };
  }

  function listPackages(req) {
    const snapId = resolveSnapshot(req.snapshotId);
    const { img, target } = findImage(snapId, req.imageShortId);
    const evs = containerEvidence(snapId, img);
    const running = evs.length > 0;
    const pf = pkgFiles(snapId, img.short_id);
    const packages = [];
    for (const r of target.results) for (const p of r.packages) {
      const { usage, uses } = usageOf(p, r, evs, running);
      packages.push({ ...brief(p, r, usage, uses, p.vulns), inert: isInert(pf, p, r) });
    }
    return { snapshotId: snapId, imageShortId: img.short_id, runningContainers: strs(img.running_containers), packages };
  }

  function getPackageEvidence(req) {
    const snapId = resolveSnapshot(req.snapshotId);
    const name = String(req.package ?? "");
    if (name === "" || name.length > MAX_PACKAGE_NAME) throw errors.invalid("package 不能为空，且长度不超过 256");
    const { img, target } = findImage(snapId, req.imageShortId);
    const evs = containerEvidence(snapId, img);
    const running = evs.length > 0;
    const pf = pkgFiles(snapId, img.short_id);
    const packages = [];
    const uses = [];
    let total = 0;
    let budget = MAX_VULNS_PER_EVIDENCE;
    for (const r of target.results) for (const p of r.packages) {
      if (p.name !== name) continue;            // 只做精确匹配
      const u = usageOf(p, r, evs, running);
      uses.push(...u.uses);
      total += p.vulns.length;
      const shown = p.vulns.slice(0, Math.max(budget, 0));
      budget -= shown.length;
      packages.push({ ...brief(p, r, u.usage, u.uses, shown), inert: isInert(pf, p, r), files: fileSummary(pf, p, r) });
    }
    if (packages.length === 0) throw errors.notFound(`镜像 ${img.short_id} 里没有有漏洞的包 ${name}`);
    const { host, agents } = hostAndAgents(snapId);
    return {
      snapshotId: snapId, imageShortId: img.short_id, repoTags: strs(img.repo_tags), packages,
      vulnsTotal: total, truncated: total > MAX_VULNS_PER_EVIDENCE, uses,
      runningContainers: strs(img.running_containers), imageUser: img.user || "",
      entrypoint: strs(img.entrypoint), cmd: strs(img.cmd),
      evidenceCollectedAt: evs[0]?.collected_at || "", hostKernel: host.running_kernel || "", agents,
    };
  }

  function getCve(req) {
    const snapId = resolveSnapshot(req.snapshotId);
    const id = String(req.cveId ?? "");
    if (!VULN_ID_RE.test(id)) throw errors.invalid("cveId 格式不正确");
    const c = readJson(snapId, "cves.json")[id];
    if (!c) throw errors.notFound(`快照 ${snapId} 里没有 ${id}`);
    return {
      snapshotId: snapId, id, title: c.title || "", description: c.description || "",
      cvssJson: JSON.stringify(c.cvss || {}), cwe: strs(c.cwe), url: c.url || "", published: c.published || "",
    };
  }

  return { getSummary, listPackages, getPackageEvidence, getCve };
}

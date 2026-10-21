// 用假快照测试 src/snapshot.js（不依赖 SDK、不依赖真实快照）
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createSnapshotReader } from "../src/snapshot.js";

class E extends Error { constructor(code, msg) { super(msg); this.code = code; } }
const errors = { invalid: (m) => new E("invalid", m), notFound: (m) => new E("notFound", m), failed: (m) => new E("failed", m) };

function writeSnap(root, id, files, complete = true) {
  const d = path.join(root, id);
  fs.mkdirSync(path.join(d, "evidence"), { recursive: true });
  const sums = {};
  for (const [rel, obj] of Object.entries(files)) {
    const buf = Buffer.from(JSON.stringify(obj));
    fs.writeFileSync(path.join(d, rel), buf);
    sums[rel] = crypto.createHash("sha256").update(buf).digest("hex");
  }
  fs.writeFileSync(path.join(d, "manifest.json"), JSON.stringify({
    snapshot_id: id, created_at: new Date().toISOString(), trivy_version: "0.76.0", vuln_db_updated_at: "db1", files: sums }));
  if (complete) fs.writeFileSync(path.join(d, "COMPLETE"), "");
  return d;
}

const many = Array.from({ length: 250 }, (_, i) => ({ id: `CVE-2026-${1000 + i}`, severity: "LOW", fixed: "", status: "affected" }));
const files = {
  "images.json": [
    { short_id: "aaaaaaaaaaaa", id: "sha256:a", repo_tags: ["run:1"], running_containers: ["c1"], user: "", entrypoint: ["octobus"], cmd: null },
    { short_id: "bbbbbbbbbbbb", id: "sha256:b", repo_tags: ["idle:1"], running_containers: [], user: "app", entrypoint: null, cmd: ["sh"] },
  ],
  "packages.json": { targets: [
    { short_id: "aaaaaaaaaaaa", results: [
      { target: "run (debian 13)", class: "os-pkgs", type: "debian", packages: [
        { name: "libssl3t64", installed: "3.0", pkg_path: "", vulns: [{ id: "CVE-1", severity: "HIGH", fixed: "3.1", status: "fixed" }] },
        { name: "linux-libc-dev", installed: "6.1", pkg_path: "", vulns: many } ] },
      { target: "usr/local/bin/octobus", class: "lang-pkgs", type: "gobinary", packages: [
        { name: "stdlib", installed: "1.22", pkg_path: "", vulns: [{ id: "CVE-2", severity: "MEDIUM", fixed: "1.23", status: "fixed" }] } ] },
      { target: "Node.js", class: "lang-pkgs", type: "node-pkg", packages: [
        { name: "cross-spawn", installed: "7.0", pkg_path: "usr/lib/node_modules/x/package.json", vulns: [{ id: "CVE-3", severity: "HIGH" }] } ] } ] },
    { short_id: "bbbbbbbbbbbb", results: [
      { target: "idle (debian 13)", class: "os-pkgs", type: "debian", packages: [
        { name: "libssl3t64", installed: "3.0", pkg_path: "", vulns: [{ id: "CVE-1", severity: "HIGH" }] } ] } ] } ] },
  "cves.json": { "CVE-1": { title: "t1", description: "d1", cvss: { nvd: { V3Score: 7.5 } }, cwe: ["CWE-1"], url: "u", published: "p" } },
  "evidence/container-c1.json": { container: "c1", collected_at: "now", processes: [
    { pid: 10, user: "999", args: "octobus serve", exe: "/usr/local/bin/octobus", libs: [] },
    { pid: 11, user: "999", args: "node x.js", exe: "/usr/bin/node", libs: [] } ],
    package_usage: { libssl3t64: [{ pid: 11, args: "node x.js", via: "lib", path: "/usr/lib/x86_64-linux-gnu/libssl.so.3" }] } },
  "evidence/pkgfiles-aaaaaaaaaaaa.json": { image_id: "sha256:a", dpkg: true, packages: {
    "linux-libc-dev": { files: 3, counts: { header: 3 }, inert: true, executables: [], shared_libs: [], scripts: [], other_sample: [] },
    "libssl3t64": { files: 2, counts: { shared_lib: 2 }, inert: false, executables: [], shared_libs: ["/usr/lib/libssl.so.3"], scripts: [], other_sample: [] } } },
  "evidence/host.json": { running_kernel: "6.8.0-124-generic", reboot_required: false },
  "evidence/agents.json": { agents: [{ name: "reviewer", image: "guest", driver: "docker" }] },
};

const root = fs.mkdtempSync(path.join(os.tmpdir(), "snap-"));
writeSnap(root, "20261020T010000", files);
writeSnap(root, "20261021T010000", files);
writeSnap(root, "20261022T010000", files, false);   // 没有 COMPLETE，必须被忽略
const r = createSnapshotReader({ snapshotDir: root, maxAgeHours: 26 }, errors);

test("不传 snapshotId 时用最新的完整快照，忽略未完成的", () => {
  const s = r.getSummary({});
  assert.equal(s.snapshotId, "20261021T010000");
  assert.equal(s.stale, false);
  assert.equal(s.images[0].uniqueVulns, 253);
  assert.equal(s.hostKernel, "6.8.0-124-generic");
  assert.deepEqual(s.agents, [{ name: "reviewer", image: "guest", driver: "docker" }]);
});

test("路径穿越和非法格式被拒绝", () => {
  for (const bad of ["../../etc", "20261021T010000/..", "x"]) assert.throws(() => r.getSummary({ snapshotId: bad }), { code: "invalid" });
  assert.throws(() => r.getSummary({ snapshotId: "20261022T010000" }), { code: "notFound" });
  assert.throws(() => r.listPackages({ imageShortId: "../x" }), { code: "invalid" });
  assert.throws(() => r.getCve({ cveId: "../../x" }), { code: "invalid" });
});

test("运行时使用情况的四种结论", () => {
  const p = r.listPackages({ imageShortId: "aaaaaaaaaaaa" }).packages;
  const by = (n) => p.find((x) => x.name === n);
  assert.equal(by("libssl3t64").usage, "in_use");
  assert.equal(by("linux-libc-dev").usage, "not_observed");
  assert.equal(by("stdlib").usage, "in_use");               // Go 程序：可执行文件正被运行
  assert.deepEqual(by("stdlib").usedVia, ["exe:/usr/local/bin/octobus"]);
  assert.equal(by("cross-spawn").usage, "not_tracked");
  const idle = r.listPackages({ imageShortId: "bbbbbbbbbbbb" }).packages;
  assert.equal(idle[0].usage, "no_runtime_evidence");       // 镜像没在运行
});

test("包证据：精确匹配、漏洞条数截断", () => {
  const e = r.getPackageEvidence({ imageShortId: "aaaaaaaaaaaa", package: "linux-libc-dev" });
  assert.equal(e.vulnsTotal, 250);
  assert.equal(e.truncated, true);
  assert.equal(e.packages[0].vulns.length, 200);
  assert.throws(() => r.getPackageEvidence({ imageShortId: "aaaaaaaaaaaa", package: "libssl" }), { code: "notFound" });
  const s = r.getPackageEvidence({ imageShortId: "aaaaaaaaaaaa", package: "libssl3t64" });
  assert.equal(s.uses[0].user, "999");
});

test("包文件清单：inert 标记和文件分类", () => {
  const p = r.listPackages({ imageShortId: "aaaaaaaaaaaa" }).packages;
  assert.equal(p.find((x) => x.name === "linux-libc-dev").inert, true);
  assert.equal(p.find((x) => x.name === "libssl3t64").inert, false);
  assert.equal(p.find((x) => x.name === "stdlib").inert, false);          // Go 程序不是系统包
  assert.equal(p.find((x) => x.name === "linux-libc-dev").files, undefined); // ListPackages 不带文件明细
  const e = r.getPackageEvidence({ imageShortId: "aaaaaaaaaaaa", package: "libssl3t64" });
  assert.deepEqual(e.packages[0].files.sharedLibs, ["/usr/lib/libssl.so.3"]);
  const g = r.getPackageEvidence({ imageShortId: "aaaaaaaaaaaa", package: "stdlib" });
  assert.match(g.packages[0].files.note, /不是系统包/);
  const idle = r.getPackageEvidence({ imageShortId: "bbbbbbbbbbbb", package: "libssl3t64" });
  assert.match(idle.packages[0].files.note, /没有包文件清单/);           // 快照里没有这个镜像的清单
});

test("CVE 详情", () => {
  const c = r.getCve({ cveId: "CVE-1" });
  assert.equal(c.description, "d1");
  assert.equal(JSON.parse(c.cvssJson).nvd.V3Score, 7.5);
  assert.throws(() => r.getCve({ cveId: "CVE-404" }), { code: "notFound" });
});

test("文件被改过时拒绝返回数据", () => {
  const root2 = fs.mkdtempSync(path.join(os.tmpdir(), "snap-"));
  const d = writeSnap(root2, "20261021T010000", files);
  fs.writeFileSync(path.join(d, "cves.json"), JSON.stringify({ "CVE-1": { description: "篡改" } }));
  const r2 = createSnapshotReader({ snapshotDir: root2 }, errors);
  assert.throws(() => r2.getCve({ cveId: "CVE-1" }), { code: "failed" });
});

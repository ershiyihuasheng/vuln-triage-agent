# 镜像漏洞适用性研判 Agent

Trivy 会把镜像里每个"版本命中"的包都报出来，但很多漏洞在当前环境里根本触发不了。
本项目基于 agent-compose + OctoBus，每天自动扫描宿主机全部本地镜像，结合**运行时证据**和**包文件清单**，
对每个有漏洞的包给出结论：

| 结论（主语：这个包上报告的漏洞） | 含义 | 实例（摘自真实报告） |
|---|---|---|
| **受影响** | 漏洞代码会被执行 | nginx 的 libssl3：nginx 进程正在加载 `libssl.so.3`（规则 R2） |
| **不受影响** | 当前环境触发不了，**必须附前提条件** | gpgv：CVE 只影响 gpgsm，而 gpgv 包文件清单只有 `/usr/bin/gpgv`。前提：清单完整、环境中无其他包提供 gpgsm |
| **待确认** | 证据不足，需人工确认 | curl：包内有可执行程序，采集时未观察到运行，不能证明服务不会调用 |

同一镜像在服务**启动前后**结论不同（nginx:1.27 实测）：启动前 受影响 1 / 待确认 59 / 不受影响 19；
启动后 libpcre2-8-0、libssl3、zlib1g 因被 nginx 进程加载，由规则直接判为受影响（4 / 57 / 18）。

选题属于安全技术方向（自拟）：在修复之前回答"这些漏洞里哪些真的需要修"，把修复精力集中到有证据的少数包上。

## 架构

```
宿主机 ──────────────────────────────────────────────────────────────────────────
 cron 02:00 → collector/collect.sh（root）
   Trivy 扫描 + 运行证据（docker top、/proc/PID/maps）+ 包文件清单（docker create/cp，不运行镜像）
   → 快照 /opt/vuln-agent/snapshots/<时间>/（manifest sha256 + COMPLETE）
   → scheduler trigger 通知研判
                │ 只读挂载
OctoBus 容器 ───▼────────────────────────────────────────────────────────────────
 vulndata 服务：GetSummary / ListPackages / GetPackageEvidence / GetCVE
 读取前校验 COMPLETE 和 sha256；超过 26h 的快照标记为过期；能力集 triage 只开放这 4 个方法
                ▲ gRPC（沙箱 token → capproxy → OctoBus token）
agent-compose 容器 ──────────────────────────────────────────────────────────────
 项目 vuln-triage / agent triager（docker 沙箱）/ 调度脚本 agent-compose.yml
   pretriage.py   经 OctoBus 取数，规则 R1–R4 先判
   plan.py        证据未变 → 沿用缓存；其余每 8 个包一批
   scheduler.llm  每批一次大模型调用（daemon 直接请求，大模型不能执行命令）
   validate.py    校验大模型结论，不合格降为"待确认"
   report.py      报告 → /opt/vuln-agent/reports/<快照>.md
```

| 组件 | 职责 | 为什么这样分 |
|---|---|---|
| 宿主机 collect.sh | 采集（需要 root） | 高权限操作不进沙箱 |
| OctoBus | 把快照作为只读能力对外提供；鉴权、限定方法、记录调用 | 沙箱拿不到真实凭据，也不能绕过网关读数据 |
| agent-compose | 定时/事件触发、沙箱、大模型调用、运行记录 | 编排与执行环境 |

**脚本与大模型分工**：取数、规则、缓存、校验、出报告全部由代码完成；大模型只判断"漏洞代码在不在这个包里、会不会被用到"这类模糊问题。

## 闭环

| 环节 | 实现 |
|---|---|
| 触发 | 宿主机 cron 02:00 采集，完成后 `scheduler trigger`；agent-compose 自身 `scheduler.cron` 03:30 兜底 |
| 取数 | 沙箱经 OctoBus 调用 vulndata |
| 判定 | 规则 → 大模型 → 校验 |
| 产出 | Markdown 报告：结论、依据类型、说明、前提条件、主要 CVE 与修复版本、来源 |
| 留痕 | 快照 manifest；OctoBus 访问日志；agent-compose 运行记录；报告"来源"列（规则编号 / 大模型 / 缓存） |

## 知识与判据

代码中实际使用的判据（规则见 `agent-compose/vuln-triage/triage/rules.yaml`）：

| 判据 | 依据 | 位置 |
|---|---|---|
| 进程加载了包内的库或运行包内程序 → 受影响 | 代码已在内存中执行；只做包级，宁可多报 | 规则 R2 |
| linux-libc-dev → 不受影响 | 只有内核头文件（实测 1039 个 .h），容器使用宿主机内核 | 规则 R1 |
| 包内文件全是文档/头文件/静态库 → 不受影响 | **白名单**分类，认不出的文件一律视为可执行 | 规则 R4、pkgfiles.py |
| qemu-utils 且所有 agent 驱动均为 docker → 不受影响 | 只供 microsandbox/boxlite 驱动使用；换驱动即失效 | 规则 R3 |
| **"采集时未观察到"不能判不受影响** | git、curl、dash 等按需调用的工具平时不在进程表里 | 无对应排除规则，交大模型；validate.py |
| Go 程序按进程 exe 判断，不看 .so | Go 静态二进制不加载 .so，按库判断会漏报 | evidence.py、snapshot.js |
| 路径统一到 /usr | Ubuntu `/lib` 是 `usr/lib` 的链接，不统一会漏报"受影响" | evidence.py |
| 同名包按"包路径 + 扫描目标"区分 | node 的同名包出现在多个路径，按包名会混淆证据 | plan.py |
| CVSS、"暂无修复版本"、镜像标签不作为适用性依据 | 严重度不等于可触发；标签可变，一律用镜像 ID | rules.yaml、collect.sh |
| 大模型结论必须核对：引用的证据须存在，"不受影响"须有前提 | 大模型会出错、会波动 | validate.py |

## 部署

前置：Docker、agent-compose v2610.1.0（`/opt/agent-compose`）、Trivy 0.76.0。token 只通过文件 / `--token-stdin` / `.env` 传递，不入库。

```bash
# 以下在仓库根目录执行
# 1. OctoBus（compose 中不发布端口，仅加入 agent-compose_default 网络）
mkdir -p /opt/octobus && cp octobus/docker-compose.yml /opt/octobus/
(cd /opt/octobus && docker compose up -d)
A="-e OCTOBUS_ADMIN_TOKEN=$(cat /opt/octobus/admin.token)"
docker cp octobus/vulndata octobus:/tmp/vulndata-build
docker exec -u 0 octobus chown -R octobus:octobus /tmp/vulndata-build
docker exec $A octobus octobus service import vulndata /tmp/vulndata-build
docker exec $A octobus octobus instance create vulndata-prod --service vulndata \
  --config-json '{"snapshotDir":"/snapshots","maxAgeHours":26}'
docker exec $A octobus octobus capset add-instance triage vulndata-prod --no-all-methods
for m in GetSummary ListPackages GetPackageEvidence GetCVE; do
  docker exec $A octobus octobus capset select-method triage vulndata-prod vulndata.v1.VulndataService/$m
done
#    能力集 triage 的创建与 token 绑定按 OctoBus 官方文档执行

# 2. 采集
mkdir -p /opt/vuln-agent && cp -r collector /opt/vuln-agent/
cp collector/cron.vuln-collect /etc/cron.d/vuln-collect
/opt/vuln-agent/collector/collect.sh

# 3. agent-compose（大模型超时调到 600s，见"问题与处理"第 1 条）
cp agent-compose/docker-compose.override.yml /opt/agent-compose/
#    /opt/agent-compose/.env：COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml、LLM_TIMEOUT=600s
(cd /opt/agent-compose && docker compose up -d)
cp -r agent-compose/vuln-triage /opt/agent-compose/data/work/
cp agent-compose/vuln-triage/.env.example /opt/agent-compose/data/work/vuln-triage/.env   # 填入 OCTOBUS_DEV_TOKEN
docker exec -w /data/work/vuln-triage agent-compose agent-compose up
```

## 登录与核验

| 地址 | 用户名 | 端口 |
|---|---|---|
| `<公网IP>` | root | 22 |

```bash
AC="docker exec -w /data/work/vuln-triage agent-compose agent-compose"
A="-e OCTOBUS_ADMIN_TOKEN=$(cat /opt/octobus/admin.token)"

docker exec agent-compose agent-compose version; docker exec agent-compose agent-compose project ls
$AC scheduler inspect triager; $AC scheduler runs triager          # 触发器与运行记录
docker exec $A octobus octobus status
docker exec $A octobus octobus capset list-methods triage          # 暴露的方法
docker exec $A octobus octobus logs --capset triage --tail 20      # 调用审计日志
ls /opt/vuln-agent/reports/                                        # 报告

# 手动研判（可只研判部分镜像）
$AC scheduler trigger triager daily-triage --payload '{"reason":"manual","images":["nginx"]}' --detach
```

暴露面：公网只开放 22；agent-compose 控制面绑定 `127.0.0.1:7410`；OctoBus 未发布端口；两个容器 `restart: always`。

## 问题与处理

| 现象 | 原因 | 处理 |
|---|---|---|
| 大模型调用 60 秒超时 | daemon 读环境变量 `LLM_TIMEOUT`；官方 `.env` 的 `COMPOSE_FILE` 阻止加载 override 文件 | override 传入 600s，并加入 `COMPOSE_FILE` |
| agent 方式下大模型用 curl 从外网下载 .deb "查证" | 提示词禁令不是强制约束 | 改为脚本经 OctoBus 预取证据 + `scheduler.llm` 只传文字，大模型无法执行命令；token 消耗同时下降一个数量级 |
| 命令失败但运行显示成功 | `scheduler.shell` 非零退出不抛异常 | 封装 `sh()` 检查 `success`，脚本 `set -euo pipefail` |
| 换用 deepseek 后 7 批结论全部作废 | 该模型先输出思考过程再输出 JSON，原解析方法截错位置 | 按 JSON 语法从最后一个结果对象解析，并核对批次编号；用真实输出验证 |
| 一批因网络中断（connection reset）失败 | 单次调用无重试 | 调用报错时同一模型重试 2 次（报错不计费，解析失败不重试） |
| Trivy 按镜像 ID 扫描时访问远程仓库 | 默认按 docker、containerd、podman、remote 顺序查找 | `--image-src docker` |

## 已知限制

- 包级结论：不分析具体函数是否被调用；"采集时未观察到"的包多数落在"待确认"。
- 大模型结论有波动：证据变化后重判，结论可能不同（实测 libkrb5support0 由"不受影响"变为"待确认"，方向保守）。
- 研判沙箱可访问外网（docker 驱动加入 daemon 网络，yml 无限制选项）；同网络内可连到 OctoBus 9000 端口，依靠 token 鉴权拦截。
- 大模型判出的"不受影响"，"依据类型"由理由文字推断，报告中标"（推断）"。

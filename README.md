# 镜像漏洞适用性研判 Agent

漏洞扫描器会把镜像里每个"版本命中"的包都报出来，但其中很多漏洞在当前环境里根本触发不了。
本项目在 agent-compose + OctoBus 上搭建一个研判 Agent：每天自动扫描宿主机上的全部本地镜像，
结合运行时证据和包的文件清单，对每个有漏洞的包给出三种结论之一：

| 结论 | 含义（主语是"这个包上报告的漏洞"） |
|---|---|
| **受影响** | 漏洞所在代码会被执行，建议优先修复 |
| **不受影响** | 当前环境下触发不了；**必须附前提条件**，前提变化则结论失效 |
| **待确认** | 证据不足以判断，需要人工确认 |

范围：只研判本地镜像。宿主机只提供内核版本和沙箱驱动作为证据，不扫描宿主机软件包。

## 场景与预期价值（自拟选题）

属于安全技术方向，与"漏洞复测""漏洞闭环跟踪"相邻：在修复之前先回答"这些漏洞里哪些真的需要修"。

- 场景：本机 3 个镜像，Trivy 报出 285 个有漏洞的包、上千条 CVE。逐条人工判断不现实，按 CVSS 排序又会把大量触发不了的漏洞排在前面。
- 价值：本次实测 285 个包中 90 个判为"不受影响"（每条附前提条件），37 个"受影响"（有进程证据），
  修复工作可先集中在 37 个上；158 个"待确认"给出了具体缺什么证据。
- 结论附带证据和前提，复核人可以逐条核对，而不是只看到一个分数。

## 运行环境与登录

| 项目 | 值 |
|---|---|
| 地址 | `<公网IP>` |
| 用户名 | root |
| 端口 | 22 |
| 系统 | Ubuntu，2 核 2G |

考官核验命令：

```bash
AC="docker exec -w /data/work/vuln-triage agent-compose agent-compose"
A="-e OCTOBUS_ADMIN_TOKEN=$(cat /opt/octobus/admin.token)"

# agent-compose：版本、项目、agent、调度器与触发器、运行记录
docker exec agent-compose agent-compose version
docker exec agent-compose agent-compose status
docker exec agent-compose agent-compose project ls
$AC agent ls ; $AC scheduler inspect triager ; $AC scheduler runs triager

# OctoBus：状态、能力集与暴露的方法、调用审计日志
docker exec $A octobus octobus status
docker exec $A octobus octobus capset list-methods triage
docker exec $A octobus octobus logs --capset triage --tail 20

# 快照与报告
ls /opt/vuln-agent/snapshots/ /opt/vuln-agent/reports/
```

## 端口暴露与鉴权

| 组件 | 监听 | 公网可达 | 鉴权 |
|---|---|---|---|
| sshd | 0.0.0.0:22 | 是（安全组只对考官来源开放） | 公钥 |
| agent-compose 控制面 | 宿主机 `127.0.0.1:7410` | 否 | 只能在服务器本机访问 |
| OctoBus | 容器内 9000，**未发布到宿主机**（compose 中没有 `ports`） | 否 | 管理接口需 admin token；能力调用需能力集 token |

OctoBus 只加入 docker 网络 `agent-compose_default`，agent-compose 和研判沙箱按容器名访问。
沙箱的能力调用经 agent-compose 的 capproxy 转发到 OctoBus 网关，再由网关路由到 vulndata 实例；
沙箱只持有 agent-compose 下发的沙箱 token，不持有 OctoBus 的能力集 token。

两个容器的重启策略都是 `always`，服务器重启后自动恢复。

## 审计

每次能力调用都记录在 OctoBus 访问日志中（能力集、服务、实例、方法、时间、状态码），例如：

```
{"ts":"2026-10-21T07:57:31.080Z","protocol":"grpc","capset":"triage","service":"vulndata",
 "instance":"vulndata-prod","method":"vulndata.v1.VulndataService/GetPackageEvidence", ...}
```

其余留痕：
- 快照目录中的 `manifest.json` 记录每个数据文件的 sha256，vulndata 读取前核对
- agent-compose 运行记录：`inspect run <运行ID>` 中的 `result_json` 包含本次的规则 / 缓存 / LLM / 降级统计和所用模型
- 报告中每条结论的"来源"列：规则编号、LLM、或沿用缓存

## 架构

```
宿主机（Ubuntu，2C2G）
│
├─ ① 采集  cron 每天 02:00 → collector/collect.sh（root）
│    更新 Trivy 漏洞库 → 发现全部本地镜像 → 采集运行证据（docker top、/proc/PID/maps）
│    → Trivy 逐个扫描（systemd-run 限制 CPU/内存）→ 整理 packages.json / cves.json
│    → 包文件清单（docker create 不运行镜像，docker cp 取 dpkg 信息）
│    → manifest.json（各文件 sha256）+ COMPLETE 标记
│    → /opt/vuln-agent/snapshots/<时间>/（保留最近 5 份）
│    → 通知 agent-compose 开始研判（scheduler trigger）
│
├─ ② OctoBus（容器）
│    vulndata 服务（octobus/vulndata）：只读挂载快照目录，提供 4 个方法
│      GetSummary / ListPackages / GetPackageEvidence / GetCVE
│    读取前检查：COMPLETE 存在、sha256 与 manifest 一致、快照未超过 26 小时、路径不越出快照目录
│    triage 能力集：只开放这 4 个方法
│
└─ ③ agent-compose（容器）
     项目 vuln-triage，agent triager（docker 沙箱），调度脚本在 agent-compose.yml
     pretriage.py    经 OctoBus 取数据；规则先判（R1–R4），判不了的进入待研判
     plan.py         与缓存比对，证据未变的沿用上次结论；其余每 8 个包一批
     build_prompts.py + scheduler.llm   每批调用一次 LLM（百炼，4 个模型依次兜底）
                     LLM 只读证据、写结论，不能执行命令
     validate.py     校验 LLM 结论：引用的证据必须真实存在，"不受影响"必须有前提条件，不合格降为"待确认"
     report.py       生成报告 → /work/reports/<快照>.md（宿主机入口 /opt/vuln-agent/reports）
```

### 闭环对应

| 环节 | 实现 |
|---|---|
| 触发 | cron 02:00 采集，采集结束 `scheduler trigger`；调度器另有 03:30 定时作为兜底（同一时间只跑一个，证据未变走缓存） |
| 获取 | 研判沙箱通过 OctoBus 的 vulndata 服务读取快照（能力调用经 OctoBus） |
| 判断 | 规则 → LLM → 校验 |
| 输出 | Markdown 报告，每条结论带依据类型、说明、前提条件、建议、来源 |
| 审计 | 快照 manifest + sha256；OctoBus 调用记录；agent-compose 运行记录（`inspect run`）；报告"来源"列标明规则编号 / LLM / 缓存 |

## 目录

```
collector/                      宿主机采集脚本（部署到 /opt/vuln-agent/collector/）
  collect.sh                    主流程，步骤 0–9，带 flock 防并发、超时、失败不写 COMPLETE
  discover.py evidence.py normalize.py pkgfiles.py manifest.py
  cron.vuln-collect             复制到 /etc/cron.d/vuln-collect
octobus/
  docker-compose.yml            OctoBus 部署（镜像按 sha256 固定，挂载快照目录只读）
  vulndata/                     自定义 OctoBus 服务（proto + Node.js，带单元测试）
agent-compose/
  docker-compose.override.yml   把 LLM_TIMEOUT 传进 daemon（见"踩坑记录"）
  vuln-triage/agent-compose.yml 研判项目：agent、能力集、共享卷、调度脚本
  vuln-triage/triage/           沙箱内运行的研判脚本、规则、LLM 提示词
```

## 预研判规则（triage/rules.yaml）

| 规则 | 条件 | 结论 | 依据类型 |
|---|---|---|---|
| R2 | 运行中的进程加载了该包的库或正在运行它的程序 | 受影响 | 进程正在加载或运行 |
| R1 | linux-libc-dev（只有内核头文件，容器用宿主机内核） | 不受影响 | 包内无可执行代码 |
| R4 | 包内文件全是文档 / 头文件 / 静态库（按 dpkg 文件清单白名单分类） | 不受影响 | 包内无可执行代码 |
| R3 | qemu-utils，且所有 agent 的沙箱驱动都是 docker | 不受影响 | 组件仅特定驱动使用 |

运行时证据分 4 类：`in_use`（正在使用）、`not_observed`（采集时未观察到，**不等于不可达**）、
`no_runtime_evidence`（镜像没有运行中的容器）、`not_tracked`（包类型无法从运行时追踪）。

## 知识与判据（实施中积累，代码中实际使用）

| # | 判据 / 经验 | 来源与依据 | 用在哪里 |
|---|---|---|---|
| 1 | **"采集时未观察到"不能判"不受影响"**。git、curl、dash 这类按需调用的工具，平时不在进程表里，服务随时可能以子进程调用。这类包一律不能因为"没看到进程"而排除 | 快照只是某一时刻；本机实测 130 个包属于此类 | rules.yaml 不为 not_observed 设排除规则，交给 LLM；validate.py 拒绝无前提条件的"不受影响" |
| 2 | **Go 静态二进制不会出现在 /proc/PID/maps 的 .so 列表里**，按库文件判断会漏报；必须按进程的 exe 路径判断 Go 模块（含 stdlib）是否在用 | 实测 octobus 二进制不加载任何 .so | evidence.py、snapshot.js 中 gobinary 按 exe 判 |
| 3 | **路径必须规范化**：Ubuntu 的 /lib 是指向 usr/lib 的链接，maps 里是 /usr/lib/...，dpkg 清单里可能是 /lib/...，不规范化就匹配不上，"正在使用"会漏报 | 实测发现 | evidence.py 统一到 /usr |
| 4 | **linux-libc-dev 上的内核 CVE 不适用于镜像**：包内只有内核头文件（实测 1039 个 .h），容器用宿主机内核，风险应按宿主机内核版本判断 | 实测文件清单 | 规则 R1 |
| 5 | **qemu-utils 只被 microsandbox/boxlite 驱动使用**，docker 驱动下不会执行；换驱动后结论失效 | agent-compose 镜像内容与驱动配置 | 规则 R3（前提：所有 agent 驱动都是 docker，从快照中的 agents.json 检查） |
| 6 | **"包内无可执行代码"按白名单判断**：只有文件全部是文档、头文件、静态库才算；未知类型一律当作可能执行。实测效果有限（待研判从 252 降到 247），说明大部分包含可执行内容，不能靠这条大面积排除 | 实测 | pkgfiles.py、规则 R4 |
| 7 | **不能作为适用性依据的字段**：CVSS / 严重级别（只表示漏洞本身多严重，不表示本环境能否触发）；"暂无修复版本"（不代表不受影响）；镜像标签（同名标签可指向不同镜像，一律用镜像 ID） | 设计取舍 | 规则不使用严重级别作判断条件；扫描和快照按镜像 ID |
| 8 | **同一镜像里可能有同名包**（例如 node 的 pacote 出现在两个路径），只按包名区分会把两份证据混在一起；唯一标识必须包含包路径和扫描目标 | 首次全量运行中 4 个包因此被降级 | plan.py 的缓存键和分批 |
| 9 | **LLM 的结论必须核对**：它引用的文件、进程必须在快照中存在；"不受影响"必须写出前提条件；不满足就降为"待确认" | agent 方式下 LLM 曾自行联网下载 .deb 查证（见踩坑 6） | validate.py |
| 10 | **快照最长 26 小时有效**：每天采集一次，留 2 小时余量；超时的快照不允许用于研判 | 采集周期 | vulndata 实例配置 maxAgeHours |

移除这些知识的影响：去掉 1，大量按需工具会被误判"不受影响"（漏报）；去掉 2、3，正在运行的 Go 程序和库会被漏判"受影响"；
去掉 4、5、6，相应包会交给 LLM，消耗 token 且结论不稳定。

## 部署

以下命令均在服务器上以 root 执行。token 只通过文件和 `--token-stdin` 传递，不出现在命令行和仓库中。

### 1. 依赖

- Docker、agent-compose v2610.1.0（按官方文档部署，目录 `/opt/agent-compose`）
- Trivy 0.76.0（官方 apt 源安装）
- OctoBus（`octobus/docker-compose.yml`，部署目录 `/opt/octobus`）

### 2. OctoBus：导入 vulndata 服务并开放给研判 agent

```bash
# 复制服务源码进容器并导入（重复导入会更新服务）
docker cp octobus/vulndata octobus:/tmp/vulndata-build
docker exec -u 0 octobus chown -R octobus:octobus /tmp/vulndata-build
docker exec $A octobus octobus service import vulndata /tmp/vulndata-build

# 创建实例：快照目录和最大允许的快照年龄
docker exec $A octobus octobus instance create vulndata-prod --service vulndata \
  --config-json '{"snapshotDir":"/snapshots","maxAgeHours":26}'

# triage 能力集只开放 4 个方法
docker exec $A octobus octobus capset add-instance triage vulndata-prod --no-all-methods
for m in GetSummary ListPackages GetPackageEvidence GetCVE; do
  docker exec $A octobus octobus capset select-method triage vulndata-prod vulndata.v1.VulndataService/$m
done
docker exec $A octobus octobus capset list-methods triage
```

`$A` 为管理端认证参数（读取 `/opt/octobus/admin.token`）。能力集的创建和 token 绑定按 OctoBus 官方文档执行，
token 文件放在 `/opt/octobus/`，权限 600。

### 3. 采集

```bash
mkdir -p /opt/vuln-agent/collector /opt/vuln-agent/snapshots
cp collector/* /opt/vuln-agent/collector/ && chmod +x /opt/vuln-agent/collector/collect.sh
cp collector/cron.vuln-collect /etc/cron.d/vuln-collect
/opt/vuln-agent/collector/collect.sh          # 手动跑一次，生成第一份快照
```

### 4. agent-compose 研判项目

```bash
# LLM 超时调到 600s（见踩坑记录 1）
cp agent-compose/docker-compose.override.yml /opt/agent-compose/
#   在 /opt/agent-compose/.env 中：COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml
#                                   LLM_TIMEOUT=600s
cd /opt/agent-compose && docker compose up -d

# 项目目录（daemon 内路径 /data/work/vuln-triage）
cp -r agent-compose/vuln-triage /opt/agent-compose/data/work/
#   在 /opt/agent-compose/data/work/vuln-triage/.env 写入 OCTOBUS_DEV_TOKEN（不入库）
docker exec -w /data/work/vuln-triage agent-compose agent-compose config --quiet
docker exec -w /data/work/vuln-triage agent-compose agent-compose up
```

## 使用

```bash
AC="docker exec -w /data/work/vuln-triage agent-compose agent-compose"

# 研判最新快照
$AC scheduler trigger triager daily-triage --payload '{"reason":"manual"}' --detach
# 指定快照
$AC scheduler trigger triager daily-triage --payload '{"reason":"manual","snapshot_id":"20261021T124353"}' --detach
# 只研判部分镜像（镜像名包含匹配或短 ID）
$AC scheduler trigger triager daily-triage --payload '{"reason":"test","images":["nginx"]}' --detach

# 查看运行状态和统计（需完整运行 ID）
$AC inspect run <完整运行ID>

# 报告
ls /opt/vuln-agent/reports/
```

## 实测数据（3 个镜像，285 个有漏洞的包）

| 项目 | 结果 |
|---|---|
| 首次全量研判 | 2 小时 28 分，31 批，规则 38 / LLM 247 |
| 证据不变时重跑 | 1 分 54 秒，缓存 243，LLM 只研判 4 个 |
| 结论分布 | 受影响 37 / 待确认 158 / 不受影响 90 |
| 单镜像扫描（guest 镜像，漏洞库已缓存） | 约 2 秒，内存峰值约 287MB |

## 设计取舍

- **证据预取 + 每批一次 LLM 调用，而不是让 agent 自己查询**：实测 agent 方式研判 5 个包消耗 26 万到 80 万 token（依模型），
  全量 247 个包会超出全部免费额度；改为脚本先通过 OctoBus 取齐证据，LLM 只做判断，并且无法执行命令。
- **校验不信任 LLM**：LLM 引用的文件路径、进程证据都要在快照里存在；"不受影响"缺前提条件直接降级为"待确认"。
- **"不受影响"必须附前提条件**：结论只在当前环境成立，前提变化（启动新服务、换驱动、包内容变化）即失效。
- **宁可多报**：R2 只要有进程加载就判"受影响"，不做函数级可达性分析。
- **不跑 PoC**：大多数 CVE 没有公开 PoC，PoC 不一定安全，失败也证明不了"不受影响"。

## 踩坑记录

1. **LLM 默认 60 秒超时**：daemon 从环境变量 `LLM_TIMEOUT` 读取（默认 60s）。官方 compose 的 `env_file` 属于 UI 服务，
   而 `.env` 里的 `COMPOSE_FILE=docker-compose.yml` 会阻止自动加载 override 文件，需要把 override 加进 `COMPOSE_FILE`。
2. **百炼 Responses 接口忽略 outputSchema**，而 `JSONResult` 严格解析 JSON，模型输出带代码块就失败；改为脚本自己解析和校验。
3. **`scheduler.shell` 命令非零退出不会抛异常**（返回 success=false，运行仍显示成功），脚本里必须检查 `success`，shell 用 `set -euo pipefail`。
4. **ProtoJSON 省略默认值**（false / 0 / "" / []），调用方读取字段必须带默认值。
5. **Trivy 按镜像 ID 扫描时会回退到远程仓库**，需加 `--image-src docker`。
6. **安全事件**：agent 方式下，LLM 无视提示词禁令，用 curl 从 archive.ubuntu.com 下载 .deb 来"查证"。
   结论：提示词规则不等于强制约束。改为 LLM 不能执行命令；沙箱网络限制仍是待办。
7. **同名包放在同一批**会让 LLM 对同一个包给出多条结论，已在分批时把同名包分开。

## 已知限制

- 结论是**包级别**的：只判断"包里有没有漏洞代码、会不会被加载"，不判断具体函数是否被调用。
- "采集时未观察到" 不等于 "不会被使用"，这类包多数落在"待确认"。
- LLM 判出的"不受影响"，依据类型目前是从理由文字按关键词推断的，报告中标"（推断）"。
- 沙箱可以访问外网（docker 驱动加入 daemon 网络，yml 中没有限制选项），出网限制待加。
- 同一 docker 网络中的沙箱在网络层面能连到 OctoBus 的 9000 端口，目前依靠 token 鉴权拦截，没有做网络隔离。
- 报告质量尚未做人工标注抽检。

## 后续计划

- 提示词直接输出固定的依据类型，由校验脚本核对证据，去掉"（推断）"
- 人工标注约 20 个"不受影响"样本，统计准确率
- 跨镜像复用"漏洞代码不在本包"类结论；批次并行调用 LLM
- 沙箱出网限制（iptables）

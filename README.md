# 镜像漏洞适用性研判

Trivy 按版本号报漏洞，镜像里只要装了受影响版本的包就会报出来，其中很多漏洞在实际运行环境里触发不了。这个项目每天扫描宿主机上的全部本地镜像，结合容器的运行情况和包里实际装的文件，给每个有漏洞的包一个结论：受影响、不受影响或待确认。判为不受影响的，会写明成立的前提条件。

报告节选（列有删减）：

```
| 包         | 结论     | 说明                                                                 | 来源       |
|------------|----------|----------------------------------------------------------------------|------------|
| libssl3t64 | 受影响   | 运行中的进程加载了 /usr/lib/x86_64-linux-gnu/libssl.so.3             | 规则 R2    |
| gpgv       | 不受影响 | CVE 只涉及 gpgsm 的 CMS 解析，gpgv 包里只有 /usr/bin/gpgv            | 大模型     |
| curl       | 待确认   | 包里有 /usr/bin/curl，采集时没有看到它运行，不能证明服务不会调用它   | 大模型     |
```

## 工作原理

```
宿主机
  cron 02:00 ─> collector/collect.sh
                 Trivy 扫描、采集容器进程和加载的库、读取包文件清单
                 写入快照 /opt/vuln-agent/snapshots/<时间>/
                 完成后通知 agent-compose 开始研判
                        │ 只读挂载
OctoBus                 ▼
  vulndata 服务：GetSummary / ListPackages / GetPackageEvidence / GetCVE
  能力集 triage 只开放这 4 个方法
                        ▲ gRPC
agent-compose           │
  研判沙箱：pretriage.py ─> plan.py ─> build_prompts.py ─> validate.py ─> report.py
  scheduler.llm：由 daemon 调用大模型
```

采集放在宿主机上，因为读取容器进程、调用 Docker 和 Trivy 都需要 root 权限。每次采集生成一份快照，所有文件写完后才创建 `COMPLETE` 标记，每个文件的 sha256 记录在 `manifest.json` 里。

研判在 agent-compose 的沙箱里进行。沙箱不能直接读快照，只能通过 OctoBus 上的 vulndata 服务查询。vulndata 读文件前会核对 `COMPLETE` 和 sha256，能力集 triage 只开放 4 个只读方法，OctoBus 的访问凭据由 agent-compose daemon 持有，沙箱拿不到。每次调用都记录在 OctoBus 的访问日志里。

研判按以下顺序进行：规则能判断的直接给结论；证据和上次相同的沿用上次结论；剩下的每 8 个包一批交给大模型；大模型的结论经过校验后才写进报告。大模型通过 `scheduler.llm` 调用，由 daemon 直接发请求，模型只收到证据文字、返回结论文字，不能执行命令。

## 研判逻辑

### 规则

规则写在 `agent-compose/vuln-triage/triage/rules.yaml`，由 `pretriage.py` 按文件中的顺序匹配，命中一条即停止：

| 规则 | 条件 | 结论 |
|---|---|---|
| R2 | 运行中的进程加载了包里的库，或者正在运行包里的程序 | 受影响 |
| R1 | 包名是 linux-libc-dev | 不受影响 |
| R4 | 包里的文件全部是文档、手册、头文件或静态库 | 不受影响 |
| R3 | 包名是 qemu-utils，并且所有 agent 都使用 docker 驱动 | 不受影响 |

R2 排在最前面，保证有进程在使用的包不会被后面的规则判为不受影响。四条规则都不命中的包交给大模型。

### 缓存

`plan.py` 用镜像、包名、版本、包路径、漏洞列表、运行状态和文件分类组成缓存键。这些都没变的包直接沿用上次的结论，任何一项变化都会重新研判。

### 大模型与校验

`build_prompts.py` 通过 OctoBus 取出每个包的文件清单、使用它的进程、镜像启动命令和漏洞描述，连同 `judge_prompt.md` 拼成提示词。`validate.py` 检查大模型的回答：结论必须是规定的几种之一，引用的证据必须存在，判为不受影响的必须写出前提条件。不符合的改为待确认，并记录原因。

### 判断依据

- 采集时没有看到进程使用，不能作为不受影响的依据。git、curl、dash 这类工具平时不在进程列表里，服务随时可能临时调用它们。所以没有对应的排除规则，这类包交给大模型，大模型判断不了就是待确认。
- Go 程序把依赖编译进可执行文件，运行时不加载 .so（在 octobus 主程序上确认过）。按加载的库判断会漏掉 Go 依赖，所以 Go 程序改为判断进程的可执行文件是不是它（`collector/evidence.py`、`octobus/vulndata/src/snapshot.js`）。
- Ubuntu 的 /lib 是指向 /usr/lib 的链接。/proc/PID/maps 里的路径和 dpkg 文件清单里的写法可能不同，不统一就对不上包，会漏判受影响。采集时把路径统一到 /usr（`evidence.py`）。
- linux-libc-dev 里只有内核头文件，Trivy 会把内核漏洞报在这个包上。容器使用宿主机内核，这类漏洞应该按宿主机内核版本判断，不属于镜像的问题（R1）。
- agent-compose 镜像里的 qemu-utils 只有 microsandbox、boxlite 这类虚拟机驱动会用到，使用 docker 驱动时不会执行。换驱动后这条结论失效（R3）。
- 判断包里是否只有不可执行文件时用白名单：只有确认是文档、头文件、静态库的才算，认不出的文件一律当作可执行（`collector/pkgfiles.py`、R4）。
- 同一个镜像里可能有多个同名的 node 包，分别装在不同路径下。只按包名区分会把它们的证据混在一起，所以包的标识里加上了路径和扫描目标（`plan.py`）。
- CVSS 评分、有没有修复版本都不用来判断能否触发。镜像一律按 ID 识别，不按标签。

## 部署

需要 Docker、agent-compose v2610.1.0（部署在 `/opt/agent-compose`）和 Trivy 0.76.0。凭据通过文件、`--token-stdin` 或 `.env` 传入，不进入仓库。以下命令在仓库根目录执行。

1. 部署 OctoBus。compose 文件里没有发布端口，容器只加入 `agent-compose_default` 网络，快照目录以只读方式挂载到 `/snapshots`。

   ```bash
   mkdir -p /opt/octobus && cp octobus/docker-compose.yml /opt/octobus/
   (cd /opt/octobus && docker compose up -d)
   ```

2. 导入 vulndata 服务，创建实例，在能力集 triage 里选中 4 个方法。能力集的创建按 OctoBus 官方文档操作；管理员 token 和能力集 token 用同一个密钥，原因见排错记录「agent-compose 连接 OctoBus 只能配一个 token」。

   ```bash
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
   ```

3. 安装采集脚本和定时任务，手动运行一次生成第一份快照。

   ```bash
   mkdir -p /opt/vuln-agent && cp -r collector /opt/vuln-agent/
   cp collector/cron.vuln-collect /etc/cron.d/vuln-collect
   /opt/vuln-agent/collector/collect.sh
   ```

4. 调大 agent-compose 的大模型超时时间（原因见排错记录第一条）。

   ```bash
   cp agent-compose/docker-compose.override.yml /opt/agent-compose/
   # 在 /opt/agent-compose/.env 中设置：
   #   COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml
   #   LLM_TIMEOUT=600s
   (cd /opt/agent-compose && docker compose up -d)
   ```

5. 部署研判项目。`.env` 中填入 `OCTOBUS_DEV_TOKEN`。

   ```bash
   cp -r agent-compose/vuln-triage /opt/agent-compose/data/work/
   cp agent-compose/vuln-triage/.env.example /opt/agent-compose/data/work/vuln-triage/.env
   docker exec -w /data/work/vuln-triage agent-compose agent-compose up
   ```

## 使用

每天 02:00 自动采集，采集完成后自动研判。agent-compose 的调度器在 03:30 还有一次定时触发，用于采集没能触发研判时补跑；同一时间只会有一次研判在运行。

手动研判：

```bash
AC="docker exec -w /data/work/vuln-triage agent-compose agent-compose"

# 研判最新的快照
$AC scheduler trigger triager daily-triage --payload '{"reason":"manual"}' --detach
# 指定快照
$AC scheduler trigger triager daily-triage --payload '{"snapshot_id":"20261022T165114"}' --detach
# 只研判部分镜像，按镜像名包含或短 ID 匹配
$AC scheduler trigger triager daily-triage --payload '{"images":["nginx"]}' --detach
```

查看运行结果（需要完整的运行 ID）：

```bash
$AC scheduler runs triager
$AC inspect run <运行ID>
```

报告在 `/opt/vuln-agent/reports/<快照编号>.md`。

使用的模型在 `agent-compose.yml` 的 `MODELS` 里配置，修改后执行 `agent-compose up` 生效。

## 运行环境

| 地址 | 用户名 | 端口 |
|---|---|---|
| `43.163.234.9` | root | 22 |

公网只开放 22 端口。agent-compose 控制面绑定在 `127.0.0.1:7410`；OctoBus 没有发布端口；两个容器的重启策略都是 `always`。

核验命令：

```bash
AC="docker exec -w /data/work/vuln-triage agent-compose agent-compose"
A="-e OCTOBUS_ADMIN_TOKEN=$(cat /opt/octobus/admin.token)"

docker exec agent-compose agent-compose version
docker exec agent-compose agent-compose project ls
$AC scheduler inspect triager
$AC scheduler runs triager
docker exec $A octobus octobus status
docker exec $A octobus octobus capset list-methods triage
docker exec $A octobus octobus logs --capset triage --tail 20
ls /opt/vuln-agent/reports/
```

## 排错记录

### 导入 OctoBus 示例服务时报 `repo root with sdk package not found`

部署后用官方的 calculator 示例验证 OctoBus，导入一直失败，报 `repo root with sdk package not found`。修改依赖、离线安装、预先装好 SDK 都没有用。

在 OctoBus 源码里搜这句报错，位置在 `internal/packageimport/importer.go`。这里有一份写死的示例包名单（`octobus-calculator-js` 等 3 个），服务包 `package.json` 里的 `name` 命中名单时，导入会改走一条给源码仓库使用的分支：从当前目录往上找同时含有 `go.mod` 和 `sdk/package.json` 的目录，把仓库里的 SDK 复制过来。我们用的是发布镜像，容器里没有源码仓库，所以一定失败。

把示例 `package.json` 里的 `name` 改成名单以外的名字后，导入正常，OctoBus 会自己从 npm 安装 SDK。

### OctoBus 管理接口没有鉴权

首次启动时按文档设置了 `OCTOBUS_BOOTSTRAP_ADMIN_TOKEN`，但不带 token、或者带错误的 token 执行 `octobus service list` 都能成功。

查源码发现，管理接口要不要校验 token，取决于数据库的 `admin_tokens` 表里有没有记录：表是空的，就整个跳过校验。而启动时设置的 bootstrap token 并没有写进这张表。

用 `octobus admin-token add` 显式添加一条管理员 token 后，不带 token 或 token 错误都返回 401。能力集也有同样的情况：没有添加 token 的能力集，调用入口是公开的，所以能力集也都添加了 token。

### agent-compose 连接 OctoBus 只能配一个 token

`agent-compose.yml` 的 `octobus_servers` 里只有一个 `token` 字段。agent-compose 用它做两件事：读取 OctoBus 管理接口上的能力集信息，以及转发沙箱的能力调用。OctoBus 这两类接口认的是不同的 token，前者要管理员 token，后者要能力集 token。官方对接文档写的是填能力集 token，这在管理接口没有鉴权时可行；给管理接口加了 token 之后，读取能力集信息就会被拒绝。

解决办法是生成一个密钥，同时注册为管理员 token（`octobus admin-token add`）和能力集 token（`octobus capset add-token`），`agent-compose.yml` 里引用这一个。这个密钥只保存在服务器上的 token 文件和 `.env` 里，合并后没有扩大暴露范围。

### 大模型调用 60 秒超时

每批研判都在 60 秒左右失败，运行记录里是 `scheduler.llm` 超时。一批 8 个包，模型实际需要 3 到 5 分钟。

daemon 的超时时间来自环境变量 `LLM_TIMEOUT`，默认 60s，镜像里也写了这个默认值。直接在 `/opt/agent-compose/.env` 里加变量没有效果，因为官方 compose 里的 `env_file` 只给 UI 服务使用。改用 override 文件传给 daemon 后仍然不生效，原因是 `.env` 里有 `COMPOSE_FILE=docker-compose.yml`，它会让 compose 不再自动加载 override 文件。

解决办法是新建 `docker-compose.override.yml`：

```yaml
services:
  agent-compose:
    environment:
      LLM_TIMEOUT: ${LLM_TIMEOUT:-60s}
```

并修改 `/opt/agent-compose/.env`：

```
COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml
LLM_TIMEOUT=600s
```

执行 `docker compose up -d` 重建容器，`docker exec agent-compose printenv LLM_TIMEOUT` 输出 `600s` 即生效。

### 大模型在沙箱里联网下载文件

最初的做法是让 agent 在沙箱里自己查证据、自己下结论。测试中有一次，模型为了确认某个包里有哪些文件，用 curl 从 archive.ubuntu.com 下载了 .deb 包，而提示词里明确禁止了联网。

提示词里的禁止只是建议，模型不一定遵守。docker 驱动的沙箱加入了 daemon 所在的网络，可以访问外网，agent-compose.yml 里没有限制出网的选项。另外，agent 每查一次都会重发全部上下文，token 消耗也很高。

改为由脚本通过 OctoBus 取好证据，再用 `scheduler.llm` 把证据文字发给模型。`scheduler.llm` 由 daemon 直接请求模型，不启动 agent，模型手里没有可以执行的命令。

### 研判脚本出错，整次运行仍显示成功

调度脚本通过 `scheduler.shell` 在沙箱里依次运行 pretriage.py、plan.py 等脚本。搭建时做过测试：被运行的脚本出错退出后，`scheduler.shell` 不会报错，只是在返回结果里把 `success` 标为 false。调度脚本如果不检查这个值，就会接着执行下一步，最后整次运行仍显示成功。比如 pretriage.py 取数失败，后面的步骤会拿着空数据继续跑，生成一份几乎为空的报告，而运行记录里看不出任何问题。

调度脚本里因此写了一个 `sh()` 函数，所有命令都经它执行。它在执行后检查 `success`，为 false 就抛出错误，让整次运行标记为失败，错误信息里带上出错的命令和输出。它还在每条命令前加上 `set -euo pipefail`：一条命令由多步组成时（比如先生成文件再读取），其中任何一步出错，整条命令都算失败。

### 换模型后整批结论无法解析

调度脚本从原来的模型切换到 deepseek-v4.1-flash 后，7 批结论全部无法解析，53 个包变成了待确认。

查看 `/work/llm/` 下保存的模型回答，每批有 40 到 100KB，开头是一大段英文分析，最后才是 JSON 结果。原来的解析方法取第一个 `{` 到最后一个 `}` 之间的内容，而分析文字里本身就有 `{`，截出来的不是合法的 JSON。

`validate.py` 改为：找出所有以 `{"batch"` 或 `{"results"` 开头的位置，从最后一个往前逐个按 JSON 语法解析，取第一个包含 `results` 并且批次编号一致的对象。改完后先用这 7 批实际的回答验证，7 批都能正确解析出每个包的结论。现在固定使用一个模型，不再自动切换。

### 一批调用因连接中断失败

一次运行中有一批报错 `connection reset by peer`，请求还没收到回答连接就断了，这一批的 8 个包被改为待确认。

`judge` 函数里加了重试：调用报错时同一个模型最多再试 2 次。只有调用报错才重试，这时没有收到回答，不会产生费用；回答收到了但解析不了，不重试。

### Trivy 按镜像 ID 扫描时会去访问远程仓库

Trivy 默认按 docker、containerd、podman、远程仓库的顺序查找镜像。用镜像 ID 扫描时，如果前几种来源没找到，它会拿这个 ID 去远程仓库查找，扫到的不一定是本机的镜像。

`collect.sh` 里扫描时加上 `--image-src docker`，只从本机 Docker 读取镜像。

## 已知限制

- 结论是包级别的，只判断漏洞代码是否在包里、包是否被加载，不分析具体函数有没有被调用。采集时没有看到使用的包，大多数会落在待确认。
- 证据变化后会重新交给大模型，结论可能和上次不同。
- 研判沙箱可以访问外网；同一个 Docker 网络里的沙箱能连到 OctoBus 的 9000 端口，目前靠 token 鉴权拦截。

## 目录结构

```
collector/                     采集脚本
├── collect.sh                 主流程，依次调用下面几个脚本
├── discover.py                镜像清单
├── evidence.py                容器进程和加载的库
├── normalize.py               整理 Trivy 结果
├── pkgfiles.py                包文件清单
├── manifest.py                文件 sha256
└── cron.vuln-collect          定时任务
octobus/
├── docker-compose.yml
└── vulndata/                  vulndata 服务（proto、实现、单元测试）
agent-compose/
├── docker-compose.override.yml   传入 LLM_TIMEOUT
└── vuln-triage/                  研判项目
    ├── agent-compose.yml         agent、能力集、卷、调度脚本
    ├── .env.example
    └── triage/                   规则、研判脚本、提示词
```

部署到服务器上的位置：

| 仓库目录 | 服务器目录 |
|---|---|
| `collector/` | `/opt/vuln-agent/collector/`（cron.vuln-collect 放到 `/etc/cron.d/vuln-collect`） |
| `octobus/` | `/opt/octobus/`；vulndata 源码在 `/opt/vuln-agent/octobus/vulndata/` |
| `agent-compose/docker-compose.override.yml` | `/opt/agent-compose/` |
| `agent-compose/vuln-triage/` | `/opt/agent-compose/data/work/vuln-triage/`（daemon 容器内为 `/data/work/vuln-triage`） |

运行数据：快照在 `/opt/vuln-agent/snapshots/`，报告在 `/opt/vuln-agent/reports/`，采集日志在 `/var/log/vuln-collect.log`。

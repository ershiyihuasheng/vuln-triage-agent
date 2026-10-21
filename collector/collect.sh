#!/bin/bash
# 漏洞研判 Agent —— 宿主机采集脚本
# 范围：本机全部镜像。宿主机只采集内核版本（容器用宿主机内核，内核类 CVE 的规则要用它做前提）
set -euo pipefail

# ===== 可调参数（换机器时只改这里）=====
BASE=/opt/vuln-agent
SNAP_ROOT=$BASE/snapshots
LOCK=/run/lock/vuln-collect.lock
KEEP=5               # 保留最近几份完整快照（实测一份约 250MB，磁盘剩 22G）
DB_TIMEOUT=5m        # 下载漏洞库的超时（实测 17 秒）
SCAN_TIMEOUT=15m     # trivy 自己的超时（实测：有缓存的镜像 2 秒；新镜像首次扫描待实测）
OUTER_TIMEOUT=20m    # 外层兜底超时，比 SCAN_TIMEOUT 长
CPU_QUOTA=180%       # 以单核为 100%，2 核的 90%
MEM_HIGH=80%         # 超过后内核回收内存、进程变慢，但不杀
MEM_MAX=90%          # 最后防线，超过即杀
AC_CONTAINER=agent-compose          # agent-compose daemon 的容器名
AC_PROJECT_DIR=/data/work/vuln-triage      # 容器内的项目目录，用来查 agent 的驱动类型
TRIGGER_SCHEDULER="triager"                # 研判用的 scheduler 名；为空 = 不触发（研判部分还没写）
TRIGGER_NAME="daily-triage"                     # 对应的 trigger 名
# ========================================

# 第 0 步：加锁。上一次没结束就直接退出，避免两个采集同时写
exec 9>"$LOCK"
flock -n 9 || { echo "另一个采集正在运行，本次退出"; exit 0; }

# 第 1 步：新建时间戳目录，不碰任何旧快照
SNAP_ID=$(date +%Y%m%dT%H%M%S)
D=$SNAP_ROOT/$SNAP_ID
mkdir -p "$D/raw"
echo "[1] 快照目录: $D"

# 资源受限地执行一条命令：systemd 临时 scope 限 CPU/内存 + 低优先级 + 外层超时
# 已实测：--scope 会原样返回命令的退出码，百分比参数可用
limited() {
  systemd-run --scope --quiet \
    -p CPUQuota="$CPU_QUOTA" -p MemoryHigh="$MEM_HIGH" -p MemoryMax="$MEM_MAX" \
    nice -n 10 ionice -c 3 timeout "$OUTER_TIMEOUT" "$@"
}

# 第 2 步：统一下载一次漏洞库，后面所有扫描都跳过更新 → 同一快照用同一版库
timeout "$DB_TIMEOUT" trivy image --download-db-only --quiet
trivy version --format json > "$D/trivy-version.json"
echo "[2] 漏洞库已就绪"

# 第 3 步：发现镜像 = 本机全部镜像（按 ID 去重），并记录哪些正在运行
docker image ls -q --no-trunc | sort -u > "$D/image-ids.txt"
docker image inspect $(cat "$D/image-ids.txt") > "$D/images-inspect.json"
RUNNING=$(docker ps -q)
if [ -n "$RUNNING" ]; then docker inspect $RUNNING > "$D/containers-inspect.json"; else echo '[]' > "$D/containers-inspect.json"; fi
python3 "$(dirname "$0")/discover.py" "$D/images-inspect.json" "$D/containers-inspect.json" "$D/images.json" "$D/targets.txt"
echo "[3] 镜像清单: $D/images.json"

# 第 4 步：运行时证据（进程、加载的库、库属于哪个包）+ 宿主机内核版本 + agent 驱动类型
# 紧跟第 3 步执行：扫描要几十秒，期间容器可能启停；和镜像清单同一时刻采集，"哪些容器在运行"两边一致
echo "[4] 采集运行时证据"
python3 "$(dirname "$0")/evidence.py" "$D/containers-inspect.json" "$D/evidence"
# 驱动类型是内核类规则的前提（docker 驱动 = 用宿主机内核）。查不到不让整份快照作废：
# 记下失败，规则看到"前提无法确认"就不生效，交给 LLM / 人工
if ! docker exec -w "$AC_PROJECT_DIR" "$AC_CONTAINER" agent-compose agent ls --json > "$D/evidence/agents.json" 2>/dev/null; then
  echo '{"error": "agent ls 执行失败，驱动类型未知"}' > "$D/evidence/agents.json"
  echo "  警告: 没有拿到 agent 驱动类型"
fi

# 第 5 步：逐个扫描镜像（不并行：2C2G 上内存紧张，宿主机扫描时实测峰值 1.36GB 并用到 swap）
# 用镜像 ID 扫描：已实测可行，无名字的镜像也能扫，且 ID 不会像标签那样被改指向
# </dev/null：不让扫描命令读标准输入，否则会把 targets.txt 里还没处理的镜像 ID 读走
# --image-src docker：只从本机 docker 读镜像。默认找不到会去公网仓库按 ID 拉（实测），可能扫错镜像、外泄镜像 ID
while read -r SID; do
  echo "[5] 扫描镜像 $SID"
  limited trivy image --image-src docker --scanners vuln --format json --skip-db-update --quiet \
    --timeout "$SCAN_TIMEOUT" --output "$D/raw/image-$SID.json" "$SID" </dev/null
done < "$D/targets.txt"

# 第 6 步：整理成小文件。按包存放漏洞记录，CVE 描述每个只存一份；raw/ 保留不动
echo "[6] 整理扫描结果"
python3 "$(dirname "$0")/normalize.py" "$D"

# 第 6.5 步：每个有漏洞的系统包装了哪些文件（docker create 不启动 → docker cp → docker rm）
echo "[6.5] 采集包文件清单"
python3 "$(dirname "$0")/pkgfiles.py" "$D"

# 第 7 步：写 manifest，最后创建 COMPLETE。
# COMPLETE 必须是最后写的：前面任何一步失败，set -e 会让脚本在这之前退出，这份快照就当作不存在
echo "[7] 写 manifest"
python3 "$(dirname "$0")/manifest.py" "$D" "$SNAP_ID"
touch "$D/COMPLETE"
echo "[7] 快照完成: $SNAP_ID"

# 第 8 步：清理。有锁保证此刻没有别的采集在写，所以除本次外没有 COMPLETE 的目录都是失败残留
for dir in "$SNAP_ROOT"/*/; do
  dir=${dir%/}
  [ "$dir" = "$D" ] && continue
  [ -f "$dir/COMPLETE" ] || { echo "[8] 删除未完成的快照: $(basename "$dir")"; rm -rf "$dir"; }
done
# 只保留最新的 KEEP 份完整快照（目录名是时间戳，按名字排序就是按时间排序）
ls -d "$SNAP_ROOT"/*/ | sed 's#/$##' | sort | head -n -"$KEEP" | while read -r dir; do
  echo "[8] 删除旧快照: $(basename "$dir")"
  rm -rf "$dir"
done

# 第 9 步：触发研判，把快照 ID 作为 payload 传过去
if [ -n "$TRIGGER_SCHEDULER" ]; then
  docker exec -w "$AC_PROJECT_DIR" "$AC_CONTAINER" agent-compose scheduler trigger \
    "$TRIGGER_SCHEDULER" "$TRIGGER_NAME" --payload "{\"reason\":\"snapshot\",\"snapshot_id\":\"$SNAP_ID\"}" --detach
  echo "[9] 已触发研判"
else
  echo "[9] 未配置研判 scheduler，跳过触发"
fi

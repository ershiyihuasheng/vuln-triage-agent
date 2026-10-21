# vulndata

漏洞快照只读查询服务（OctoBus on-demand 服务包）。读取宿主机采集脚本生成、只读挂载到 octobus 容器 `/snapshots` 的快照。

方法：GetSummary / ListPackages / GetPackageEvidence / GetCVE，详见 `proto/vulndata.proto`。

安全约束：所有参数按不可信输入处理（格式校验、只做精确匹配，防路径穿越）；只读带 COMPLETE 的快照；读文件前用 manifest 的 sha256 校验；GetPackageEvidence 漏洞条数有上限。

# GCP FREE SCHEDULE

用于在 GCP Linux 实例上批量封禁 CDN 段（Akamai、Fastly、Cloudflare），减少经由公共 CDN 的访问暴露面，提升网络侧隐私隔离能力。

## 1. 项目目标

`cdn_ip_ban.sh` 会从上游地址源下载最新 IP 列表，并通过 `iptables` 写入 `DROP` 规则，阻断与这些网段的双向通信。

- 入站：拦截来源为 CDN 网段的流量（`-s <cidr> -j DROP`）
- 出站：拦截目的为 CDN 网段的流量（`-d <cidr> -j DROP`）
- 按 CDN 维度维护独立链：`AKAMAI_BLOCK` / `FASTLY_BLOCK` / `CLOUDFLARE_BLOCK`

## 2. 运行环境

- 系统：Debian 12（脚本注释中指定）或兼容发行版
- 权限：`root`（`install/update/uninstall` 必须）
- 依赖：
  - `iptables`
  - `curl`（或 `wget`）
  - `jq`
  - `iptables-persistent`（用于持久化规则）

脚本会在依赖缺失时尝试自动执行：

```bash
apt-get update -qq
apt-get install -y iptables ipset ipset-persistent curl jq iptables-persistent util-linux
```

## 3. 快速开始（运行）

### 3.1 查看帮助

```bash
bash ./cdn_ip_ban.sh help
```

### 3.2 安装全部 CDN 封禁规则

```bash
sudo bash ./cdn_ip_ban.sh install
```

### 3.3 仅封禁 Cloudflare，并启用 IPv6

```bash
sudo bash ./cdn_ip_ban.sh install --provider=cloudflare --ipv6
```

### 3.4 更新地址并刷新规则

```bash
sudo bash ./cdn_ip_ban.sh update
```

### 3.5 查看状态

```bash
bash ./cdn_ip_ban.sh status
```

### 3.6 卸载规则

```bash
sudo bash ./cdn_ip_ban.sh uninstall
```

## 4. 参数说明

- `install`：下载 IP 列表并写入 iptables 规则
- `update`：重新下载列表并刷新链内规则
- `uninstall`：删除链、解除挂接、移除列表文件
- `status`：查看链是否存在、规则数量、是否挂接到 `INPUT/OUTPUT`
- `--provider=...`：指定供应商，支持 `akamai`、`fastly`、`cloudflare`、`all`，可逗号分隔多值
- `--ipv6`：开启 IPv6 列表下载与拦截（默认仅 IPv4）

## 5. 部署建议（GCP）

### 5.1 基础部署流程

1. 创建 Debian 12 实例，并通过 SSH 登录。
2. 上传脚本到实例（例如 `/opt/cdn-ip-ban/cdn_ip_ban.sh`）。
3. 赋权：

```bash
sudo chmod +x /opt/cdn-ip-ban/cdn_ip_ban.sh
```

4. 首次执行：

```bash
cd /opt/cdn-ip-ban
sudo ./cdn_ip_ban.sh install --provider=all
```

GitHub Raw 安装建议带 sha256 校验：

```bash
curl -fsSL https://raw.githubusercontent.com/<USER>/<REPO>/main/install.sh \
| sudo bash -s -- \
  --raw-base=https://raw.githubusercontent.com/<USER>/<REPO>/main \
  --script-sha256=<EXPECTED_SHA256> \
  --provider=all
```

5. 验证：

```bash
./cdn_ip_ban.sh status
sudo iptables -S | grep -E 'AKAMAI_BLOCK|FASTLY_BLOCK|CLOUDFLARE_BLOCK'
```

### 5.2 定时更新（推荐）

CDN 网段会变更，建议用 `cron` 每日更新一次：

```bash
sudo crontab -e
```

加入：

```cron
0 3 * * * /opt/cdn-ip-ban/cdn_ip_ban.sh update >> /var/log/cdn_ip_ban_cron.log 2>&1
```

### 5.3 GCP 防火墙协同

- 本脚本工作在实例 OS 层（iptables）。
- GCP VPC Firewall 工作在云网络层。
- 最佳实践：**云防火墙负责边界准入，实例 iptables 负责细粒度补充封禁**。

## 6. 工作原理

1. **参数解析**：确定命令、供应商、是否启用 IPv6。  
2. **依赖检查**：校验 `iptables/curl|wget/jq`。  
3. **下载并清洗列表**：
   - 文本源：按行读取，去注释和空白，正则校验 CIDR/IP。
   - JSON 源：通过 `jq` 抽取字段。
4. **链管理**：
   - 若不存在则创建自定义链；
   - 每次刷新前先 `-F` 清空链。
5. **写入规则**：
   - 对每个网段写入两条 `DROP`（入站+出站）。
6. **挂接主链**：
   - 将自定义链插到 `INPUT` 和 `OUTPUT` 头部（`-I ... 1`）。
7. **持久化**：
   - 优先 `netfilter-persistent save`，否则回退 `iptables-save`。

## 7. 上游 IP 列表来源

来自脚本内置地址（`cdn_ip_ban.sh`）：

- Akamai（文本，IPv4）：  
  `https://raw.githubusercontent.com/platformbuilds/Akamai-ASN-and-IPs-List/master/akamai_ip_list.lst`
- Fastly（JSON，IPv4/IPv6 字段）：  
  `https://api.fastly.com/public-ip-list`
- Cloudflare IPv4（文本）：  
  `https://www.cloudflare.com/ips-v4`
- Cloudflare IPv6（文本）：  
  `https://www.cloudflare.com/ips-v6`

## 8. 文件与日志

- IP 列表目录：`/etc/cdn_blocked_ips`
  - `akamai_ips.txt`
  - `fastly_ips.txt`
  - `cloudflare_ips.txt`
- 日志文件：`/var/log/cdn_ip_ban.log`
- 进程锁：`/var/run/cdn_ip_ban.lock`

## 9. 注意事项与风险

- 封禁 CDN 网段会影响大量正常网站/API（尤其 Cloudflare/Fastly 承载面广）。
- 启用 `--ipv6` 后影响范围更大，请确认业务是否使用 IPv6。
- 该脚本默认不处理 `ip6tables` 独立链；IPv6 规则写入行为依赖系统 `iptables` 后端实现（nft/legacy）。
- 建议先在测试实例验证，再推广到生产实例。

## 10. 回滚与排障

### 回滚

```bash
sudo ./cdn_ip_ban.sh uninstall --provider=all
```

### 常见检查

```bash
sudo iptables -L AKAMAI_BLOCK -n --line-numbers
sudo iptables -L FASTLY_BLOCK -n --line-numbers
sudo iptables -L CLOUDFLARE_BLOCK -n --line-numbers
tail -n 200 /var/log/cdn_ip_ban.log
```

## 11. 已知行为说明

脚本的参数解析为“先解析前置选项，再识别命令”。为避免歧义，建议使用如下写法：

```bash
sudo ./cdn_ip_ban.sh --provider=cloudflare --ipv6 install
```

> Note: 当前版本已支持命令前后混合选项写法（如 `install --provider=...` 与 `--provider=... install`）。

## 12. Optional SOCKS5 Bypass (按应用/命令分流)

脚本内置可选 bypass 能力，无需 sing-box/clash/redsocks：

- 白名单文件：`/etc/cdn_bypass_white.list`
- 代理配置：`/etc/cdn_bypass_proxy.conf`
- 运行命令：`proxy-run`

### 12.1 初始化

`install` 时会自动创建配置文件并从仓库拉取社区白名单，也可手动执行：

```bash
sudo ./cdn_ip_ban.sh bypass-init
```

### 12.2 ENABLED 开关

`/etc/cdn_bypass_proxy.conf` 包含 `ENABLED` 字段，可一键全局开关 bypass：

```ini
# 开启（默认）
ENABLED=true
SOCKS5_PROXY=”socks5h://127.0.0.1:1080”

# 关闭：proxy-run 将直接执行命令，不再检查白名单
ENABLED=false
```

修改后立即生效，无需重启脚本。

### 12.3 社区白名单与自定义条目

白名单文件分为两个区域：

```text
# == community entries (auto-synced, do not edit this section manually) ==
github.com
google.com
...（由仓库维护）
# == end community entries ==

# --- User custom entries ---
myserver.example.com
203.0.113.10
```

- **社区区域**：由 `bypass-init` / `bypass-update` 自动从仓库拉取，覆盖该区域内容
- **用户区域**：写在社区区域下方，不受自动更新影响

更新社区白名单：

```bash
sudo ./cdn_ip_ban.sh bypass-update
```

### 12.4 查看状态

```bash
./cdn_ip_ban.sh bypass-status
```

输出示例：

```
==========================================
  Optional SOCKS5 Bypass Status

  Proxy config: /etc/cdn_bypass_proxy.conf
  - Bypass enabled:     true
  - Active SOCKS5 proxy: socks5h://127.0.0.1:1080

  Whitelist: /etc/cdn_bypass_white.list
  - Total entries:      65
  - Community entries:  60
  - User entries:       5
==========================================
```

### 12.5 按需分流执行

命中白名单的目标走 SOCKS5，其余直接执行：

```bash
./cdn_ip_ban.sh proxy-run --target=github.com -- curl -I https://github.com
./cdn_ip_ban.sh proxy-run -- curl -I https://github.com   # 自动从 URL 推断目标
```

临时覆盖代理地址：

```bash
./cdn_ip_ban.sh proxy-run --socks5=socks5h://127.0.0.1:1081 --target=github.com -- curl -I https://github.com
```

> **说明**：该能力是”按命令分流”，不是全系统透明代理。SOCKS5 代理服务需自行部署（如 SSH 本地隧道 `ssh -fN -D 1080 user@remote`）。

## 13. 一键封装安装

仓库内安装：

```bash
sudo chmod +x ./cdn_ip_ban.sh ./install.sh
sudo ./install.sh --provider=all
```

GitHub Raw 一键安装（替换 `<USER>/<REPO>`）：

```bash
curl -fsSL https://raw.githubusercontent.com/<USER>/<REPO>/main/install.sh \
| sudo bash -s -- --raw-base=https://raw.githubusercontent.com/<USER>/<REPO>/main --provider=all
```

## 14. 规则引擎升级说明

当前版本默认使用 `ipset` + `iptables/ip6tables`：

- 每个 CDN 使用独立 `ipset`（`*_V4` / `*_V6`）
- `INPUT` 与 `OUTPUT` 分别使用 `src`/`dst` 匹配
- 更新过程使用 `ipset swap` 原子切换，避免刷新空窗

## 15. Source Override

可通过环境变量覆盖上游地址：

```bash
export AKAMAI_IP_LIST_URL="https://<your-source>"
export FASTLY_IP_LIST_URL="https://api.fastly.com/public-ip-list"
export CLOUDFLARE_IP_LIST_V4_URL="https://www.cloudflare.com/ips-v4"
export CLOUDFLARE_IP_LIST_V6_URL="https://www.cloudflare.com/ips-v6"
```

然后执行：

```bash
sudo ./cdn_ip_ban.sh install --provider=all
```

尽管脚本示例中也给出了 `install --provider=...` 形式，但在不同 shell/调用习惯下，前置选项写法更稳妥。

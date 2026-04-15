# XDP 验证路径

这份文档描述当前 DNS eBPF 阶段的三段验证顺序：

1. `veth + netns` 本地 smoke
2. `bpftool` attach / detach 烟测
3. Host-VM 验证

## 1. 本地 smoke

本地 smoke 使用一条固定的 veth 对：

- host 侧：`dnslab0`
- netns 侧：`dnslab1`
- namespace：`dnslab-ns`
- host IP：`10.200.1.1/24`
- netns IP：`10.200.1.2/24`

运行方式：

```bash
bash scripts/lab/dns-veth-netns.sh
```

也可以只跑某一个阶段：

```bash
bash scripts/lab/dns-veth-netns.sh baseline
bash scripts/lab/dns-veth-netns.sh xdp-miss
bash scripts/lab/dns-veth-netns.sh xdp-hit
```

这轮的验收点：

- `baseline`：所有请求都走用户态
- `xdp-miss`：请求被 XDP 看见，但主要回退到用户态
- `xdp-hit`：热点请求命中 `dns_hot_map`，用户态请求数下降

## 2. bpftool 烟测

这一步验证：

- 对象文件可以被加载并 pin
- `bpftool` 可以 attach 到指定接口
- `bpftool` 可以 detach 并恢复原状

运行方式：

```bash
bash scripts/lab/bpftool-smoke.sh
```

验收时要看三件事：

1. `bpftool net show dev <iface>` 能看到 XDP 附着
2. 通过 DNS 请求能拿到正确响应
3. detach 后 `bpftool net show dev <iface>` 不再显示 XDP

## 3. Host-VM 验证

Host-VM 阶段复用同一套验证逻辑，只替换：

- veth / 物理接口名
- host / VM 地址
- 目标 DNS 端口

建议做法：

- DNS 服务继续保持用户态
- XDP 挂在流量经过的 host-facing 接口上
- 先跑 `baseline`
- 再跑 `xdp-miss`
- 再跑 `xdp-hit`
- 最后 detach 回到纯用户态路径

如果 VM 的接口名或 IP 不固定，只需要覆盖脚本环境变量：

- `DNSLAB_HOST_IF`
- `DNSLAB_NS_IF`
- `DNSLAB_NS`
- `DNSLAB_HOST_IP`
- `DNSLAB_NS_IP`
- `DNSLAB_DNS_LISTEN`
- `DNSLAB_TARGET`
- `DNSLAB_PIN_PATH`

## 4. 统一口径

所有阶段都尽量保持：

- 同一组 queries
- 同一组并发和时长
- 关闭用户态 cache
- `xdp-hit` 只做热点预热，不改 query 集

这样能把性能变化尽量归因到 XDP 路径本身，而不是其他变量。

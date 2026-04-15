# 基于 eBPF 的多协议网络服务实时监控与热点请求加速系统

本项目面向 **DNS** 与 **gRPC** 两类典型网络服务，构建一个集 **实时监控、热点缓存、快速路径处理、虚拟化场景验证** 于一体的原型系统，用于验证 eBPF 在多协议网络服务性能优化中的可行性与效果。

## 1. 项目背景

传统网络服务在 Linux 环境中通常需要经过完整内核协议栈、虚拟化转发链路以及用户态应用处理路径，因此在高并发、热点请求和虚拟化部署场景下，往往存在较高的通信开销与时延开销。

eBPF 技术能够在不修改内核源码的前提下，将可控逻辑加载到内核中执行，因此非常适合用于实现网络服务性能监控、热点请求快速处理以及 Host-VM 场景下的数据路径优化。

## 2. 项目目标

1. 对至少两种网络服务实现基于 eBPF 的实时性能监控。
2. 对至少一种服务实现可验证的 eBPF 加速方案。
3. 在虚拟化 / Host-VM 场景下验证优化前后的通信开销变化。
4. 设计并实现一个“内核侧热点缓存 + 用户态完整缓存”的双端缓存机制。

## 3. 服务选型

### DNS

DNS 具有请求/响应模型简单、热点域名明显、适合缓存和快速返回等特点，适合作为本项目的 eBPF 加速对象。

### gRPC

gRPC 代表现代微服务 / RPC 通信场景，协议代表性强，适合作为重点监控对象，用于体现项目的多协议支持能力。

### 最终定位

- DNS：监控 + 加速
- gRPC：监控为主

## 4. 技术路线

本项目采用“先监控、后优化；先简单、后扩展”的路线。

1. 跑通 DNS 与 gRPC 基线服务
2. 完成 eBPF 监控能力
3. 对 DNS 实现热点缓存快速路径
4. 在 Host-VM 场景下验证优化效果
5. 完善双端缓存机制与实验结果展示

## 5. 系统总体设计

系统由四个核心部分组成：

1. 基础服务层：DNS 与 gRPC 服务
2. eBPF 监控层：请求数、延迟、错误率、连接情况等指标采集
3. eBPF 快速路径优化层：DNS 热点请求内核侧直接处理
4. 用户态控制与缓存协同层：加载 eBPF 程序、读取指标、更新缓存内容

## 6. 模块划分

### 6.1 服务基础模块

- DNS 服务模块：接收 DNS 查询请求，返回解析结果，作为基线和回退服务
- gRPC 服务模块：提供简单查询类 RPC 接口，作为第二类实验对象

### 6.2 eBPF 监控模块

- DNS 监控子模块：统计请求数、响应数、命中 / 未命中、平均时延、P95 / P99
- gRPC 监控子模块：统计请求量、响应量、错误率、连接建立情况、时延和重传
- 系统与网络指标子模块：采集 CPU 开销、内核态 / 用户态负载变化等信息

### 6.3 eBPF 加速模块

- DNS 热点缓存快速路径模块：命中时直接构造并返回响应，未命中则放行到用户态
- 缓存命中统计模块：统计命中率与热点项访问次数

### 6.4 双端缓存协同模块

- 内核侧热点缓存模块：存储高频查询项，支持 TTL、过期删除、简单淘汰
- 用户态完整缓存模块：存储更完整的记录集，负责复杂缓存逻辑
- 缓存同步与更新模块：用户态根据访问频率维护热点项并回填到 BPF map

### 6.5 虚拟化验证模块

- Host-VM 部署模块：Host 挂载 eBPF 程序，VM 内运行 DNS / gRPC 服务
- 通信开销评估模块：比较优化前后 Host ↔ VM 路径的时延、QPS、CPU 等指标

### 6.6 用户态控制模块

- eBPF 加载器模块：加载 eBPF 程序、管理 map、获取 ring buffer / metrics 数据
- 指标展示模块：输出日志、表格或简单图表
- 实验控制模块：启停实验、切换优化开关、统一采集结果

## 7. 双端缓存机制

### 第一层：eBPF 热点缓存

- 位于内核快速路径
- 存储最热的查询项
- 追求极低处理时延
- 容量较小，逻辑保持简洁

### 第二层：用户态完整缓存

- 位于 DNS 服务或用户态 agent
- 存储更完整的记录集
- 支持更复杂的 TTL、更新、回源与淘汰逻辑

### 协同流程

1. 请求首先进入 eBPF 热点缓存
2. 命中则直接快速返回
3. 未命中则转交用户态 DNS 服务处理
4. 用户态命中完整缓存或完成回源后返回结果
5. 热点项由用户态回填到 eBPF 热点缓存
6. 冷门项按访问频率或 TTL 淘汰

## 8. 虚拟化场景设计

- Host：挂载 eBPF 程序，负责监控与热点缓存快速处理
- VM：运行 DNS 与 gRPC 服务
- 流量路径：客户端请求先到 Host，再决定是否进入 VM 用户态服务

### 优化逻辑

- DNS：热点请求在 Host 侧命中缓存时直接返回，减少 Host 与 VM 间的通信开销
- gRPC：重点观测连接建立、请求时延与网络队列情况，用于分析虚拟化通信额外开销

## 9. 预期创新点

1. 多协议统一监控
2. 热点请求快速路径优化
3. 双端缓存机制
4. 虚拟化场景优化验证

## 10. 预期结果

- 实现 DNS 和 gRPC 的实时性能监控
- 实现 DNS 热点请求的 eBPF 快速处理
- 在 Host-VM 场景下观察到时延下降或 CPU 开销降低
- 输出完整的系统设计、实验数据与答辩材料

## 11. 阶段性推进计划

### 第一阶段：定题与范围收敛

- 明确服务选型：DNS + gRPC
- 明确优化主战场：DNS
- 明确监控对象：DNS + gRPC
- 输出整体方案文档

### 第二阶段：基线系统搭建

- 跑通 DNS 服务
- 跑通 gRPC 服务
- 获取无优化基线性能数据
- 准备 Host-VM 环境

### 第三阶段：eBPF 监控实现

- 实现 DNS 监控
- 实现 gRPC 监控
- 输出基础性能指标

### 第四阶段：DNS 快速路径优化

- 实现 DNS 热点缓存
- 实现命中后快速响应
- 统计命中率与加速效果

### 第五阶段：虚拟化场景验证

- 在 Host-VM 场景下部署服务
- 对比优化前后通信路径和性能变化

### 第六阶段：系统整合与答辩准备

- 整理双端缓存机制
- 完善性能对比实验
- 完成 README、PPT、答辩材料

## 12. 不做内容清单

本项目明确不做：

- 完整的 gRPC 应用层加速
- LDAP 深度支持
- 工业级通用缓存系统
- 复杂 AI / 智能调参策略
- 完整工业级 KVM 网络栈改造
- 复杂 Web Dashboard

## 13. 推荐仓库目录结构

```text
project/
├── README.md
├── docs/
│   ├── design.md
│   ├── experiment.md
│   └── figures/
├── bpf/
│   ├── dns_monitor.c
│   ├── grpc_monitor.c
│   ├── dns_cache_fastpath.c
│   └── common.h
├── user/
│   ├── loader/
│   ├── controller/
│   ├── metrics/
│   └── cache_manager/
├── services/
│   ├── dns/
│   └── grpc/
├── scripts/
│   ├── benchmark/
│   ├── lab/
│   └── deploy/
└── tests/
```

## 14. 当前仓库状态

本仓库已创建基础目录骨架，后续可继续补充：

- eBPF 监控代码
- DNS / gRPC 基线服务
- 用户态加载与控制逻辑
- 实验脚本与结果记录
- 本地 `veth + netns` smoke、`bpftool` attach/detach 烟测、Host-VM 验证文档

## 15. 实现顺序

本项目不要并行把所有东西都写开。推荐按下面顺序推进，每一步都要能形成可验证产物。

### 第 1 步：DNS baseline 骨架

目标：先把一个最小可跑的 DNS 服务跑起来，作为后续 eBPF 优化的对照组。

需要实现：

- `services/dns/cmd/dnsd/main.go`
- `services/dns/internal/config`
- `services/dns/internal/dnsmsg`
- `services/dns/internal/store`
- `services/dns/internal/cache`
- `services/dns/internal/server`
- `services/dns/internal/metrics`

产物：

- UDP DNS 服务可启动
- 支持固定 `A` 记录查询
- 支持 TTL
- 支持基础日志和指标

### 第 2 步：DNS 压测工具

目标：先能稳定测出 baseline 数据。

需要实现：

- `scripts/benchmark/` 下的压测脚本
- Go 压测工具或 `dig` 批量调用脚本
- 结果导出为 `csv` 或 `json`

产物：

- QPS
- 平均延迟
- P95 / P99
- 命中率 / 未命中率

### 第 3 步：用户态测试工具链

目标：把性能测试和回归测试固定下来，避免后面每次都临时手工测。

需要实现：

- `internal/testkit/loadgen`
- `internal/testkit/report`
- `internal/testkit/assert`
- `internal/testkit/profiler`
- `internal/testkit/benchcmp`

产物：

- 可重复压测
- 可重复生成报告
- 可做 baseline vs 优化版对比

### 第 4 步：eBPF 监控

目标：先只做观测，不做加速。

需要实现：

- DNS 请求计数
- DNS 时延统计
- DNS 命中 / 未命中统计
- gRPC 请求量和错误率统计

产物：

- eBPF 程序初版
- 用户态加载器
- 指标读取和输出

### 第 5 步：DNS 热点缓存 fast path

目标：实现真正的内核侧加速。

需要实现：

- `BPF map` 热点缓存
- XDP 查表命中逻辑
- 未命中 `XDP_PASS`
- 用户态回填热点项

产物：

- 命中直返
- 未命中回退用户态
- 热点项可动态回填

### 第 6 步：虚拟化场景验证

目标：验证 Host-VM 场景下的收益。

需要实现：

- Host 侧挂载 eBPF
- VM 内运行 DNS / gRPC 服务
- 对比优化前后路径和时延

产物：

- Host-VM 实验图
- 对比数据
- 答辩材料素材

### 第 7 步：gRPC 监控补齐

目标：完成多协议监控要求。

需要实现：

- gRPC 请求量统计
- gRPC 延迟统计
- gRPC 错误率统计
- 网络连接情况统计

产物：

- gRPC 监控指标
- 多协议统一展示

## 16. 第一批 Go 文件建议

如果现在开始写代码，先只开这几个文件。

### DNS 服务主线

- `services/dns/cmd/dnsd/main.go`
- `services/dns/internal/server/server.go`
- `services/dns/internal/dnsmsg/message.go`
- `services/dns/internal/store/store.go`
- `services/dns/internal/cache/cache.go`
- `services/dns/internal/metrics/metrics.go`
- `services/dns/internal/config/config.go`

### 工具测试主线

- `services/dns/internal/testkit/loadgen/loadgen.go`
- `services/dns/internal/testkit/profiler/profiler.go`
- `services/dns/internal/testkit/report/report.go`
- `services/dns/internal/testkit/assert/assert.go`
- `services/dns/internal/testkit/benchcmp/benchcmp.go`

### 后续优化主线

- `bpf/dns_monitor.c`
- `bpf/dns_cache_fastpath.c`
- `user/loader/`
- `user/controller/`
- `user/cache_manager/`

## 17. 现在的执行建议

当前最稳的推进顺序是：

1. 先写 `dnsmsg`，把 DNS 报文编解码搞定
2. 再写 `store`，放固定域名记录
3. 再写 `cache`，做用户态缓存
4. 再写 `server`，把 UDP 服务跑起来
5. 再写 `loadgen`，拿到基线性能数据
6. 最后再进 eBPF 监控和 fast path

如果你愿意，下一步我可以直接按这个顺序把 `services/dns/` 的目录和第一批 Go 文件骨架补出来。

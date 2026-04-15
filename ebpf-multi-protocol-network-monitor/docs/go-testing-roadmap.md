# Go 测试学习路线

这个路线是面向测试开发岗和当前 DNS baseline 项目的，目标不是“会写测试代码”，而是能建立一套稳定的测试体系。

## 1. 第一阶段：测试基础语法

先掌握 Go 原生测试最常见的写法。

你需要熟悉的内容：

- `*_test.go` 文件命名
- `TestXxx(t *testing.T)`
- `t.Fatal` / `t.Fatalf`
- `t.Error` / `t.Errorf`
- 表驱动测试
- `t.Run`
- `t.Setenv`
- `t.TempDir`

建议练习对象：

- `internal/config`
- `internal/logging`

## 2. 第二阶段：单元测试设计

这一阶段重点是学会给“小功能”写稳定测试。

你需要熟悉的内容：

- 输入和输出的边界
- 默认值测试
- 错误分支测试
- 分支覆盖
- 失败用例设计

建议练习对象：

- 配置解析
- 日志级别和输出格式
- 缓存命中 / 未命中

## 3. 第三阶段：集成测试

这一阶段开始测多个模块协同。

你需要熟悉的内容：

- 本地 UDP/TCP 测试
- 临时目录和临时文件
- mock 或 fake 数据源
- 端到端请求与响应校验

建议练习对象：

- `dnsmsg`
- `cache`
- `server`

## 4. 第四阶段：性能和质量测试

这一阶段是投递测试开发岗最关键的部分。

你需要熟悉的内容：

- Benchmark
- `go test -bench`
- `go test -benchmem`
- `go test -race`
- `go test -cover`
- `go test -fuzz`
- `pprof`

建议练习对象：

- `loadgen`
- `profiler`
- `benchcmp`

## 5. 第五阶段：项目化测试体系

这一阶段你要把测试从“写几个 case”变成“有体系的验证工具”。

你需要建立的能力：

- 统一测试入口
- 基线和优化版对比
- 压测结果导出
- 回归测试
- 指标记录和分析

建议练习对象：

- `services/dns/internal/testkit`
- `internal/metrics`

## 6. 当前项目的推荐学习顺序

按下面顺序推进，学习和项目同步进行：

1. `internal/config`：表驱动测试
2. `internal/logging`：输出断言测试
3. `services/dns/internal/cache`：TTL 和命中测试
4. `services/dns/internal/dnsmsg`：编解码测试
5. `services/dns/internal/server`：集成测试
6. `services/dns/internal/testkit/loadgen`：压测测试
7. `services/dns/internal/testkit/profiler`：性能采集
8. `services/dns/internal/testkit/benchcmp`：结果对比

## 7. 最常用的命令

```bash
go test ./...
go test -v ./internal/config
go test -v ./internal/logging
go test -race ./...
go test -cover ./...
go test -bench=. ./...
go test -fuzz=. ./...
```

## 8. 你现在已经完成的内容

- `internal/config` 的默认值、环境变量、flag、校验测试
- `internal/logging` 的文本输出、JSON 输出、非法参数、文件输出测试

下一步建议开始：

- `cache` 的 TTL 测试
- `dnsmsg` 的编解码测试


module ebpf-multi-protocol-network-monitor

go 1.22

require github.com/cilium/ebpf v0.12.3

require (
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
	golang.org/x/sys v0.14.1-0.20231108175955-e4099bfacb8c // indirect
)

replace github.com/cilium/ebpf => /Users/tankaiwen/go/pkg/mod/github.com/cilium/ebpf@v0.12.3

replace golang.org/x/exp => /Users/tankaiwen/go/pkg/mod/golang.org/x/exp@v0.0.0-20231110203233-9a3e6036ecaa

replace golang.org/x/sys => /Users/tankaiwen/go/pkg/mod/golang.org/x/sys@v0.38.0

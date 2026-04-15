#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=/dev/null
source "$SCRIPT_DIR/common.sh"

lab_require_cmd ip
lab_require_cmd bpftool
lab_require_cmd curl
lab_ensure_build "$ROOT"

HOST_IF="${DNSLAB_HOST_IF:-dnslab0}"
NS_IF="${DNSLAB_NS_IF:-dnslab1}"
NS="${DNSLAB_NS:-dnslab-ns}"
HOST_IP="${DNSLAB_HOST_IP:-10.200.1.1}"
NS_IP="${DNSLAB_NS_IP:-10.200.1.2}"
DNS_LISTEN="${DNSLAB_DNS_LISTEN:-${HOST_IP}:1053}"
TARGET="${DNSLAB_TARGET:-${HOST_IP}:1053}"
METRICS_LISTEN="${DNSLAB_METRICS_LISTEN:-127.0.0.1:19090}"
METRICS_PATH="${DNSLAB_METRICS_PATH:-/metrics}"
PIN_PATH="${DNSLAB_PIN_PATH:-/sys/fs/bpf/dns-veth-netns}"
READY_FILE="${DNSLAB_READY_FILE:-$(mktemp /tmp/dnsxdp-ready.XXXXXX)}"
ATTACH_WAIT="${DNSLAB_ATTACH_WAIT:-5s}"
DURATION="${DNSLAB_DURATION:-5s}"
CONCURRENCY="${DNSLAB_CONCURRENCY:-8}"
TIMEOUT="${DNSLAB_TIMEOUT:-1s}"
MODE="${1:-all}"

DNSD_PID=""
BENCH_PID=""
RESULT_DIR="$(mktemp -d /tmp/dnslab-results.XXXXXX)"

cleanup() {
	lab_kill_pid "$BENCH_PID" "dnsbench"
	lab_kill_pid "$DNSD_PID" "dnsd"
	bpftool net detach xdp dev "$HOST_IF" >/dev/null 2>&1 || true
	lab_teardown_veth_netns "$HOST_IF" "$NS"
	rm -rf "$PIN_PATH" "$RESULT_DIR" "$READY_FILE"
}
trap cleanup EXIT INT TERM

start_dnsd() {
	local log="$RESULT_DIR/dnsd.log"
	"$ROOT/dist/dnsd" \
		--dns.listen "$DNS_LISTEN" \
		--dns.enable-cache=false \
		--metrics.enabled=true \
		--metrics.listen "$METRICS_LISTEN" \
		--metrics.path "$METRICS_PATH" \
		--xdp.enabled=false \
		>"$log" 2>&1 &
	DNSD_PID=$!
	lab_wait_for_log "$log" "dns server listening" 20
	lab_wait_for_log "$log" "metrics endpoint listening" 20
	echo "dnsd log: $log"
}

print_metrics() {
	echo "dnsd metrics:"
	curl -fsS "http://${METRICS_LISTEN}${METRICS_PATH}" || true
}

run_baseline() {
	local log="$RESULT_DIR/baseline.log"
	echo "running baseline benchmark"
	ip netns exec "$NS" "$ROOT/dist/dnsbench" \
		--bench.mode baseline \
		--loadgen.target "$TARGET" \
		--loadgen.duration "$DURATION" \
		--loadgen.concurrency "$CONCURRENCY" \
		--loadgen.timeout "$TIMEOUT" \
		--dns.enable-cache=false \
		--metrics.enabled=false \
		>"$log" 2>&1
	cat "$log"
	print_metrics
}

run_xdp_mode() {
	local mode="$1"
	local log="$RESULT_DIR/${mode}.log"
	rm -f "$READY_FILE"
	rm -rf "$PIN_PATH"

	echo "running ${mode} benchmark"
	ip netns exec "$NS" "$ROOT/dist/dnsbench" \
		--bench.mode "$mode" \
		--loadgen.target "$TARGET" \
		--loadgen.duration "$DURATION" \
		--loadgen.concurrency "$CONCURRENCY" \
		--loadgen.timeout "$TIMEOUT" \
		--dns.enable-cache=false \
		--metrics.enabled=false \
		--xdp.enabled=true \
		--xdp.auto-attach=false \
		--xdp.attach-wait "$ATTACH_WAIT" \
		--xdp.ready-file "$READY_FILE" \
		--xdp.iface "$HOST_IF" \
		--xdp.object "$ROOT/dist/dns_ingress.o" \
		--xdp.pin-path "$PIN_PATH" \
		>"$log" 2>&1 &
	BENCH_PID=$!

	lab_wait_for_file "$READY_FILE" 20
	echo "attaching xdp via bpftool on ${HOST_IF}"
	if ! bpftool net attach xdp pinned "$PIN_PATH/dns_ingress" dev "$HOST_IF" xdpgeneric; then
		echo "bpftool attach failed" >&2
		lab_kill_pid "$BENCH_PID" "dnsbench"
		return 1
	fi
	bpftool net show dev "$HOST_IF" || true

	wait "$BENCH_PID"
	BENCH_PID=""

	echo "detaching xdp via bpftool from ${HOST_IF}"
	bpftool net detach xdp dev "$HOST_IF" || true
	bpftool net show dev "$HOST_IF" || true

	cat "$log"
	print_metrics
}

main() {
	lab_setup_veth_netns "$HOST_IF" "$NS_IF" "$NS" "$HOST_IP" "$NS_IP"
	start_dnsd

	case "$MODE" in
		all)
			run_baseline
			run_xdp_mode xdp-miss
			run_xdp_mode xdp-hit
			;;
		baseline|xdp-miss|xdp-hit)
			if [[ "$MODE" == "baseline" ]]; then
				run_baseline
			else
				run_xdp_mode "$MODE"
			fi
			;;
		*)
			echo "usage: $0 [baseline|xdp-miss|xdp-hit|all]" >&2
			return 2
			;;
	esac
}

main "$@"

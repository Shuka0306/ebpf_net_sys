lab_script_dir() {
	local src="${BASH_SOURCE[0]}"
	cd "$(dirname "$src")" && pwd
}

lab_repo_root() {
	local dir
	dir="$(lab_script_dir)"
	cd "$dir/../.." && pwd
}

lab_require_cmd() {
	local cmd="$1"
	if ! command -v "$cmd" >/dev/null 2>&1; then
		echo "missing required command: $cmd" >&2
		exit 1
	fi
}

lab_ensure_build() {
	local root="$1"
	if [[ -x "$root/dist/dnsd" && -x "$root/dist/dnsbench" && -f "$root/dist/dns_ingress.o" ]]; then
		return 0
	fi

	( cd "$root" && make bpf dnsd dnsbench )
}

lab_wait_for_file() {
	local path="$1"
	local timeout="${2:-30}"
	local deadline=$((SECONDS + timeout))
	while [[ ! -e "$path" ]]; do
		if (( SECONDS >= deadline )); then
			echo "timeout waiting for file: $path" >&2
			return 1
		fi
		sleep 0.2
	done
}

lab_wait_for_log() {
	local file="$1"
	local needle="$2"
	local timeout="${3:-30}"
	local deadline=$((SECONDS + timeout))
	while ! grep -qF "$needle" "$file" 2>/dev/null; do
		if (( SECONDS >= deadline )); then
			echo "timeout waiting for log pattern: $needle" >&2
			return 1
		fi
		sleep 0.2
	done
}

lab_kill_pid() {
	local pid="$1"
	local name="${2:-process}"
	if [[ -z "$pid" ]]; then
		return 0
	fi
	if kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	else
		echo "$name already exited: $pid" >&2
	fi
}

lab_teardown_veth_netns() {
	local host_if="$1"
	local ns="$2"

	ip link show "$host_if" >/dev/null 2>&1 && ip link del "$host_if" || true
	ip netns list | awk '{print $1}' | grep -qx "$ns" && ip netns del "$ns" || true
}

lab_setup_veth_netns() {
	local host_if="$1"
	local ns_if="$2"
	local ns="$3"
	local host_ip="$4"
	local ns_ip="$5"

	lab_teardown_veth_netns "$host_if" "$ns"
	ip netns add "$ns"
	ip link add "$host_if" type veth peer name "$ns_if"
	ip addr add "$host_ip/24" dev "$host_if"
	ip link set "$host_if" up
	ip link set "$ns_if" netns "$ns"
	ip -n "$ns" link set lo up
	ip -n "$ns" addr add "$ns_ip/24" dev "$ns_if"
	ip -n "$ns" link set "$ns_if" up
	ip -n "$ns" route replace "$host_ip/32" dev "$ns_if"
}

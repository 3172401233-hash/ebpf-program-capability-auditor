"""内核能力规格表: helper、程序类型、attach 类型与上下文布局。

数据为常用子集, 版本号为该能力引入的最低内核版本。
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class HelperSpec:
    id: int
    name: str
    min_kernel: tuple[int, int]
    privileged: bool = False
    map_op: str | None = None  # "read" / "write" / None
    tail_call: bool = False


HELPERS: dict[int, HelperSpec] = {}


def _h(id, name, min_kernel, privileged=False, map_op=None, tail_call=False):
    HELPERS[id] = HelperSpec(id, name, min_kernel, privileged, map_op, tail_call)


_h(1, "bpf_map_lookup_elem", (3, 18), map_op="read")
_h(2, "bpf_map_update_elem", (3, 18), map_op="write")
_h(3, "bpf_map_delete_elem", (3, 18), map_op="write")
_h(4, "bpf_probe_read", (3, 18), privileged=True)
_h(5, "bpf_ktime_get_ns", (3, 18))
_h(6, "bpf_trace_printk", (3, 18))
_h(7, "bpf_get_prandom_u32", (3, 18))
_h(12, "bpf_tail_call", (4, 2), tail_call=True)
_h(14, "bpf_get_current_pid_tgid", (3, 18))
_h(15, "bpf_get_current_uid_gid", (3, 18))
_h(16, "bpf_get_current_comm", (3, 18))
_h(25, "bpf_perf_event_output", (4, 3))
_h(27, "bpf_get_stackid", (4, 6), privileged=True)
_h(35, "bpf_get_current_task", (4, 8), privileged=True)
_h(36, "bpf_probe_write_user", (4, 8), privileged=True)
_h(44, "bpf_xdp_adjust_head", (4, 10))
_h(45, "bpf_probe_read_str", (4, 11), privileged=True)
_h(51, "bpf_redirect_map", (4, 14))
_h(54, "bpf_xdp_adjust_meta", (4, 15))
_h(65, "bpf_xdp_adjust_tail", (4, 15))
_h(67, "bpf_get_stack", (4, 18), privileged=True)
_h(80, "bpf_get_current_cgroup_id", (4, 18))
_h(87, "bpf_map_push_elem", (4, 20), map_op="write")
_h(88, "bpf_map_pop_elem", (5, 0), map_op="write")
_h(89, "bpf_map_peek_elem", (5, 0), map_op="read")
_h(93, "bpf_spin_lock", (5, 1))
_h(94, "bpf_spin_unlock", (5, 1))
_h(121, "bpf_get_current_task_btf", (5, 11), privileged=True)
_h(125, "bpf_ringbuf_output", (5, 8))
_h(126, "bpf_ringbuf_reserve", (5, 8))
_h(131, "bpf_csum_level", (5, 10))
_h(144, "bpf_get_task_stack", (5, 13), privileged=True)
_h(158, "bpf_ktime_get_coarse_ns", (5, 16))
_h(167, "bpf_kptr_xchg", (6, 2))

HELPERS_BY_NAME = {h.name: h for h in HELPERS.values()}


@dataclass(frozen=True)
class ProgTypeSpec:
    name: str
    min_kernel: tuple[int, int]
    context: str
    allowed_attach: frozenset[str]


@dataclass(frozen=True)
class AttachSpec:
    name: str
    min_kernel: tuple[int, int]


ATTACH_TYPES: dict[str, AttachSpec] = {
    "SOCKET_FILTER": AttachSpec("SOCKET_FILTER", (3, 19)),
    "CGROUP_INET_INGRESS": AttachSpec("CGROUP_INET_INGRESS", (4, 10)),
    "CGROUP_INET_EGRESS": AttachSpec("CGROUP_INET_EGRESS", (4, 10)),
    "CGROUP_INET_SOCK_CREATE": AttachSpec("CGROUP_INET_SOCK_CREATE", (4, 10)),
    "CGROUP_INET4_CONNECT": AttachSpec("CGROUP_INET4_CONNECT", (4, 17)),
    "XDP": AttachSpec("XDP", (4, 8)),
    "TRACEPOINT": AttachSpec("TRACEPOINT", (4, 7)),
    "SCHED_CLS": AttachSpec("SCHED_CLS", (4, 1)),
}

_SK_BUFF_ATTACH = frozenset({
    "SOCKET_FILTER",
    "CGROUP_INET_INGRESS",
    "CGROUP_INET_EGRESS",
    "SCHED_CLS",
})

PROG_TYPES: dict[str, ProgTypeSpec] = {
    "SOCKET_FILTER": ProgTypeSpec("SOCKET_FILTER", (3, 19), "__sk_buff", _SK_BUFF_ATTACH),
    "SCHED_CLS": ProgTypeSpec("SCHED_CLS", (4, 1), "__sk_buff", frozenset({"SCHED_CLS"})),
    "XDP": ProgTypeSpec("XDP", (4, 8), "xdp_md", frozenset({"XDP"})),
    "CGROUP_SKB": ProgTypeSpec(
        "CGROUP_SKB", (4, 10), "__sk_buff",
        frozenset({"CGROUP_INET_INGRESS", "CGROUP_INET_EGRESS"}),
    ),
    "CGROUP_SOCK": ProgTypeSpec(
        "CGROUP_SOCK", (4, 10), "bpf_sock",
        frozenset({"CGROUP_INET_SOCK_CREATE"}),
    ),
    "TRACEPOINT": ProgTypeSpec("TRACEPOINT", (4, 7), "tracepoint_raw", frozenset({"TRACEPOINT"})),
}


@dataclass(frozen=True)
class ContextField:
    name: str
    offset: int
    size: int
    min_kernel: tuple[int, int] = (3, 18)


@dataclass(frozen=True)
class ContextSpec:
    name: str
    fields: tuple[ContextField, ...]

    def find(self, offset: int, size: int) -> ContextField | None:
        for f in self.fields:
            if f.offset <= offset and offset + size <= f.offset + f.size:
                return f
        return None


def _ctx(name, fields):
    return ContextSpec(name, tuple(ContextField(*f) for f in fields))


CONTEXTS: dict[str, ContextSpec] = {
    "__sk_buff": _ctx("__sk_buff", [
        ("len", 0, 4),
        ("pkt_type", 4, 4),
        ("mark", 8, 4),
        ("queue_mapping", 12, 4),
        ("protocol", 16, 4),
        ("vlan_present", 20, 4),
        ("vlan_tci", 24, 4),
        ("vlan_proto", 28, 4),
        ("priority", 32, 4),
        ("ingress_ifindex", 36, 4),
        ("ifindex", 40, 4),
        ("tc_index", 44, 4),
        ("cb", 48, 20),
        ("hash", 68, 4),
        ("tc_classid", 72, 4),
        ("data", 76, 4),
        ("data_end", 80, 4),
        ("napi_id", 84, 4),
        ("family", 88, 4),
        ("remote_ip4", 92, 4),
        ("local_ip4", 96, 4),
        ("remote_ip6", 100, 16),
        ("local_ip6", 116, 16),
        ("remote_port", 132, 4),
        ("local_port", 136, 4),
        ("data_meta", 140, 4),
        ("tstamp", 144, 8),
        ("wire_len", 152, 4),
        ("gso_segs", 156, 4),
    ]),
    "xdp_md": _ctx("xdp_md", [
        ("data", 0, 4),
        ("data_end", 4, 4),
        ("data_meta", 8, 4),
        ("ingress_ifindex", 12, 4),
        ("rx_queue_index", 16, 4),
        ("egress_ifindex", 20, 4, (5, 9)),
    ]),
    "bpf_sock": _ctx("bpf_sock", [
        ("bound_dev_if", 0, 4),
        ("family", 4, 4),
        ("type", 8, 4),
        ("protocol", 12, 4),
        ("mark", 16, 4),
        ("priority", 20, 4),
        ("src_ip4", 24, 4),
        ("src_ip6", 28, 16),
        ("src_port", 44, 4),
        ("dst_port", 48, 4),
        ("dst_ip4", 52, 4),
        ("dst_ip6", 56, 16),
        ("state", 72, 4),
        ("rx_queue_mapping", 76, 4),
    ]),
    "tracepoint_raw": _ctx("tracepoint_raw", [
        ("args", 0, 128),
    ]),
}

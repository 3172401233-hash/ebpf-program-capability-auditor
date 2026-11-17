import unittest

from ebpf_audit import Auditor, MapPermission, ERROR, WARNING, INFO
from ebpf_audit.instruction import (
    encode, encode_ld_imm64, BPF_PSEUDO_MAP_FD, BPF_PSEUDO_CALL,
)

LDX_W = 0x61
LDX_DW = 0x79
STX_W = 0x63
MOV64_REG = 0xBF
CALL = 0x85
EXIT = 0x95
JA = 0x05
JEQ_IMM = 0x15

HELPER_LOOKUP = 1
HELPER_UPDATE = 2
HELPER_PROBE_READ = 4
HELPER_TAIL_CALL = 12
HELPER_RINGBUF_OUTPUT = 125


def mov(dst, src):
    return encode(MOV64_REG, dst=dst, src=src)


def call(imm, src=0):
    return encode(CALL, imm=imm, src=src)


def categories(report, severity=None):
    return {
        f.category for f in report.findings
        if severity is None or f.severity == severity
    }


class SocketTraceTests(unittest.TestCase):
    """socket filter 程序: 合法路径与特权 helper 滥用。"""

    def test_valid_socket_filter(self):
        code = b"".join([
            mov(6, 1),                                    # r6 = ctx
            encode_ld_imm64(1, BPF_PSEUDO_MAP_FD, 1),     # r1 = map 1
            call(HELPER_LOOKUP),                          # r0 = value ptr
            encode(LDX_W, dst=0, src=0, off=0),           # 读 map 值 [0,4)
            encode(LDX_W, dst=0, src=6, off=0),           # 读 ctx len
            encode(EXIT),
        ])
        auditor = Auditor(
            "SOCKET_FILTER", "SOCKET_FILTER",
            helper_whitelist=["bpf_map_lookup_elem"],
            map_permissions=[MapPermission(1, value_size=8)],
        )
        report = auditor.audit(code)
        self.assertTrue(report.ok, report.summary())
        self.assertEqual(report.helpers_used, ["bpf_map_lookup_elem"])
        self.assertEqual(report.map_accesses[1].max_read_end, 4)
        self.assertIn("__sk_buff.len", report.context_fields_read)

    def test_unprivileged_calls_privileged_helper(self):
        code = call(HELPER_PROBE_READ) + encode(EXIT)
        auditor = Auditor("SOCKET_FILTER", "SOCKET_FILTER", unprivileged=True)
        report = auditor.audit(code)
        self.assertFalse(report.ok)
        self.assertIn("privilege", categories(report, ERROR))

    def test_privileged_allowed_when_privileged(self):
        code = call(HELPER_PROBE_READ) + encode(EXIT)
        auditor = Auditor("SOCKET_FILTER", "SOCKET_FILTER", unprivileged=False)
        report = auditor.audit(code)
        self.assertTrue(report.ok, report.summary())

    def test_helper_not_in_whitelist(self):
        code = b"".join([
            encode_ld_imm64(1, BPF_PSEUDO_MAP_FD, 1),
            call(HELPER_LOOKUP),
            encode(EXIT),
        ])
        auditor = Auditor(
            "SOCKET_FILTER", "SOCKET_FILTER",
            helper_whitelist=["bpf_ktime_get_ns"],
            map_permissions=[MapPermission(1)],
        )
        report = auditor.audit(code)
        self.assertFalse(report.ok)
        self.assertIn("helper", categories(report, ERROR))

    def test_unknown_helper(self):
        code = call(9999) + encode(EXIT)
        report = Auditor("SOCKET_FILTER", "SOCKET_FILTER").audit(code)
        self.assertFalse(report.ok)
        self.assertIn("helper", categories(report, ERROR))

    def test_whitelist_unknown_name_rejected(self):
        with self.assertRaises(ValueError):
            Auditor("SOCKET_FILTER", "SOCKET_FILTER",
                    helper_whitelist=["bpf_not_a_helper"])


class XdpTests(unittest.TestCase):
    def test_valid_xdp(self):
        code = b"".join([
            encode(LDX_W, dst=2, src=1, off=0),    # data
            encode(LDX_W, dst=3, src=1, off=4),    # data_end
            encode(EXIT),
        ])
        report = Auditor("XDP", "XDP").audit(code)
        self.assertTrue(report.ok, report.summary())
        self.assertIn("xdp_md.data", report.context_fields_read)

    def test_xdp_reads_sk_buff_field(self):
        # xdp_md 只有 24 字节, 偏移 76 是 __sk_buff.data, 不属于 XDP 上下文
        code = encode(LDX_W, dst=2, src=1, off=76) + encode(EXIT)
        report = Auditor("XDP", "XDP").audit(code)
        self.assertFalse(report.ok)
        self.assertIn("context", categories(report, ERROR))

    def test_xdp_field_requires_newer_kernel(self):
        # egress_ifindex 需要 5.9
        code = encode(LDX_W, dst=2, src=1, off=20) + encode(EXIT)
        report = Auditor("XDP", "XDP", kernel_version=(5, 4)).audit(code)
        self.assertFalse(report.ok)
        self.assertIn("kernel_version", categories(report, ERROR))

    def test_xdp_prog_type_too_old_kernel(self):
        code = encode(EXIT)
        report = Auditor("XDP", "XDP", kernel_version=(4, 4)).audit(code)
        self.assertFalse(report.ok)
        self.assertIn("kernel_version", categories(report, ERROR))


class CgroupTests(unittest.TestCase):
    def test_valid_cgroup_skb(self):
        code = encode(LDX_W, dst=2, src=1, off=8) + encode(EXIT)  # mark
        report = Auditor("CGROUP_SKB", "CGROUP_INET_EGRESS").audit(code)
        self.assertTrue(report.ok, report.summary())
        self.assertIn("__sk_buff.mark", report.context_fields_read)

    def test_cgroup_sock_context(self):
        code = encode(LDX_W, dst=2, src=1, off=4) + encode(EXIT)  # family
        report = Auditor("CGROUP_SOCK", "CGROUP_INET_SOCK_CREATE").audit(code)
        self.assertTrue(report.ok, report.summary())
        self.assertIn("bpf_sock.family", report.context_fields_read)

    def test_attach_type_mismatch(self):
        code = encode(EXIT)
        report = Auditor("CGROUP_SOCK", "CGROUP_INET_EGRESS").audit(code)
        self.assertFalse(report.ok)
        self.assertIn("attach_type", categories(report, ERROR))

    def test_context_write_rejected(self):
        code = encode(STX_W, dst=1, src=2, off=0) + encode(EXIT)
        report = Auditor("CGROUP_SKB", "CGROUP_INET_INGRESS").audit(code)
        self.assertFalse(report.ok)
        self.assertIn("context", categories(report, ERROR))


class MapTests(unittest.TestCase):
    def test_illegal_map_write_via_helper(self):
        code = b"".join([
            encode_ld_imm64(1, BPF_PSEUDO_MAP_FD, 7),
            call(HELPER_UPDATE),
            encode(EXIT),
        ])
        auditor = Auditor(
            "SOCKET_FILTER", "SOCKET_FILTER",
            map_permissions=[MapPermission(7, writable=False)],
        )
        report = auditor.audit(code)
        self.assertFalse(report.ok)
        self.assertIn("map", categories(report, ERROR))
        self.assertEqual(report.map_accesses[7].writes, 1)

    def test_illegal_map_write_via_value_pointer(self):
        code = b"".join([
            encode_ld_imm64(1, BPF_PSEUDO_MAP_FD, 7),
            call(HELPER_LOOKUP),
            encode(STX_W, dst=0, src=2, off=0),
            encode(EXIT),
        ])
        auditor = Auditor(
            "SOCKET_FILTER", "SOCKET_FILTER",
            map_permissions=[MapPermission(7, writable=False, value_size=8)],
        )
        report = auditor.audit(code)
        self.assertFalse(report.ok)
        self.assertIn("map", categories(report, ERROR))

    def test_map_value_read_out_of_range(self):
        code = b"".join([
            encode_ld_imm64(1, BPF_PSEUDO_MAP_FD, 3),
            call(HELPER_LOOKUP),
            encode(LDX_DW, dst=0, src=0, off=4),   # [4,12) 超出 value_size=8
            encode(EXIT),
        ])
        auditor = Auditor(
            "SOCKET_FILTER", "SOCKET_FILTER",
            map_permissions=[MapPermission(3, value_size=8)],
        )
        report = auditor.audit(code)
        self.assertFalse(report.ok)
        self.assertIn("map", categories(report, ERROR))
        self.assertEqual(report.map_accesses[3].max_read_end, 12)

    def test_map_max_range_within_bounds(self):
        code = b"".join([
            encode_ld_imm64(1, BPF_PSEUDO_MAP_FD, 3),
            call(HELPER_LOOKUP),
            encode(LDX_DW, dst=4, src=0, off=0),
            encode(LDX_DW, dst=5, src=0, off=8),
            encode(EXIT),
        ])
        auditor = Auditor(
            "SOCKET_FILTER", "SOCKET_FILTER",
            map_permissions=[MapPermission(3, value_size=16)],
        )
        report = auditor.audit(code)
        self.assertTrue(report.ok, report.summary())
        self.assertEqual(report.map_accesses[3].max_read_end, 16)


class StructuralTests(unittest.TestCase):
    def test_truncated_instructions(self):
        code = encode(EXIT) + b"\x05\x00\x00"
        report = Auditor("SOCKET_FILTER", "SOCKET_FILTER").audit(code)
        self.assertFalse(report.ok)
        self.assertIn("truncated", categories(report, ERROR))

    def test_fully_truncated_program(self):
        report = Auditor("SOCKET_FILTER", "SOCKET_FILTER").audit(b"\x95\x00")
        self.assertFalse(report.ok)
        self.assertIn("truncated", categories(report, ERROR))
        self.assertIn("empty", categories(report, ERROR))

    def test_jump_out_of_bounds(self):
        code = encode(JA, off=5) + encode(EXIT)
        report = Auditor("SOCKET_FILTER", "SOCKET_FILTER").audit(code)
        self.assertFalse(report.ok)
        self.assertIn("jump", categories(report, ERROR))

    def test_negative_jump_out_of_bounds(self):
        code = encode(EXIT) + encode(JA, off=-5) + encode(EXIT)
        report = Auditor("SOCKET_FILTER", "SOCKET_FILTER").audit(code)
        self.assertFalse(report.ok)
        self.assertIn("jump", categories(report, ERROR))

    def test_missing_exit(self):
        code = encode(LDX_W, dst=2, src=1, off=0)
        report = Auditor("SOCKET_FILTER", "SOCKET_FILTER").audit(code)
        self.assertFalse(report.ok)
        self.assertIn("exit", categories(report, ERROR))

    def test_tail_call_reported(self):
        code = b"".join([
            encode_ld_imm64(1, BPF_PSEUDO_MAP_FD, 9),
            call(HELPER_TAIL_CALL),
            encode(EXIT),
        ])
        auditor = Auditor(
            "CGROUP_SKB", "CGROUP_INET_INGRESS",
            map_permissions=[MapPermission(9)],
        )
        report = auditor.audit(code)
        self.assertTrue(report.ok, report.summary())
        self.assertIn("tail_call", categories(report, WARNING))

    def test_static_subprogram_call_reported(self):
        code = call(1, src=BPF_PSEUDO_CALL) + encode(EXIT)
        report = Auditor("SOCKET_FILTER", "SOCKET_FILTER").audit(code)
        self.assertTrue(report.ok, report.summary())
        self.assertIn("call", categories(report, INFO))

    def test_helper_too_new_for_kernel(self):
        code = call(HELPER_RINGBUF_OUTPUT) + encode(EXIT)
        report = Auditor(
            "TRACEPOINT", "TRACEPOINT", kernel_version=(5, 4),
        ).audit(code)
        self.assertFalse(report.ok)
        self.assertIn("kernel_version", categories(report, ERROR))

    def test_unknown_prog_type(self):
        report = Auditor("NOT_A_TYPE", "XDP").audit(encode(EXIT))
        self.assertFalse(report.ok)
        self.assertIn("prog_type", categories(report, ERROR))


if __name__ == "__main__":
    unittest.main()

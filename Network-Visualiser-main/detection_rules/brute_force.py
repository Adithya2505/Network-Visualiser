from collections import defaultdict

BRUTE_FORCE_THRESHOLD = 100
BRUTE_FORCE_PORTS = {22, 21, 23, 3389, 5900, 25, 110, 143}
SERVICE_NAMES = {
    22: "SSH", 21: "FTP", 23: "Telnet", 3389: "RDP",
    5900: "VNC", 25: "SMTP", 110: "POP3", 143: "IMAP",
}

def new_state():
    return {
        "attempt_cnt": defaultdict(int),
    }

def update(state, f):
    if f["tcp_flags"] is None or f["dst_port"] is None:
        return
    if not ((f["tcp_flags"] & 0x02) and not (f["tcp_flags"] & 0x10)):
        return
    if f["dst_port"] in BRUTE_FORCE_PORTS:
        state["attempt_cnt"][(f["src_ip"], f["dst_ip"], f["dst_port"])] += 1

def finalize(state):
    alerts = []
    for (src, dst, port), cnt in state["attempt_cnt"].items():
        if cnt > BRUTE_FORCE_THRESHOLD:
            service = SERVICE_NAMES.get(port, f"port {port}")
            alerts.append({
                "type":    "Brute Force",
                "source":  src,
                "target":  dst,
                "details": (
                    f"{src} made {cnt} connection attempts to {dst}:{port} ({service}). "
                    f"Consistent with credential stuffing or dictionary attack."
                ),
            })
    return alerts
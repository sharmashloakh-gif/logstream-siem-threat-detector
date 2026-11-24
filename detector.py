import re
from collections import defaultdict, deque

SQLI_PATTERNS = [
    re.compile(r"(\bUNION\b.*\bSELECT\b)", re.IGNORECASE),
    re.compile(r"(\bOR\b\s+1=1)", re.IGNORECASE),
    re.compile(r"(--|;\s*DROP\s+TABLE)", re.IGNORECASE),
]

class ThreatDetector:
    def __init__(self, fail_threshold: int = 5, window_sec: int = 60):
        self.fail_threshold = fail_threshold
        self.window_sec = window_sec
        self.failed_logins = defaultdict(deque)

    def inspect_event(self, ip: str, path: str, payload: str, status_code: int, ts: float) -> list[str]:
        alerts = []
        for pat in SQLI_PATTERNS:
            if pat.search(payload) or pat.search(path):
                alerts.append(f"SQLI_ATTEMPT from {ip} on {path}")
                break
        if status_code == 401:
            q = self.failed_logins[ip]
            q.append(ts)
            while q and q[0] < ts - self.window_sec:
                q.popleft()
            if len(q) >= self.fail_threshold:
                alerts.append(f"BRUTE_FORCE from {ip} ({len(q)} failures in {self.window_sec}s)")
        return alerts

if __name__ == "__main__":
    td = ThreatDetector(fail_threshold=3)
    for t in range(3):
        print(td.inspect_event("192.168.1.50", "/login", "user=admin", 401, float(t)))
    print(td.inspect_event("10.0.0.8", "/search", "q=' OR 1=1 --", 200, 5.0))

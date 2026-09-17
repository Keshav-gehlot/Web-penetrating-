from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass
from threading import Lock
from typing import Any


@dataclass
class Sample:
    timestamp: float
    send_bps: float
    recv_bps: float
    connections: int
    new_connections: int


class NetworkAnomalyEngine:
    """Small in-process baseline detector for native PHANTOM telemetry.

    It reports signals only; it does not generate traffic or attempt remediation.
    """

    def __init__(self, window: int = 30) -> None:
        self.window = max(10, window)
        self._samples: deque[Sample] = deque(maxlen=self.window)
        self._lock = Lock()

    @staticmethod
    def _z(value: float, values: list[float]) -> float:
        if len(values) < 8:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        deviation = math.sqrt(variance)
        return 0.0 if deviation < 1e-9 else (value - mean) / deviation

    def observe(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        io = snapshot.get("network_io", {})
        sample = Sample(
            timestamp=float(snapshot.get("timestamp", time.time())),
            send_bps=float(io.get("send_bytes_per_second", 0)),
            recv_bps=float(io.get("recv_bytes_per_second", 0)),
            connections=int(snapshot.get("connection_count", 0)),
            new_connections=int(snapshot.get("new_connection_count", 0)),
        )
        with self._lock:
            history = list(self._samples)
            send_z = self._z(sample.send_bps, [x.send_bps for x in history])
            recv_z = self._z(sample.recv_bps, [x.recv_bps for x in history])
            conn_z = self._z(float(sample.connections), [float(x.connections) for x in history])
            reasons: list[str] = []
            if max(abs(send_z), abs(recv_z)) >= 4.0:
                reasons.append("network throughput is significantly above the recent baseline")
            if conn_z >= 4.0:
                reasons.append("connection count is significantly above the recent baseline")
            if sample.new_connections >= 25:
                reasons.append("large burst of newly observed connections")
            if sample.connections >= 100 and sample.new_connections >= 20:
                reasons.append("high connection volume with a large new-connection burst")
            if reasons:
                severity = "high" if len(reasons) >= 2 or max(abs(send_z), abs(recv_z)) >= 6 else "medium"
                status = "anomalous"
            else:
                severity = "info"
                status = "normal" if len(history) >= 8 else "learning"
            self._samples.append(sample)
            return {
                "status": status,
                "severity": severity,
                "reasons": reasons,
                "sample": {
                    "timestamp": sample.timestamp,
                    "send_bps": sample.send_bps,
                    "recv_bps": sample.recv_bps,
                    "connections": sample.connections,
                    "new_connections": sample.new_connections,
                },
                "baseline": {"window": len(history), "send_z": round(send_z, 2), "recv_z": round(recv_z, 2), "connections_z": round(conn_z, 2)},
            }


engine = NetworkAnomalyEngine()

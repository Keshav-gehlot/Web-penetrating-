from app.network_monitor import NetworkMonitor


def test_network_monitor_snapshot_shape(monkeypatch):
    class Counter:
        bytes_sent = 100
        bytes_recv = 200
        packets_sent = 3
        packets_recv = 4

    class Conn:
        status = "ESTABLISHED"
        pid = None
        laddr = type("Addr", (), {"ip": "192.0.2.10", "port": 50000})()
        raddr = type("Addr", (), {"ip": "198.51.100.20", "port": 443})()

    monkeypatch.setattr("app.network_monitor.psutil.net_connections", lambda kind="inet": [Conn()])
    monkeypatch.setattr("app.network_monitor.psutil.net_io_counters", lambda pernic=False: {"eth0": Counter()} if pernic else Counter())
    monkeypatch.setattr("app.network_monitor.psutil.net_if_addrs", lambda: {"eth0": []})
    monkeypatch.setattr("app.network_monitor.socket.gethostname", lambda: "phantom-test")

    snapshot = NetworkMonitor().snapshot()
    assert snapshot["hostname"] == "phantom-test"
    assert snapshot["connection_count"] == 1
    assert snapshot["connections"][0]["remote_address"]["ip"] == "198.51.100.20"
    assert "network_io" in snapshot


def test_sensitive_external_service_gets_risk():
    monitor = NetworkMonitor()
    risk, score, reasons = monitor._risk("0.0.0.0:3389", "203.0.113.20", 3389, "ESTABLISHED")
    assert risk in {"medium", "high"}
    assert score >= 3
    assert reasons

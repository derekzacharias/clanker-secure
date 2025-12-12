from clanker.core.observability import metrics, render_prometheus_metrics


def test_metrics_snapshot_tracks_api_and_scans():
    metrics.reset()
    metrics.record_api_request(200, 100.0)
    metrics.record_api_request(500, 200.0)
    metrics.record_scan_started("network")
    metrics.record_scan_finished("network", "completed", 2.5)

    snap = metrics.snapshot(queue_stats={"in_queue": 2})

    assert snap["api"]["requests_total"] == 2
    assert snap["api"]["error_responses"] == 1
    assert snap["api"]["avg_latency_ms"] == 150.0
    assert snap["api"]["last_latency_ms"] == 200.0
    assert snap["scanner"]["network"]["started"] == 1
    assert snap["scanner"]["network"]["completed"] == 1
    assert snap["scanner"]["network"]["avg_duration_seconds"] == 2.5
    assert snap["queues"]["network"]["in_queue"] == 2


def test_render_prometheus_metrics():
    metrics.reset()
    metrics.record_api_request(200, 120.0)
    metrics.record_scan_started("network")
    metrics.record_scan_finished("network", "completed", 3.0)
    snap = metrics.snapshot(queue_stats={"in_queue": 1, "enqueued": 2})
    body = render_prometheus_metrics(snap)
    assert "clanker_api_requests_total 1.0" in body
    assert "clanker_scanner_network_completed_total 1.0" in body
    assert "clanker_queue_network_in_queue 1.0" in body

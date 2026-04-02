from app.detection.detector import detector_node, parse_http_request, route_by_confidence


def test_parse_http_request_normalizes_method_and_sets_fields():
    req = parse_http_request(method="post", url="/api/login", body="a=1", source_ip="1.2.3.4")

    assert req["method"] == "POST"
    assert req["url"] == "/api/login"
    assert req["body"] == "a=1"
    assert req["source_ip"] == "1.2.3.4"
    assert "request_id" in req
    assert "timestamp" in req


def test_detector_node_returns_low_tier_for_empty_payload():
    req = parse_http_request(method="GET", url="/health", body="", source_ip="10.0.0.1")
    result = detector_node({"http_request": req})

    detection = result["detection_result"]
    assert detection["tier"] == "low"
    assert detection["is_attack"] is False
    assert detection["is_grey_zone"] is False


def test_route_by_confidence_maps_all_tiers():
    assert route_by_confidence({"detection_result": {"tier": "high"}}) == "auto_respond"
    assert route_by_confidence({"detection_result": {"tier": "grey"}}) == "llm_analyze"
    assert route_by_confidence({"detection_result": {"tier": "low"}}) == "pass_through"

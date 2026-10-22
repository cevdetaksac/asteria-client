from client_block_store import report_targets_from_rule, extract_ips_from_rule


def test_cidr_prefix_kept():
    r = {"remoteip": "15.235.180.0/24,1.2.3.4"}
    assert extract_ips_from_rule(r) == ["15.235.180.0", "1.2.3.4"]
    t = report_targets_from_rule(r)
    assert t == {"15.235.180.0": "15.235.180.0/24"}
    assert t.get("1.2.3.4", "1.2.3.4") == "1.2.3.4"


def test_mask_form_and_host():
    r = {"remoteip": "15.235.204.0/255.255.255.0,9.9.9.9/255.255.255.255,2001:db8::1/128"}
    t = report_targets_from_rule(r)
    assert t["15.235.204.0"] == "15.235.204.0/24"
    assert t["9.9.9.9"] == "9.9.9.9"
    assert t["2001:db8::1"] == "2001:db8::1"


def test_garbage_ignored():
    assert report_targets_from_rule({"remoteip": "Any"}) == {}
    assert report_targets_from_rule({"remoteip": "x/24,1.2.3.0/99"}) == {}
    assert report_targets_from_rule({}) == {}

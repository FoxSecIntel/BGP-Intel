from core.lookup import is_valid_ip


def test_valid_ipv4():
    assert is_valid_ip("8.8.8.8") is True


def test_valid_ipv6():
    assert is_valid_ip("2001:4860:4860::8888") is True


def test_invalid_ip():
    assert is_valid_ip("999.999.1.1") is False

"""Недоверенный URL и каждый redirect обязаны соблюдать сетевые ограничения."""
import socket
from urllib.parse import urlparse
from unittest.mock import MagicMock, Mock

import pytest
import requests

from url_scanner.expander import expand_url_sync


PUBLIC_URL = "https://public.example/start"
PRIVATE_URL = "http://127.0.0.1:8080/admin"


@pytest.fixture
def transport(monkeypatch):
    """Все HTTP и DNS операции заменены; настоящая сеть недоступна."""
    session = MagicMock()
    session.__enter__.return_value = session

    def response(url, **kwargs):
        return Mock(url=url, status_code=200, history=[], headers={})

    session.head.side_effect = response
    session.get.side_effect = response
    monkeypatch.setattr(requests, "Session", Mock(return_value=session))
    network_guard = Mock(side_effect=RuntimeError("Real network is forbidden"))
    monkeypatch.setattr(socket, "create_connection", network_guard)

    def resolve(host, port, *args, **kwargs):
        ip = "10.0.0.5" if host == "internal.example" else "8.8.8.8"
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    yield session
    if network_guard.called:
        raise RuntimeError("A URL contract test attempted to use real network")


def expand_or_reject(url):
    # Запрет может быть явной ошибкой; проверяем отсутствие исходящего запроса.
    try:
        return expand_url_sync(url)
    except (ValueError, requests.RequestException):
        return None


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8080/admin",
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://169.254.169.254/",
    "http://[::1]:8080/",
    "http://[fe80::1]/",
    "http://localhost:8080/",
    "http://internal.example:8000/",
])
@pytest.mark.xfail(strict=True, raises=AssertionError, reason="MM-H01: private endpoints reach HTTP transport")
def test_private_endpoints_are_rejected_before_http(url, transport):
    expand_or_reject(url)
    transport.head.assert_not_called()
    transport.get.assert_not_called()


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="MM-H01: mixed public/private DNS reaches HTTP transport")
def test_host_with_a_private_dns_answer_is_rejected(monkeypatch, transport):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *args, **kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port)),
        (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", port, 0, 0)),
    ])
    expand_or_reject(PUBLIC_URL)
    transport.head.assert_not_called()
    transport.get.assert_not_called()


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="MM-H01: public redirect reaches a private endpoint")
def test_public_redirect_does_not_send_a_request_to_private_address(transport):
    contacted = []

    def head(url, **kwargs):
        contacted.append(url)
        if url == PUBLIC_URL:
            if kwargs.get("allow_redirects"):
                # Имитация автоматического следования requests без настоящего соединения.
                contacted.append(PRIVATE_URL)
                return Mock(url=PRIVATE_URL, status_code=200, history=[Mock(url=PUBLIC_URL)], headers={})
            return Mock(url=PUBLIC_URL, status_code=302, history=[], headers={"Location": PRIVATE_URL})
        return Mock(url=url, status_code=200, history=[], headers={})

    transport.head.side_effect = head
    transport.get.side_effect = head
    expand_or_reject(PUBLIC_URL)
    assert PRIVATE_URL not in contacted


def test_public_endpoint_remains_available(transport):
    result = expand_url_sync(PUBLIC_URL)
    assert result is not None
    final_url, _ = result
    assert final_url == PUBLIC_URL
    assert transport.head.call_count == 1
    assert urlparse(transport.head.call_args.args[0]).hostname == "public.example"

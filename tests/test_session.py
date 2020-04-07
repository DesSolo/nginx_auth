import pytest
from nginx_auth.cookies_manager import CookiesManager


@pytest.fixture
def manager():
    return CookiesManager('TestSecretKey')


@pytest.fixture
def client_request():
    return {
        'ip': '127.0.0.1',
        'user_agent': 'curl'
    }


@pytest.fixture
def cookie(manager, client_request):
    return manager.generate_new(username='valid_user', **client_request)


def build_fake_cookie(created_ts, last_activity_ts, secret_hash, username):
    return f"{created_ts}:{last_activity_ts}:{secret_hash}:{username}"


def test_length_cookie(cookie):
    assert len(cookie.split(':')) == 4


def test_valid_cookie(manager, cookie, client_request):
    assert manager.is_valid(cookie, **client_request) is True


def test_empty_cookie(manager, client_request):
    assert manager.is_valid('', **client_request) is False


def test_edited_cookie(manager, cookie, client_request):
    created_ts, last_activity_ts, secret_hash, username = cookie.split(':')
    assert manager.is_valid(
        build_fake_cookie(created_ts, last_activity_ts, secret_hash, 'bad_user'),
        **client_request
    ) is False

    assert manager.is_valid(
        build_fake_cookie(created_ts, last_activity_ts, 'not_valid_hash', username),
        **client_request
    ) is False

    assert manager.is_valid(
        build_fake_cookie(created_ts, 123, secret_hash, username),
        **client_request
    ) is False

    assert manager.is_valid(
        build_fake_cookie('None', last_activity_ts, secret_hash, username),
        **client_request
    ) is False


def test_changed_user_agent_cookie(manager, cookie, client_request):
    for user_agent in ['curl', 'wget', 'Firefox', '', None]:
        if user_agent == client_request['user_agent']:
            assert manager.is_valid(cookie, client_request['ip'], user_agent) is True
            continue
        assert manager.is_valid(cookie, client_request['ip'], user_agent) is False


def test_changed_ip_cookie(manager, cookie, client_request):
    for ip in ['127.0.0.1', '10.0.0.1', '192.168.1.1', '', None]:
        if ip == client_request['ip']:
            assert manager.is_valid(cookie, ip, client_request['user_agent']) is True
            continue
        assert manager.is_valid(cookie, ip, client_request['user_agent']) is False


def test_hacked_cookie(manager, cookie):
    assert manager.is_valid(cookie, '', '') is False
    assert manager.is_valid(cookie, '10.0.0.15', 'admin') is False

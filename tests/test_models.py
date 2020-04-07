import pytest
from nginx_auth import models
from base64 import b64decode


@pytest.mark.parametrize('username, password', [('test_user1', 'secret1'), ('test_user2', 'secret2')])
def test_valid_account(username, password):
    account = models.Account(username=username, password=password)
    assert account.username == username
    assert account.password != password
    assert account.password.get_secret_value() == password


@pytest.mark.parametrize('username, password', [(None, 'secret1'), ('', None)])
def test_invalid_account(username, password):
    with pytest.raises(ValueError):
        models.Account(username=username, password=password)


valid_headers = [
    {'X-Real-IP': '127.0.0.1', 'User-Agent': 'curl', 'Authorization': 'Basic dGVzdF91c2VyOnRlc3RfcGFzc3dvcmQ='},
    {'X-Real-IP': '10.0.0.1', 'User-Agent': 'wget', 'Authorization': 'Basic dGVzdF91c2VyMjp0ZXN0X3Bhc3N3b3JkMg=='},
    {'X-Real-IP': '192.168.1.1', 'User-Agent': '', 'Authorization': 'Basic dGVzdF91c2VyMzp0ZXN0X3Bhc3N3b3JkMw=='}
]


@pytest.mark.parametrize('headers', valid_headers)
def test_base_valid(headers):
    model = models.Base(**headers)
    assert str(model.real_ip) == headers['X-Real-IP']
    assert model.user_agent == headers['User-Agent']
    _, credentials = headers['Authorization'].split(' ')
    decoded_username, decoded_password = b64decode(credentials).decode('utf-8').split(':')
    assert model.authorization.username == decoded_username
    assert model.authorization.password != decoded_password
    assert model.authorization.password.get_secret_value() == decoded_password


def test_base_empty_authorisation():
    headers = {'X-Real-IP': '127.0.0.1', 'User-Agent': 'curl'}
    model = models.Base(**headers)
    assert model.authorization is None

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
    model = models.BaseHeader(**headers)
    assert str(model.real_ip) == headers['X-Real-IP']
    assert model.user_agent == headers['User-Agent']
    _, credentials = headers['Authorization'].split(' ')
    decoded_username, decoded_password = b64decode(credentials).decode('utf-8').split(':')
    assert model.authorization.username == decoded_username
    assert model.authorization.password != decoded_password
    assert model.authorization.password.get_secret_value() == decoded_password


invalid_headers = [
    {'Authorization': 'Basic not_base64'},
    {'Authorization': 'not_empty'},
    {'Authorization': ''},
    {'not_valid_authorization_key': 'Basic dGVzdF91c2VyOnRlc3RfcGFzc3dvcmQ='},
    {'': ''}
]


@pytest.mark.parametrize('authorisation', invalid_headers)
def test_base_invalid_authorisation(authorisation):
    with pytest.raises(ValueError):
        models.BaseHeader(**authorisation)


def test_base_empty_authorisation():
    headers = {'X-Real-IP': '127.0.0.1', 'User-Agent': 'curl'}
    model = models.BaseHeader(**headers)
    assert model.authorization is None


def test_radius_valid():
    headers = {'User-Agent': 'curl', 'X-Radius-Realm': 'test_realm'}
    model = models.RadiusHeader(**headers)
    assert model.realm == 'test_realm'


def test_radius_default():
    headers = {'User-Agent': 'curl'}
    model = models.RadiusHeader(**headers)
    assert model.realm == 'Restricted area'
    assert model.real_ip == '127.0.0.1'


ldap_valid_headers = [
    {'User-Agent': 'curl', 'X-Ldap-Realm': 'test_realm', 'X-Ldap-BaseDN': 'test_dn', 'X-Ldap-Template': 'test_template'},
    {'User-Agent': 'curl', 'X-Ldap-Realm': 'test_realm', 'X-Ldap-BaseDN': 'test_dn'},
    {'User-Agent': 'curl', 'X-Ldap-BaseDN': 'test_dn'},
]


@pytest.mark.parametrize('header', ldap_valid_headers)
def test_ldap_valid(header):
    model = models.LdapHeader(**header)
    assert model.realm == header.get('X-Ldap-Realm', model.realm)
    assert model.base_dn == header['X-Ldap-BaseDN']
    assert model.template == header.get('X-Ldap-Template', model.template)

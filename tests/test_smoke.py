import pytest
import requests
from requests.auth import HTTPBasicAuth

address = 'http://127.0.0.1:8010'

valid_credentials = [
    ('test_valid_user1', 'test_valid_password1'),
    ('test_valid_user2', 'test_valid_password2'),
    ('test_valid_user3', 'test_valid_password3')
]

not_valid_credentials = [
    ('test_not_valid_user1', 'test_not_valid_password1'),
    ('test_not_valid_user2', 'test_not_valid_password2'),
    ('test_not_valid_user3', 'test_not_valid_password3'),
    ('', 'empty_user'),
    ('empty_password', ''),
    ('', '')
]


def test_default_401():
    response = requests.get(address + '/login')
    assert response.status_code == 401


@pytest.mark.parametrize('username, password', not_valid_credentials)
def test_not_valid_authorise(username, password):
    response = requests.get(address + '/login', auth=HTTPBasicAuth(username, password))
    assert response.status_code == 401


@pytest.mark.parametrize('username, password', valid_credentials)
def test_valid_authorise(username, password):
    response = requests.get(address + '/login', auth=HTTPBasicAuth(username, password))
    assert response.status_code == 200


@pytest.mark.parametrize('username, password', valid_credentials)
def test_valid_response(username, password):
    response = requests.get(address + '/login', auth=HTTPBasicAuth(username, password))
    assert 'session_id' in response.cookies
    session_id = response.cookies['session_id']
    assert session_id.split(':')[-1] == username
    assert response.headers['X-Auth-User'] == username
    assert response.text == 'Auth success'


@pytest.mark.parametrize('username, password', valid_credentials)
def test_cookies_authorise(username, password):
    response = requests.get(address + '/login', auth=HTTPBasicAuth(username, password))
    cookie_secret = response.cookies['session_id']
    response = requests.get(address + '/login', cookies={'session_id': cookie_secret})
    assert response.status_code == 200


def test_logout_remove_cookies():
    response = requests.get(address + '/logout', cookies={'session_id': 'test_session_id'})
    assert 'session_id' not in response.cookies

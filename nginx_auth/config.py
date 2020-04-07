import os
from secrets import token_urlsafe


def generate_new_secret_key():
    secret_key = token_urlsafe(20)
    print('Generated new secret key:', secret_key)
    return secret_key


COOKIE_KEY = os.getenv('COOKIE_KEY', 'session_id')
LISTEN_PORT = os.getenv('LISTEN_PORT', 8000)
SECRET_KEY = os.getenv('SECRET_KEY', generate_new_secret_key())

# X-Ldap-URL "ldap://example.com";
# X-Ldap-BindDN "cn=root,dc=test,dc=local";
# X-Ldap-BindPass "secret";

from hashlib import sha224
from datetime import datetime


class CookiesManager:
    signature = '{secret_key}:{created_ts}:{last_activity_ts}:{ip}:{user_agent}{username}'

    def __init__(self, secret_key):
        self.secret_key = secret_key

    def generate_hash(self, ip, user_agent, username, created_ts=None, last_activity_ts=None):
        if not created_ts:
            created_ts = int(datetime.now().timestamp())
        if not last_activity_ts:
            last_activity_ts = int(datetime.now().timestamp())
        mapper = {
            'secret_key': self.secret_key,
            'created_ts': created_ts,
            'last_activity_ts': last_activity_ts,
            'ip': ip,
            'user_agent': user_agent,
            'username': username
        }
        return sha224(bytes(self.signature.format(**mapper), 'utf-8')).hexdigest()

    def generate_new(self, ip, user_agent, username):
        created_ts = last_activity_ts = int(datetime.now().timestamp())
        secret_hash = self.generate_hash(ip, user_agent, username)
        return f"{created_ts}:{last_activity_ts}:{secret_hash}:{username}"

    def is_valid(self, cookie: str, ip, user_agent):
        try:
            created_ts, last_activity_ts, secret_hash, username = cookie.split(':')
        except ValueError:
            return False
        new_hash = self.generate_hash(ip, user_agent, username, created_ts, last_activity_ts)
        return new_hash == secret_hash

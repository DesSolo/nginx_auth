from base64 import b64decode
from pydantic import BaseModel, Field, validator, SecretStr
from pydantic.validators import IPv4Address
from typing import Optional

_models_classes = {}


def register_model(name=None):
    def wrapper(cls):
        if name:
            _models_classes[name] = cls
            return
        _models_classes[cls.__name__.replace('Header', '')] = cls

    return wrapper


class Account(BaseModel):
    username: str
    password: SecretStr


class BaseHeader(BaseModel):
    real_ip: IPv4Address = Field('127.0.0.1', alias='X-Real-IP')
    user_agent: str = Field(..., alias='User-Agent')
    authorization: Optional[Account] = Field(None, alias='Authorization')

    @validator('authorization', pre=True, always=True)
    def validate_authorisation(cls, v):
        if not v:
            return v
        _, credentials = v.split(' ')
        username, password = b64decode(credentials).decode('utf-8').split(':', 1)
        return Account(username=username, password=password)


def get_model_class(name: str) -> BaseHeader:
    return _models_classes[name]


@register_model()
class RadiusHeader(BaseHeader):
    realm: str = Field('Restricted area', alias='X-Radius-Realm')


@register_model()
class LdapHeader(BaseHeader):
    realm: str = Field('Restricted area', alias='X-Ldap-Realm')
    base_dn: str = Field(..., alias='X-Ldap-BaseDN')
    template: str = Field('(sAMAccountName=%(username)s)', alias='X-Ldap-Template')

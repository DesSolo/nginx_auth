from base64 import b64decode
from pydantic import BaseModel, Field, validator, SecretStr
from pydantic.validators import IPv4Address
from typing import Optional


class Account(BaseModel):
    username: str
    password: SecretStr


class Base(BaseModel):
    real_ip: IPv4Address = Field('127.0.0.1', alias='X-Real-IP')
    user_agent: str = Field(..., alias='User-Agent')
    authorization: Optional[Account] = Field(None, alias='Authorization')

    @validator('authorization', pre=True, always=True)
    def validate_authorisation(cls, v):
        if not v:
            return v
        try:
            _, credentials = v.split(' ')
            username, password = b64decode(credentials).decode('utf-8').split(':', 1)
            return Account(username=username, password=password)
        except Exception as ex:
            return None


class Radius(Base):
    realm: str = Field('Restricted area', alias='X-Radius-Realm')

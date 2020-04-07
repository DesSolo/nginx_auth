import abc

_authorisation_classes = {}


def register_authorisation(name=None):
    def wrapper(cls):
        if name:
            _authorisation_classes[name] = cls()
            return
        _authorisation_classes[cls.__name__.replace('Authorisation', '')] = cls()

    return wrapper


class BaseAuthorisation(abc.ABC):

    @abc.abstractmethod
    def authorise(self, username, password, ip, realm) -> bool:
        pass


def get_authorisation_class(name: str) -> BaseAuthorisation:
    return _authorisation_classes[name]


@register_authorisation()
class RadiusAuthorisation(BaseAuthorisation):
    def authorise(self, username, password, ip, realm) -> bool:
        pass


@register_authorisation()
class LdapAuthorisation(BaseAuthorisation):
    def authorise(self, username, password, ip, realm) -> bool:
        pass

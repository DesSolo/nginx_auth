import abc


class BaseAuthorisation(abc.ABC):

    @abc.abstractmethod
    def authorisation(self, username, password, ip, realm) -> bool:
        pass


class RadiusAuthorisation(BaseAuthorisation):
    def authorisation(self, username, password, ip, realm) -> bool:
        pass

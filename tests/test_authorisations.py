import pytest
import authirisations


@pytest.mark.parametrize('name', ['Radius', 'Ldap'])
def test_get_registered_classes_by_name(name):
    cls = authirisations.get_authorisation_class(name)
    assert isinstance(cls, authirisations.BaseAuthorisation) is True

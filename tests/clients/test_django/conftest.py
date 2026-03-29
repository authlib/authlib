import pytest

from tests.django_helper import RequestClient


@pytest.fixture
def factory():
    return RequestClient()

import os

import gevent
import pytest


@pytest.fixture(scope="module")
def user_pass():
    yield 'admin', 'admin'


def test_can_authenticate_admin_user(volttron_instance, user_pass):
    instance = volttron_instance

    webadmin = instance.web_admin_api

    user, password = user_pass
    gevent.sleep(1)
    resp = webadmin.authenticate(user, password)
    assert resp.ok
    assert resp.headers.get('Content-Type') == 'application/json'

    resp = webadmin.authenticate('fake', password)
    assert resp.status_code == 401  # unauthorized
    assert resp.headers.get('Content-Type') == 'application/json'


@pytest.mark.skip(reason="Can't test using platformwrapper. Needs to be unit test")
def test_can_create_admin_user(volttron_instance, user_pass):
    instance = volttron_instance
    webadmin = instance.web_admin_api
    user, password = user_pass

    resp = webadmin.create_web_admin(user, password)
    assert resp.ok
    # Allow file operation to run
    gevent.sleep(2)

    resp = webadmin.authenticate(user, password)
    assert resp.ok
    assert resp.headers.get('Content-Type') == 'application/json'

    resp = webadmin.authenticate('fake', password)
    assert resp.status_code == 401  # unauthorized
    assert resp.headers.get('Content-Type') == 'text/html'


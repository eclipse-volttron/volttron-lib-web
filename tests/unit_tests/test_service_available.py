from volttrontesting import PlatformWrapper


def test_web_service_available():
    p = PlatformWrapper()
    names = p.get_service_names()
    assert 'volttron.services.web' in names

import os
from pathlib import Path
import shutil

from unittest.mock import MagicMock
from web_utils import get_test_web_env, mock_platform_web_service


def test_register_routes(mock_platform_web_service):
    html_root = "/tmp/junk/html"
    attempt_to_get_file = "/tmp/junk/index.html"
    should_get_index_file = os.path.join(html_root, "index.html")
    file_contents_bad = "HOLY COW!"
    file_contents_good = "Woot there it is!"
    try:

        os.makedirs(html_root, exist_ok=True)
        with open(attempt_to_get_file, "w") as should_not_get:
            should_not_get.write(file_contents_bad)
        with open(should_get_index_file, "w") as should_get:
            should_get.write(file_contents_good)

        pws = mock_platform_web_service

        pws.register_path_route(f"/.*", html_root)
        pws.register_path_route(f"/flubber", ".")
        # Test to make sure the route is resolved to a full directory so easier
        # to detect chroot for html paths.
        assert len(pws.registeredroutes) == 2
        for x in pws.registeredroutes:
            # x is a tuple regex, 'path', directory
            assert Path(x[2]).is_absolute()

        start_response = MagicMock()
        data = pws.app_routing(get_test_web_env("/index.html"), start_response)
        data = "".join([x.decode("utf-8") for x in data])
        assert "200 OK" in start_response.call_args[0]
        assert data == file_contents_good

        # Test relative route to the index.html file above the html_root, but using a
        # rooted path to do so.
        start_response.reset_mock()
        data = pws.app_routing(get_test_web_env("/../index.html"), start_response)
        data = "".join([x.decode("utf-8") for x in data])
        assert "403 Forbidden" in start_response.call_args[0]
        assert "403 Forbidden" in data

        # Test relative route to the index.html file above the html_root.
        start_response.reset_mock()
        data = pws.app_routing(get_test_web_env("../index.html"), start_response)
        data = "".join([x.decode("utf-8") for x in data])
        assert "200 OK" not in start_response.call_args[0]
        assert data != file_contents_bad

    finally:
        shutil.rmtree(str(Path(html_root).parent), ignore_errors=True)

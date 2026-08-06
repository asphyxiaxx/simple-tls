import certifi
import requests
from requests.adapters import HTTPAdapter

from simple_tls.pyssl import SSLContext, create_default_context

URL = "https://tls.browserleaks.com/"


class CustomHTTPAdapter(HTTPAdapter):
    def __init__(self, ssl_context: SSLContext | None = None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        # Inject the custom SSL context into the urllib3 pool manager
        kwargs["ssl_context"] = self.ssl_context
        return super().init_poolmanager(*args, **kwargs)


def test_requests(context: SSLContext, url: str):
    adapter = CustomHTTPAdapter(context)
    session = requests.Session()
    session.mount("https://", adapter)
    response = session.get(url, timeout=30, allow_redirects=False)
    return response


if __name__ == "__main__":
    context = create_default_context(capath=certifi.where())
    resp = test_requests(context, URL)

    print(resp)
    print(resp.text)

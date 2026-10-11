import certifi
import httpx

from simple_tls.pyssl import SSLContext, create_default_context

URL = "https://tls.peet.ws/api/all"


def test_httpx(context: SSLContext, url: str):
    with httpx.Client(
        http2=True,
        verify=context,
        follow_redirects=False,
        timeout=30,
    ) as client:
        response = client.request("GET", url)
        response.raise_for_status()
        return response


if __name__ == "__main__":
    context = create_default_context(capath=certifi.where())
    resp = test_httpx(context, URL)

    print(resp)
    print(resp.text)

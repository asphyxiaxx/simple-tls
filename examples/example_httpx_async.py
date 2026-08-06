import asyncio

import certifi
import httpx

from simple_tls.pyssl import SSLContext, create_default_context

URL = "https://tls.peet.ws/api/all"


async def test_httx_async(context: SSLContext, url: str):
    async with httpx.AsyncClient(
        http2=True,
        verify=context,
        follow_redirects=False,
        timeout=30,
    ) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response


if __name__ == "__main__":
    context = create_default_context(capath=certifi.where())
    resp = asyncio.run(test_httx_async(context, URL))

    print(resp)
    print(resp.text)

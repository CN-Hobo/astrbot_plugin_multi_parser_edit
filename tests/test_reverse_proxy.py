from pathlib import Path

import httpx
import pytest
from astrbot_multi_parser.core.contracts import ParseResult
from astrbot_multi_parser.core.media import ImageMaterializer
from astrbot_multi_parser.core.reverse_proxy import (
    _PROXY_COOKIES,
    challenge_retry_url,
    cookie_headers,
    is_proxy_url,
    proxy_get,
    reverse_proxy_prefix,
    rewrite_url,
    solve_challenge,
    unwrap_proxy_url,
)
from astrbot_multi_parser.platforms.github import GitHubParser
from astrbot_multi_parser.platforms.pixiv import PixivParser

PROXY_PREFIX = "https://proxy.example/fxdl.php?url="
PROXY_CONFIG = {
    "enable_reverse_proxy": True,
    "reverse_proxy_prefix": PROXY_PREFIX,
}
KEY = "00112233445566778899aabbccddeeff"
IV = "ffeeddccbbaa99887766554433221100"
PLAINTEXT = "0123456789abcdef0123456789abcdef"


def build_challenge_html(redirect_url: str, cookie_name: str = "__test") -> str:
    """构造与反代一致的 AES JS 挑战页，密文由已知明文加密得到。"""
    from Crypto.Cipher import AES

    key = bytes.fromhex(KEY)
    iv = bytes.fromhex(IV)
    cipher_text = AES.new(key, AES.MODE_CBC, iv).encrypt(bytes.fromhex(PLAINTEXT))
    return (
        '<html><body><script src="/aes.js"></script><script>'
        f'var a=toNumbers("{KEY}"),b=toNumbers("{IV}"),'
        f'c=toNumbers("{cipher_text.hex()}");'
        f'document.cookie="{cookie_name}="+toHex(slowAES.decrypt(c,2,a,b))'
        '+"; expires=Thu, 31-Dec-37 23:55:55 GMT; path=/";'
        f'location.href="{redirect_url}";'
        "</script></body></html>"
    )


@pytest.fixture(autouse=True)
def clear_proxy_cookies():
    """隔离各用例之间的模块级挑战 Cookie 缓存。"""
    _PROXY_COOKIES.clear()
    yield
    _PROXY_COOKIES.clear()


def test_reverse_proxy_prefix_requires_enabled_and_valid_url():
    assert reverse_proxy_prefix({}) == ""
    assert reverse_proxy_prefix(PROXY_CONFIG) == PROXY_PREFIX
    assert (
        reverse_proxy_prefix({**PROXY_CONFIG, "reverse_proxy_prefix": "ftp://x/"}) == ""
    )
    assert (
        reverse_proxy_prefix({**PROXY_CONFIG, "reverse_proxy_prefix": "https://a b/"})
        == ""
    )
    assert reverse_proxy_prefix({**PROXY_CONFIG, "reverse_proxy_prefix": "  "}) == ""


def test_rewrite_url_only_wraps_declared_hosts_and_stays_idempotent():
    proxied = rewrite_url(
        "https://www.pixiv.net/ajax/illust/1", PROXY_CONFIG, ("pixiv.net",)
    )
    assert proxied == PROXY_PREFIX + "https%3A%2F%2Fwww.pixiv.net%2Fajax%2Fillust%2F1"
    assert rewrite_url(proxied, PROXY_CONFIG, ("pixiv.net",)) == proxied

    assert (
        rewrite_url("https://i.pximg.net/a.jpg", PROXY_CONFIG, ("pixiv.net",))
        == "https://i.pximg.net/a.jpg"
    )
    assert (
        rewrite_url("https://www.pixiv.net/a", {}, ("pixiv.net",))
        == "https://www.pixiv.net/a"
    )


def test_is_proxy_url_and_unwrap_proxy_url():
    wrapped = PROXY_PREFIX + "https%3A%2F%2Fopengraph.githubassets.com%2Fa%2Fb"
    rewritten = "https://proxy.example/fxdl/index.php?url=https%3A%2F%2Fopengraph.githubassets.com%2Fa%2Fb"

    assert is_proxy_url(wrapped, PROXY_CONFIG)
    assert not is_proxy_url("https://opengraph.githubassets.com/a/b", PROXY_CONFIG)
    assert unwrap_proxy_url(wrapped, PROXY_CONFIG) == (
        "https://opengraph.githubassets.com/a/b"
    )
    assert unwrap_proxy_url(rewritten, PROXY_CONFIG) == (
        "https://opengraph.githubassets.com/a/b"
    )
    assert unwrap_proxy_url(wrapped, {}) == wrapped


def test_solve_challenge_returns_cookie_and_redirect():
    solved = solve_challenge(build_challenge_html("https://proxy.example/?i=1"))

    assert solved == (f"__test={PLAINTEXT}", "https://proxy.example/?i=1")
    assert solve_challenge("<html>normal page</html>") is None


def test_challenge_retry_url_caches_cookie_for_prefix_and_user_agent():
    html = build_challenge_html("https://proxy.example/fxdl.php?pwd=1&i=1")

    assert challenge_retry_url(PROXY_CONFIG, html, PROXY_PREFIX, "agent") == (
        "https://proxy.example/fxdl.php?pwd=1&i=1"
    )
    assert cookie_headers(PROXY_CONFIG, "agent") == {"Cookie": f"__test={PLAINTEXT}"}
    assert cookie_headers(PROXY_CONFIG, "other-agent") == {}
    assert challenge_retry_url({}, html, PROXY_PREFIX, "agent") == ""


async def test_proxy_get_follows_challenge_and_reuses_cookie():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.headers.get("Cookie"):
            return httpx.Response(200, json={"ok": True}, request=request)
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            text=build_challenge_html(f"{request.url}&i=1"),
            request=request,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        response = await proxy_get(
            client,
            PROXY_CONFIG,
            "https://www.pixiv.net/ajax/illust/1",
            headers={"User-Agent": "parser-agent"},
            host_suffixes=("pixiv.net",),
        )

    assert response.json() == {"ok": True}
    assert [request.url.host for request in requests] == [
        "proxy.example",
        "proxy.example",
    ]
    assert requests[1].headers["Cookie"] == f"__test={PLAINTEXT}"
    assert "pixiv.net" in str(requests[0].url)


async def test_proxy_get_without_reverse_proxy_keeps_plain_request():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("Cookie") is None
        return httpx.Response(200, json={"ok": True}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        response = await proxy_get(
            client, {}, "https://www.pixiv.net/ajax/illust/1", host_suffixes=()
        )

    assert response.json() == {"ok": True}


async def test_proxy_get_ignores_challenge_redirect_outside_trust_scope():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            text=build_challenge_html("https://evil.example/steal?next=1"),
            request=request,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        response = await proxy_get(
            client,
            PROXY_CONFIG,
            "https://www.pixiv.net/ajax/illust/1",
            headers={"User-Agent": "parser-agent"},
            host_suffixes=("pixiv.net",),
        )

    assert len(requests) == 1
    assert response.headers["Content-Type"] == "text/html"


async def test_proxy_get_follows_redirect_before_challenge():
    """代理先 301 规范化路径、再返回挑战页，两种跳转要连续处理。"""
    config = {**PROXY_CONFIG, "reverse_proxy_prefix": "https://proxy.example/fxdl?url="}
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/fxdl":
            return httpx.Response(
                301,
                headers={"Location": "https://proxy.example/fxdl/?i=1"},
                request=request,
            )
        if not request.headers.get("Cookie"):
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text=build_challenge_html(f"{request.url}&i=2"),
                request=request,
            )
        return httpx.Response(200, json={"ok": True}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        response = await proxy_get(
            client,
            config,
            "https://www.pixiv.net/ajax/illust/1",
            headers={"User-Agent": "parser-agent"},
            host_suffixes=("pixiv.net",),
        )

    assert response.json() == {"ok": True}
    assert [request.url.path for request in requests] == [
        "/fxdl",
        "/fxdl/",
        "/fxdl/",
    ]
    assert requests[-1].headers["Cookie"] == f"__test={PLAINTEXT}"


async def test_proxy_get_stops_at_redirect_leaving_trust_scope():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            301,
            headers={"Location": "https://evil.example/steal"},
            request=request,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        response = await proxy_get(
            client,
            PROXY_CONFIG,
            "https://www.pixiv.net/ajax/illust/1",
            headers={"User-Agent": "parser-agent"},
            host_suffixes=("pixiv.net",),
        )

    assert response.status_code == 301


async def test_github_fetches_opengraph_card_through_reverse_proxy():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if not request.headers.get("Cookie"):
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text=build_challenge_html(f"{request.url}&i=1"),
                request=request,
            )
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html; charset=utf-8"},
            text=(
                '<meta property="og:image" content="https://proxy.example/'
                "fxdl/index.php?url=https%3A%2F%2Fopengraph.githubassets.com%2F"
                'hash/AstrBotDevs/AstrBot">'
            ),
            request=request,
        )

    parser = GitHubParser(PROXY_CONFIG)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        card_url = await parser._fetch_opengraph_url(
            client,
            "https://github.com/AstrBotDevs/AstrBot",
        )

    assert card_url == "https://opengraph.githubassets.com/hash/AstrBotDevs/AstrBot"
    assert {request.url.host for request in requests} == {"proxy.example"}
    assert requests[-1].headers["Cookie"] == f"__test={PLAINTEXT}"


async def test_pixiv_request_body_solves_reverse_proxy_challenge():
    def handler(request: httpx.Request) -> httpx.Response:
        if not request.headers.get("Cookie"):
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text=build_challenge_html(f"{request.url}&i=1"),
                request=request,
            )
        assert request.url.host == "proxy.example"
        return httpx.Response(
            200,
            json={"error": False, "body": {"title": "测试作品"}},
            request=request,
        )

    parser = PixivParser(PROXY_CONFIG)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        body = await parser._request_body(
            client, "https://www.pixiv.net/ajax/illust/123456"
        )

    assert body["title"] == "测试作品"


async def test_image_download_solves_reverse_proxy_challenge(tmp_path):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if not request.headers.get("Cookie"):
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text=build_challenge_html(f"{request.url}&i=1"),
                request=request,
            )
        return httpx.Response(
            200,
            headers={"Content-Type": "image/png"},
            content=b"image-bytes",
            request=request,
        )

    config = {**PROXY_CONFIG, "image_temp_dir": str(tmp_path)}
    materializer = ImageMaterializer(config, ("pximg.net",), ("pximg.net",))
    result = ParseResult(
        platform="pixiv", image_urls=["https://i.pximg.net/img-original/a.png"]
    )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await materializer.materialize(result, client, "https://www.pixiv.net/")

    image_path = Path(result.image_urls[0])
    assert image_path.read_bytes() == b"image-bytes"
    assert {request.url.host for request in requests} == {"proxy.example"}
    assert requests[-1].headers["Referer"] == "https://www.pixiv.net/"
    result.cleanup_temporary_files()


def test_parsers_declare_reverse_proxy_hosts_for_github_and_pixiv():
    assert GitHubParser({}).reverse_proxy_host_suffixes == (
        "github.com",
        "opengraph.githubassets.com",
        "repository-images.githubusercontent.com",
    )
    assert PixivParser({}).reverse_proxy_host_suffixes == ("pixiv.net", "pximg.net")

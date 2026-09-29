"""反向代理前缀包装与 AES JS 挑战求解。

反向代理把目标 URL 编码后拼接在配置前缀之后转发；代理所在的免费主机可能先返回
一段基于 AES 的 JS 挑战页，需要解出 Cookie 并继续请求挑战页给出的跳转地址才能拿到
真实内容。URL 改写只对平台声明的可信主机生效，反代自身的地址保持原样，避免重复包装。
"""

import re
import threading
from collections.abc import Mapping, Sequence
from urllib.parse import parse_qs, quote, unquote, urljoin, urlsplit

import httpx
from astrbot.api import logger

from .http import host_matches

MAX_PROXY_ROUNDS = 4
DEFAULT_COOKIE_NAME = "__test"

_PROXY_COOKIE_LOCK = threading.Lock()
# (反代前缀, 请求使用的 User-Agent) -> Cookie 请求头值；前缀变更后自然失效。
_PROXY_COOKIES: dict[tuple[str, str], str] = {}
_WARNED_MISSING_AES = False

_CHALLENGE_A_PATTERN = re.compile(r'var a=toNumbers\("([0-9a-f]+)"\)')
_CHALLENGE_B_PATTERN = re.compile(r',b=toNumbers\("([0-9a-f]+)"\)')
_CHALLENGE_C_PATTERN = re.compile(r',c=toNumbers\("([0-9a-f]+)"\)')
_CHALLENGE_REDIRECT_PATTERN = re.compile(r'location\.href="([^"]+)"')
_CHALLENGE_COOKIE_PATTERN = re.compile(
    r"document\.cookie\s*=\s*['\"]([A-Za-z0-9_.-]+)="
)


def reverse_proxy_prefix(config: Mapping[str, object]) -> str:
    """读取配置中的反向代理地址前缀。

    Args:
        config: 插件配置映射。

    Returns:
        校验通过的 http(s) 前缀；未启用或前缀非法时返回空串。
    """
    if config.get("enable_reverse_proxy") is not True:
        return ""
    prefix = str(config.get("reverse_proxy_prefix") or "").strip()
    if not prefix or any(character.isspace() for character in prefix):
        return ""
    try:
        parsed = urlsplit(prefix)
    except ValueError:
        return ""
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    return prefix


def rewrite_url(
    url: str, config: Mapping[str, object], host_suffixes: Sequence[str]
) -> str:
    """把可信主机上的目标 URL 包装为反向代理地址。

    Args:
        url: 目标 URL。
        config: 插件配置映射。
        host_suffixes: 允许走反向代理的主机后缀。

    Returns:
        包装后的代理地址；未启用、协议非法或主机不匹配时原样返回。
    """
    prefix = reverse_proxy_prefix(config)
    if not prefix or not url.startswith(("http://", "https://")):
        return url
    try:
        hostname = urlsplit(url).hostname
    except ValueError:
        return url
    if not host_matches(hostname or "", host_suffixes):
        return url
    return prefix + quote(url, safe="")


def is_proxy_url(url: str, config: Mapping[str, object]) -> bool:
    """判断 URL 是否属于已配置反代自身。

    Args:
        url: 待判断的 URL。
        config: 插件配置映射。

    Returns:
        URL 指向反代主机时返回 True，此时应跳过目标站的主机校验。
    """
    prefix = reverse_proxy_prefix(config)
    if not prefix or not url:
        return False
    try:
        parsed = urlsplit(url)
        prefix_host = urlsplit(prefix).hostname
    except ValueError:
        return False
    return bool(prefix_host) and (parsed.hostname or "").lower() == prefix_host.lower()


def unwrap_proxy_url(url: str, config: Mapping[str, object]) -> str:
    """还原被反代改写过的地址，便于按原始主机做可信校验。

    Args:
        url: 可能被反代改写的地址。
        config: 插件配置映射。

    Returns:
        原始目标地址；URL 不属于反代或缺少内层地址时原样返回。
    """
    prefix = reverse_proxy_prefix(config)
    if not prefix or not is_proxy_url(url, config):
        return url
    if url.startswith(prefix):
        return unquote(url[len(prefix) :])
    values = parse_qs(urlsplit(url).query).get("url")
    if values and values[0].startswith(("http://", "https://")):
        return values[0]
    return url


def is_challenge_response(text: str) -> bool:
    """判断响应正文是否为反代的 AES JS 挑战页。"""
    if not text:
        return False
    return "slowAES" in text or "var a=toNumbers" in text


def solve_challenge(html: str) -> tuple[str, str] | None:
    """解析 AES JS 挑战页，解出 Cookie 与跳转地址。

    Args:
        html: 反向代理返回的挑战页正文。

    Returns:
        Cookie 请求头值与跳转地址；参数缺失或 AES 库不可用时返回 None。
    """
    a_match = _CHALLENGE_A_PATTERN.search(html)
    b_match = _CHALLENGE_B_PATTERN.search(html)
    c_match = _CHALLENGE_C_PATTERN.search(html)
    redirect_match = _CHALLENGE_REDIRECT_PATTERN.search(html)
    if not all((a_match, b_match, c_match, redirect_match)):
        return None
    cipher_type = _aes_cipher_type()
    if cipher_type is None:
        return None
    cookie_name_match = _CHALLENGE_COOKIE_PATTERN.search(html)
    cookie_name = (
        cookie_name_match.group(1) if cookie_name_match else DEFAULT_COOKIE_NAME
    )
    cipher = cipher_type.new(
        bytes.fromhex(a_match.group(1)),
        cipher_type.MODE_CBC,
        bytes.fromhex(b_match.group(1)),
    )
    cookie_value = cipher.decrypt(bytes.fromhex(c_match.group(1))).hex()
    return f"{cookie_name}={cookie_value}", redirect_match.group(1)


def cookie_headers(config: Mapping[str, object], user_agent: str) -> dict[str, str]:
    """返回当前反代 Cookie 请求头，未缓存时返回空字典。

    Args:
        config: 插件配置映射。
        user_agent: 求解挑战时使用的 User-Agent。

    Returns:
        只包含 Cookie 的请求头字典。
    """
    prefix = reverse_proxy_prefix(config)
    if not prefix:
        return {}
    with _PROXY_COOKIE_LOCK:
        cookie = _PROXY_COOKIES.get((prefix, (user_agent or "").strip()))
    return {"Cookie": cookie} if cookie else {}


def challenge_retry_url(
    config: Mapping[str, object],
    html: str,
    response_url: str,
    user_agent: str,
) -> str:
    """求解挑战页并缓存 Cookie，返回应继续请求的绝对地址。

    Args:
        config: 插件配置映射。
        html: 挑战页正文。
        response_url: 返回挑战页的请求地址，用于解析相对跳转地址。
        user_agent: 挑战 Cookie 的缓存键之一。

    Returns:
        跟进跳转所需的绝对地址；未启用反代、非挑战页或求解失败时返回空串。
    """
    prefix = reverse_proxy_prefix(config)
    if not prefix or not is_challenge_response(html):
        return ""
    solved = solve_challenge(html)
    if not solved:
        logger.warning("反向代理 AES JS 挑战求解失败，将按普通响应继续处理")
        return ""
    cookie, redirect_url = solved
    with _PROXY_COOKIE_LOCK:
        _PROXY_COOKIES[(prefix, (user_agent or "").strip())] = cookie
    return urljoin(response_url, redirect_url)


async def proxy_get(
    client: httpx.AsyncClient,
    config: Mapping[str, object],
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    host_suffixes: Sequence[str] = (),
) -> httpx.Response:
    """经反向代理 GET 目标 URL，逐跳处理代理的重定向与 AES JS 挑战页。

    未启用反代时退化为普通 GET，因此调用方无需区分两种模式。启用后代理可能先把
    短路径 301 到规范路径、再返回挑战页，两类跳转共用同一个请求轮次上限，且每一
    跳都要求目标落在代理主机或已声明的目标站内。

    Args:
        client: 已配置超时的 httpx 客户端。
        config: 插件配置映射。
        url: 目标 URL。
        headers: 额外请求头，Cookie 由本函数按缓存追加。
        host_suffixes: 允许走反向代理的主机后缀。

    Returns:
        跳转与挑战都处理完的最终响应；无法继续时返回当前这一跳的响应。
    """
    request_headers = dict(headers or {})
    user_agent = str(request_headers.get("User-Agent", ""))
    request_url = rewrite_url(url, config, host_suffixes)
    response = await client.get(
        request_url,
        headers={**request_headers, **cookie_headers(config, user_agent)},
    )
    if not reverse_proxy_prefix(config):
        return response
    for _ in range(MAX_PROXY_ROUNDS):
        if 300 <= response.status_code < 400:
            location = response.headers.get("Location")
            if not location:
                return response
            next_url = urljoin(str(response.url), location)
        else:
            next_url = challenge_retry_url(
                config, response.text, str(response.url), user_agent
            )
            if not next_url:
                return response
        next_host = urlsplit(next_url).hostname or ""
        if not (
            is_proxy_url(next_url, config) or host_matches(next_host, host_suffixes)
        ):
            logger.warning("反向代理跳转地址不在信任范围，忽略该跳转")
            return response
        request_url = rewrite_url(next_url, config, host_suffixes)
        response = await client.get(
            request_url,
            headers={**request_headers, **cookie_headers(config, user_agent)},
        )
    return response


def _aes_cipher_type():
    """返回可用的 AES 实现模块，缺失时记录一次警告并返回 None。"""
    global _WARNED_MISSING_AES
    try:
        from Crypto.Cipher import AES

        return AES
    except ImportError:
        pass
    try:
        from Cryptodome.Cipher import AES

        return AES
    except ImportError:
        if not _WARNED_MISSING_AES:
            _WARNED_MISSING_AES = True
            logger.warning("缺少 pycryptodome，反向代理的 AES JS 挑战无法自动求解")
        return None

"""定义平台解析器契约及跨平台共用流程。"""

from collections.abc import Mapping

import httpx
from astrbot.api import logger

from .contracts import ParseContext, ParseResult
from .http import (
    AUTH_FAILURE_STATUS_CODES,
    CookieAccessError,
    build_cookie_access_error,
    cookie_config_value,
    raise_for_cookie_access,
    request_timeout,
)
from .media import ImageMaterializer


class BaseParser:
    """平台解析器的稳定契约。"""

    name = "base"
    # 子类通过声明元数据接入统一 Cookie 策略，不在平台模块重复状态判断。
    display_name = "平台"
    cookie_config_key = ""
    cookie_failure_status_codes = AUTH_FAILURE_STATUS_CODES
    image_host_suffixes: tuple[str, ...] = ()
    # 声明需要经反向代理访问的主机；未声明的平台不会改写任何请求。
    reverse_proxy_host_suffixes: tuple[str, ...] = ()
    # 创建 HTTP 客户端的公共参数：禁用进程环境代理，网络行为只由插件配置决定。
    http_client_options = {"trust_env": False}

    def __init__(self, config: Mapping[str, object]):
        self.config = config

    @property
    def request_timeout(self) -> float:
        return request_timeout(self.config)

    async def match(self, context: ParseContext) -> bool:
        raise NotImplementedError

    async def parse(self, context: ParseContext) -> ParseResult:
        raise NotImplementedError

    def cookie_access_error(self) -> CookieAccessError:
        """根据当前平台 Cookie 配置生成不泄漏凭据的用户提示。"""
        return build_cookie_access_error(
            self.display_name,
            cookie_config_value(self.config, self.cookie_config_key),
        )

    def raise_for_response_status(self, response: httpx.Response) -> None:
        """统一处理平台内容请求的 Cookie 拒绝和其他 HTTP 错误。

        Cookie 状态识别属于跨平台协议，集中在基类避免适配器复制；平台只声明
        配置键和特殊状态码。媒体下载不经过此入口，因此防盗链失败不会误报。
        """
        raise_for_cookie_access(
            response,
            platform=self.display_name,
            cookie_value=cookie_config_value(self.config, self.cookie_config_key),
            status_codes=self.cookie_failure_status_codes,
        )
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError:
            # 失败会转成给用户的提示语，这里留下主机与状态码便于对照日志定位。
            logger.warning(
                f"{self.display_name}请求返回异常状态 "
                f"{response.status_code}（{response.url.host}）"
            )
            raise

    async def materialize_images(
        self,
        result: ParseResult,
        client: httpx.AsyncClient,
        referer: str,
    ) -> ParseResult:
        materializer = ImageMaterializer(
            self.config,
            self.image_host_suffixes,
            self.reverse_proxy_host_suffixes,
        )
        return await materializer.materialize(result, client, referer)

    async def materialize_public_images(
        self,
        result: ParseResult,
        referer: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> ParseResult:
        """使用不含平台 Cookie 的独立客户端读取公开图片。"""
        async with httpx.AsyncClient(
            timeout=self.request_timeout,
            follow_redirects=False,
            headers=headers,
            **self.http_client_options,
        ) as client:
            return await self.materialize_images(result, client, referer)

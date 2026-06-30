import json
from typing import Optional

class BaseSessionProvider:
    def resolve_token(self) -> Optional[str]:
        raise NotImplementedError

    def resolve_cookies(self) -> Optional[dict[str, str]]:
        return None

class TokenSessionProvider(BaseSessionProvider):
    def __init__(self, token: str):
        self._token = token

    def resolve_token(self) -> Optional[str]:
        return self._token

class CookieSessionProvider(BaseSessionProvider):
    def __init__(self, cookies: dict[str, str], token_cookie_name: str = "token"):
        self._cookies = cookies
        self._token_cookie_name = token_cookie_name

    def resolve_token(self) -> Optional[str]:
        return self._cookies.get(self._token_cookie_name)

    def resolve_cookies(self) -> Optional[dict[str, str]]:
        return self._cookies

class StorageStateSessionProvider(BaseSessionProvider):
    def __init__(self, file_path: str, token_cookie_name: str = "token"):
        self.file_path = file_path
        self.token_cookie_name = token_cookie_name

    def resolve_token(self) -> Optional[str]:
        cookies = self.resolve_cookies()
        if cookies:
            return cookies.get(self.token_cookie_name)
        return None

    def resolve_cookies(self) -> Optional[dict[str, str]]:
        try:
            with open(self.file_path, "r") as f:
                data = json.load(f)
            cookies = {}
            for cookie in data.get("cookies", []):
                cookies[cookie["name"]] = cookie["value"]
            return cookies
        except Exception:
            return None

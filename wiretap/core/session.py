import json
import os
from typing import Optional

class BaseSessionProvider:
    def resolve_token(self) -> Optional[str]:
        raise NotImplementedError

    def resolve_cookies(self) -> Optional[dict[str, str]]:
        return None

class TokenSessionProvider(BaseSessionProvider):
    def __init__(self, token: str, session_file: Optional[str] = None):
        self._token = token
        # Bug fix #2: Accept an explicit path instead of relying on cwd.
        # Falls back to ./session_details.json for backwards compatibility,
        # but callers (e.g. CLI) should pass an absolute path.
        self._session_file = session_file or os.path.join(os.getcwd(), "session_details.json")

    def resolve_token(self) -> Optional[str]:
        return self._token

    def resolve_cookies(self) -> Optional[dict[str, str]]:
        if os.path.exists(self._session_file):
            try:
                with open(self._session_file, "r") as f:
                    data = json.load(f)
                if data.get("token") == self._token:
                    return data.get("cookies")
                # Fallback to returning the cookies anyway if token doesn't match but present
                if "cookies" in data:
                    return data["cookies"]
            except Exception:
                pass
        return None


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

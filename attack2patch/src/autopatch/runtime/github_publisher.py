from __future__ import annotations

import importlib.util
import os
import time
from typing import Any, Protocol

import httpx

from autopatch.config import GitHubAppSettings
from autopatch.types import PullRequestRequest, PullRequestResult


class _ResponseLike(Protocol):
    status_code: int

    def json(self) -> Any: ...


class _HttpClient(Protocol):
    def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        json: dict[str, Any] | None = None,
    ) -> _ResponseLike: ...


class GitHubAppPullRequestPublisher:
    """Create draft pull requests with a least-privilege GitHub App installation."""

    name = "github-app"

    def __init__(
        self,
        settings: GitHubAppSettings,
        *,
        client: _HttpClient | None = None,
    ) -> None:
        self.settings = settings
        self._client = client

    def available(self) -> bool:
        return bool(
            self.settings.enabled
            and self.settings.repository
            and os.getenv(self.settings.app_id_env)
            and os.getenv(self.settings.installation_id_env)
            and os.getenv(self.settings.private_key_env)
            and importlib.util.find_spec("jwt") is not None
        )

    def create_pull_request(self, request: PullRequestRequest) -> PullRequestResult:
        if request.repository != self.settings.repository:
            raise PermissionError("pull request repository is not the configured GitHub App target")
        token = self._installation_token()
        response = self._post(
            f"{self.settings.api_url.rstrip('/')}/repos/{request.repository}/pulls",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            payload={
                "title": request.title,
                "head": request.head,
                "base": request.base,
                "body": request.body,
                "draft": request.draft,
                "maintainer_can_modify": True,
            },
        )
        if response.status_code != 201:
            raise RuntimeError(f"GitHub pull request creation returned HTTP {response.status_code}")
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("GitHub pull request response must be an object")
        return PullRequestResult(
            number=int(payload["number"]),
            url=str(payload.get("html_url") or payload.get("url")),
            state=str(payload.get("state") or "open"),
            draft=bool(payload.get("draft", request.draft)),
            head=request.head,
            base=request.base,
        )

    def _installation_token(self) -> str:
        installation_id = os.getenv(self.settings.installation_id_env)
        if not installation_id:
            raise RuntimeError(
                f"missing GitHub App installation id: {self.settings.installation_id_env}"
            )
        response = self._post(
            (
                f"{self.settings.api_url.rstrip('/')}/app/installations/"
                f"{installation_id}/access_tokens"
            ),
            headers={
                "Authorization": f"Bearer {self._app_jwt()}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            payload=None,
        )
        if response.status_code != 201:
            raise RuntimeError(f"GitHub App token exchange returned HTTP {response.status_code}")
        payload = response.json()
        if not isinstance(payload, dict) or not payload.get("token"):
            raise ValueError("GitHub App token response did not include a token")
        return str(payload["token"])

    def _app_jwt(self) -> str:
        app_id = os.getenv(self.settings.app_id_env)
        private_key = os.getenv(self.settings.private_key_env)
        if not app_id or not private_key:
            raise RuntimeError("missing GitHub App id or private key environment variable")
        try:
            import jwt
        except ImportError as exc:
            raise RuntimeError("GitHub App publishing requires PyJWT[crypto]") from exc
        now = int(time.time())
        encoded = jwt.encode(
            {"iat": now - 60, "exp": now + 540, "iss": app_id},
            private_key.replace("\\n", "\n"),
            algorithm="RS256",
        )
        return str(encoded)

    def _post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        payload: dict[str, Any] | None,
    ) -> _ResponseLike:
        try:
            if self._client is None:
                with httpx.Client(timeout=self.settings.timeout_seconds) as client:
                    return client.post(url, headers=headers, json=payload)
            return self._client.post(url, headers=headers, json=payload)
        except httpx.HTTPError as exc:
            raise RuntimeError(f"GitHub API request failed: {type(exc).__name__}") from exc

from __future__ import annotations

from typing import Any

from autopatch.config import GitHubAppSettings
from autopatch.runtime.github_publisher import GitHubAppPullRequestPublisher
from autopatch.types import PullRequestRequest


class _Response:
    def __init__(self, status_code: int, payload: dict[str, Any]) -> None:
        self.status_code = status_code
        self.payload = payload

    def json(self) -> dict[str, Any]:
        return self.payload


class _Client:
    def __init__(self) -> None:
        self.responses = [
            _Response(201, {"token": "installation-token"}),
            _Response(
                201,
                {
                    "number": 17,
                    "html_url": "https://github.example/acme/app/pull/17",
                    "state": "open",
                    "draft": True,
                },
            ),
        ]
        self.requests: list[dict[str, Any]] = []

    def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        json: dict[str, Any] | None = None,
    ) -> _Response:
        self.requests.append({"url": url, "headers": headers, "json": json})
        return self.responses.pop(0)


def test_github_app_provider_exchanges_token_and_creates_draft_pr(monkeypatch) -> None:
    settings = GitHubAppSettings(enabled=True, repository="acme/app")
    client = _Client()
    publisher = GitHubAppPullRequestPublisher(settings, client=client)
    monkeypatch.setenv("GITHUB_APP_INSTALLATION_ID", "42")
    monkeypatch.setattr(publisher, "_app_jwt", lambda: "app-jwt")

    result = publisher.create_pull_request(
        PullRequestRequest(
            repository="acme/app",
            head="attack2patch/security/run-1",
            base="main",
            title="Verified security patch",
            body="Evidence",
            draft=True,
        )
    )

    assert result.number == 17
    assert result.draft is True
    assert client.requests[0]["url"].endswith("/app/installations/42/access_tokens")
    assert client.requests[1]["json"]["draft"] is True
    assert client.requests[1]["headers"]["Authorization"] == "Bearer installation-token"

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

    def get(self, url: str, *, headers: dict[str, str]) -> _Response:
        raise AssertionError(f"unexpected GET {url}")


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


class _SmokeClient:
    def __init__(self, *, permissions: dict[str, str] | None = None) -> None:
        self.permissions = permissions or {"contents": "write", "pull_requests": "write"}
        self.requests: list[dict[str, Any]] = []

    def get(self, url: str, *, headers: dict[str, str]) -> _Response:
        self.requests.append({"method": "GET", "url": url, "headers": headers})
        if url.endswith("/installation"):
            return _Response(200, {"id": 42})
        return _Response(200, {"full_name": "acme/app"})

    def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        json: dict[str, Any] | None = None,
    ) -> _Response:
        self.requests.append(
            {"method": "POST", "url": url, "headers": headers, "json": json}
        )
        return _Response(
            201,
            {
                "token": "installation-token",
                "permissions": self.permissions,
                "repository_selection": "selected",
            },
        )


def test_github_app_smoke_verifies_installation_permissions_and_repository(monkeypatch) -> None:
    settings = GitHubAppSettings(enabled=True, repository="acme/app")
    client = _SmokeClient()
    publisher = GitHubAppPullRequestPublisher(settings, client=client)
    monkeypatch.setenv("GITHUB_APP_ID", "7")
    monkeypatch.setenv("GITHUB_APP_INSTALLATION_ID", "42")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "test-key")
    monkeypatch.setattr(publisher, "_app_jwt", lambda: "app-jwt")

    result = publisher.smoke_test()

    assert result.repository == "acme/app"
    assert result.repository_selection == "selected"
    assert result.permissions["pull_requests"] == "write"
    assert [request["method"] for request in client.requests] == ["GET", "POST", "GET"]
    assert all("installation-token" not in str(request) for request in [result.model_dump()])


def test_github_app_smoke_fails_closed_on_insufficient_permissions(monkeypatch) -> None:
    settings = GitHubAppSettings(enabled=True, repository="acme/app")
    publisher = GitHubAppPullRequestPublisher(
        settings,
        client=_SmokeClient(permissions={"contents": "read", "pull_requests": "write"}),
    )
    monkeypatch.setenv("GITHUB_APP_ID", "7")
    monkeypatch.setenv("GITHUB_APP_INSTALLATION_ID", "42")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "test-key")
    monkeypatch.setattr(publisher, "_app_jwt", lambda: "app-jwt")

    try:
        publisher.smoke_test()
    except PermissionError as exc:
        assert "contents" in str(exc)
    else:
        raise AssertionError("insufficient GitHub App permissions must fail closed")

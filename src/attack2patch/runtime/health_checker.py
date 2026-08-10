from urllib.request import urlopen


def is_healthy(url: str, timeout_seconds: float = 3.0) -> bool:
    try:
        with urlopen(url, timeout=timeout_seconds) as response:  # noqa: S310 - configured URL
            return response.status == 200
    except OSError:
        return False

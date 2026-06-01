import os
import sys
from pathlib import Path

import requests


def load_env_file(path: str | Path = ".env") -> None:
    env_path = Path(path)

    if not env_path.is_absolute():
        env_path = Path(__file__).resolve().parent / env_path

    if not env_path.exists():
        return

    for line_number, line in enumerate(env_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if "=" not in line:
            raise RuntimeError(f"Invalid .env line {line_number}: expected KEY=value")

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if not key:
            raise RuntimeError(f"Invalid .env line {line_number}: environment variable name is empty")

        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {"'", '"'}
        ):
            value = value[1:-1]

        os.environ.setdefault(key, value)


def require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def login_to_orchestrator(
    session: requests.Session,
    orch_fqdn: str,
    orch_user: str,
    orch_password: str,
    *,
    login_type: int = 2,
    verify_ssl: bool = True,
    timeout: tuple[float, float] = (9.15, 12),
) -> dict[str, str]:
    headers: dict[str, str] = {}

    login_url = (
        f"https://{orch_fqdn}/gms/rest/authentication/login"
        "?source=menu_rest_apis_id"
    )

    response = session.post(
        login_url,
        json={
            "user": orch_user,
            "password": orch_password,
            "token": "",
            "loginType": login_type,
        },
        verify=verify_ssl,
        timeout=timeout,
        headers=headers,
    )

    if response.status_code != 200:
        raise RuntimeError(
            "Login failed. "
            f"HTTP {response.status_code}: {response.text[:500]}"
        )

    csrf_token: str | None = None

    for cookie in response.cookies:
        if cookie.name == "orchCsrfToken":
            csrf_token = cookie.value
            break

    if csrf_token is None:
        raise RuntimeError("Login succeeded, but the orchCsrfToken cookie was not returned.")

    headers["X-XSRF-TOKEN"] = csrf_token

    return headers


def logout_from_orchestrator(
    session: requests.Session,
    orch_fqdn: str,
    headers: dict[str, str],
    *,
    verify_ssl: bool = True,
    timeout: tuple[float, float] = (9.15, 12),
) -> None:
    logout_url = (
        f"https://{orch_fqdn}/gms/rest/authentication/logout"
        "?source=menu_rest_apis_id"
    )

    try:
        session.get(
            logout_url,
            verify=verify_ssl,
            timeout=timeout,
            headers=headers,
        )
    except requests.RequestException as exc:
        print(f"Warning: logout request failed: {exc}", file=sys.stderr)


def main() -> None:
    load_env_file()

    orch_fqdn = require_env("ORCH_FQDN")
    orch_user = require_env("ORCH_USER")
    orch_password = require_env("ORCH_PASSWORD")

    login_type = int(os.getenv("ORCH_LOGIN_TYPE", "2"))
    verify_ssl = os.getenv("ORCH_VERIFY_SSL", "true").lower() not in {
        "0",
        "false",
        "no",
    }

    timeout = (9.15, 12)

    with requests.Session() as session:
        headers: dict[str, str] = {}

        try:
            headers = login_to_orchestrator(
                session,
                orch_fqdn,
                orch_user,
                orch_password,
                login_type=login_type,
                verify_ssl=verify_ssl,
                timeout=timeout,
            )

            appliances_url = (
                f"https://{orch_fqdn}/gms/rest/appliance"
                "?source=menu_rest_apis_id"
            )

            response = session.get(
                appliances_url,
                verify=verify_ssl,
                timeout=timeout,
                headers=headers,
            )

            if response.status_code != 200:
                raise RuntimeError(
                    "Failed to get appliances. "
                    f"HTTP {response.status_code}: {response.text[:500]}"
                )

            print(response.text)

        finally:
            logout_from_orchestrator(
                session,
                orch_fqdn,
                headers,
                verify_ssl=verify_ssl,
                timeout=timeout,
            )


if __name__ == "__main__":
    main()
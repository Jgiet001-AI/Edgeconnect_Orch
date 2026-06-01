import os
import sys
from pathlib import Path

import redis
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


def save_session_to_redis(orch_fqdn: str, csrf_token: str, cookie_header: str) -> str:
    # Persist the Orchestrator session (CSRF token + cookies) to the user's local Redis.
    # Stored as a hash keyed by orchestrator FQDN so multiple orchestrators don't collide.
    # delete+hset replaces any prior value every run (and avoids WRONGTYPE on a former string).
    redis_host = os.getenv("REDIS_HOST", "localhost")
    redis_port = int(os.getenv("REDIS_PORT", "6379"))
    redis_db = int(os.getenv("REDIS_DB", "0"))

    key = f"orchestratorEdge[{orch_fqdn}]"

    try:
        client = redis.Redis(
            host=redis_host,
            port=redis_port,
            db=redis_db,
            decode_responses=True,
        )
        client.delete(key)
        client.hset(key, mapping={"csrfToken": csrf_token, "cookie": cookie_header})
    except redis.RedisError as exc:
        raise RuntimeError(
            f"Failed to save session to Redis at {redis_host}:{redis_port}: {exc}"
        ) from exc

    return key


def request_mfa_code(
    session: requests.Session,
    orch_fqdn: str,
    orch_user: str,
    orch_password: str,
    *,
    verify_ssl: bool = True,
    timeout: tuple[float, float] = (9.15, 12),
) -> None:
    # Ask Orchestrator to email a one-time 2-factor code to the user's mailbox.
    # isEncrypted/randomizer are only needed for client-side password encryption;
    # we send over HTTPS, so they are omitted.
    login_token_url = (
        f"https://{orch_fqdn}/gms/rest/authentication/loginToken"
        "?source=menu_rest_apis_id"
    )

    response = session.post(
        login_token_url,
        json={
            "user": orch_user,
            "password": orch_password,
            "TempCode": True,
        },
        verify=verify_ssl,
        timeout=timeout,
    )

    # Orchestrator returns 204 No Content on success when the code is emailed;
    # pyedgeconnect's send_mfa accepts both 200 and 204.
    if response.status_code not in {200, 204}:
        raise RuntimeError(
            "Failed to request 2-factor code. "
            f"HTTP {response.status_code}: {response.text[:500]}"
        )


def login_to_orchestrator(
    session: requests.Session,
    orch_fqdn: str,
    orch_user: str,
    orch_password: str,
    *,
    token: str = "",
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
            "token": token,
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
    mfa_enabled = os.getenv("ORCH_MFA", "true").lower() not in {
        "0",
        "false",
        "no",
    }

    timeout = (9.15, 12)

    with requests.Session() as session:
        headers: dict[str, str] = {}

        try:
            token = ""

            if mfa_enabled:
                request_mfa_code(
                    session,
                    orch_fqdn,
                    orch_user,
                    orch_password,
                    verify_ssl=verify_ssl,
                    timeout=timeout,
                )
                token = input("Enter the 2-factor code emailed to you: ").strip()

            headers = login_to_orchestrator(
                session,
                orch_fqdn,
                orch_user,
                orch_password,
                token=token,
                login_type=login_type,
                verify_ssl=verify_ssl,
                timeout=timeout,
            )

            auth_token = headers.get("X-XSRF-TOKEN", "")
            cookie_header = "; ".join(f"{c.name}={c.value}" for c in session.cookies)
            saved_key = save_session_to_redis(orch_fqdn, auth_token, cookie_header)
            print(f"Saved Orchestrator session (CSRF token + cookies) to Redis under key: {saved_key}")

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
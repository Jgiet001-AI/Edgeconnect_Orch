import requests

session = requests.Session()

orch_fqdn = "jg-demo-2-sewan-orchsp-useast1.silverpeak.cloud"
orch_user = "jean.giet@hpe.com"
orch_password = "!R0ck2018"
login_type = 2  # 0 for local, 1 for radius, 2 for tacacs
timeout_values = (9.15, 12)
verify_ssl = True
headers = {}

# login with username/password
login_response = session.post(
    f"https://{orch_fqdn}/gms/rest/authentication/login?source=menu_rest_apis_id",
    json={
        "user": orch_user,
        "password": orch_password,
        "token": "",
        "loginType": login_type,
    },
    verify=verify_ssl,
    timeout=timeout_values,
    headers=headers,
)

if login_response.status_code == 200:
    # get and set X-XSRF-TOKEN
    for cookie in login_response.cookies:
        if cookie.name == "orchCsrfToken":
            # This relates to the 'Enforce CSRF Check' under the
            # Advanced Security Settings in Orchestrator
            headers["X-XSRF-TOKEN"] = cookie.value

get_appliances = session.get(
    f"https://{orch_fqdn}/gms/rest/appliance?source=menu_rest_apis_id",
    verify=verify_ssl,
    timeout=timeout_values,
    headers=headers,
)

print(get_appliances.content)

# Log out of session
session.get(
    f"https://{orch_fqdn}/gms/rest/authentication/logout?source=menu_rest_apis_id",
    verify=verify_ssl,
    timeout=timeout_values,
    headers=headers,
)
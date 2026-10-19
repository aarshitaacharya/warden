"""Generate the Keycloak realm import from the Acme directory."""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from warden import acme  # noqa: E402

roles = sorted({r for u in acme.USERS.values() for r in u["roles"]} | {"employee"})
realm = {
    "realm": "acme", "enabled": True, "sslRequired": "none",
    "accessTokenLifespan": 900,
    # Step-up: acr "2" is reached by authenticating with a passkey (WebAuthn).
    "attributes": {"acr.loa.map": json.dumps({"pwd": 1, "passkey": 2}), "webAuthnPolicyUserVerificationRequirement": "required"},
    "roles": {"realm": [{"name": r} for r in roles]},
    "users": [
        {"username": u, "enabled": True, "email": f"{u}@acme.test",
         "firstName": u.title(), "lastName": "Acme",
         "credentials": [{"type": "password", "value": f"{u}-dev-pass", "temporary": False}],
         "realmRoles": ["employee"] + m["roles"],
         "attributes": {"manager": [m["manager"] or ""], "dept": [m["dept"]]}}
        for u, m in acme.USERS.items()
    ],
    "clients": [
        {"clientId": "warden-gateway", "enabled": True, "publicClient": False, "standardFlowEnabled": True,
         "redirectUris": ["http://localhost:8000/*"], "secret": "gateway-dev-secret",
         "defaultClientScopes": ["roles", "profile"]},
        *[{"clientId": s, "enabled": True, "publicClient": False, "serviceAccountsEnabled": True,
           "standardFlowEnabled": False, "secret": m["secret"]} for s, m in acme.SERVICES.items()],
        *[{"clientId": a, "enabled": True, "publicClient": False, "serviceAccountsEnabled": True,
           "standardFlowEnabled": False, "secret": m["secret"]} for a, m in acme.AGENTS.items()],
    ],
}
out = pathlib.Path(__file__).resolve().parents[1] / "infra/keycloak/acme-realm.json"
out.write_text(json.dumps(realm, indent=2) + "\n")
print("wrote", out)

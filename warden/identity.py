"""Identity layer: token issuing (dev IdP + STS), RFC 8693 exchange, verification.

In production, Keycloak authenticates humans and services and Warden trusts its
JWKS. Keycloak's standard token exchange does not carry an actor (`act`) claim,
so Warden's own STS performs the agent delegation exchange. For local runs and
tests, `DevIdP` plays Keycloak's role with the same claim layout.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from . import acme

AUDIENCE = "warden-gateway"
DEV_ISSUER = "https://idp.acme.test/realms/acme"
STS_ISSUER = "https://sts.warden.test"
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
STEPUP_ACR = {"passkey", "urn:warden:passkey", "2"}
MAX_AGENT_TTL = 300


class AuthError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


@dataclass
class Identity:
    kind: str                      # user | service | agent
    subject: str                   # user id, service id, or the delegating user for agents
    agent_id: str | None = None
    roles: list[str] = field(default_factory=list)
    scopes: set[str] = field(default_factory=set)
    acr: str = "pwd"
    device_id: str | None = None
    device_trusted: bool = False
    jti: str = ""
    exp: int = 0
    claims: dict = field(default_factory=dict)

    @property
    def stepped_up(self) -> bool:
        return self.acr in STEPUP_ACR

    @property
    def label(self) -> str:
        return f"agent:{self.agent_id}->{self.subject}" if self.agent_id else f"{self.kind}:{self.subject}"


class Keyring:
    """One RSA signing key plus its public JWK."""

    def __init__(self, kid: str):
        self.kid = kid
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    @property
    def public_key(self):
        return self._key.public_key()

    def sign(self, claims: dict) -> str:
        return jwt.encode(claims, self._key, algorithm="RS256", headers={"kid": self.kid})

    def jwk(self) -> dict:
        import json
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.public_key))
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return jwk


class RevocationList:
    def __init__(self):
        self.jtis: set[str] = set()
        self.users: dict[str, float] = {}     # user -> revoked-before timestamp
        self.agents: dict[str, float] = {}

    def revoke_token(self, jti: str):
        self.jtis.add(jti)

    def revoke_user(self, user: str):
        self.users[user] = time.time()

    def revoke_agent(self, agent_id: str):
        self.agents[agent_id] = time.time()

    def is_revoked(self, ident: Identity, iat: float) -> str | None:
        if ident.jti in self.jtis:
            return "token_revoked"
        if ident.kind != "service" and self.users.get(ident.subject, 0) >= iat:
            return "user_revoked"
        if ident.agent_id and self.agents.get(ident.agent_id, 0) >= iat:
            return "agent_revoked"
        return None


class DevIdP:
    """Stand-in for Keycloak: issues user, service and agent-client tokens."""

    def __init__(self, keyring: Keyring | None = None):
        self.keys = keyring or Keyring("dev-idp-1")

    def _base(self, sub: str, typ: str, ttl: int, **extra) -> dict:
        now = int(time.time())
        c = {"iss": DEV_ISSUER, "aud": AUDIENCE, "sub": sub, "typ": typ,
             "iat": now, "exp": now + ttl, "jti": uuid.uuid4().hex}
        c.update(extra)
        return c

    def user_token(self, user: str, *, passkey: bool = False, device_id: str = "laptop-1",
                   device_trusted: bool = True, ttl: int = 900) -> str:
        meta = acme.USERS[user]
        claims = self._base(
            user, "user", ttl,
            realm_access={"roles": ["employee"] + meta["roles"]},
            acr="passkey" if passkey else "pwd",
            amr=["webauthn"] if passkey else ["pwd"],
            device_id=device_id, device_trusted=device_trusted,
        )
        return self.keys.sign(claims)

    def service_token(self, service: str, secret: str, *, cert_thumbprint: str | None = None, ttl: int = 600) -> str:
        meta = acme.SERVICES.get(service)
        if not meta or meta["secret"] != secret:
            raise AuthError("invalid_client")
        extra = {"scope": " ".join(meta["scopes"]), "device_trusted": True}
        if cert_thumbprint:
            extra["cnf"] = {"x5t#S256": cert_thumbprint}
        return self.keys.sign(self._base(service, "service", ttl, **extra))

    def agent_client_token(self, agent_id: str, secret: str, ttl: int = 300) -> str:
        """The agent's own credential. Only valid as an actor_token."""
        meta = acme.AGENTS.get(agent_id)
        if not meta or meta["secret"] != secret:
            raise AuthError("invalid_client")
        return self.keys.sign(self._base(agent_id, "agent_client", ttl))


class Verifier:
    """Verifies tokens from allow-listed issuers and applies revocation."""

    def __init__(self, revocations: RevocationList | None = None):
        self._issuers: dict[str, dict] = {}
        self.revocations = revocations or RevocationList()

    def trust(self, issuer: str, keys: dict[str, object]):
        """keys: kid -> public key object."""
        self._issuers[issuer] = keys

    def trust_keyring(self, issuer: str, keyring: Keyring):
        self.trust(issuer, {keyring.kid: keyring.public_key})

    def trust_jwks(self, issuer: str, jwks: dict):
        keys = {k["kid"]: jwt.algorithms.RSAAlgorithm.from_jwk(k) for k in jwks["keys"] if k.get("use", "sig") == "sig"}
        self.trust(issuer, keys)

    def decode(self, token: str, *, allow_agent_client: bool = False,
               cert_thumbprint: str | None = None) -> Identity:
        try:
            header = jwt.get_unverified_header(token)
            unverified = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError:
            raise AuthError("malformed_token")
        if header.get("alg") != "RS256":
            raise AuthError("bad_algorithm")
        keys = self._issuers.get(unverified.get("iss", ""))
        if keys is None:
            raise AuthError("untrusted_issuer")
        key = keys.get(header.get("kid"))
        if key is None:
            raise AuthError("unknown_key")
        try:
            claims = jwt.decode(token, key, algorithms=["RS256"], audience=AUDIENCE,
                                options={"require": ["exp", "iat", "sub", "jti"]})
        except jwt.ExpiredSignatureError:
            raise AuthError("token_expired")
        except jwt.PyJWTError as e:
            raise AuthError("invalid_token", str(e))

        typ = claims.get("typ")
        if typ == "agent_client" and not allow_agent_client:
            raise AuthError("agent_credential_not_accepted", "agent client credentials are only valid as actor_token")
        bound = (claims.get("cnf") or {}).get("x5t#S256")
        if bound and bound != cert_thumbprint:
            raise AuthError("certificate_binding_mismatch")

        roles = claims.get("realm_access", {}).get("roles", claims.get("roles", []))
        ident = Identity(
            kind="agent" if typ == "agent" else typ,
            subject=claims["sub"],
            agent_id=(claims.get("act") or {}).get("sub"),
            roles=list(roles),
            scopes=set(claims.get("scope", "").split()),
            acr=claims.get("acr", "pwd"),
            device_id=claims.get("device_id"),
            device_trusted=bool(claims.get("device_trusted", False)),
            jti=claims["jti"], exp=claims["exp"], claims=claims,
        )
        if ident.kind not in {"user", "service", "agent", "agent_client"}:
            raise AuthError("unknown_token_type")
        why = self.revocations.is_revoked(ident, claims["iat"])
        if why:
            raise AuthError(why)
        return ident


class STS:
    """RFC 8693 token exchange: user token + agent credential -> delegated token."""

    def __init__(self, verifier: Verifier, keyring: Keyring | None = None):
        self.verifier = verifier
        self.keys = keyring or Keyring("warden-sts-1")
        verifier.trust_keyring(STS_ISSUER, self.keys)
        self.issued: list[dict] = []     # lightweight audit trail for analytics

    def exchange(self, *, subject_token: str, actor_token: str,
                 scope: str = "", ttl: int = MAX_AGENT_TTL,
                 grant_type: str = TOKEN_EXCHANGE) -> dict:
        if grant_type != TOKEN_EXCHANGE:
            raise AuthError("unsupported_grant_type")
        user = self.verifier.decode(subject_token)
        if user.kind != "user":
            raise AuthError("invalid_subject_token", "subject_token must be a human user token")
        actor = self.verifier.decode(actor_token, allow_agent_client=True)
        if actor.kind != "agent_client":
            raise AuthError("invalid_actor_token", "actor_token must be an agent credential")
        agent = acme.AGENTS.get(actor.subject)
        if agent is None:
            raise AuthError("unknown_agent")

        requested = set(scope.split()) or set(agent["scopes"])
        granted = requested & set(agent["scopes"])
        if not granted:
            raise AuthError("invalid_scope", "no requested scope is within the agent's maximum")
        ttl = max(1, min(ttl, MAX_AGENT_TTL, user.exp - int(time.time())))

        now = int(time.time())
        jti = uuid.uuid4().hex
        claims = {
            "iss": STS_ISSUER, "aud": AUDIENCE, "sub": user.subject,
            "act": {"sub": actor.subject}, "typ": "agent",
            "scope": " ".join(sorted(granted)),
            "iat": now, "exp": now + ttl, "jti": jti,
            # Delegation never upgrades the human's assurance or device posture.
            "acr": user.acr, "device_id": user.device_id, "device_trusted": user.device_trusted,
            "realm_access": {"roles": user.roles},
            "parent_jti": user.jti,
        }
        self.issued.append({"jti": jti, "user": user.subject, "agent": actor.subject,
                            "scopes": sorted(granted), "iat": now, "exp": now + ttl})
        return {"access_token": self.keys.sign(claims), "issued_token_type": ACCESS_TOKEN_TYPE,
                "token_type": "Bearer", "expires_in": ttl, "scope": claims["scope"]}


def build_dev_stack() -> tuple[DevIdP, Verifier, STS]:
    verifier = Verifier()
    idp = DevIdP()
    verifier.trust_keyring(DEV_ISSUER, idp.keys)
    return idp, verifier, STS(verifier)

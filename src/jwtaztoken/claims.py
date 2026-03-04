"""Well-known Azure AD / Entra ID JWT claim descriptions.

This module maps standard and Azure-specific claim names to human-readable
descriptions so the CLI can annotate every field in a decoded token.
"""

from __future__ import annotations

# -- Standard OIDC / JWT claims ------------------------------------------------

STANDARD_CLAIMS: dict[str, str] = {
    "iss": "Issuer — the STS that issued the token",
    "sub": "Subject — principal the token asserts information about",
    "aud": "Audience — intended recipient(s) of the token",
    "exp": "Expiration time (Unix timestamp)",
    "nbf": "Not before — token is not valid before this time (Unix timestamp)",
    "iat": "Issued at (Unix timestamp)",
    "jti": "JWT ID — unique identifier for this token",
    "nonce": "Nonce — mitigates token-replay attacks",
    "auth_time": "Time of authentication (Unix timestamp)",
    "at_hash": "Access-token hash value",
    "c_hash": "Authorization-code hash value",
}

# -- Microsoft Entra ID (Azure AD) specific claims ----------------------------

AZURE_CLAIMS: dict[str, str] = {
    "aio": "Azure internal claim — opaque, not for external use",
    "acr": "Authentication context class reference (v1 tokens)",
    "amr": "Authentication methods references (e.g. pwd, mfa, rsa)",
    "appid": "Application (client) ID of the app that requested the token (v1)",
    "appidacr": "Application authentication context class ref (v1)",
    "azp": "Authorized party — client_id of the requesting app (v2)",
    "azpacr": "Authorized party authentication context class ref (v2)",
    "preferred_username": "Human-readable username (usually UPN or email)",
    "email": "Email address of the user",
    "name": "Display name of the user",
    "given_name": "First / given name",
    "family_name": "Last / family name",
    "groups": "Group object IDs the user belongs to",
    "hasgroups": "True when there are too many groups to include inline",
    "idp": "Identity provider that authenticated the subject",
    "idtyp": "Token type indicator (e.g. 'app' for app-only tokens)",
    "in_corp": "Signals that the client is inside the corporate network",
    "ipaddr": "IP address the user authenticated from",
    "login_hint": "Opaque login hint for seamless re-authentication",
    "oid": "Object ID of the user/principal in the directory",
    "onprem_sid": "On-premises security identifier",
    "platf": "Device platform",
    "puid": "Microsoft-internal persistent user ID",
    "pwd_exp": "Password expiration (seconds since auth_time)",
    "pwd_url": "URL where the user can change their password",
    "rh": "Azure internal routing hint",
    "roles": "Application roles assigned to the user/app",
    "scp": "Scopes (delegated permissions) granted to the app",
    "sid": "Session ID — used for per-session sign-out",
    "signin_state": "Sign-in state claim (e.g. device known, MFA done)",
    "tenant_ctry": "Resource tenant's country/region (from admin config)",
    "tenant_region_scope": "Tenant region scope (e.g. NA, EU, AS)",
    "tid": "Tenant ID (directory ID) the token was issued for",
    "unique_name": "Unique human-readable name (v1, usually UPN)",
    "upn": "User principal name (UPN)",
    "uti": "Token identifier claim — internal, opaque",
    "ver": "Token version (1.0 or 2.0)",
    "verified_primary_email": "Verified primary email from the user's profile",
    "verified_secondary_email": "Verified secondary email from the user's profile",
    "vnet": "VNET information for the token request",
    "wids": "Tenant-wide Entra ID built-in roles assigned to the user",
    "xms_cc": "Client capabilities (e.g. ['cp1'] for CAE support)",
    "xms_edov": "Indicates whether the email owner has been verified",
    "xms_pdl": "Preferred data location",
    "xms_pl": "Preferred language of the user",
    "xms_tpl": "Target preferred language",
    "xms_st": "Security token extra fields",
    "xms_tcdt": "Tenant creation date",
    "xms_rd": "Relay domain for federated auth",
    "xms_idrel": "Identity relationship type",
    "ctry": "User's country/region",
    "deviceid": "Device ID of the authenticating device",
    "fwd": "Forwarded IP (original client IP when going through a proxy)",
}

# Merge into one lookup for convenience
ALL_CLAIMS: dict[str, str] = {**STANDARD_CLAIMS, **AZURE_CLAIMS}


def describe_claim(claim_name: str) -> str:
    """Return a human-readable description for a claim, or a fallback."""
    return ALL_CLAIMS.get(claim_name, "Custom or undocumented claim")

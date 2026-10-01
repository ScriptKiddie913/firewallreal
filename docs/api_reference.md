# SentinelFW Management REST API Reference (v1)

SentinelFW exposes a versioned, secure REST API under `/api/v1/` powered by Python stdlib `http.server`.

## 1. Authentication & Security Headers

All management endpoints require authentication via Bearer tokens or authenticated browser session cookies with CSRF validation:

- **Bearer Token:** Pass header `Authorization: Bearer <token>` or `X-API-Key: <token>`.
- **Session Cookie:** Handled automatically by browser upon login at `/login`. State-changing methods (`POST`, `PUT`, `DELETE`) require `X-CSRF-Token` matching the session cookie.
- **Rate Limiting:** IP sliding-window limiter enforces a ceiling of 240 requests/minute per client IP (HTTP 429 on breach).
- **Mandatory Security Headers:**
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Content-Security-Policy: default-src 'self' ...`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`

---

## 2. Interactive OpenAPI & Documentation

- **OpenAPI 3.0 Specification:** `GET /api/v1/openapi.json`
- **Interactive Swagger Console:** `GET /api/v1/docs`

---

## 3. Core Resource Endpoints

### Policies
- `GET /api/v1/policies` — Lists all active firewall policies and rule hit counts.
- `POST /api/v1/policies` — Appends or updates a security policy rule.
- `PUT /api/v1/policies/{id}` — Updates an existing policy by numeric ID.
- `DELETE /api/v1/policies/{id}` — Deletes a policy by ID.
- `GET /api/v1/policies/shadowed` — Analyzes and returns rules shadowed by earlier rules.

### Threat Response & Bans
- `GET /api/v1/bans` — Returns all active temporary and permanent IP bans.
- `POST /api/v1/bans` — Manually bans an IP address (`ip`, `reason`, `duration`).
- `DELETE /api/v1/bans/{ip}` — Unbans an IP address.

### Zero Trust & Posture
- `POST /api/v1/ztna/evaluate` — Evaluates client posture against target application policy.

### Virtual Domains (Multi-Tenancy)
- `GET /api/v1/vdoms` — Lists configured VDOMs, allocated interfaces, and quota usage.
- `POST /api/v1/vdoms` — Creates a new isolated tenant VDOM.

### Forensics & Analytics
- `GET /api/v1/forensics/incident_bundle?target={ip}` — Generates a forensic incident package.
- `GET /metrics` — Prometheus metrics export.

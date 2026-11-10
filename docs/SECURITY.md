# Core security boundaries

The core links accounts for a principal authenticated by its host application. It does not establish that principal from a browser claim, merge primary logins, or make linked networks accept Passport login. Use an immutable host account ID. Provider handles, Matrix IDs and ActivityPub actor URLs belong in separate connection records.

## Provider credentials

The backend sees temporary OAuth credentials while checking ownership. Pending OAuth/PKCE/DPoP state and Mastodon client credentials are encrypted at rest using a host-side key. That is not an end-to-end encrypted vault. The current Matrix and OAuth adapters terminate/revoke temporary sessions after checks. A future profile-writing feature needs separate write consent and a different token lifecycle.

Flow state is tied to the authenticated principal, expected provider/account and an HttpOnly browser cookie. It expires and is consumed once. ActivityPub profile challenges are tied to the principal, account and discovered actor. WebFinger discovery alone is not ownership proof.

The outbound connector validates HTTPS and the actual DNS addresses used by sockets, denies private/reserved networks, limits response sizes/time, rechecks redirects and refuses credential-bearing POST redirects. A reverse proxy and egress policy should provide additional operational controls. Do not expose PostgreSQL or the encryption key to client code.

## Standards and future adapters

Matrix account data is not inherently end-to-end encrypted. Storing ciphertext there requires an explicit client-side key, recovery and device model. A private room alone does not solve secret custody.

A local Matrix session cannot mint a MiAuth token for an independent server. MiAuth and IndieAuth need their own consent and validation adapters. Nostr should use public-key proofs and approved NIP-07/NIP-46 signing; do not derive signing keys from Matrix IDs or collect `nsec` values.

A third-party Sign in with Leeloo flow needs a maintained OIDC provider, registered relying parties and conformance checks. An ownership stamp, popup lifecycle or JSON object from an embedding page is not an authentication assertion. Do not invent an unreviewed DID method or OAuth replacement as a shortcut.

## Operations and tenant model

Require explicit HTTPS configuration and exact embedding origins. The plugin denies cross-origin mutations and does not enable cross-origin account APIs by default. Cookie/session configuration, rate limits, log filtering, TLS and backup policies belong to the host. Use the example's query-stripping logger as a starting point, not a complete production policy.

Keep each installation in its own process and database. Configuration, OAuth clients, signing-key cache and stores are process-scoped. This implementation is not a multi-tenant sandbox.

The ActivityPub actor is an ownership-checking service actor. Its empty collection endpoints and non-accepting inbox do not implement a social-network server, posting bridge or universal inbox.

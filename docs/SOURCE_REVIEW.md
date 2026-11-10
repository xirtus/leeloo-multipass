# Core source review

The reusable core adapts original account-linking code owned by Andreas Xirtus into a standalone Fastify/PostgreSQL package. It has no game/player/score/inventory database dependencies, production account data, server credentials, private deployment paths or mandatory hosted endpoint.

Runtime configuration is supplied by `MULTIPASS_PUBLIC_URL`, `MULTIPASS_STORAGE_KEY`, `MULTIPASS_DATABASE_URL` and optional embedding/login settings, or equivalent plugin options. There are no fallback branded hosts or personal account handles. Public network URLs in the directory are outbound discovery/login references rather than required application infrastructure.

Core source is MIT-licensed, with original authorship retained. Bundled Geist and brand-symbol assets retain their own license/provenance notices in the UI directory; they are not relicensed as MIT. The dependency manifest and lockfile identify the maintained third-party libraries. No provider library internals are copied into this source.

Before publication, run tests/build/check/package-preview; inspect the generated artifact list; scan for secret material and private/user-specific defaults; verify that examples deny unauthenticated access. Real PostgreSQL tests must use a dedicated temporary database. A successful scan and test run do not certify a future IdP, signer or encrypted vault.

Validation on 10 November 2026: 10 boundary/configuration tests and 7 real PostgreSQL tests passed against a dedicated temporary database. The TypeScript/static-UI build, JavaScript syntax check and npm package preview passed. The temporary database and private test environment file were removed afterward. The package preview contained 53 files, including retained asset licenses; no npm publication was performed.

# Leeloo Multipass
<img width="1600" height="1200" alt="image" src="https://github.com/user-attachments/assets/3517c569-3890-4f07-9308-c803466cac6d" />

<img width="722" height="574" alt="image" src="https://github.com/user-attachments/assets/da847cb9-73b7-4c5f-800d-7c297faa5577" />

A reusable account-linking Passport core for Fastify and PostgreSQL. It provides a stamp-book UI, saved external identities, provider ownership checks, encrypted short-lived authorization state, and signed ActivityPub profile retrieval. It is independent of any game database and has no required hosted service.

The browser launcher lives in the separate `leeloo-multipass-sdk` project. This core does not issue third-party sign-in assertions or implement a new identity provider. The package is `private` to prevent accidental npm publication while the initial public source release is reviewed.

## Interface

The dark-paper stamp book uses Geist, a navy cover, and pastel network symbols. Solid stamps show verified ownership; dashed stamps show saved addresses.

![Leeloo Multipass desktop stamp book](docs/images/passport-desktop.png)

<details>
<summary>Mobile passport preview</summary>

<img src="docs/images/passport-mobile.png" width="390" alt="Leeloo Multipass mobile stamp book with pastel network stamps on dark paper" />

</details>

Screenshots use fictional demonstration accounts and verification states; they do not assert ownership of real profiles.

## What works

- Bluesky / AT Protocol identity-only OAuth with a maintained Node OAuth client, PKCE and DPoP; DID ownership is checked against the expected account.
- Mastodon-compatible instance OAuth with `read:accounts`; local account ID and address are checked.
- Matrix browser SSO on homeservers that expose it; the returned Matrix ID is checked and the temporary device session is logged out.
- Threads and ActivityPub public-profile proof through WebFinger, signed actor retrieval and a one-time code placed in the public bio.
- Saved HTTPS profile references, visibly distinct from verified ownership.
- Principal-isolated storage, expiring single-use flow state, encrypted pending credentials, and unique verified-subject binding.

Native MiAuth, IndieAuth, Nostr signer proofs, profile sync, a client-encrypted vault and third-party IdP login are future adapters/components. Directory entries identify networks and available profile-reference/proof paths; they do not turn every network into an implemented native login.

## Requirements

Node.js 22 or later, PostgreSQL, Fastify 5, and `@fastify/cookie` 11. Provider callbacks need a public HTTPS origin. Register your host application's real authentication/session system before using private Passport operations.

```sh
npm ci --ignore-scripts
npm run build
```

Configure one installation using host-side environment variables or equivalent plugin options:

| Variable | Purpose |
| --- | --- |
| `MULTIPASS_PUBLIC_URL` | Required HTTPS origin, such as `https://passport.example`; no embedded path or credentials |
| `MULTIPASS_STORAGE_KEY` | Required high-entropy host-side secret of at least 32 characters; generate once and keep outside source |
| `MULTIPASS_DATABASE_URL` | Required PostgreSQL connection string for a dedicated Multipass database |
| `MULTIPASS_EMBED_ORIGINS` | Optional comma-separated exact HTTPS origins allowed to frame the UI; default is same-origin only |
| `MULTIPASS_SIGN_IN_URL` | Host application's login URL; defaults to `/login` on the configured public origin |

For example, generate the storage secret on the host with `openssl rand -hex 32`. Do not commit its output. Preserve that key and the database across deployments: changing the key without a migration makes existing encrypted state and the ActivityPub signing key unreadable.

```sh
npm run migrate
```

The migration creates only `passport_principals`, network/state/audit tables and its own migration history. Host account IDs are opaque text; there are no player, game, score, inventory or wallet dependencies.

## Register with a host application

```js
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import { registerPassportRoutes } from 'leeloo-multipass';

const app = Fastify();
app.register(cookie);
app.register(registerPassportRoutes, {
  authenticate: async request => {
    const session = await yourHostSessionService.verifyRequest(request);
    return session ? { principalId: session.immutableAccountId } : null;
  },
});
await app.listen({ host: '127.0.0.1', port: 8788 });
```

`yourHostSessionService` is the host's existing, verified session implementation. It is intentionally not supplied by this package. Never implement this adapter by trusting a user ID, Matrix ID or profile supplied in a request header/body. The [example host](examples/host.mjs) denies all private operations until the adapter is replaced; it does not invent a login session.

Open `/v1/networks/ui`. The current browser SDK's default connection path is compatible with this API. External authorization should run in a top-level trusted Passport tab rather than inside an untrusted game/application frame.

## Host responsibilities

Use an explicit trusted reverse proxy/TLS configuration. Register cookie parsing first, configure real session validation, rate limits, request-size limits and database permissions. Strip callback query parameters and cookies/authorization headers from request logs. Do not enable wildcard credentialed CORS. The plugin itself accepts mutations only from its configured public origin.

The current implementation is one installation/database per process. It rejects conflicting configuration in the same process. Use separate processes/databases for tenants; do not advertise the module's shared configuration as tenant isolation.

The plugin should be registered with `app.register()` so its error handler remains encapsulated. It returns generic provider failures without serializing tokens or request details. Other routes in your host application remain under the host's own error/session policies.

## Tests and release checks

```sh
npm test
npm run build
npm run check
npm pack --dry-run
```

Unit tests run without a database. Optional real PostgreSQL tests must target a fresh, isolated database:

```sh
MULTIPASS_RUN_DATABASE_TESTS=1 npm test
```

Those tests exercise the schema, idempotent migrations, server-authenticated principal registration, cross-principal isolation, unique verified ownership, handle changes, state encryption/expiry/consumption and persisted actor keys. Never point them at an application database.

Read [security boundaries](docs/SECURITY.md) and [source review](docs/SOURCE_REVIEW.md) before hosting or extending the core.

## Related projects

[Leeloo Multipass core](https://github.com/xirtus/leeloo-multipass) · [Leeloo Multipass SDK](https://github.com/xirtus/leeloo-multipass-sdk) · [Contribution workflow](CONTRIBUTING.md). New work targets `unstable`.

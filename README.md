# @koamishin/auth-js

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/@koamishin/auth-js.svg?style=flat-square)](https://www.npmjs.com/package/@koamishin/auth-js)

Official browser JavaScript and TypeScript SDK for **Koamishin Portal**, using OAuth 2.0 authorization codes and PKCE. The Portal currently does not issue OIDC ID tokens; do not assume OIDC conformance.

---

## Features

- **Publishable Keys**: Environment-aware `pk_test_...` and `pk_live_...` keys with automatic environment validation and secret-key guardrails (plus backward compatibility with legacy OAuth `clientId`s).
- **Standard PKCE**: High-security authorization code flow using standard Web Crypto API.
- **Browser client**: Zero external runtime dependencies; compatible with browser code in React, Vue, Next.js, Nuxt, SvelteKit, and vanilla JS.
- **Silent Refresh**: Built-in `refreshToken()` support to renew expired sessions.
- **Session Tokens**: `getSessionToken()` mints sixty-second JWTs your backends verify offline against the JWKS document (`verifySessionToken()`), instead of calling userinfo per request.
- **Next.js App Router & Proxy Support**: `@koamishin/auth-js/nextjs` and `@koamishin/auth-js/nextjs/server` provide Clerk-style `<KoamishinProvider>`, `<Show>`, `<SignInButton>`, `<SignUpButton>`, `<UserButton>`, `<AuthenticateWithRedirectCallback />`, `koamishinMiddleware()`, `createRouteMatcher()`, and server `auth()`.
- **Role & Tenant Aware**: Access Spatie roles, permissions, organization/application context, and public metadata inside frontend components.

---

## Installation

```bash
npm install @koamishin/auth-js
```

---

## Quickstart

### 1. Initialize Client

Create a shared authentication client file (e.g., `src/auth.ts`) using your environment's **Publishable Key** (`pk_test_...` for development or `pk_live_...` for production):

```typescript
import { createKoamishinClient } from '@koamishin/auth-js';

export const koamishin = createKoamishinClient({
  portalUrl: 'https://auth.company.internal',
  publishableKey:
    import.meta.env.VITE_KOAMISHIN_PUBLISHABLE_KEY ??
    'pk_test_your_publishable_key', // or process.env.NEXT_PUBLIC_KOAMISHIN_PUBLISHABLE_KEY
  redirectUri: 'https://crm.company.internal/auth/callback',
  scopes: ['openid', 'profile', 'email', 'roles', 'metadata:public'],
});
```

Request `metadata:public` explicitly if your application needs public metadata; it is not included in the default scopes.

> **Legacy OAuth clients:** `clientId` remains supported in place of `publishableKey` for existing Passport client configurations.
>
> **Never use Secret Keys (`sk_test_...` / `sk_live_...`) in browser code.** Secret keys grant server-to-server privileges and must stay on trusted backends. `createKoamishinClient` throws immediately if an `sk_...` key is supplied.

---

### 2. Sign In Button

Call `redirectToSignIn()` to send the user to your centralized Koamishin Portal:

```typescript
import { koamishin } from './auth';

// Triggers PKCE challenge and redirects browser to Koamishin Portal
async function handleLogin() {
  await koamishin.redirectToSignIn();
}

async function handleRegistration() {
  await koamishin.redirectToSignUp();
}
```

The Portal displays the requesting application's configured login or registration page and returns to its registered callback. Pending OAuth transactions are scoped to the Portal and client and expire after ten minutes. SSO is disabled by default and can be enabled for opted-in applications in the Portal.

The client uses `window`, `sessionStorage`, and Web Crypto and must run in the browser, not during server-side rendering. Tokens are accessible to browser JavaScript; use a public OAuth client and assess your application's browser-storage risks.

---

### 3. Handle Callback (`/auth/callback`)

When the portal redirects the user back, call `handleRedirectCallback()` to exchange the authorization code for tokens and user claims:

```typescript
import { koamishin } from './auth';

async function onPageLoad() {
  try {
    const { user, tokens } = await koamishin.handleRedirectCallback();

    console.log('Signed in as:', user.name, user.email);
    console.log('Roles:', user.roles);

    // Redirect to app dashboard
    window.location.href = '/dashboard';
  } catch (error) {
    console.error('Authentication failed:', error);
  }
}

onPageLoad();
```

---

### 4. Fetch User Information

```typescript
import { koamishin } from './auth';

const user = await koamishin.getUser();
console.log('User ID:', user.sub);
console.log('Environment:', user.environment);
console.log('Roles:', user.roles);
console.log('Permissions:', user.permissions);
console.log('Public metadata:', user.public_metadata);
```

---

### 5. Refresh Token & Logout

```typescript
import { koamishin } from './auth';

// Renew expired access token silently
const newTokens = await koamishin.refreshToken();

// Local cleanup is immediate; await the remote result before navigating.
const result = await koamishin.signOut();
if (result.status === 'revoked') {
    window.location.href = '/';
} else {
    // Show result.message for "failed", or ask the user to reauthenticate
    // for "reauthentication_required".
}
```

### 6. Session Tokens

A session token is a short-lived JWT (60 seconds) your application's backends verify **offline** against the portal's JWKS document — no userinfo call per request:

```typescript
import {
  decodeSessionToken,
  verifySessionToken,
} from '@koamishin/auth-js';

const sessionToken = await koamishin.getSessionToken();

// Verify cryptographically on your server or edge runtime against /oauth/jwks:
const verifiedClaims = await verifySessionToken(sessionToken, {
  portalUrl: process.env.NEXT_PUBLIC_KOAMISHIN_PORTAL_URL!,
  publishableKey: process.env.NEXT_PUBLIC_KOAMISHIN_PUBLISHABLE_KEY!,
  applicationId: process.env.KOAMISHIN_APPLICATION_ID!,
});
console.log(verifiedClaims.sub, verifiedClaims.sid, verifiedClaims.sts);

// Browser-side decode is unverified — display and routing only:
const claims = decodeSessionToken(sessionToken);
console.log(claims.sub, claims.sid, claims.sts);
```

Configure `applicationId` to enforce cross-application isolation. A publishable key infers an expected environment, but does not bind the token to an application or OAuth client; `azp` is not a client ID and is not used for client binding. When an application ID or explicit/inferred environment is configured, verification requires the corresponding claim to be a nonempty matching string. Current Portal application tokens issue `application_id` as a string; older or third-party tokens with a numeric ID are rejected when that restriction is configured. Portal-level browser-session tokens and older tokens that omit these claims also fail such checks; obtain a compatible application session token. Without an `applicationId`, a valid token from another application at the same Portal and environment is not excluded by this check.

**Breaking major-version migration:** Next.js server `auth()` and middleware now require a nonblank Portal URL, public client identifier, application ID and explicit or publishable-key-inferred environment. Missing or conflicting browser/server identity configuration throws an actionable error even on unauthenticated requests; configure each verifier before upgrading. Both independently verify the selected credential and never trust `x-koamishin-*` request headers. An explicit Authorization header takes precedence over the cookie; an invalid, empty, or unsupported header fails authentication without cookie fallback. Generic `verifySessionToken()` still supports unrestricted Portal-level tokens when no application or environment restriction is configured.

Callback completion reports an error if the server session cookie cannot be minted or written, rather than reporting successful sign-in. OAuth credentials can still remain in browser storage after this failure; on reload, the provider may recover the user but exposes an error while server-session minting remains unavailable. Applications using custom UI must surface that error and should not treat browser sign-in alone as proof that server authentication is ready.

For server `auth()` and middleware, application ID and environment resolve independently from the call's nonblank option, the matching `NEXT_PUBLIC_KOAMISHIN_*` variable, and the server-only `KOAMISHIN_*` variable. Blank values are skipped, but conflicting nonblank values are configuration errors rather than overrides. Conflicting client ID/publishable key values or an explicit environment inconsistent with the publishable key also fail. Middleware options are not inherited by a later `auth()` call; use consistent shared environment configuration or pass the same options explicitly.

---

## Next.js App Router Quickstart (Clerk-Style)

### 1. Configure `.env.local`

```dotenv
NEXT_PUBLIC_KOAMISHIN_PORTAL_URL=https://auth.company.internal
NEXT_PUBLIC_KOAMISHIN_ENVIRONMENT=development
NEXT_PUBLIC_KOAMISHIN_PUBLISHABLE_KEY=pk_test_your_publishable_key
NEXT_PUBLIC_KOAMISHIN_REDIRECT_URI=http://localhost:3000/auth/callback
KOAMISHIN_APPLICATION_ID=your_application_id
```

Add `transpilePackages: ['@koamishin/auth-js']` to `next.config.ts` when consuming TypeScript sources directly.

### 2. Add `koamishinMiddleware()` to `proxy.ts` (or `middleware.ts` on Next.js <=15)

```typescript
import {
  koamishinMiddleware,
  createRouteMatcher,
} from '@koamishin/auth-js/nextjs/server';

const isProtectedRoute = createRouteMatcher(['/dashboard(.*)']);

export default koamishinMiddleware(async (auth, req) => {
  if (isProtectedRoute(req)) {
    await auth.protect();
  }
});

export const config = {
  matcher: [
    '/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)',
    '/(api|trpc)(.*)',
  ],
};
```

### 3. Add `<KoamishinProvider>` and Auth Components to `app/layout.tsx`

```tsx
import {
  KoamishinProvider,
  Show,
  SignInButton,
  SignUpButton,
  UserButton,
} from '@koamishin/auth-js/nextjs';
import { Suspense } from 'react';
import './globals.css';

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col">
        <KoamishinProvider>
          <header className="flex justify-end items-center p-4 gap-4 h-16">
            <Suspense>
              <Show when="signed-out">
                <SignInButton />
                <SignUpButton>
                  <button className="bg-purple-700 text-white rounded-full font-medium text-sm sm:text-base h-10 sm:h-12 px-4 sm:px-5 cursor-pointer">
                    Sign Up
                  </button>
                </SignUpButton>
              </Show>
              <UserButton />
            </Suspense>
          </header>
          {children}
        </KoamishinProvider>
      </body>
    </html>
  );
}
```

### 4. Add Callback Route (`app/auth/callback/page.tsx`)

```tsx
import { Suspense } from 'react';
import { AuthenticateWithRedirectCallback } from '@koamishin/auth-js/nextjs';

export default function CallbackPage() {
  return (
    <Suspense>
      <AuthenticateWithRedirectCallback afterSignInUrl="/dashboard" />
    </Suspense>
  );
}
```

### 5. Read Verified Claims in Server & Client Components

```tsx
import { auth } from '@koamishin/auth-js/nextjs/server';

export default async function DashboardPage() {
  const { userId, sessionId, sessionClaims } = await auth();
  return <pre>{JSON.stringify({ userId, sessionId, sessionClaims }, null, 2)}</pre>;
}
```

---

## API Reference

### `KoamishinConfig`

| Option | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `portalUrl` | `string` | Yes | Base URL of your Koamishin Portal instance. |
| `publishableKey` | `string` | Yes (or `clientId`) | Environment publishable key (`pk_test_...` or `pk_live_...`, e.g. `VITE_KOAMISHIN_PUBLISHABLE_KEY` / `NEXT_PUBLIC_KOAMISHIN_PUBLISHABLE_KEY`). Never pass an `sk_...` secret key. |
| `clientId` | `string` | Legacy fallback | Legacy OAuth 2.0 public client UUID when not using a publishable key. |
| `redirectUri` | `string` | Yes | Exact callback URL registered for the application environment. |
| `scopes` | `string[]` | No | Requested OAuth scopes (defaults to `['openid', 'profile', 'email', 'roles']`). |
| `onTransition` | `(event: AuthTransitionEvent) => void \| Promise<void>` | No | Optional listener invoked on authentication lifecycle events. |

### `KoamishinClient`

| Method | Returns | Description |
| :--- | :--- | :--- |
| `getEnvironment()` | `'development' \| 'production' \| null` | Returns `'development'` for `pk_test_...`, `'production'` for `pk_live_...`, or `null` for legacy `clientId`s. |
| `redirectToSignIn()` | `Promise<void>` | Generates PKCE code challenge and redirects browser to portal. |
| `redirectToSignUp()` | `Promise<void>` | Starts the same flow on the application's hosted registration page. |
| `handleRedirectCallback()` | `Promise<{ user, tokens }>` | Exchanges one-time code for access & refresh tokens, returns user claims. |
| `getUser(token?, cache?)` | `Promise<KoamishinUser>` | Fetches user claims from `/api/oauth/userinfo` and verifies `environment` matches any configured key. By default it caches the user and requires an explicit token to match an existing stored session; use `getUser(token, false)` to inspect a token without replacing cached identity. |
| `refreshToken(token?)` | `Promise<TokenResponse>` | Exchanges refresh token for new access token. |
| `getSessionToken(token?)` | `Promise<SessionToken>` | Mints a short-lived session token (`POST /api/oauth/session-token`) for offline verification by your backends. |
| `syncSessionCookie(token?)` | `Promise<SessionToken>` | Mints a fresh 60-second session token and writes the client-scoped cookie for SSR/proxy verification. Requires a stored session and, if supplied, a matching access token. |
| `getStoredAccessToken()` | `string \| null` | Returns the stored OAuth access token for this client, or `null` when signed out. |
| `getStoredUser()` | `KoamishinUser \| null` | Returns the cached user profile from `sessionStorage`, or `null` when unavailable. |
| `signOut()` | `Promise<SignOutResult>` | Immediately clears local session state, then reports `revoked`, `failed`, or `reauthentication_required`. Await it before navigating. |
| `onTransition(listener)` | `() => void` | Subscribes a listener to authentication lifecycle transitions (`token_exchange`, `token_refresh`, `refresh_failure`, `sign_out`, `session_invalidated`, `generation_change`). Returns an unsubscribe function. |

The package also exports:
- `verifySessionToken(sessionToken, options)` → `Promise<SessionTokenClaims>`: cryptographically verifies an RS256 session token against the Portal's `/oauth/jwks` endpoint and checks `iss`, `exp`, `nbf`, `environment`, and optional `applicationId`.
- `decodeSessionToken(sessionToken)` → `SessionTokenClaims`: decodes a session token's claims **without** verifying the signature. Use it for display and routing only; a backend must verify the token against the JWKS document before trusting any claim.

Browser storage is scoped by Portal URL and publishable key (or legacy client ID), keeping `pk_test_...` and `pk_live_...` sessions isolated on the same origin. This changes earlier unscoped storage keys, so users of earlier versions must sign in again. Remove the old `koamishin_access_token` and `koamishin_refresh_token` keys during migration if present.

An initial OAuth token response may include an opaque `revocation_token`. The SDK stores it in sessionStorage and preserves it when refresh responses omit it. Treat it as a secret: do not log it or put it in a URL. Sign-out clears the local access token, refresh token, revocation credential, user, pending OAuth transactions and session cookie immediately, then posts JSON `{ "revocation_token": "..." }` to Portal's `/api/oauth/revoke-family` without following redirects. Only HTTP 204 confirms revocation of that token family; other responses and network errors return `failed` without exposing server response bodies. Local cleanup also happens on failure, so the SDK cannot retry with that credential. `reauthentication_required` means there was no credential (including legacy sessions); remote revocation is not confirmed. Reauthentication can provide a credential for a new family, but cannot retroactively confirm revocation of an old legacy family. This does not sign out other token families or the Portal browser session.

Replacing a session via a new callback first attempts to revoke the stored family when its credential is available. If revocation is not confirmed, the replacement is rejected and the SDK attempts to revoke the newly issued family; the existing local session remains. While a session is stored, `refreshToken(explicitToken)` rejects an explicit token different from the stored refresh token: token strings alone cannot establish whether they belong to different families. Use the stored token or reauthenticate. With no existing session, an explicit refresh token remains supported.

If sign-out occurs while any OAuth callback or refresh is in flight, the result is `failed` (unconfirmed), even if Portal confirms revocation of an older family. Its response cannot restore the local session. If a stale refresh returns a revocation credential after sign-out, the SDK attempts to revoke it only when no newer session is active; otherwise it leaves the newer session untouched and reports uncertainty. A missing credential, network error, or lost exchange response can still leave a family active remotely. In-memory race guards apply within one JavaScript realm only; tabs, page unloads, and other processes are not coordinated, and already-issued or copied credentials can race independently.

On provider hydration, only an HTTP 401 from userinfo triggers a refresh. A network failure, 5xx or other unconfirmed error preserves the stored session and reports a retryable error instead of revoking the family. Only an OAuth `invalid_grant` response is classified as a definite invalid refresh grant; the UI requests reauthentication without automatically revoking the family. In that case, the SDK clears the matching unusable access/refresh tokens, cached user and cookie, but retains any revocation credential for explicit sign-out. A changed session is not cleared. A refresh whose outcome is ambiguous records uncertainty, so a later successful family revocation cannot falsely confirm the earlier outcome.

The SDK retains a non-secret uncertainty marker in sessionStorage after an unconfirmed family outcome, including sign-out during an exchange. Later 204 responses do not erase that uncertainty or produce `revoked` for the overall sign-out. The marker is deliberately conservative and lasts for the browser storage session, even if later cleanup may have succeeded. Clearing browser storage removes the marker but does not revoke any family; use Portal's administrative controls to address an unknown family.

The Next.js provider's `signOut` returns the same result and redirects only after confirmed revocation. Its `error` exposes an unconfirmed sign-out; `UserButton` displays it. Keep `UserButton` mounted outside `Show when="signed-in"` so its error remains visible after local sign-out. Applications using custom UI must handle the result or `error` themselves. Return destinations must be same-origin absolute paths such as `/dashboard`; external and protocol-relative URLs are rejected. This is an asynchronous API change: callers must await it if they need remote confirmation.

Revocation cannot invalidate already-issued session JWTs for an offline verifier: they may remain valid until expiry (and configured clock skew). Applications needing immediate denial must use an online revocation check or another server-side session mechanism.

The browser checks the minted JWT's structure, algorithm, issuer and basic session claims before writing its cookie; that check does not verify the signature or prove the server will accept it. The pre-cookie check requires a nonempty subject and session ID, valid time claims, and an issued lifetime of at most 65 seconds (allowing five seconds for clock skew); it caps cookie lifetime at 60 seconds and the JWT's remaining lifetime. Issuers producing longer-lived session JWTs are incompatible with this cookie flow. Server verification remains mandatory. A JWT with a `kid` requires an exact JWKS key ID match; older JWKS documents with only kid-less keys will not verify such tokens. Fetched JWKS RSA signing keys must be importable, at least 2048 bits, and have unique IDs. For unknown signing key IDs, concurrent JWKS fetches are coalesced and forced refresh attempts are limited to one per Portal per JavaScript process every 30 seconds. An actual key rotation may therefore be rejected temporarily after a recent unknown-key refresh; retry after the interval. Deployments should publish new keys before using them, use a new `kid` for every key, and retain appropriate old keys during rotation. Reusing a `kid` can leave the old key cached for up to five minutes.

Session cookies are namespaced by canonical Portal origin/base path and public client identifier, using `getSessionCookieName(portalUrl, publishableKeyOrClientId)`. The browser and each server verifier must use the same Portal URL and identifier; the server rejects missing identifiers and conflicting public/server environment configuration. Explicit provider props cannot be compared automatically with server-only configuration: if they differ, SSR reads a different cookie and treats the browser as signed out.

This namespace relies on a public client identifier mapping to exactly one application/environment within a Portal. The current Portal rejects ambiguous legacy OAuth client IDs, duplicate publishable keys, and OAuth client IDs mapped to multiple environments. Older or third-party issuers must enforce the same uniqueness; reusing or rebinding an identifier for a different application/environment can cause cookie collisions and requires a coordinated migration. Server verifiers must still enforce their configured application ID and environment independently. The cookie name contains reversible encoded configuration: use only public client identifiers, and never put credentials in the Portal URL path or identifier. Secret-key prefixes and URLs containing userinfo, query strings or fragments are rejected.

The cookie namespace is storage isolation, not cryptographic OAuth-client binding. Server verification enforces application and environment claims, but an otherwise valid token issued to another OAuth client in the same application/environment may still be accepted as a bearer token or if supplied in that namespace. `azp` is not treated as a client ID. Stronger client isolation requires a separately coordinated issuer-signed audience or client-identifier contract.

The old unscoped `__koamishin_session` cookie is never trusted or migrated by the new verifier. A browser with only that legacy cookie must sign in again; a browser retaining valid scoped OAuth credentials may instead mint the new cookie during hydration. The SDK does not delete the legacy cookie automatically. Portal URLs are canonicalized for storage and cookie naming; sessions previously stored under noncanonical spellings may need to sign in again. JWT issuer comparison remains exact against the canonical configured Portal URL, including its base path. This is a coordinated breaking change: deploy the updated browser SDK and server verifier together. `SESSION_COOKIE_NAME` is retained only as the legacy name; use `getSessionCookieName()` for the active name.

Cookies use the browser-enforced `__Host-` prefix with `Path=/; Secure; SameSite=Lax`, preventing sibling subdomains from setting a competing domain cookie. HTTPS is required except on browser-supported loopback development hosts; insecure non-loopback origins fail explicitly. They are written by JavaScript and therefore are **not HttpOnly**; XSS can read or use them. Different client namespaces do not overwrite or clear each other's cookies, but tabs signed into different accounts under the **same client identifier** still share that client's cookie. Their browser storage is tab-scoped while the cookie is origin-shared, so one tab can overwrite or clear the other's server identity. Namespacing does not provide same-client per-tab isolation or cross-tab coordination.

Portal URLs themselves also require HTTPS except for `localhost` (including a trailing dot), IPv4 loopback addresses in `127.0.0.0/8`, and IPv6 `::1`. Hostnames merely containing `localhost`, arbitrary `*.localhost` names, and non-loopback HTTP are rejected before credential, revocation or JWKS requests. Local `.test` sites require HTTPS with a trusted development certificate.

---

## License

MIT © [Koamishin](https://github.com/koamishin)

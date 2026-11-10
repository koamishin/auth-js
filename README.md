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

// Sign out and clear stored session tokens
koamishin.signOut();
window.location.href = '/';
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
});
console.log(verifiedClaims.sub, verifiedClaims.sid, verifiedClaims.sts);

// Browser-side decode is unverified — display and routing only:
const claims = decodeSessionToken(sessionToken);
console.log(claims.sub, claims.sid, claims.sts);
```

Backends should also check `application_id` and `environment` against their own configuration before trusting a token, since tokens are minted per application. See the Koamishin Auth session token documentation for the full claim set.

---

## Next.js App Router Quickstart (Clerk-Style)

### 1. Configure `.env.local`

```dotenv
NEXT_PUBLIC_KOAMISHIN_PORTAL_URL=https://auth.company.internal
NEXT_PUBLIC_KOAMISHIN_ENVIRONMENT=development
NEXT_PUBLIC_KOAMISHIN_PUBLISHABLE_KEY=pk_test_your_publishable_key
NEXT_PUBLIC_KOAMISHIN_REDIRECT_URI=http://localhost:3000/auth/callback
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
              <Show when="signed-in">
                <UserButton />
              </Show>
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

### `KoamishinClient`

| Method | Returns | Description |
| :--- | :--- | :--- |
| `getEnvironment()` | `'development' \| 'production' \| null` | Returns `'development'` for `pk_test_...`, `'production'` for `pk_live_...`, or `null` for legacy `clientId`s. |
| `redirectToSignIn()` | `Promise<void>` | Generates PKCE code challenge and redirects browser to portal. |
| `redirectToSignUp()` | `Promise<void>` | Starts the same flow on the application's hosted registration page. |
| `handleRedirectCallback()` | `Promise<{ user, tokens }>` | Exchanges one-time code for access & refresh tokens, returns user claims. |
| `getUser(token?)` | `Promise<KoamishinUser>` | Fetches user claims from `/api/oauth/userinfo` and verifies `environment` matches any configured `pk_test_...` / `pk_live_...` key. |
| `refreshToken(token?)` | `Promise<TokenResponse>` | Exchanges refresh token for new access token. |
| `getSessionToken(token?)` | `Promise<SessionToken>` | Mints a short-lived session token (`POST /api/oauth/session-token`) for offline verification by your backends. |
| `syncSessionCookie(token?)` | `Promise<SessionToken>` | Mints a fresh 60-second session token and writes it to the `__koamishin_session` cookie for SSR/proxy verification. |
| `getStoredAccessToken()` | `string \| null` | Returns the stored OAuth access token for this client, or `null` when signed out. |
| `getStoredUser()` | `KoamishinUser \| null` | Returns the cached user profile from `sessionStorage`, or `null` when unavailable. |
| `signOut()` | `void` | Clears stored tokens from browser session storage and expires the `__koamishin_session` cookie. |

The package also exports:
- `verifySessionToken(sessionToken, options)` → `Promise<SessionTokenClaims>`: cryptographically verifies an RS256 session token against the Portal's `/oauth/jwks` endpoint and checks `iss`, `exp`, `nbf`, `environment`, and optional `applicationId`.
- `decodeSessionToken(sessionToken)` → `SessionTokenClaims`: decodes a session token's claims **without** verifying the signature. Use it for display and routing only; a backend must verify the token against the JWKS document before trusting any claim.

Browser storage is scoped by Portal URL and publishable key (or legacy client ID), keeping `pk_test_...` and `pk_live_...` sessions isolated on the same origin. This changes earlier unscoped storage keys, so users of earlier versions must sign in again. Remove the old `koamishin_access_token` and `koamishin_refresh_token` keys during migration if present. Local sign-out does not revoke Portal tokens or end other application sessions.

---

## License

MIT © [Koamishin](https://github.com/koamishin)

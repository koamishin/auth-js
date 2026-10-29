# @koamishin/auth-js

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/@koamishin/auth-js.svg?style=flat-square)](https://www.npmjs.com/package/@koamishin/auth-js)

Official browser JavaScript and TypeScript SDK for **Koamishin Portal**, using OAuth 2.0 authorization codes and PKCE. The Portal currently does not issue OIDC ID tokens; do not assume OIDC conformance.

---

## Features

- **Standard PKCE**: High-security authorization code flow using standard Web Crypto API.
- **Browser client**: Zero external runtime dependencies; compatible with browser code in React, Vue, Next.js, Nuxt, SvelteKit, and vanilla JS.
- **Silent Refresh**: Built-in `refreshToken()` support to renew expired sessions.
- **Role Aware**: Access Spatie roles and permissions inside frontend components.

---

## Installation

```bash
npm install @koamishin/auth-js
```

---

## Quickstart

### 1. Initialize Client

Create a shared authentication client file (e.g., `src/auth.ts`):

```typescript
import { createKoamishinClient } from '@koamishin/auth-js';

export const koamishin = createKoamishinClient({
  portalUrl: 'https://auth.company.internal',
  clientId: '01a17b-client-id-here',
  redirectUri: 'https://crm.company.internal/auth/callback',
});
```

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
console.log('Roles:', user.roles);
console.log('Permissions:', user.permissions);
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

---

## API Reference

### `KoamishinClient`

| Method | Returns | Description |
| :--- | :--- | :--- |
| `redirectToSignIn()` | `Promise<void>` | Generates PKCE code challenge and redirects browser to portal. |
| `redirectToSignUp()` | `Promise<void>` | Starts the same flow on the application's hosted registration page. |
| `handleRedirectCallback()` | `Promise<{ user, tokens }>` | Exchanges one-time code for access & refresh tokens, returns user claims. |
| `getUser(token?)` | `Promise<KoamishinUser>` | Fetches user claims from `/api/oauth/userinfo`. |
| `refreshToken(token?)` | `Promise<TokenResponse>` | Exchanges refresh token for new access token. |
| `signOut()` | `void` | Clears stored tokens from browser session storage. |

Browser storage is scoped by Portal URL and client ID. This changes earlier unscoped storage keys, so users of earlier versions must sign in again. Remove the old `koamishin_access_token` and `koamishin_refresh_token` keys during migration if present. Local sign-out does not revoke Portal tokens or end other application sessions.

---

## License

MIT © [Koamishin](https://github.com/koamishin)

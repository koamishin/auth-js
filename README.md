# @koamishin/auth-js

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/@koamishin/auth-js.svg?style=flat-square)](https://www.npmjs.com/package/@koamishin/auth-js)

Official client JavaScript and TypeScript SDK for **Koamishin Portal** — a centralized, self-hostable identity management system operating like Clerk and Google Auth with OAuth2, OpenID Connect (OIDC), and PKCE.

---

## Features

- **Standard PKCE**: High-security authorization code flow using standard Web Crypto API.
- **Universal**: Zero external runtime dependencies; compatible with React, Vue, Next.js, Nuxt, SvelteKit, and vanilla JS.
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
```

---

### 3. Handle Callback (`/auth/callback`)

When the portal redirects the user back, call `handleRedirectCallback()` to exchange the authorization code for JWT tokens and user claims:

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
| `handleRedirectCallback()` | `Promise<{ user, tokens }>` | Exchanges one-time code for access & refresh tokens, returns user claims. |
| `getUser(token?)` | `Promise<KoamishinUser>` | Fetches user claims from `/api/oauth/userinfo`. |
| `refreshToken(token?)` | `Promise<TokenResponse>` | Exchanges refresh token for new access token. |
| `signOut()` | `void` | Clears stored tokens from browser session storage. |

---

## License

MIT © [Koamishin](https://github.com/koamishin)

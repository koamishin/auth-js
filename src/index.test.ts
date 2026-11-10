import { afterEach, expect, test, vi } from 'vitest';
import {
    SESSION_COOKIE_NAME,
    createKoamishinClient,
    decodeSessionToken,
    verifySessionToken,
} from './index';

const b64url = (value: string): string =>
    btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const sessionTokenJwt = (claims: Record<string, unknown>): string =>
    `${b64url('{"alg":"RS256","kid":"key-a"}')}.${b64url(
        JSON.stringify(claims),
    )}.signature`;

const sessionTokenClaims = (
    overrides: Record<string, unknown> = {},
): Record<string, unknown> => ({
    sub: 'user-1',
    iss: 'https://portal.test',
    iat: 1_700_000_000,
    nbf: 1_700_000_000,
    exp: 1_700_000_060,
    jti: 'token-1',
    sid: 'session-1',
    v: '2',
    fva: [0, -1],
    sts: 'active',
    tasks: [],
    application_id: '100',
    environment: 'production',
    ...overrides,
});

afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
});

test('application clients keep their transactions and sessions separate', async () => {
    const storage = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const location = { href: '', search: '' };
    vi.stubGlobal('window', { location });
    const fetchMock = vi.fn(async (url: string, options: RequestInit) => {
        if (url.endsWith('/oauth/token')) {
            const code = (options.body as URLSearchParams).get('code');
            return {
                ok: true,
                json: async () => ({
                    access_token: `token-${code}`,
                    expires_in: 60,
                }),
            };
        }

        const token = (options.headers as Record<string, string>).Authorization;
        return { ok: true, json: async () => ({ sub: token }) };
    });
    vi.stubGlobal('fetch', fetchMock);

    const appA = createKoamishinClient({
        portalUrl: 'https://portal.test',
        clientId: 'app-a',
        redirectUri: 'https://app.test/a/callback',
    });
    const appB = createKoamishinClient({
        portalUrl: 'https://portal.test',
        clientId: 'app-b',
        redirectUri: 'https://app.test/b/callback',
    });
    await appA.redirectToSignIn();
    const login = new URL(location.href);
    await appB.redirectToSignUp();
    const registration = new URL(location.href);

    expect(login.searchParams.has('screen_hint')).toBe(false);
    expect(login.searchParams.has('flow')).toBe(false);
    expect(registration.searchParams.has('flow')).toBe(false);
    expect(registration.searchParams.get('screen_hint')).toBe('signup');
    expect(login.searchParams.get('code_challenge_method')).toBe('S256');
    expect(registration.searchParams.get('code_challenge_method')).toBe('S256');
    expect(login.searchParams.get('state')).not.toBe(
        registration.searchParams.get('state'),
    );

    location.search = `?code=wrong&state=${registration.searchParams.get('state')}`;
    await expect(appA.handleRedirectCallback()).rejects.toThrow(
        'OAuth state mismatch',
    );
    expect(fetchMock).not.toHaveBeenCalled();

    location.search = `?code=a&state=${login.searchParams.get('state')}`;
    await appA.handleRedirectCallback();
    location.search = `?code=b&state=${registration.searchParams.get('state')}`;
    await appB.handleRedirectCallback();

    expect((await appA.getUser()).sub).toBe('Bearer token-a');
    expect((await appB.getUser()).sub).toBe('Bearer token-b');
    await appA.redirectToSignIn();
    const pendingState = new URL(location.href).searchParams.get('state');
    appA.signOut();
    await expect(appA.getUser()).rejects.toThrow('No access token available');
    location.search = `?code=after-logout&state=${pendingState}`;
    await expect(appA.handleRedirectCallback()).rejects.toThrow(
        'OAuth state mismatch',
    );
    expect((await appB.getUser()).sub).toBe('Bearer token-b');
});

test('a client keeps parallel login and registration transactions separate', async () => {
    const storage = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const location = { href: '', search: '' };
    vi.stubGlobal('window', { location });
    const fetchMock = vi.fn(async (url: string, options: RequestInit) => {
        if (url.endsWith('/oauth/token')) {
            return {
                ok: true,
                json: async () => ({
                    access_token: (options.body as URLSearchParams).get('code'),
                    expires_in: 60,
                }),
            };
        }
        return {
            ok: true,
            json: async () => ({
                sub: (options.headers as Record<string, string>).Authorization,
            }),
        };
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = createKoamishinClient({
        portalUrl: 'https://portal.test',
        clientId: 'app',
        redirectUri: 'https://app.test/callback',
    });

    await client.redirectToSignIn();
    const first = new URL(location.href).searchParams.get('state');
    await client.redirectToSignUp();
    const second = new URL(location.href).searchParams.get('state');
    expect(first).not.toBe(second);

    location.search = `?code=second&state=${second}`;
    expect((await client.handleRedirectCallback()).user.sub).toBe(
        'Bearer second',
    );
    location.search = `?code=first&state=${first}`;
    expect((await client.handleRedirectCallback()).user.sub).toBe(
        'Bearer first',
    );
    await expect(client.handleRedirectCallback()).rejects.toThrow(
        'OAuth state mismatch',
    );
    expect(fetchMock).toHaveBeenCalledTimes(4);
});

test('an expired browser transaction cannot exchange a callback code', async () => {
    vi.useFakeTimers();
    const storage = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const location = { href: '', search: '' };
    vi.stubGlobal('window', { location });
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const client = createKoamishinClient({
        portalUrl: 'https://portal.test',
        clientId: 'app',
        redirectUri: 'https://app.test/callback',
    });

    await client.redirectToSignIn();
    const state = new URL(location.href).searchParams.get('state');
    vi.advanceTimersByTime(600_001);
    location.search = `?code=expired&state=${state}`;
    await expect(client.handleRedirectCallback()).rejects.toThrow(
        'OAuth state mismatch',
    );
    expect(fetchMock).not.toHaveBeenCalled();
});

test('publishable keys drive PKCE auth, token exchange, refresh, environment detection, and isolated session storage', async () => {
    const storage = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const location = { href: '', search: '' };
    vi.stubGlobal('window', { location });

    const fetchMock = vi.fn(async (url: string, options: RequestInit) => {
        if (url.endsWith('/oauth/token')) {
            const body = options.body as URLSearchParams;
            const grantType = body.get('grant_type');
            const clientId = body.get('client_id');

            if (grantType === 'authorization_code') {
                const code = body.get('code');
                return {
                    ok: true,
                    json: async () => ({
                        token_type: 'Bearer',
                        expires_in: 300,
                        access_token: `access-${clientId}-${code}`,
                        refresh_token: `refresh-${clientId}-${code}`,
                    }),
                };
            }

            if (grantType === 'refresh_token') {
                const refresh = body.get('refresh_token');
                return {
                    ok: true,
                    json: async () => ({
                        token_type: 'Bearer',
                        expires_in: 300,
                        access_token: `renewed-${clientId}-${refresh}`,
                        refresh_token: `next-${refresh}`,
                    }),
                };
            }
        }

        const authHeader = (options.headers as Record<string, string>)
            .Authorization;
        const isLive = authHeader.includes('pk_live_');
        return {
            ok: true,
            json: async () => ({
                sub: authHeader,
                name: 'Jane Doe',
                email: 'jane@example.test',
                email_verified: true,
                roles: ['member'],
                permissions: ['read:projects'],
                organization_id: 'org_123',
                application_id: 'app_456',
                environment: isLive ? 'production' : 'development',
                public_metadata: { plan: isLive ? 'pro' : 'sandbox' },
            }),
        };
    });
    vi.stubGlobal('fetch', fetchMock);

    const devClient = createKoamishinClient({
        portalUrl: 'https://portal.test/',
        publishableKey: '  pk_test_devKey123  ',
        redirectUri: 'https://app.test/auth/callback',
    });
    const prodClient = createKoamishinClient({
        portalUrl: 'https://portal.test',
        publishableKey: 'pk_live_prodKey456',
        redirectUri: 'https://app.test/auth/callback',
    });
    const legacyClient = createKoamishinClient({
        portalUrl: 'https://portal.test',
        clientId: 'legacy-client-id',
        redirectUri: 'https://app.test/auth/callback',
    });

    expect(devClient.getEnvironment()).toBe('development');
    expect(prodClient.getEnvironment()).toBe('production');
    expect(legacyClient.getEnvironment()).toBeNull();

    await devClient.redirectToSignIn();
    const devAuthorizeUrl = new URL(location.href);
    expect(devAuthorizeUrl.origin + devAuthorizeUrl.pathname).toBe(
        'https://portal.test/oauth/authorize',
    );
    expect(devAuthorizeUrl.searchParams.get('client_id')).toBe(
        'pk_test_devKey123',
    );
    expect(devAuthorizeUrl.searchParams.get('code_challenge_method')).toBe(
        'S256',
    );
    expect(devAuthorizeUrl.searchParams.get('code_challenge')).toMatch(
        /^[A-Za-z0-9_-]{43}$/,
    );

    await prodClient.redirectToSignUp();
    const prodAuthorizeUrl = new URL(location.href);
    expect(prodAuthorizeUrl.searchParams.get('client_id')).toBe(
        'pk_live_prodKey456',
    );
    expect(prodAuthorizeUrl.searchParams.get('screen_hint')).toBe('signup');
    expect(prodAuthorizeUrl.searchParams.get('code_challenge_method')).toBe(
        'S256',
    );

    // Cross-environment state cannot be consumed by the wrong publishable key client
    location.search = `?code=wrong&state=${prodAuthorizeUrl.searchParams.get('state')}`;
    await expect(devClient.handleRedirectCallback()).rejects.toThrow(
        'OAuth state mismatch',
    );

    // Exchange dev callback code
    location.search = `?code=dev-code&state=${devAuthorizeUrl.searchParams.get('state')}`;
    const devCallback = await devClient.handleRedirectCallback();
    expect(devCallback.user.environment).toBe('development');
    expect(devCallback.user.organization_id).toBe('org_123');
    expect(devCallback.user.application_id).toBe('app_456');
    expect(devCallback.user.public_metadata).toEqual({ plan: 'sandbox' });

    // Exchange prod callback code
    location.search = `?code=prod-code&state=${prodAuthorizeUrl.searchParams.get('state')}`;
    const prodCallback = await prodClient.handleRedirectCallback();
    expect(prodCallback.user.environment).toBe('production');
    expect(prodCallback.user.public_metadata).toEqual({ plan: 'pro' });

    // Verify token exchange sent publishableKey as client_id
    const firstTokenBody = fetchMock.mock.calls[0][1]?.body as URLSearchParams;
    expect(firstTokenBody.get('client_id')).toBe('pk_test_devKey123');
    expect(firstTokenBody.get('code_verifier')).toMatch(/^[A-Za-z0-9_-]{43}$/);

    // Refresh dev token without affecting prod session
    const refreshedDev = await devClient.refreshToken();
    expect(refreshedDev.access_token).toBe(
        'renewed-pk_test_devKey123-refresh-pk_test_devKey123-dev-code',
    );
    const refreshBody = fetchMock.mock.calls[4][1]?.body as URLSearchParams;
    expect(refreshBody.get('grant_type')).toBe('refresh_token');
    expect(refreshBody.get('client_id')).toBe('pk_test_devKey123');

    expect((await devClient.getUser()).sub).toBe(
        'Bearer renewed-pk_test_devKey123-refresh-pk_test_devKey123-dev-code',
    );
    expect((await prodClient.getUser()).sub).toBe(
        'Bearer access-pk_live_prodKey456-prod-code',
    );

    // Signing out dev preserves prod sessionStorage
    devClient.signOut();
    await expect(devClient.getUser()).rejects.toThrow(
        'No access token available',
    );
    expect((await prodClient.getUser()).sub).toBe(
        'Bearer access-pk_live_prodKey456-prod-code',
    );
});

test('rejects secret keys in browser client configuration', () => {
    expect(() =>
        createKoamishinClient({
            portalUrl: 'https://portal.test',
            publishableKey: 'sk_test_secret123',
            redirectUri: 'https://app.test/callback',
        }),
    ).toThrow(
        'Secret keys (sk_...) must never be used in browser code. Use a publishableKey (pk_test_... or pk_live_...) instead.',
    );

    expect(() =>
        createKoamishinClient({
            portalUrl: 'https://portal.test',
            publishableKey: '  sk_live_secret456  ',
            redirectUri: 'https://app.test/callback',
        }),
    ).toThrow(
        'Secret keys (sk_...) must never be used in browser code. Use a publishableKey (pk_test_... or pk_live_...) instead.',
    );

    expect(() =>
        createKoamishinClient({
            portalUrl: 'https://portal.test',
            clientId: 'sk_live_passed_as_client_id',
            redirectUri: 'https://app.test/callback',
        }),
    ).toThrow(
        'Secret keys (sk_...) must never be used in browser code. Use a publishableKey (pk_test_... or pk_live_...) instead.',
    );
});

test('rejects empty identifiers and conflicting publishableKey and clientId', () => {
    expect(() =>
        createKoamishinClient({
            portalUrl: 'https://portal.test',
            publishableKey: '   ',
            redirectUri: 'https://app.test/callback',
        }),
    ).toThrow('A Koamishin publishableKey or clientId is required.');

    expect(() =>
        createKoamishinClient({
            portalUrl: 'https://portal.test',
            clientId: '',
            redirectUri: 'https://app.test/callback',
        }),
    ).toThrow('A Koamishin publishableKey or clientId is required.');

    expect(() =>
        createKoamishinClient({
            portalUrl: 'https://portal.test',
            publishableKey: 'pk_test_abc',
            clientId: 'pk_live_xyz',
            redirectUri: 'https://app.test/callback',
        }),
    ).toThrow(
        'Provide either publishableKey or clientId, or ensure both match.',
    );

    const matchingClient = createKoamishinClient({
        portalUrl: 'https://portal.test',
        publishableKey: ' pk_test_same ',
        clientId: 'pk_test_same',
        redirectUri: 'https://app.test/callback',
    });
    expect(matchingClient.getEnvironment()).toBe('development');
});

test('rejects userinfo responses whose environment mismatches the configured publishable key', async () => {
    const storage = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const location = { href: '', search: '' };
    vi.stubGlobal('window', { location });

    let reportedEnvironment = 'production';
    const fetchMock = vi.fn(async (url: string) => {
        if (url.endsWith('/oauth/token')) {
            return {
                ok: true,
                json: async () => ({
                    token_type: 'Bearer',
                    expires_in: 60,
                    access_token: 'mismatched-token',
                }),
            };
        }

        return {
            ok: true,
            json: async () => ({
                sub: 'user-1',
                name: 'Test User',
                email: 'user@example.test',
                email_verified: true,
                roles: [],
                permissions: [],
                environment: reportedEnvironment,
            }),
        };
    });
    vi.stubGlobal('fetch', fetchMock);

    const devClient = createKoamishinClient({
        portalUrl: 'https://portal.test',
        publishableKey: 'pk_test_devOnly',
        redirectUri: 'https://app.test/callback',
    });
    const prodClient = createKoamishinClient({
        portalUrl: 'https://portal.test',
        publishableKey: 'pk_live_prodOnly',
        redirectUri: 'https://app.test/callback',
    });
    const legacyClient = createKoamishinClient({
        portalUrl: 'https://portal.test',
        clientId: 'legacy-opaque-id',
        redirectUri: 'https://app.test/callback',
    });

    // pk_test_... rejects production userinfo on direct getUser() and callback
    await expect(devClient.getUser('token-from-prod')).rejects.toThrow(
        'Userinfo environment does not match the configured publishable key.',
    );

    await devClient.redirectToSignIn();
    const state = new URL(location.href).searchParams.get('state');
    location.search = `?code=abc&state=${state}`;
    await expect(devClient.handleRedirectCallback()).rejects.toThrow(
        'Userinfo environment does not match the configured publishable key.',
    );
    await expect(devClient.getUser()).rejects.toThrow(
        'No access token available.',
    );

    // Legacy clientId has null getEnvironment() and accepts any userinfo environment
    expect((await legacyClient.getUser('legacy-token')).environment).toBe(
        'production',
    );

    // pk_live_... rejects development userinfo
    reportedEnvironment = 'development';
    await expect(prodClient.getUser('token-from-dev')).rejects.toThrow(
        'Userinfo environment does not match the configured publishable key.',
    );

    for (const response of [null, {}, { environment: 7 }, []]) {
        vi.stubGlobal(
            'fetch',
            vi.fn(async () => ({
                ok: true,
                json: async () => response,
            })),
        );
        await expect(devClient.getUser('token')).rejects.toThrow(
            'Userinfo environment does not match the configured publishable key.',
        );
    }
});

test('session tokens mint from the current access token', async () => {
    const storage = new Map<string, string>([
        [
            'koamishin:https%3A%2F%2Fportal.test:app-a:access_token',
            'access-secret',
        ],
    ]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const minted = {
        token: 'header.payload.signature',
        token_type: 'Bearer',
        expires_in: 60,
        expires_at: 1_700_000_060,
    };
    const fetchMock = vi.fn(async (url: string, options: RequestInit) => {
        expect(url).toBe('https://portal.test/api/oauth/session-token');
        expect(options.method).toBe('POST');
        return { ok: true, json: async () => minted };
    });
    vi.stubGlobal('fetch', fetchMock);

    const client = createKoamishinClient({
        portalUrl: 'https://portal.test',
        clientId: 'app-a',
        redirectUri: 'https://app.test/callback',
    });

    expect(await client.getSessionToken()).toEqual(minted);
    expect(await client.getSessionToken('explicit-secret')).toEqual(minted);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(
        (fetchMock.mock.calls[0][1].headers as Record<string, string>)
            .Authorization,
    ).toBe('Bearer access-secret');
    expect(
        (fetchMock.mock.calls[1][1].headers as Record<string, string>)
            .Authorization,
    ).toBe('Bearer explicit-secret');
});

test('session token minting requires a sign-in', async () => {
    vi.stubGlobal('sessionStorage', {
        getItem: () => null,
        setItem: () => undefined,
        removeItem: () => undefined,
    });

    const client = createKoamishinClient({
        portalUrl: 'https://portal.test',
        clientId: 'app-a',
        redirectUri: 'https://app.test/callback',
    });

    await expect(client.getSessionToken()).rejects.toThrow(
        'No access token available.',
    );
});

test('session token minting surfaces portal refusals', async () => {
    vi.stubGlobal('sessionStorage', {
        getItem: () => 'stale-secret',
        setItem: () => undefined,
        removeItem: () => undefined,
    });
    vi.stubGlobal(
        'fetch',
        vi.fn(async () => ({
            ok: false,
            text: async () => 'Only user tokens can mint session tokens.',
        })),
    );

    const client = createKoamishinClient({
        portalUrl: 'https://portal.test',
        clientId: 'app-a',
        redirectUri: 'https://app.test/callback',
    });

    await expect(client.getSessionToken()).rejects.toThrow(
        'Session token mint failed: Only user tokens can mint session tokens.',
    );
});

test('session token claims decode without verification', () => {
    const claims = sessionTokenClaims();

    expect(decodeSessionToken(sessionTokenJwt(claims))).toEqual(claims);
    expect(
        decodeSessionToken({
            token: sessionTokenJwt(claims),
            token_type: 'Bearer',
            expires_in: 60,
            expires_at: 1_700_000_060,
        }),
    ).toEqual(claims);
    expect(decodeSessionToken(sessionTokenJwt(claims)).o).toBeUndefined();

    expect(() => decodeSessionToken('not-a-jwt')).toThrow(
        'The session token is not a JWT.',
    );
    expect(() => decodeSessionToken('a.!.c')).toThrow(
        'The session token payload is not valid JSON.',
    );
    expect(() =>
        decodeSessionToken(sessionTokenJwt({ sub: 'user-1', v: '1' })),
    ).toThrow('The token is not a Koamishin session token.');
});

test('verifySessionToken cryptographically verifies RS256 session tokens against JWKS and enforces claims', async () => {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
        },
        true,
        ['sign', 'verify'],
    );
    const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    const jwks = {
        keys: [
            {
                kty: 'RSA',
                alg: 'RS256',
                use: 'sig',
                kid: 'key-1',
                n: publicJwk.n,
                e: publicJwk.e,
            },
        ],
    };

    const signJwt = async (claims: Record<string, unknown>, kid = 'key-1') => {
        const header = b64url(
            JSON.stringify({ alg: 'RS256', typ: 'JWT', kid }),
        );
        const payload = b64url(JSON.stringify(claims));
        const signingInput = new TextEncoder().encode(`${header}.${payload}`);
        const sigBuffer = await crypto.subtle.sign(
            'RSASSA-PKCS1-v1_5',
            keyPair.privateKey,
            signingInput,
        );
        const sigBytes = new Uint8Array(sigBuffer);
        let binary = '';
        for (let i = 0; i < sigBytes.length; i++) {
            binary += String.fromCharCode(sigBytes[i]);
        }
        return `${header}.${payload}.${b64url(binary)}`;
    };

    const now = Math.floor(Date.now() / 1000);
    const validClaims = sessionTokenClaims({
        iss: 'https://portal.test',
        iat: now - 5,
        nbf: now - 5,
        exp: now + 55,
        environment: 'development',
        application_id: '42',
    });

    const validJwt = await signJwt(validClaims);
    const verified = await verifySessionToken(validJwt, {
        portalUrl: 'https://portal.test/',
        publishableKey: 'pk_test_example',
        applicationId: '42',
        jwks,
    });
    expect(verified).toEqual(validClaims);

    // Tampered payload fails cryptographic verification
    const tamperedParts = validJwt.split('.');
    tamperedParts[1] = b64url(
        JSON.stringify({ ...validClaims, sub: 'attacker' }),
    );
    await expect(
        verifySessionToken(tamperedParts.join('.'), {
            portalUrl: 'https://portal.test',
            publishableKey: 'pk_test_example',
            jwks,
        }),
    ).rejects.toThrow('Invalid session token signature.');

    // Wrong environment rejected
    await expect(
        verifySessionToken(validJwt, {
            portalUrl: 'https://portal.test',
            publishableKey: 'pk_live_example',
            jwks,
        }),
    ).rejects.toThrow(
        'Session token environment does not match the configured environment.',
    );

    // Expired token rejected
    const expiredJwt = await signJwt(
        sessionTokenClaims({
            iss: 'https://portal.test',
            iat: now - 120,
            nbf: now - 120,
            exp: now - 60,
            environment: 'development',
        }),
    );
    await expect(
        verifySessionToken(expiredJwt, {
            portalUrl: 'https://portal.test',
            publishableKey: 'pk_test_example',
            jwks,
        }),
    ).rejects.toThrow('Session token has expired.');
});

test('syncSessionCookie writes and signOut clears the __koamishin_session cookie', async () => {
    const storage = new Map<string, string>([
        [
            'koamishin:https%3A%2F%2Fportal.test:pk_test_123:access_token',
            'access-1',
        ],
    ]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const doc = { cookie: '' };
    vi.stubGlobal('document', doc);
    vi.stubGlobal(
        'fetch',
        vi.fn(async () => ({
            ok: true,
            json: async () => ({
                token: 'jwt.token.value',
                token_type: 'Bearer',
                expires_in: 60,
                expires_at: 1_700_000_060,
            }),
        })),
    );

    const client = createKoamishinClient({
        portalUrl: 'https://portal.test',
        publishableKey: 'pk_test_123',
        redirectUri: 'https://app.test/auth/callback',
    });

    await client.syncSessionCookie();
    expect(doc.cookie).toContain(`${SESSION_COOKIE_NAME}=jwt.token.value`);

    client.signOut();
    expect(doc.cookie).toContain(`${SESSION_COOKIE_NAME}=; Path=/; Max-Age=0`);
});

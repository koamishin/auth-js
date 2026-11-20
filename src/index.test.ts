import { afterEach, expect, test, vi } from 'vitest';
import {
    AuthTransitionEvent,
    SESSION_COOKIE_NAME,
    getSessionCookieName,
    normalizePortalUrl,
    createKoamishinClient,
    decodeSessionToken,
    verifySessionToken,
} from './index';

const b64url = (value: string): string =>
    btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const utf8b64url = (value: string): string =>
    b64url(Array.from(new TextEncoder().encode(value), (byte) => String.fromCharCode(byte)).join(''));

const sessionTokenJwt = (claims: Record<string, unknown>): string =>
    `${b64url('{"alg":"RS256","kid":"key-a"}')}.${b64url(
        JSON.stringify(claims),
    )}.c2ln`;

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

const activeSessionTokenClaims = (overrides: Record<string, unknown> = {}) => {
    const now = Math.floor(Date.now() / 1000);
    return sessionTokenClaims({ iat: now, nbf: now, exp: now + 60, ...overrides });
};

function createCookieJar() {
    const values = new Map<string, string>();
    const writes: string[] = [];
    const document = {
        get cookie() {
            return [...values].map(([name, value]) => `${name}=${value}`).join('; ');
        },
        set cookie(value: string) {
            writes.push(value);
            const [pair, ...attributes] = value.split(';');
            const equals = pair.indexOf('=');
            const name = pair.slice(0, equals);
            if (attributes.some((part) => part.trim().toLowerCase() === 'max-age=0')) values.delete(name);
            else values.set(name, pair.slice(equals + 1));
        },
    };
    return { values, writes, document };
}

afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
});

test('persists the family credential across refresh and confirms remote sign-out', async () => {
    const storage = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const location = { href: '', search: '' };
    vi.stubGlobal('window', { location });
    const fetchMock = vi.fn(async (url: string, options?: RequestInit) => {
        if (url.endsWith('/revoke-family')) return { status: 204 };
        if (url.endsWith('/userinfo')) return { ok: true, json: async () => ({ sub: 'user' }) };
        const grant = (options?.body as URLSearchParams).get('grant_type');
        return { ok: true, json: async () => grant === 'authorization_code'
            ? { access_token: 'access', refresh_token: 'refresh', revocation_token: 'opaque-secret' }
            : { access_token: 'new-access', refresh_token: 'new-refresh' } };
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    await client.redirectToSignIn();
    location.search = `?code=code&state=${new URL(location.href).searchParams.get('state')}`;
    await client.handleRedirectCallback();
    await client.refreshToken();
    expect(await client.signOut()).toEqual({ status: 'revoked' });
    expect(client.getStoredAccessToken()).toBeNull();
    expect([...storage.values()]).not.toContain('opaque-secret');
    expect(fetchMock).toHaveBeenLastCalledWith('https://portal.test/api/oauth/revoke-family', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ revocation_token: 'opaque-secret' }),
        redirect: 'error',
    });
});

test.each(['http', 'unexpected-success', 'network', 'legacy'])('sign-out cleans local state and reports %s without leaking secrets', async (kind) => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:app:';
    const storage = new Map([[`${prefix}access_token`, 'access'], [`${prefix}refresh_token`, 'refresh']]);
    if (kind !== 'legacy') storage.set(`${prefix}revocation_token`, 'secret');
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const fetchMock = vi.fn(async () => {
        if (kind === 'network') throw new Error('secret');
        return { status: kind === 'unexpected-success' ? 200 : 500, text: async () => 'secret' };
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    const result = await client.signOut();
    expect(result.status).toBe(kind === 'legacy' ? 'reauthentication_required' : 'failed');
    expect(JSON.stringify(result)).not.toContain('secret');
    expect([...storage.values()]).toEqual(['1']);
    if (kind === 'legacy') expect(fetchMock).not.toHaveBeenCalled();
});

test('concurrent sign-out during refresh remains unconfirmed and cannot restore the session', async () => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:app:';
    const storage = new Map([[`${prefix}access_token`, 'access'], [`${prefix}refresh_token`, 'refresh'], [`${prefix}revocation_token`, 'secret']]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    let resolveRefresh!: (response: unknown) => void;
    let resolveRevoke!: (response: unknown) => void;
    const fetchMock = vi.fn((url: string, options?: RequestInit) => {
        if (url.endsWith('/revoke-family') && JSON.parse(String(options?.body)).revocation_token === 'new-secret') {
            return Promise.resolve({ status: 204 });
        }
        return new Promise((resolve) => {
            if (url.endsWith('/revoke-family')) resolveRevoke = resolve;
            else resolveRefresh = resolve;
        });
    });
    vi.stubGlobal('fetch', fetchMock);
    const config = { portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' };
    const client = createKoamishinClient(config);
    const refresh = client.refreshToken();
    const first = client.signOut();
    const second = createKoamishinClient(config).signOut();
    expect((await second).status).toBe('failed');
    expect([...storage.values()]).toEqual(['1']);
    resolveRefresh({ ok: true, json: async () => ({ access_token: 'new', revocation_token: 'new-secret' }) });
    await expect(refresh).rejects.toThrow('Session changed');
    resolveRevoke({ status: 204 });
    expect((await first).status).toBe('failed');
    expect([...storage.values()]).toEqual(['1']);
    expect(fetchMock).toHaveBeenCalledTimes(3);
});

test('concurrent refresh callers share one rotation request', async () => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:app:';
    const storage = new Map([[`${prefix}access_token`, 'access'], [`${prefix}refresh_token`, 'refresh'], [`${prefix}revocation_token`, 'secret']]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const responses: Array<(response: unknown) => void> = [];
    const fetchMock = vi.fn((_url: string, _options: RequestInit) => new Promise((resolve) => responses.push(resolve)));
    vi.stubGlobal('fetch', fetchMock);
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    const first = client.refreshToken();
    const second = client.refreshToken();
    expect(first).toBe(second);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    responses[0]({ ok: true, json: async () => ({ access_token: 'new', refresh_token: 'rotated', revocation_token: 'new-secret' }) });
    await Promise.all([first, second]);
    expect(storage.get(`${prefix}access_token`)).toBe('new');
    expect(storage.get(`${prefix}refresh_token`)).toBe('rotated');
    expect(storage.get(`${prefix}revocation_token`)).toBe('new-secret');
    const next = client.refreshToken();
    expect((fetchMock.mock.calls[1][1].body as URLSearchParams).get('refresh_token')).toBe('rotated');
    responses[1]({ ok: true, json: async () => ({ access_token: 'next', refresh_token: 'rotated-again' }) });
    await next;
});

test('a different explicit refresh token is refused without modifying the active family', async () => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:app:';
    const storage = new Map([[`${prefix}access_token`, 'access'], [`${prefix}refresh_token`, 'refresh'], [`${prefix}revocation_token`, 'old-secret'], [`${prefix}user`, '{}']]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    await expect(client.refreshToken('other-refresh')).rejects.toThrow('Cannot replace an active session');
    expect(storage.get(`${prefix}revocation_token`)).toBe('old-secret');
    expect(storage.get(`${prefix}refresh_token`)).toBe('refresh');
    expect(storage.get(`${prefix}user`)).toBe('{}');
    expect(fetchMock).not.toHaveBeenCalled();
});

test('queued explicit refresh rechecks the session before sending its request', async () => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:app:';
    const storage = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    let finish!: (value: unknown) => void;
    const fetchMock = vi.fn(() => new Promise((resolve) => { finish = resolve; }));
    vi.stubGlobal('fetch', fetchMock);
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    const first = client.refreshToken('token-a');
    const second = client.refreshToken('token-b');
    const rejected = expect(second).rejects.toThrow('Cannot replace an active session');
    finish({ ok: true, json: async () => ({ access_token: 'access-a', refresh_token: 'refresh-a', revocation_token: 'family-a' }) });
    await first;
    await rejected;
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(storage.get(`${prefix}access_token`)).toBe('access-a');
    expect(storage.get(`${prefix}revocation_token`)).toBe('family-a');
});

test('an old refresh flight is not reused after a new session starts', async () => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:app:';
    const storage = new Map([[`${prefix}access_token`, 'old-access'], [`${prefix}refresh_token`, 'old-refresh']]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    let finish!: (value: unknown) => void;
    const fetchMock = vi.fn(() => new Promise((resolve) => { finish = resolve; }));
    vi.stubGlobal('fetch', fetchMock);
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    const old = client.refreshToken('old-refresh');
    const rejected = expect(old).rejects.toThrow('Session changed');
    expect((await client.signOut()).status).toBe('failed');
    storage.set(`${prefix}access_token`, 'new-access');
    storage.set(`${prefix}refresh_token`, 'new-refresh');
    storage.set(`${prefix}revocation_token`, 'new-family');
    await expect(client.refreshToken('old-refresh')).rejects.toThrow('Cannot replace an active session');
    finish({ ok: true, json: async () => ({ access_token: 'stale', revocation_token: 'old-family' }) });
    await rejected;
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(storage.get(`${prefix}access_token`)).toBe('new-access');
});

test('sign-out during a legacy stored refresh is unconfirmed and cleans the returned family', async () => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:app:';
    const storage = new Map([[`${prefix}access_token`, 'old'], [`${prefix}refresh_token`, 'old-refresh']]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    let finishRefresh!: (value: unknown) => void;
    const revoked: string[] = [];
    vi.stubGlobal('fetch', vi.fn((url: string, options?: RequestInit) => {
        if (url.endsWith('/revoke-family')) {
            revoked.push(JSON.parse(String(options?.body)).revocation_token);
            return Promise.resolve({ status: 204 });
        }
        return new Promise((resolve) => { finishRefresh = resolve; });
    }));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    const refresh = client.refreshToken();
    expect((await client.signOut()).status).toBe('failed');
    finishRefresh({ ok: true, json: async () => ({ access_token: 'foreign', revocation_token: 'foreign-secret' }) });
    await expect(refresh).rejects.toThrow('issued token family was revoked');
    expect(revoked).toEqual(['foreign-secret']);
    expect([...storage.values()]).toEqual(['1']);
});

test('a stale refresh does not revoke a newer active session', async () => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:app:';
    const storage = new Map([[`${prefix}access_token`, 'old'], [`${prefix}refresh_token`, 'old-refresh']]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    let finishRefresh!: (value: unknown) => void;
    const fetchMock = vi.fn(() => new Promise((resolve) => { finishRefresh = resolve; }));
    vi.stubGlobal('fetch', fetchMock);
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    const refresh = client.refreshToken();
    expect((await client.signOut()).status).toBe('failed');
    storage.set(`${prefix}access_token`, 'new-access');
    storage.set(`${prefix}refresh_token`, 'new-refresh');
    storage.set(`${prefix}revocation_token`, 'new-family');
    finishRefresh({ ok: true, json: async () => ({ access_token: 'stale', revocation_token: 'same-or-different-family' }) });
    await expect(refresh).rejects.toThrow('could not be confirmed');
    expect(storage.get(`${prefix}revocation_token`)).toBe('new-family');
    expect(fetchMock).toHaveBeenCalledTimes(1);
});

test.each([
    [401, undefined, 'access_token_invalid'],
    [403, undefined, 'unavailable'],
    [500, undefined, 'unavailable'],
])('userinfo HTTP %s is classified without exposing the response', async (status, _unused, expected) => {
    vi.stubGlobal('sessionStorage', { getItem: () => 'access' });
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false, status, text: async () => 'sentinel-secret' })));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    const error = await client.getUser().catch((value: Error & { code?: string }) => value);
    expect(error.code).toBe(expected);
    expect(error.message).not.toContain('sentinel-secret');
});

test.each([
    [400, 'invalid_grant', 'invalid_grant'],
    [400, 'invalid_client', 'unavailable'],
    [500, 'invalid_grant', 'unavailable'],
])('refresh HTTP %s error %s is classified without revocation', async (status, oauthError, expected) => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:classification:';
    const storage = new Map([[`${prefix}refresh_token`, 'refresh'], [`${prefix}revocation_token`, 'credential']]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const fetchMock = vi.fn(async () => ({ ok: false, status, json: async () => ({ error: oauthError, detail: 'sentinel-secret' }) }));
    vi.stubGlobal('fetch', fetchMock);
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'classification', redirectUri: 'https://app.test/callback' });
    const error = await client.refreshToken().catch((value: Error & { code?: string }) => value);
    expect(error.code).toBe(expected);
    expect(error.message).not.toContain('sentinel-secret');
    expect(storage.get(`${prefix}revocation_token`)).toBe('credential');
    expect(fetchMock).toHaveBeenCalledTimes(1);
});

test.each(['network', 'unreadable', 'server'])('unconfirmed %s refresh remains unconfirmed after a later session', async (failure) => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:unknown-refresh:';
    const storage = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
        if (url.endsWith('/revoke-family')) return { status: 204 };
        if (failure === 'network') throw new Error('sentinel-secret');
        if (failure === 'unreadable') return { ok: true, json: async () => { throw new Error('sentinel-secret'); } };
        return { ok: false, status: 503 };
    }));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'unknown-refresh', redirectUri: 'https://app.test/callback' });
    await expect(client.refreshToken('external-refresh')).rejects.toThrow('Retry later');
    storage.set(`${prefix}access_token`, 'new-access');
    storage.set(`${prefix}refresh_token`, 'new-refresh');
    storage.set(`${prefix}revocation_token`, 'new-family');
    expect((await client.signOut()).status).toBe('failed');
});

test.each([
    {},
    { access_token: '' },
    { access_token: 'access', refresh_token: null },
    { access_token: 'access', revocation_token: '' },
])('malformed successful refresh response remains unconfirmed', async (body) => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:malformed-refresh:';
    const storage = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    vi.stubGlobal('fetch', vi.fn(async (url: string) => url.endsWith('/revoke-family')
        ? { status: 204 }
        : { ok: true, json: async () => body }));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'malformed-refresh', redirectUri: 'https://app.test/callback' });
    await expect(client.refreshToken('external-refresh')).rejects.toThrow('Token refresh response was invalid');
    expect(client.getStoredAccessToken()).toBeNull();
    storage.set(`${prefix}access_token`, 'new-access');
    storage.set(`${prefix}revocation_token`, 'new-family');
    expect((await client.signOut()).status).toBe('failed');
});

test.each([null, {}, { access_token: '' }, { access_token: 'access', revocation_token: null }])(
    'malformed successful callback exchange stays unconfirmed',
    async (body) => {
        const prefix = 'koamishin:https%3A%2F%2Fportal.test:malformed-callback:';
        const storage = new Map<string, string>();
        vi.stubGlobal('sessionStorage', {
            getItem: (key: string) => storage.get(key) ?? null,
            setItem: (key: string, value: string) => storage.set(key, value),
            removeItem: (key: string) => storage.delete(key),
        });
        const location = { href: '', search: '' };
        vi.stubGlobal('window', { location });
        const fetchMock = vi.fn(async (url: string) => url.endsWith('/revoke-family')
            ? { status: 204 }
            : { ok: true, json: async () => body });
        vi.stubGlobal('fetch', fetchMock);
        const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'malformed-callback', redirectUri: 'https://app.test/callback' });
        await client.redirectToSignIn();
        location.search = `?code=code&state=${new URL(location.href).searchParams.get('state')}`;
        await expect(client.handleRedirectCallback()).rejects.toThrow('Remote token issuance could not be confirmed');
        expect(client.getStoredAccessToken()).toBeNull();
        expect(fetchMock).toHaveBeenCalledTimes(1);
        storage.set(`${prefix}access_token`, 'later-access');
        storage.set(`${prefix}revocation_token`, 'later-family');
        expect((await client.signOut()).status).toBe('failed');
    },
);

test('explicit old userinfo credentials cannot overwrite a newer cached identity', async () => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:explicit-stale:';
    const storage = new Map([[`${prefix}access_token`, 'new-access'], [`${prefix}user`, '{"sub":"new-user"}']]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'explicit-stale', redirectUri: 'https://app.test/callback' });
    await expect(client.getUser('old-access')).rejects.toThrow('Session changed');
    expect(fetchMock).not.toHaveBeenCalled();
    expect(client.getStoredUser()?.sub).toBe('new-user');
});

test('a delayed userinfo 401 after refresh cannot be mistaken for the current token', async () => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:stale-401:';
    const storage = new Map([[`${prefix}access_token`, 'old-access'], [`${prefix}refresh_token`, 'refresh']]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    let finishUser!: (value: unknown) => void;
    const fetchMock = vi.fn((url: string) => url.endsWith('/userinfo')
        ? new Promise((resolve) => { finishUser = resolve; })
        : Promise.resolve({ ok: true, json: async () => ({ access_token: 'new-access' }) }));
    vi.stubGlobal('fetch', fetchMock);
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'stale-401', redirectUri: 'https://app.test/callback' });
    const userinfo = client.getUser();
    await client.refreshToken();
    finishUser({ ok: false, status: 401 });
    const error = await userinfo.catch((value: Error & { code?: string }) => value);
    expect(error.message).toContain('Session changed');
    expect(error.code).toBeUndefined();
    expect(client.getStoredAccessToken()).toBe('new-access');
    expect(fetchMock).toHaveBeenCalledTimes(2);
});

test('a delayed userinfo response cannot cache identity after access-token refresh', async () => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:stale-userinfo:';
    const storage = new Map([[`${prefix}access_token`, 'old-access'], [`${prefix}refresh_token`, 'refresh'], [`${prefix}user`, '{"sub":"current"}']]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    let finishUser!: (value: unknown) => void;
    vi.stubGlobal('fetch', vi.fn((url: string) => url.endsWith('/userinfo')
        ? new Promise((resolve) => { finishUser = resolve; })
        : Promise.resolve({ ok: true, json: async () => ({ access_token: 'new-access' }) })));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'stale-userinfo', redirectUri: 'https://app.test/callback' });
    const userinfo = client.getUser();
    await client.refreshToken();
    finishUser({ ok: true, json: async () => ({ sub: 'stale' }) });
    await expect(userinfo).rejects.toThrow('Session changed');
    expect(client.getStoredUser()?.sub).toBe('current');
    expect(client.getStoredAccessToken()).toBe('new-access');
});

test('explicit userinfo without a stored session is read-only and cannot cache identity', async () => {
    const storage = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    vi.stubGlobal('fetch', vi.fn((url: string) => url.endsWith('/userinfo')
        ? Promise.resolve({ ok: true, json: async () => ({ sub: 'user-a' }) })
        : Promise.resolve({ ok: true, json: async () => ({ access_token: 'session-b', refresh_token: 'refresh-b' }) })));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'empty-userinfo', redirectUri: 'https://app.test/callback' });
    await expect(client.getUser('token-a')).rejects.toThrow('Session changed');
    expect((await client.getUser('token-a', false)).sub).toBe('user-a');
    await client.refreshToken('external-refresh-b');
    expect(client.getStoredAccessToken()).toBe('session-b');
    expect(client.getStoredUser()).toBeNull();
});

test('explicit cookie mint started without a session cannot overwrite a later session cookie', async () => {
    const storage = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const doc = { cookie: 'new-session-cookie' };
    vi.stubGlobal('document', doc);
    vi.stubGlobal('fetch', vi.fn((url: string) => url.endsWith('/session-token')
        ? Promise.reject(new Error('unexpected mint'))
        : Promise.resolve({ ok: true, json: async () => ({ access_token: 'session-b', refresh_token: 'refresh-b' }) })));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'empty-mint', redirectUri: 'https://app.test/callback' });
    await expect(client.syncSessionCookie('token-a')).rejects.toThrow('Session changed');
    await client.refreshToken('external-refresh-b');
    expect(client.getStoredAccessToken()).toBe('session-b');
    expect(doc.cookie).toBe('new-session-cookie');
});

test('explicit token after sign-out cannot leave cached identity or cookie for a later session', async () => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:after-signout:';
    const storage = new Map([[`${prefix}access_token`, 'old-access'], [`${prefix}refresh_token`, 'old-refresh']]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const jar = createCookieJar();
    vi.stubGlobal('document', jar.document);
    vi.stubGlobal('fetch', vi.fn(async (url: string) => url.endsWith('/userinfo')
        ? { ok: true, json: async () => ({ sub: 'user-a' }) }
        : { ok: true, json: async () => ({ access_token: 'session-b', refresh_token: 'refresh-b' }) }));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'after-signout', redirectUri: 'https://app.test/callback' });
    await client.signOut();
    await expect(client.getUser('token-a')).rejects.toThrow('Session changed');
    await expect(client.syncSessionCookie('token-a')).rejects.toThrow('Session changed');
    expect((await client.getUser('token-a', false)).sub).toBe('user-a');
    await client.refreshToken('external-refresh-b');
    expect(client.getStoredAccessToken()).toBe('session-b');
    expect(client.getStoredUser()).toBeNull();
    expect(jar.values.has(getSessionCookieName('https://portal.test', 'after-signout'))).toBe(false);
});

test('a delayed session mint cannot write a cookie after access-token refresh', async () => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:stale-mint:';
    const storage = new Map([[`${prefix}access_token`, 'old-access'], [`${prefix}refresh_token`, 'refresh']]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const doc = { cookie: '' };
    vi.stubGlobal('document', doc);
    let finishMint!: (value: unknown) => void;
    vi.stubGlobal('fetch', vi.fn((url: string) => url.endsWith('/session-token')
        ? new Promise((resolve) => { finishMint = resolve; })
        : Promise.resolve({ ok: true, json: async () => ({ access_token: 'new-access' }) })));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'stale-mint', redirectUri: 'https://app.test/callback' });
    const mint = client.syncSessionCookie();
    await client.refreshToken();
    finishMint({ ok: true, json: async () => ({ token: sessionTokenJwt(activeSessionTokenClaims()), token_type: 'Bearer', expires_in: 60, expires_at: 123 }) });
    await expect(mint).rejects.toThrow('Session changed');
    expect(doc.cookie).toBe('');
});

test('invalidating an expired session clears cached identity but preserves the revocation credential', async () => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:invalidated:';
    const storage = new Map([
        [`${prefix}access_token`, 'old-access'], [`${prefix}refresh_token`, 'old-refresh'],
        [`${prefix}revocation_token`, 'family'], [`${prefix}user`, '{"sub":"old-user"}'],
    ]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const doc = { cookie: 'old-cookie' };
    vi.stubGlobal('document', doc);
    const fetchMock = vi.fn(async () => ({ status: 204 }));
    vi.stubGlobal('fetch', fetchMock);
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'invalidated', redirectUri: 'https://app.test/callback' });
    expect(client.invalidateSession('newer-access')).toBe(false);
    expect(client.getStoredUser()?.sub).toBe('old-user');
    expect(client.invalidateSession('old-access')).toBe(true);
    expect(client.getStoredAccessToken()).toBeNull();
    expect(client.getStoredUser()).toBeNull();
    expect(storage.has(`${prefix}refresh_token`)).toBe(false);
    expect(storage.get(`${prefix}revocation_token`)).toBe('family');
    expect(doc.cookie).toContain('Max-Age=0');
    expect(fetchMock).not.toHaveBeenCalled();
    expect((await client.signOut()).status).toBe('revoked');
});

test.each(['rotated-same-family-token', 'unrelated-token'])('different explicit token %s never revokes the active family', async (token) => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:app:';
    const storage = new Map([[`${prefix}access_token`, 'old'], [`${prefix}refresh_token`, 'old-refresh'], [`${prefix}revocation_token`, 'old-secret'], [`${prefix}user`, '{"sub":"old"}']]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    await expect(client.refreshToken(token)).rejects.toThrow('Cannot replace an active session');
    expect(storage.get(`${prefix}access_token`)).toBe('old');
    expect(storage.get(`${prefix}revocation_token`)).toBe('old-secret');
    expect(fetchMock).not.toHaveBeenCalled();
});

test.each(['success', 'failure'])('callback replacement revokes the old family or retains it on %s', async (outcome) => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:app:';
    const storage = new Map([[`${prefix}access_token`, 'old'], [`${prefix}revocation_token`, 'old-secret'], [`${prefix}user`, '{"sub":"old"}']]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const location = { href: '', search: '' };
    vi.stubGlobal('window', { location });
    const revoked: string[] = [];
    const document = { cookie: 'old-session' };
    vi.stubGlobal('document', document);
    vi.stubGlobal('fetch', vi.fn(async (url: string, options?: RequestInit) => {
        if (url.endsWith('/revoke-family')) {
            const token = JSON.parse(String(options?.body)).revocation_token;
            revoked.push(token);
            return { status: token === 'old-secret' && outcome === 'failure' ? 500 : 204 };
        }
        if (url.endsWith('/userinfo')) return { ok: true, json: async () => ({ sub: 'new' }) };
        return { ok: true, json: async () => ({ access_token: 'new', revocation_token: 'new-secret' }) };
    }));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    await client.redirectToSignIn();
    location.search = `?code=code&state=${new URL(location.href).searchParams.get('state')}`;
    if (outcome === 'success') {
        await client.handleRedirectCallback();
        expect(client.getStoredAccessToken()).toBe('new');
        expect(document.cookie).toContain('Max-Age=0');
        expect(revoked).toEqual(['old-secret']);
    } else {
        await expect(client.handleRedirectCallback()).rejects.toThrow('Previous session revocation was not confirmed');
        expect(client.getStoredAccessToken()).toBe('old');
        expect(client.getStoredUser()?.sub).toBe('old');
        expect(document.cookie).toBe('old-session');
        expect(revoked).toEqual(['old-secret', 'new-secret']);
    }
});

test('replacing a legacy session through callback remains unconfirmed', async () => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:app:';
    const storage = new Map([[`${prefix}access_token`, 'legacy'], [`${prefix}refresh_token`, 'old-refresh']]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const location = { href: '', search: '' };
    vi.stubGlobal('window', { location });
    vi.stubGlobal('fetch', vi.fn(async (url: string, options?: RequestInit) => {
        expect(options?.redirect).toBe('error');
        if (url.endsWith('/revoke-family')) return { status: 204 };
        if (url.endsWith('/userinfo')) return { ok: true, json: async () => ({ sub: 'new' }) };
        return { ok: true, json: async () => ({ access_token: 'new', revocation_token: 'new-secret' }) };
    }));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    await client.redirectToSignIn();
    location.search = `?code=code&state=${new URL(location.href).searchParams.get('state')}`;
    await client.handleRedirectCallback();
    expect((await client.signOut()).status).toBe('failed');
});

test('redirecting revocation is rejected and a later family cannot erase the unknown outcome', async () => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:app:';
    const storage = new Map([[`${prefix}access_token`, 'old'], [`${prefix}revocation_token`, 'old-secret']]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    let calls = 0;
    vi.stubGlobal('fetch', vi.fn(async (_url: string, options: RequestInit) => {
        expect(options.redirect).toBe('error');
        if (++calls === 1) throw new TypeError('redirect rejected');
        return { status: 204 };
    }));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    expect((await client.signOut()).status).toBe('failed');
    storage.set(`${prefix}access_token`, 'new');
    storage.set(`${prefix}revocation_token`, 'new-secret');
    expect((await client.signOut()).status).toBe('failed');
});

test('sign-out during PKCE generation prevents a later authentication redirect', async () => {
    const storage = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const location = { href: '', search: '' };
    vi.stubGlobal('window', { location });
    let finishDigest!: (value: ArrayBuffer) => void;
    vi.stubGlobal('crypto', {
        getRandomValues: (bytes: Uint8Array) => bytes,
        subtle: { digest: () => new Promise<ArrayBuffer>((resolve) => { finishDigest = resolve; }) },
    });
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    const redirect = client.redirectToSignIn();
    await client.signOut();
    finishDigest(new ArrayBuffer(32));
    await expect(redirect).rejects.toThrow('Session changed');
    expect(location.href).toBe('');
    expect(storage.size).toBe(0);
});

test('a lost exchange response remains unconfirmed after a later family is revoked', async () => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:app:';
    const storage = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const location = { href: '', search: '' };
    vi.stubGlobal('window', { location });
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
        if (url.endsWith('/revoke-family')) return { status: 204 };
        throw new Error('lost response');
    }));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    await client.redirectToSignIn();
    location.search = `?code=code&state=${new URL(location.href).searchParams.get('state')}`;
    await expect(client.handleRedirectCallback()).rejects.toThrow('Remote token issuance could not be confirmed');
    storage.set(`${prefix}access_token`, 'later');
    storage.set(`${prefix}revocation_token`, 'later-secret');
    expect((await client.signOut()).status).toBe('failed');
});

test('an old callback and an old sign-out cannot overwrite a newer session', async () => {
    const storage = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const location = { href: '', search: '' };
    vi.stubGlobal('window', { location });
    let finishOldCallback!: (response: unknown) => void;
    let finishOldRevoke!: (response: unknown) => void;
    const revokeBodies: string[] = [];
    vi.stubGlobal('fetch', vi.fn((url: string, options?: RequestInit) => {
        if (url.endsWith('/revoke-family')) {
            revokeBodies.push(String(options?.body));
            if (revokeBodies.length === 1) return new Promise((resolve) => { finishOldRevoke = resolve; });
            return Promise.resolve({ status: 204 });
        }
        if (url.endsWith('/userinfo')) {
            return Promise.resolve({ ok: true, json: async () => ({ sub: 'user' }) });
        }
        const code = (options?.body as URLSearchParams).get('code');
        if (code === 'delayed') return new Promise((resolve) => { finishOldCallback = resolve; });
        return Promise.resolve({ ok: true, json: async () => ({ access_token: code, revocation_token: `secret-${code}` }) });
    }));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    const beginCallback = async (code: string) => {
        await client.redirectToSignIn();
        location.search = `?code=${code}&state=${new URL(location.href).searchParams.get('state')}`;
        return client.handleRedirectCallback();
    };
    await beginCallback('first');
    const oldSignOut = client.signOut();
    await client.redirectToSignIn();
    location.search = `?code=delayed&state=${new URL(location.href).searchParams.get('state')}`;
    const oldCallback = client.handleRedirectCallback();
    await beginCallback('new');
    finishOldCallback({ ok: true, json: async () => ({ access_token: 'stale', revocation_token: 'stale-secret' }) });
    await expect(oldCallback).rejects.toThrow('Session changed');
    finishOldRevoke({ status: 204 });
    await oldSignOut;
    expect(client.getStoredAccessToken()).toBe('new');
    expect(await client.signOut()).toEqual({ status: 'revoked' });
    expect(revokeBodies.map((body) => JSON.parse(body).revocation_token)).toEqual(['secret-first', 'stale-secret', 'secret-new']);
});

test('a superseded callback revokes its issued family without touching the current cookie', async () => {
    const storage = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const location = { href: '', search: '' };
    const doc = { cookie: 'new-client-cookie' };
    vi.stubGlobal('window', { location });
    vi.stubGlobal('document', doc);
    let finishUser!: (value: unknown) => void;
    const revoked: string[] = [];
    vi.stubGlobal('fetch', vi.fn((url: string, options?: RequestInit) => {
        if (url.endsWith('/userinfo')) return new Promise((resolve) => { finishUser = resolve; });
        if (url.endsWith('/revoke-family')) {
            revoked.push(JSON.parse(String(options?.body)).revocation_token);
            return Promise.resolve({ status: 204 });
        }
        return Promise.resolve({ ok: true, json: async () => ({ access_token: 'old-access', revocation_token: 'old-secret' }) });
    }));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    await client.redirectToSignIn();
    location.search = `?code=code&state=${new URL(location.href).searchParams.get('state')}`;
    let current = true;
    const callback = client.handleRedirectCallback(() => current);
    await vi.waitFor(() => expect(finishUser).toBeTypeOf('function'));
    current = false;
    finishUser({ ok: true, json: async () => ({ sub: 'old-user' }) });
    await expect(callback).rejects.toThrow('issued token family was revoked');
    expect(client.getStoredAccessToken()).toBeNull();
    expect(doc.cookie).toBe('new-client-cookie');
    expect(revoked).toEqual(['old-secret']);
});

test.each([false, true])('sign-out is unconfirmed while an OAuth exchange is in flight (existing family: %s)', async (existingFamily) => {
    const prefix = 'koamishin:https%3A%2F%2Fportal.test:app:';
    const storage = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const location = { href: '', search: '' };
    vi.stubGlobal('window', { location });
    let finishExchange!: (response: unknown) => void;
    const fetchMock = vi.fn((url: string) => {
        if (url.endsWith('/revoke-family')) return Promise.resolve({ status: 204 });
        return new Promise((resolve) => { finishExchange = resolve; });
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    if (existingFamily) {
        storage.set(`${prefix}access_token`, 'old-access');
        storage.set(`${prefix}revocation_token`, 'old-secret');
    }
    await client.redirectToSignIn();
    location.search = `?code=code&state=${new URL(location.href).searchParams.get('state')}`;
    const callback = client.handleRedirectCallback();
    const result = await client.signOut();
    expect(result.status).toBe('failed');
    expect(client.getStoredAccessToken()).toBeNull();
    finishExchange({ ok: true, json: async () => ({ access_token: 'new', revocation_token: 'new-secret' }) });
    await expect(callback).rejects.toThrow('Session changed');
    expect(client.getStoredAccessToken()).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(existingFamily ? 3 : 2);
});

test.each(['success', 'refusal', 'network', 'missing'])('failed userinfo reports issued family cleanup: %s', async (outcome) => {
    const storage = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const location = { href: '', search: '' };
    vi.stubGlobal('window', { location });
    const fetchMock = vi.fn(async (url: string, options?: RequestInit) => {
        if (url.endsWith('/userinfo')) return { ok: false };
        if (url.endsWith('/revoke-family')) {
            expect(options?.body).toBe(JSON.stringify({ revocation_token: 'opaque-secret' }));
            if (outcome === 'network') throw new Error('opaque-secret');
            return { status: outcome === 'success' ? 204 : 500 };
        }
        return { ok: true, json: async () => ({
            access_token: 'access',
            ...(outcome === 'missing' ? {} : { revocation_token: 'opaque-secret' }),
        }) };
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    await client.redirectToSignIn();
    location.search = `?code=code&state=${new URL(location.href).searchParams.get('state')}`;
    const error = await client.handleRedirectCallback().catch((err: Error) => err);
    expect(error.message).toContain(outcome === 'success'
        ? 'issued token family was revoked'
        : 'could not be confirmed');
    expect(error.message).not.toContain('opaque-secret');
    expect(client.getStoredAccessToken()).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(outcome === 'missing' ? 2 : 3);
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
    await expect(devClient.getUser('token-from-prod', false)).rejects.toThrow(
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
    expect((await legacyClient.getUser('legacy-token', false)).environment).toBe(
        'production',
    );

    // pk_live_... rejects development userinfo
    reportedEnvironment = 'development';
    await expect(prodClient.getUser('token-from-dev', false)).rejects.toThrow(
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
        await expect(devClient.getUser('token', false)).rejects.toThrow(
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
            status: 403,
            text: async () => 'stale-secret',
        })),
    );

    const client = createKoamishinClient({
        portalUrl: 'https://portal.test',
        clientId: 'app-a',
        redirectUri: 'https://app.test/callback',
    });

    await expect(client.getSessionToken()).rejects.toThrow(
        'Session token mint failed (HTTP 403).',
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

test('session token claims preserve UTF-8 text', () => {
    const claims = sessionTokenClaims({ sub: '用户-山田', o: { id: '1', slg: 'café', rol: '管理者' } });
    const jwt = `${b64url('{"alg":"RS256"}')}.${utf8b64url(JSON.stringify(claims))}.c2ln`;

    expect(decodeSessionToken(jwt)).toEqual(claims);
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
        const payload = utf8b64url(JSON.stringify(claims));
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

    const unicodeClaims = { ...validClaims, sub: '用户-山田' };
    expect(await verifySessionToken(await signJwt(unicodeClaims), {
        portalUrl: 'https://portal.test',
        publishableKey: 'pk_test_example',
        applicationId: '42',
        jwks,
    })).toEqual(unicodeClaims);

    for (const skew of [NaN, Infinity, -Infinity, -1]) {
        await expect(verifySessionToken(validJwt, {
            portalUrl: 'https://portal.test',
            clockSkewSeconds: skew,
            jwks,
        })).rejects.toThrow('clock skew must be finite and nonnegative');
    }
    await expect(verifySessionToken(validJwt, {
        portalUrl: 'https://portal.test',
        publishableKey: 'pk_live_example',
        clientId: 'other-client',
        jwks,
    })).rejects.toThrow('publishableKey and clientId conflict');
    await expect(verifySessionToken(validJwt, {
        portalUrl: 'https://portal.test',
        publishableKey: 'pk_live_example',
        environment: 'not-production',
        jwks,
    })).rejects.toThrow('environment conflicts with the publishable key environment');

    for (const invalid of [{ sub: '' }, { sub: '   ' }, { sid: undefined }, { sid: '' }, { sid: 42 }]) {
        const invalidIdentity = await signJwt({ ...validClaims, ...invalid });
        await expect(verifySessionToken(invalidIdentity, {
            portalUrl: 'https://portal.test',
            applicationId: '42',
            jwks,
        })).rejects.toThrow('nonempty subject and session identifiers');
    }

    for (const field of ['exp', 'iat', 'nbf'] as const) {
        const payload = JSON.stringify(validClaims).replace(
            `"${field}":${validClaims[field]}`,
            `"${field}":1e999`,
        );
        const header = b64url(JSON.stringify({ alg: 'RS256', kid: 'key-1' }));
        const input = `${header}.${b64url(payload)}`;
        const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', keyPair.privateKey, new TextEncoder().encode(input));
        const invalidTimeToken = `${input}.${b64url(String.fromCharCode(...new Uint8Array(signature)))}`;
        await expect(verifySessionToken(invalidTimeToken, {
            portalUrl: 'https://portal.test',
            jwks,
        })).rejects.toThrow(field === 'exp' ? 'expired' : field === 'iat' ? 'issued-at' : 'not-before');
    }

    for (const issuer of ['https://PORTAL.test', 'https://portal.test/', 'https://portal.test/other']) {
        const differentIssuer = await signJwt({ ...validClaims, iss: issuer });
        await expect(verifySessionToken(differentIssuer, {
            portalUrl: 'https://portal.test',
            applicationId: '42',
            jwks,
        })).rejects.toThrow('Session token issuer does not match');
    }

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
    await expect(verifySessionToken(validJwt, {
        portalUrl: 'https://portal.test',
        publishableKey: 'pk_live_example',
        environment: '',
        jwks,
    })).rejects.toThrow('Session token environment does not match');

    for (const missing of [undefined, '', null]) {
        const missingEnvironment = await signJwt({ ...validClaims, environment: missing });
        await expect(verifySessionToken(missingEnvironment, {
            portalUrl: 'https://portal.test',
            publishableKey: 'pk_test_example',
            jwks,
        })).rejects.toThrow('Session token environment does not match');
        const missingApplication = await signJwt({ ...validClaims, application_id: missing });
        await expect(verifySessionToken(missingApplication, {
            portalUrl: 'https://portal.test',
            applicationId: '42',
            jwks,
        })).rejects.toThrow('Session token application_id does not match');
    }
    await expect(verifySessionToken(validJwt, {
        portalUrl: 'https://portal.test',
        applicationId: 'another-application',
        jwks,
    })).rejects.toThrow('Session token application_id does not match');
    const numericApplication = await signJwt({ ...validClaims, application_id: 42 });
    await expect(verifySessionToken(numericApplication, {
        portalUrl: 'https://portal.test',
        applicationId: '42',
        jwks,
    })).rejects.toThrow('Session token application_id does not match');
    const portalSession = await signJwt({ ...validClaims, environment: undefined, application_id: undefined, iat: undefined, nbf: undefined });
    await expect(verifySessionToken(portalSession, {
        portalUrl: 'https://portal.test',
        jwks,
    })).resolves.toMatchObject({ sub: 'user-1' });

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

test('unknown key refreshes are bounded, coalesced and permit later key rotation', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2025-01-01T00:00:00Z'));
    const generate = () => crypto.subtle.generateKey(
        { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true, ['sign', 'verify'],
    );
    const oldKey = await generate();
    const newKey = await generate();
    const oldJwk = { ...(await crypto.subtle.exportKey('jwk', oldKey.publicKey)), kid: 'old', kty: 'RSA' };
    const newJwk = { ...(await crypto.subtle.exportKey('jwk', newKey.publicKey)), kid: 'new', kty: 'RSA' };
    const { kid: _oldKid, ...kidlessOld } = oldJwk;
    const portalUrl = 'https://rotation.portal.test';
    const now = Math.floor(Date.now() / 1000);
    const sign = async (kid: string, key: CryptoKey) => {
        const header = b64url(JSON.stringify({ alg: 'RS256', kid }));
        const payload = b64url(JSON.stringify(sessionTokenClaims({ iss: portalUrl, iat: now, nbf: now, exp: now + 120 })));
        const input = `${header}.${payload}`;
        const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(input));
        return `${input}.${b64url(String.fromCharCode(...new Uint8Array(signature)))}`;
    };
    let rotated = false;
    let requests = 0;
    const invalidDocuments = [
        [null],
        [{ kty: 'RSA', kid: 'old', n: '!', e: '!' }],
        [{ kty: 'RSA', kid: 'old', n: 'AQ', e: 'AQ' }],
        [oldJwk, oldJwk],
    ];
    const fetchMock = vi.fn(async () => ({
        ok: true,
        json: async () => ({ keys: rotated ? [kidlessOld, newJwk] : ++requests === 1 ? [oldJwk] : invalidDocuments.shift() }),
    }));
    vi.stubGlobal('fetch', fetchMock);
    const oldToken = await sign('old', oldKey.privateKey);
    const newToken = await sign('new', newKey.privateKey);
    await verifySessionToken(oldToken, { portalUrl });
    const failures = await Promise.allSettled([
        verifySessionToken(newToken, { portalUrl }),
        verifySessionToken(newToken, { portalUrl }),
    ]);
    expect(failures.every((item) => item.status === 'rejected')).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect((await verifySessionToken(oldToken, { portalUrl })).sub).toBe('user-1');
    await expect(verifySessionToken(newToken, { portalUrl })).rejects.toThrow('retry shortly');
    expect(fetchMock).toHaveBeenCalledTimes(2);
    vi.advanceTimersByTime(30_000);
    await expect(verifySessionToken(newToken, { portalUrl })).rejects.toThrow('Invalid Koamishin JWKS document');
    expect((await verifySessionToken(oldToken, { portalUrl })).sub).toBe('user-1');
    vi.advanceTimersByTime(30_000);
    await expect(verifySessionToken(newToken, { portalUrl })).rejects.toThrow('Invalid Koamishin JWKS document');
    expect((await verifySessionToken(oldToken, { portalUrl })).sub).toBe('user-1');
    vi.advanceTimersByTime(30_000);
    await expect(verifySessionToken(newToken, { portalUrl })).rejects.toThrow('Invalid Koamishin JWKS document');
    expect((await verifySessionToken(oldToken, { portalUrl })).sub).toBe('user-1');
    const emptyKidToken = await sign('', oldKey.privateKey);
    await expect(verifySessionToken(emptyKidToken, { portalUrl })).rejects.toThrow('Invalid session token key ID');
    rotated = true;
    vi.advanceTimersByTime(30_000);
    expect((await verifySessionToken(newToken, { portalUrl })).sub).toBe('user-1');
    expect(fetchMock).toHaveBeenCalledTimes(6);
});

test('cookie names isolate Portal and public client identities without embedding secrets', () => {
    const base = getSessionCookieName('https://PORTAL.test/', 'pk_test_app');
    expect(base).toBe(getSessionCookieName('https://portal.test', 'pk_test_app'));
    expect(base).not.toBe(getSessionCookieName('https://portal.test', 'pk_live_app'));
    expect(base).not.toBe(getSessionCookieName('https://other.test', 'pk_test_app'));
    expect(base).not.toBe(getSessionCookieName('https://portal.test/path', 'pk_test_app'));
    expect(base).toMatch(/^__Host-koamishin_session_[A-Za-z0-9_-]+$/);
    expect(base).not.toContain('pk_test_app');
    expect(() => getSessionCookieName('https://portal.test', 'sk_private')).toThrow();
    expect(() => getSessionCookieName('https://user:password@portal.test', 'app')).toThrow();
});

test.each([
    ['http://localhost:80/', 'http://localhost'],
    ['http://LOCALHOST.:8080', 'http://localhost.:8080'],
    ['http://127.0.0.1:8080', 'http://127.0.0.1:8080'],
    ['http://127.42.1.2', 'http://127.42.1.2'],
    ['http://[::1]:8080', 'http://[::1]:8080'],
    ['https://auth.example.test/path', 'https://auth.example.test/path'],
])('accepts secure or loopback Portal URL %s', (input, expected) => {
    expect(normalizePortalUrl(input)).toBe(expected);
});

test.each([
    'http://auth.example.test',
    'http://localhost.evil.test',
    'http://api.localhost:8080',
    'http://127.0.0.1.evil.test',
    'http://[::2]',
    'http://0.0.0.0',
    'http://169.254.169.254',
    'http://user:pass@localhost',
    'http://localhost@evil.test',
])('rejects insecure or credential-bearing Portal URL %s', (input) => {
    expect(() => normalizePortalUrl(input)).toThrow();
});

test('different client cookies survive delayed mints and another client sign-out', async () => {
    const storage = new Map([
        ['koamishin:https%3A%2F%2Fportal.test:app-a:access_token', 'access-a'],
        ['koamishin:https%3A%2F%2Fportal.test:app-b:access_token', 'access-b'],
    ]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    vi.stubGlobal('window', { location: { protocol: 'https:' } });
    const jar = createCookieJar();
    jar.values.set(SESSION_COOKIE_NAME, 'legacy-cookie');
    vi.stubGlobal('document', jar.document);
    let finishA!: (value: unknown) => void;
    const minted = (sub: string) => ({
        ok: true,
        json: async () => ({ token: sessionTokenJwt(activeSessionTokenClaims({ sub })), token_type: 'Bearer', expires_in: 60, expires_at: 123 }),
    });
    vi.stubGlobal('fetch', vi.fn((_url: string, options: RequestInit) =>
        (options.headers as Record<string, string>).Authorization === 'Bearer access-a'
            ? new Promise((resolve) => { finishA = resolve; })
            : Promise.resolve(minted('user-b')),
    ));
    const appA = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app-a', redirectUri: 'https://app.test/callback' });
    const appB = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app-b', redirectUri: 'https://app.test/callback' });
    const pendingA = appA.syncSessionCookie();
    await appB.syncSessionCookie();
    const nameA = getSessionCookieName('https://portal.test', 'app-a');
    const nameB = getSessionCookieName('https://portal.test', 'app-b');
    const cookieB = jar.values.get(nameB);
    finishA(minted('user-a'));
    await pendingA;
    expect(jar.values.get(nameB)).toBe(cookieB);
    expect(decodeSessionToken(decodeURIComponent(jar.values.get(nameA)!)).sub).toBe('user-a');
    expect(decodeSessionToken(decodeURIComponent(cookieB!)).sub).toBe('user-b');
    await appA.signOut();
    expect(jar.values.has(nameA)).toBe(false);
    expect(jar.values.get(nameB)).toBe(cookieB);
    expect(jar.values.get(SESSION_COOKIE_NAME)).toBe('legacy-cookie');
    expect(jar.writes.every((value) => value.includes('Path=/') && value.includes('SameSite=Lax') && value.includes('; Secure'))).toBe(true);
});

test('canonical-equivalent Portal URLs share session fencing and cookie identity', async () => {
    const key = 'koamishin:https%3A%2F%2Fportal.test:app:access_token';
    const storage = new Map([[key, 'access-a']]);
    vi.stubGlobal('sessionStorage', {
        getItem: (name: string) => storage.get(name) ?? null,
        setItem: (name: string, value: string) => storage.set(name, value),
        removeItem: (name: string) => storage.delete(name),
    });
    const jar = createCookieJar();
    vi.stubGlobal('document', jar.document);
    let finishMint!: (value: unknown) => void;
    vi.stubGlobal('fetch', vi.fn(() => new Promise((resolve) => { finishMint = resolve; })));
    const first = createKoamishinClient({ portalUrl: 'https://PORTAL.test:443/', clientId: 'app', redirectUri: 'https://app.test/callback' });
    const second = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    expect(first.getStoredAccessToken()).toBe('access-a');
    const mint = first.syncSessionCookie();
    await second.signOut();
    finishMint({ ok: true, json: async () => ({
        token: sessionTokenJwt(activeSessionTokenClaims({ iss: 'https://PORTAL.test:443/' })),
        token_type: 'Bearer', expires_in: 60, expires_at: 123,
    }) });
    await expect(mint).rejects.toThrow('Session changed');
    expect(jar.values.has(getSessionCookieName('https://portal.test', 'app'))).toBe(false);
});

test('same-client tabs still share their cookie namespace', async () => {
    const key = 'koamishin:https%3A%2F%2Fportal.test:app:access_token';
    const tabA = new Map([[key, 'access-a']]);
    const tabB = new Map([[key, 'access-b']]);
    let active = tabA;
    vi.stubGlobal('sessionStorage', {
        getItem: (name: string) => active.get(name) ?? null,
        setItem: (name: string, value: string) => active.set(name, value),
        removeItem: (name: string) => active.delete(name),
    });
    vi.stubGlobal('window', { location: { protocol: 'http:', hostname: 'localhost' } });
    const jar = createCookieJar();
    vi.stubGlobal('document', jar.document);
    vi.stubGlobal('fetch', vi.fn(async (_url: string, options: RequestInit) => ({
        ok: true, json: async () => ({
            token: sessionTokenJwt(activeSessionTokenClaims({ sub: (options.headers as Record<string, string>).Authorization === 'Bearer access-a' ? 'user-a' : 'user-b' })),
            token_type: 'Bearer', expires_in: 60, expires_at: 123,
        }),
    })));
    const config = { portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' };
    const clientA = createKoamishinClient(config);
    const clientB = createKoamishinClient(config);
    await clientA.syncSessionCookie();
    active = tabB;
    await clientB.syncSessionCookie();
    const name = getSessionCookieName(config.portalUrl, config.clientId);
    expect(decodeSessionToken(decodeURIComponent(jar.values.get(name)!)).sub).toBe('user-b');
    active = tabA;
    await clientA.signOut();
    expect(jar.values.has(name)).toBe(false);
    expect(jar.writes.every((value) => value.includes('; Secure'))).toBe(true);
});

test('syncSessionCookie writes and signOut clears the scoped session cookie', async () => {
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
    const mintedJwt = sessionTokenJwt(activeSessionTokenClaims());
    vi.stubGlobal(
        'fetch',
        vi.fn(async () => ({
            ok: true,
            json: async () => ({
                token: mintedJwt,
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
    expect(doc.cookie).toContain(`${getSessionCookieName('https://portal.test', 'pk_test_123')}=${mintedJwt}`);

    client.signOut();
    expect(doc.cookie).toContain(`${getSessionCookieName('https://portal.test', 'pk_test_123')}=; Path=/; Max-Age=0`);
});

test('a session token mint started before sign-out cannot restore the cookie', async () => {
    const storage = new Map<string, string>([
        ['koamishin:https%3A%2F%2Fportal.test:app:access_token', 'access'],
    ]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const doc = { cookie: '' };
    vi.stubGlobal('document', doc);
    let finishMint!: (value: unknown) => void;
    vi.stubGlobal('fetch', vi.fn(() => new Promise((resolve) => { finishMint = resolve; })));
    const client = createKoamishinClient({
        portalUrl: 'https://portal.test',
        clientId: 'app',
        redirectUri: 'https://app.test/callback',
    });
    const mint = client.syncSessionCookie();
    await client.signOut();
    finishMint({ ok: true, json: async () => ({ token: sessionTokenJwt(activeSessionTokenClaims()), token_type: 'Bearer', expires_in: 60, expires_at: 123 }) });
    await expect(mint).rejects.toThrow('Session changed');
    expect(doc.cookie).toContain(`${getSessionCookieName('https://portal.test', 'app')}=; Path=/; Max-Age=0`);
});

test('a blocked cookie write is reported', async () => {
    vi.stubGlobal('sessionStorage', { getItem: () => 'access' });
    vi.stubGlobal('document', {
        get cookie() { return ''; },
        set cookie(_value: string) {},
    });
    vi.stubGlobal('fetch', vi.fn(async () => ({
        ok: true,
        json: async () => ({ token: sessionTokenJwt(activeSessionTokenClaims()), token_type: 'Bearer', expires_in: 60, expires_at: 123 }),
    })));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    await expect(client.syncSessionCookie()).rejects.toThrow('Session cookie could not be written');
});

test('session cookie writes reject insecure non-loopback origins', async () => {
    vi.stubGlobal('sessionStorage', { getItem: () => 'access' });
    vi.stubGlobal('window', { location: { protocol: 'http:', hostname: 'example.test' } });
    const doc = { cookie: '' };
    vi.stubGlobal('document', doc);
    vi.stubGlobal('fetch', vi.fn(async () => ({
        ok: true, json: async () => ({ token: sessionTokenJwt(activeSessionTokenClaims()), token_type: 'Bearer', expires_in: 60, expires_at: 123 }),
    })));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    await expect(client.syncSessionCookie()).rejects.toThrow('require HTTPS or a loopback');
    expect(doc.cookie).toBe('');
});

test('cookie Max-Age is an integer bounded by the JWT lifetime', async () => {
    vi.stubGlobal('sessionStorage', { getItem: () => 'access' });
    const doc = { cookie: '' };
    vi.stubGlobal('document', doc);
    vi.stubGlobal('fetch', vi.fn(async () => ({
        ok: true,
        json: async () => ({ token: sessionTokenJwt(activeSessionTokenClaims()), token_type: 'Bearer', expires_in: 3600.5, expires_at: 123 }),
    })));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    await client.syncSessionCookie();
    const maxAge = Number(/Max-Age=(\d+)/.exec(doc.cookie)?.[1]);
    expect(Number.isInteger(maxAge)).toBe(true);
    expect(maxAge).toBeGreaterThan(0);
    expect(maxAge).toBeLessThanOrEqual(60);
});

test.each([
    'not-a-jwt',
    `${b64url('{"alg":"none"}')}.${b64url(JSON.stringify(activeSessionTokenClaims()))}.c2ln`,
    `${b64url('{"alg":"RS256","kid":""}')}.${b64url(JSON.stringify(activeSessionTokenClaims()))}.c2ln`,
    sessionTokenJwt(activeSessionTokenClaims({ iss: 'https://other.test' })),
    sessionTokenJwt(activeSessionTokenClaims({ sid: '' })),
    sessionTokenJwt(activeSessionTokenClaims({ sub: '' })),
    sessionTokenJwt(activeSessionTokenClaims({ exp: Math.floor(Date.now() / 1000) - 1 })),
    sessionTokenJwt(activeSessionTokenClaims({ nbf: Math.floor(Date.now() / 1000) + 60 })),
    sessionTokenJwt(activeSessionTokenClaims({ exp: Math.floor(Date.now() / 1000) + 3600 })),
    sessionTokenJwt(activeSessionTokenClaims({ iat: Math.floor(Date.now() / 1000) + 20 })),
    sessionTokenJwt(activeSessionTokenClaims({ nbf: Math.floor(Date.now() / 1000) + 60, exp: Math.floor(Date.now() / 1000) + 60 })),
    `${b64url('{"alg":"RS256"}')}.${b64url(JSON.stringify(activeSessionTokenClaims()))}.a`,
])('an invalid minted JWT is rejected before the session cookie is written', async (jwt) => {
    vi.stubGlobal('sessionStorage', { getItem: () => 'access' });
    const doc = { cookie: '' };
    vi.stubGlobal('document', doc);
    vi.stubGlobal('fetch', vi.fn(async () => ({
        ok: true,
        json: async () => ({ token: jwt, token_type: 'Bearer', expires_in: 60, expires_at: 123 }),
    })));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    await expect(client.syncSessionCookie()).rejects.toThrow('Invalid minted session token');
    expect(doc.cookie).toBe('');
});

test.each(['userinfo', 'session-token'])('malformed successful %s responses do not leak body text', async (endpoint) => {
    vi.stubGlobal('sessionStorage', { getItem: () => 'access' });
    vi.stubGlobal('fetch', vi.fn(async () => ({
        ok: true,
        json: async () => { throw new SyntaxError('sentinel-secret'); },
    })));
    const client = createKoamishinClient({ portalUrl: 'https://portal.test', clientId: 'app', redirectUri: 'https://app.test/callback' });
    const result = await (endpoint === 'userinfo' ? client.getUser() : client.getSessionToken()).catch((error: Error) => error);
    expect(result.message).not.toContain('sentinel-secret');
    expect(result.message).toBe(endpoint === 'userinfo' ? 'Failed to retrieve user claims. Retry later.' : 'Invalid session token response.');
});

test('lifecycle transition hooks notify token exchange, refresh, sign-out, generation changes, and invalidation', async () => {
    const storage = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    const location = { href: 'https://app.test/start', search: '' };
    vi.stubGlobal('window', { location });
    vi.stubGlobal('document', { cookie: '' });

    const fetchMock = vi.fn(async (url: string, options?: RequestInit) => {
        if (url.endsWith('/revoke-family')) return { status: 204 };
        if (url.endsWith('/userinfo')) return { ok: true, json: async () => ({ sub: 'user-123' }) };
        const grant = (options?.body as URLSearchParams).get('grant_type');
        return {
            ok: true,
            json: async () =>
                grant === 'authorization_code'
                    ? { access_token: 'acc-1', refresh_token: 'ref-1', revocation_token: 'rev-1' }
                    : { access_token: 'acc-2', refresh_token: 'ref-2', revocation_token: 'rev-2' },
        };
    });
    vi.stubGlobal('fetch', fetchMock);

    const events: AuthTransitionEvent[] = [];
    const client = createKoamishinClient({
        portalUrl: 'https://portal.test',
        clientId: 'app',
        redirectUri: 'https://app.test/callback',
        onTransition: (event) => {
            events.push(event);
        },
    });

    // 1. Sign-in redirect + callback exchange
    await client.redirectToSignIn();
    location.search = `?code=auth-code&state=${new URL(location.href).searchParams.get('state')}`;
    await client.handleRedirectCallback();

    const genAfterExchange = events.find((e) => e.type === 'token_exchange');
    expect(genAfterExchange).toBeDefined();
    expect(genAfterExchange?.type === 'token_exchange' && genAfterExchange.tokens.access_token).toBe('acc-1');
    expect(events.some((e) => e.type === 'generation_change')).toBe(true);

    // 2. Token refresh
    await client.refreshToken();
    const refreshEvent = events.find((e) => e.type === 'token_refresh');
    expect(refreshEvent).toBeDefined();
    expect(refreshEvent?.type === 'token_refresh' && refreshEvent.tokens.access_token).toBe('acc-2');

    // 3. Sign-out
    await client.signOut();
    const signOutEvent = events.find((e) => e.type === 'sign_out');
    expect(signOutEvent).toBeDefined();
    expect(signOutEvent?.type === 'sign_out' && signOutEvent.result.status).toBe('revoked');

    // 4. Session invalidation
    storage.set('koamishin:https%3A%2F%2Fportal.test:app:access_token', 'acc-manual');
    const invalidated = client.invalidateSession('acc-manual');
    expect(invalidated).toBe(true);
    const invalidateEvent = events.find((e) => e.type === 'session_invalidated');
    expect(invalidateEvent).toBeDefined();
});

test('lifecycle transition hooks report refresh failure and honor unregister', async () => {
    const storage = new Map<string, string>([
        ['koamishin:https%3A%2F%2Fportal.test:app:access_token', 'acc-old'],
        ['koamishin:https%3A%2F%2Fportal.test:app:refresh_token', 'ref-bad'],
    ]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    vi.stubGlobal('fetch', vi.fn(async () => ({
        ok: false,
        status: 400,
        json: async () => ({ error: 'invalid_grant' }),
    })));

    const client = createKoamishinClient({
        portalUrl: 'https://portal.test',
        clientId: 'app',
        redirectUri: 'https://app.test/callback',
    });

    const received: AuthTransitionEvent[] = [];
    const unsubscribe = client.onTransition((event) => {
        received.push(event);
    });

    await expect(client.refreshToken()).rejects.toThrow('The refresh grant is invalid');
    expect(received.some((e) => e.type === 'refresh_failure')).toBe(true);

    // Unregister stops events
    unsubscribe();
    const countBefore = received.length;
    client.invalidateSession('acc-old');
    expect(received.length).toBe(countBefore);
});

test('errors in transition listeners do not disrupt core client operations', async () => {
    const storage = new Map<string, string>([
        ['koamishin:https%3A%2F%2Fportal.test:app:access_token', 'acc-test'],
    ]);
    vi.stubGlobal('sessionStorage', {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
    });
    vi.stubGlobal('document', { cookie: '' });

    const client = createKoamishinClient({
        portalUrl: 'https://portal.test',
        clientId: 'app',
        redirectUri: 'https://app.test/callback',
        onTransition: () => {
            throw new Error('Listener bomb');
        },
    });

    expect(() => client.invalidateSession('acc-test')).not.toThrow();
});

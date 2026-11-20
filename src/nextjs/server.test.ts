import { afterEach, beforeEach, expect, test, vi } from 'vitest';

const request = vi.hoisted(() => ({
    headers: new Headers(),
    cookie: undefined as string | undefined,
    cookieName: undefined as string | undefined,
}));

vi.mock('next/headers', () => ({
    headers: async () => request.headers,
    cookies: async () => ({
        get: (name: string) => request.cookie && name === request.cookieName ? { value: request.cookie } : undefined,
    }),
}));
vi.mock('next/server', () => ({
    NextResponse: {
        next: () => new Response(null),
        redirect: () => new Response(null, { status: 302 }),
    },
}));

import { auth, getSessionCookieName, koamishinMiddleware, SESSION_COOKIE_NAME } from './server';

beforeEach(() => {
    request.headers = new Headers();
    request.cookie = undefined;
    request.cookieName = getSessionCookieName('https://portal.test', 'app-client');
    vi.stubEnv('NEXT_PUBLIC_KOAMISHIN_CLIENT_ID', undefined);
    vi.stubEnv('NEXT_PUBLIC_KOAMISHIN_PUBLISHABLE_KEY', undefined);
    vi.stubEnv('NEXT_PUBLIC_KOAMISHIN_PORTAL_URL', undefined);
    vi.stubEnv('KOAMISHIN_CLIENT_ID', 'app-client');
    vi.stubEnv('KOAMISHIN_PUBLISHABLE_KEY', undefined);
    vi.stubEnv('KOAMISHIN_PORTAL_URL', undefined);
    vi.stubEnv('NEXT_PUBLIC_KOAMISHIN_APPLICATION_ID', undefined);
    vi.stubEnv('NEXT_PUBLIC_KOAMISHIN_ENVIRONMENT', undefined);
    vi.stubEnv('KOAMISHIN_APPLICATION_ID', 'app-one');
    vi.stubEnv('KOAMISHIN_ENVIRONMENT', 'production');
});

afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
});

test.each(['application', 'environment'])('server authentication fails explicitly without required %s configuration', async (missing) => {
    if (missing === 'application') {
        vi.stubEnv('NEXT_PUBLIC_KOAMISHIN_APPLICATION_ID', '  ');
        vi.stubEnv('KOAMISHIN_APPLICATION_ID', '');
    } else {
        vi.stubEnv('NEXT_PUBLIC_KOAMISHIN_ENVIRONMENT', ' ');
        vi.stubEnv('KOAMISHIN_ENVIRONMENT', '');
    }
    const options = { portalUrl: 'https://portal.test' };
    const message = missing === 'application' ? 'requires KOAMISHIN_APPLICATION_ID' : 'requires KOAMISHIN_ENVIRONMENT';
    await expect(auth(options)).rejects.toThrow(message);
    const middleware = koamishinMiddleware(options);
    await expect(middleware({
        headers: new Headers(),
        cookies: { get: () => undefined },
        nextUrl: new URL('https://app.test/'),
        url: 'https://app.test/',
    } as never)).rejects.toThrow(message);
});

test('server rejects missing or conflicting browser and server client identity', async () => {
    vi.stubEnv('KOAMISHIN_CLIENT_ID', undefined);
    await expect(auth({ portalUrl: 'https://portal.test' })).rejects.toThrow('requires the same public client identifier');
    vi.stubEnv('NEXT_PUBLIC_KOAMISHIN_CLIENT_ID', 'browser-client');
    vi.stubEnv('KOAMISHIN_CLIENT_ID', 'server-client');
    await expect(auth({ portalUrl: 'https://portal.test' })).rejects.toThrow('client ID configuration conflicts');
});

test('server rejects an explicit Portal URL that conflicts with server configuration', async () => {
    vi.stubEnv('KOAMISHIN_PORTAL_URL', 'https://other-portal.test');
    const options = { portalUrl: 'https://portal.test' };
    await expect(auth(options)).rejects.toThrow('Portal URL differs');
    const middleware = koamishinMiddleware(options);
    await expect(middleware({
        headers: new Headers(), cookies: { get: () => undefined },
        nextUrl: new URL('https://app.test/'), url: 'https://app.test/',
    } as never)).rejects.toThrow('Portal URL differs');
});

test('server accepts equivalent canonical Portal URLs', async () => {
    vi.stubEnv('KOAMISHIN_PORTAL_URL', 'https://portal.test/');
    expect(await auth({ portalUrl: 'https://portal.test' })).toMatchObject({
        isAuthenticated: false,
    });
});

test.each(['application', 'environment'])('server rejects conflicting public/server %s configuration in both entry points', async (field) => {
    if (field === 'application') vi.stubEnv('NEXT_PUBLIC_KOAMISHIN_APPLICATION_ID', 'other-app');
    else vi.stubEnv('NEXT_PUBLIC_KOAMISHIN_ENVIRONMENT', 'other-environment');
    const options = { portalUrl: 'https://portal.test' };
    await expect(auth(options)).rejects.toThrow('configuration conflicts');
    const middleware = koamishinMiddleware(options);
    await expect(middleware({
        headers: new Headers(), cookies: { get: () => undefined },
        nextUrl: new URL('https://app.test/'), url: 'https://app.test/',
    } as never)).rejects.toThrow('configuration conflicts');
});

test('server rejects conflicting identifiers and key-inferred environment', async () => {
    const portalUrl = 'https://portal.test';
    await expect(auth({ portalUrl, publishableKey: 'pk_live_a', clientId: 'another-client' })).rejects.toThrow('conflict');
    vi.stubEnv('KOAMISHIN_ENVIRONMENT', undefined);
    vi.stubEnv('KOAMISHIN_CLIENT_ID', 'pk_live_a');
    await expect(auth({ portalUrl, publishableKey: 'pk_live_a', clientId: 'pk_live_a', environment: 'not-production' })).rejects.toThrow('conflicts with the publishable key environment');
});

test.each(['clientId', 'publishableKey'])('server rejects explicit %s conflicting with server-only configuration', async (field) => {
    const portalUrl = 'https://portal.test';
    const options = field === 'clientId'
        ? { portalUrl, clientId: 'other-client' }
        : { portalUrl, publishableKey: 'pk_live_b' };
    if (field === 'publishableKey') {
        vi.stubEnv('KOAMISHIN_CLIENT_ID', undefined);
        vi.stubEnv('KOAMISHIN_PUBLISHABLE_KEY', 'pk_live_a');
    }
    await expect(auth(options)).rejects.toThrow('configuration conflicts');
    const middleware = koamishinMiddleware(options);
    await expect(middleware({
        headers: new Headers(), cookies: { get: () => undefined },
        nextUrl: new URL('https://app.test/'), url: 'https://app.test/',
    } as never)).rejects.toThrow('configuration conflicts');
});

test('auth ignores forged middleware identity headers without a verified cookie', async () => {
    request.headers.set('x-koamishin-auth-status', 'signed-in');
    request.headers.set('x-koamishin-claims', JSON.stringify({ sub: 'victim', sid: 'forged' }));
    expect(await auth({ portalUrl: 'https://portal.test' })).toMatchObject({
        isAuthenticated: false,
        userId: null,
        sessionClaims: null,
    });
});

test.each(['cookie', 'bearer'])('auth rejects an invalid %s token even with forged claims headers', async (source) => {
    request.headers.set('x-koamishin-auth-status', 'signed-in');
    request.headers.set('x-koamishin-claims', JSON.stringify({ sub: 'victim', sid: 'forged' }));
    if (source === 'cookie') request.cookie = 'not-a-jwt';
    else request.headers.set('authorization', 'Bearer not-a-jwt');
    expect(await auth({ portalUrl: 'https://portal.test' })).toMatchObject({
        isAuthenticated: false,
        userId: null,
    });
});

test('a custom middleware response does not make caller-supplied identity trusted', async () => {
    request.headers.set('x-koamishin-auth-status', 'signed-in');
    request.headers.set('x-koamishin-claims', JSON.stringify({ sub: 'victim', sid: 'forged' }));
    const middleware = koamishinMiddleware(async () => new Response(null), {
        portalUrl: 'https://portal.test',
    });
    await middleware({
        headers: request.headers,
        cookies: { get: () => undefined },
        nextUrl: new URL('https://app.test/private'),
        url: 'https://app.test/private',
    } as never);
    expect((await auth({ portalUrl: 'https://portal.test' })).isAuthenticated).toBe(false);
});

test('middleware treats a malformed encoded cookie as unauthenticated', async () => {
    const middleware = koamishinMiddleware(async (authFn) => {
        expect((await authFn()).isAuthenticated).toBe(false);
        return new Response(null);
    }, { portalUrl: 'https://portal.test' });
    await expect(middleware({
        headers: new Headers(),
        cookies: { get: () => ({ value: '%bad%' }) },
        nextUrl: new URL('https://app.test/private'),
        url: 'https://app.test/private',
    } as never)).resolves.toBeInstanceOf(Response);
});

test.each(['cookie', 'bearer'])('auth verifies the %s token rather than forwarded claims', async (source) => {
    const pair = await crypto.subtle.generateKey(
        { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true,
        ['sign', 'verify'],
    );
    const key = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const encode = (value: unknown) => b64(new TextEncoder().encode(JSON.stringify(value)));
    const now = Math.floor(Date.now() / 1000);
    const portalUrl = `https://${source}.portal.test`;
    request.cookieName = getSessionCookieName(portalUrl, 'app-client');
    const input = `${encode({ alg: 'RS256', kid: 'test' })}.${encode({
        sub: 'real-user', sid: 'real-session', v: '2', iss: portalUrl,
        iat: now, nbf: now, exp: now + 60, application_id: 'app-one', environment: 'production',
    })}`;
    const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, new TextEncoder().encode(input));
    const token = `${input}.${b64(new Uint8Array(signature))}`;
    vi.stubGlobal('fetch', vi.fn(async () => ({
        ok: true, json: async () => ({ keys: [{ ...key, kid: 'test' }] }),
    })));
    request.headers.set('x-koamishin-auth-status', 'signed-in');
    request.headers.set('x-koamishin-claims', JSON.stringify({ sub: 'victim', sid: 'forged' }));
    if (source === 'cookie') request.cookie = token;
    else request.headers.set('authorization', `Bearer ${token}`);
    expect(await auth({ portalUrl })).toMatchObject({
        isAuthenticated: true,
        userId: 'real-user',
        sessionId: 'real-session',
    });
    if (source === 'bearer') {
        vi.stubEnv('KOAMISHIN_CLIENT_ID', 'pk_live_example');
        expect((await auth({ portalUrl, publishableKey: 'pk_live_example', clientId: 'pk_live_example', environment: '' })).isAuthenticated).toBe(true);
        vi.stubEnv('KOAMISHIN_CLIENT_ID', 'app-client');
    }

    const checkBoth = async (expected: boolean, applicationId?: string) => {
        expect((await auth({ portalUrl, applicationId })).isAuthenticated).toBe(expected);
        const middleware = koamishinMiddleware(async (authFn) => {
            expect((await authFn()).isAuthenticated).toBe(expected);
            return new Response(null);
        }, { portalUrl, applicationId });
        await middleware({
            headers: request.headers,
            cookies: { get: (name: string) => request.cookie && name === request.cookieName ? { value: request.cookie } : undefined },
            nextUrl: new URL('https://app.test/private'),
            url: 'https://app.test/private',
        } as never);
    };
    vi.stubEnv('NEXT_PUBLIC_KOAMISHIN_APPLICATION_ID', '');
    vi.stubEnv('KOAMISHIN_APPLICATION_ID', 'app-two');
    await checkBoth(false);
    vi.stubEnv('NEXT_PUBLIC_KOAMISHIN_APPLICATION_ID', undefined);
    await checkBoth(false);
    vi.stubEnv('KOAMISHIN_APPLICATION_ID', 'app-one');
    await checkBoth(true);
    vi.stubEnv('NEXT_PUBLIC_KOAMISHIN_APPLICATION_ID', 'app-two');
    await expect(checkBoth(false)).rejects.toThrow('application ID configuration conflicts');
    await expect(checkBoth(true, 'app-one')).rejects.toThrow('application ID configuration conflicts');

    vi.stubEnv('NEXT_PUBLIC_KOAMISHIN_APPLICATION_ID', 'app-one');
    const otherInput = `${encode({ alg: 'RS256', kid: 'test' })}.${encode({
        sub: 'cookie-user', sid: 'cookie-session', v: '2', iss: portalUrl,
        iat: now, nbf: now, exp: now + 60, application_id: 'app-one', environment: 'production',
    })}`;
    const otherSignature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, new TextEncoder().encode(otherInput));
    request.cookie = `${otherInput}.${b64(new Uint8Array(otherSignature))}`;
    request.headers.set('authorization', `Bearer ${token}`);
    await checkBoth(true);
    expect((await auth({ portalUrl })).userId).toBe('real-user');
    request.cookie = '%bad%';
    await checkBoth(true);
    request.cookie = token;
    request.headers.set('authorization', 'Bearer invalid-token');
    await checkBoth(false);
    request.headers.set('authorization', 'Bearer ');
    await checkBoth(false);
    request.headers.set('authorization', 'Basic invalid');
    await checkBoth(false);
    request.headers.delete('authorization');
    await checkBoth(true);
    request.cookieName = SESSION_COOKIE_NAME;
    await checkBoth(false);
    request.cookieName = getSessionCookieName(portalUrl, 'another-client');
    await checkBoth(false);
    request.cookieName = getSessionCookieName(portalUrl, 'app-client');
    await checkBoth(true);
    for (const identity of [{ sub: '', sid: 'sid' }, { sub: 'user', sid: undefined }]) {
        const invalidInput = `${encode({ alg: 'RS256', kid: 'test' })}.${encode({
            ...identity, v: '2', iss: portalUrl, iat: now, nbf: now, exp: now + 60,
            application_id: 'app-one', environment: 'production',
        })}`;
        const invalidSignature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, new TextEncoder().encode(invalidInput));
        request.headers.set('authorization', `Bearer ${invalidInput}.${b64(new Uint8Array(invalidSignature))}`);
        await checkBoth(false);
    }
});

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { cookies, headers } from 'next/headers';
import {
    SESSION_COOKIE_NAME,
    KoamishinClient,
    getSessionCookieName,
    normalizePortalUrl,
    SessionTokenClaims,
    decodeSessionToken,
    verifySessionToken,
} from '../index';
import { assertCompatibleClientIdentifiers } from './config';

export { SESSION_COOKIE_NAME, getSessionCookieName, decodeSessionToken, verifySessionToken };
export type { SessionTokenClaims };

const HEADER_AUTH_STATUS = 'x-koamishin-auth-status';
const HEADER_USER_ID = 'x-koamishin-user-id';
const HEADER_SESSION_ID = 'x-koamishin-session-id';
const HEADER_CLAIMS = 'x-koamishin-claims';

export interface KoamishinAuthObject {
    userId: string | null;
    sessionId: string | null;
    sessionClaims: SessionTokenClaims | null;
    isAuthenticated: boolean;
    redirectToSignIn: (options?: { returnBackUrl?: string }) => Response;
}

export interface KoamishinMiddlewareAuth {
    (): Promise<KoamishinAuthObject>;
    protect: (options?: {
        unauthenticatedUrl?: string;
    }) => Promise<KoamishinAuthObject>;
}

export interface KoamishinMiddlewareOptions {
    portalUrl?: string;
    publishableKey?: string;
    clientId?: string;
    applicationId?: string;
    environment?: string;
    signInUrl?: string;
}

export type KoamishinMiddlewareHandler = (
    auth: KoamishinMiddlewareAuth,
    request: NextRequest,
) => Promise<Response | void> | Response | void;

class KoamishinRedirectError extends Error {
    constructor(public readonly response: Response) {
        super('KOAMISHIN_REDIRECT');
    }
}

function resolveEnvConfig(options?: KoamishinMiddlewareOptions) {
    const portalUrl =
        options?.portalUrl ??
        process.env.NEXT_PUBLIC_KOAMISHIN_PORTAL_URL ??
        process.env.KOAMISHIN_PORTAL_URL ??
        '';
    const publishableKey =
        options?.publishableKey ??
        process.env.NEXT_PUBLIC_KOAMISHIN_PUBLISHABLE_KEY ??
        process.env.KOAMISHIN_PUBLISHABLE_KEY ??
        '';
    const clientId =
        options?.clientId ??
        process.env.NEXT_PUBLIC_KOAMISHIN_CLIENT_ID ??
        process.env.KOAMISHIN_CLIENT_ID ??
        '';
    const applicationId = [
        options?.applicationId,
        process.env.NEXT_PUBLIC_KOAMISHIN_APPLICATION_ID,
        process.env.KOAMISHIN_APPLICATION_ID,
    ].find((value) => value?.trim())?.trim();
    const environment = [
        options?.environment,
        process.env.NEXT_PUBLIC_KOAMISHIN_ENVIRONMENT,
        process.env.KOAMISHIN_ENVIRONMENT,
    ].find((value) => value?.trim())?.trim();

    return {
        portalUrl,
        publishableKey,
        clientId,
        applicationId,
        environment,
    };
}

function requireServerConfig(options?: KoamishinMiddlewareOptions) {
    const config = resolveEnvConfig(options);
    if (!config.portalUrl.trim()) {
        throw new Error('Koamishin server authentication requires a Portal URL.');
    }
    if (!config.applicationId) {
        throw new Error('Koamishin server authentication requires KOAMISHIN_APPLICATION_ID or an applicationId option.');
    }
    assertCompatibleClientIdentifiers(config.publishableKey, config.clientId);
    const identifier = config.publishableKey.trim() || config.clientId.trim();
    if (!identifier || identifier.startsWith('sk_')) {
        throw new Error('Koamishin server authentication requires the same public client identifier configured in the browser.');
    }
    for (const [label, values] of [
        ['application ID', [options?.applicationId, process.env.NEXT_PUBLIC_KOAMISHIN_APPLICATION_ID, process.env.KOAMISHIN_APPLICATION_ID]],
        ['environment', [options?.environment, process.env.NEXT_PUBLIC_KOAMISHIN_ENVIRONMENT, process.env.KOAMISHIN_ENVIRONMENT]],
        ['client ID', [options?.clientId, process.env.NEXT_PUBLIC_KOAMISHIN_CLIENT_ID, process.env.KOAMISHIN_CLIENT_ID]],
        ['publishable key', [options?.publishableKey, process.env.NEXT_PUBLIC_KOAMISHIN_PUBLISHABLE_KEY, process.env.KOAMISHIN_PUBLISHABLE_KEY]],
    ] as const) {
        if (new Set(values.map((value) => value?.trim()).filter(Boolean)).size > 1) {
            throw new Error(`Koamishin ${label} configuration conflicts between options and environment variables.`);
        }
    }
    const inferredEnvironment = new KoamishinClient({
        portalUrl: config.portalUrl,
        clientId: identifier,
        redirectUri: 'http://localhost',
    }).getEnvironment();
    if (config.environment && inferredEnvironment && config.environment !== inferredEnvironment) {
        throw new Error('Koamishin environment conflicts with the publishable key environment.');
    }
    for (const [label, publicValue, serverValue] of [
        ['publishable key', process.env.NEXT_PUBLIC_KOAMISHIN_PUBLISHABLE_KEY, process.env.KOAMISHIN_PUBLISHABLE_KEY],
        ['client ID', process.env.NEXT_PUBLIC_KOAMISHIN_CLIENT_ID, process.env.KOAMISHIN_CLIENT_ID],
    ]) {
        if (publicValue?.trim() && serverValue?.trim() && publicValue.trim() !== serverValue.trim()) {
            throw new Error(`Koamishin ${label} differs between browser and server configuration.`);
        }
    }
    const browserIdentifier = process.env.NEXT_PUBLIC_KOAMISHIN_PUBLISHABLE_KEY?.trim() ||
        process.env.NEXT_PUBLIC_KOAMISHIN_CLIENT_ID?.trim();
    if (browserIdentifier && browserIdentifier !== identifier) {
        throw new Error('Koamishin client identifier differs between browser and server configuration.');
    }
    const portalUrls = [
        options?.portalUrl,
        process.env.NEXT_PUBLIC_KOAMISHIN_PORTAL_URL,
        process.env.KOAMISHIN_PORTAL_URL,
    ].filter((value): value is string => Boolean(value?.trim()))
        .map(normalizePortalUrl);
    if (new Set(portalUrls).size > 1) {
        throw new Error('Koamishin Portal URL differs between browser and server configuration.');
    }
    if (!config.environment && !identifier.startsWith('pk_test_') && !identifier.startsWith('pk_live_')) {
        throw new Error('Koamishin server authentication requires KOAMISHIN_ENVIRONMENT, an environment option, or a test/live publishable key.');
    }
    return config;
}

function selectSessionToken(cookie: string | undefined, authorization: string | null): string | null {
    if (authorization !== null) {
        return /^Bearer\s+(\S+)$/i.exec(authorization)?.[1] ?? null;
    }
    return cookie ? decodeURIComponent(cookie) : null;
}

function buildSignInRedirect(
    request: NextRequest,
    options?: KoamishinMiddlewareOptions,
    returnBackUrl?: string,
): Response {
    const targetUrl =
        returnBackUrl ?? `${request.nextUrl.pathname}${request.nextUrl.search}`;
    const baseSignIn = options?.signInUrl ?? '/';
    const redirectUrl = new URL(baseSignIn, request.url);
    redirectUrl.searchParams.set('auth', 'signin');
    redirectUrl.searchParams.set('redirect_url', targetUrl);
    return NextResponse.redirect(redirectUrl);
}

/**
 * Create a route matcher function (Clerk-style `createRouteMatcher(['/dashboard(.*)'])`).
 */
export function createRouteMatcher(
    patterns: Array<string | RegExp>,
): (request: NextRequest) => boolean {
    const regexes = patterns.map((pattern) => {
        if (pattern instanceof RegExp) {
            return pattern;
        }
        const normalized = pattern.startsWith('^')
            ? pattern
            : `^${pattern.replace(/\//g, '\\/')}$`;
        return new RegExp(normalized);
    });

    return (request: NextRequest): boolean => {
        const pathname =
            request.nextUrl?.pathname ?? new URL(request.url).pathname;
        return regexes.some((regex) => regex.test(pathname));
    };
}

/**
 * Next.js Proxy / Middleware for Koamishin authentication.
 *
 * Mirrors Clerk's `clerkMiddleware()`:
 * - By default leaves all routes public while verifying the client-scoped cookie
 *   offline against the Portal's JWKS document.
 * - Accepts an optional `(auth, req)` callback so specific routes can be
 *   protected via `await auth.protect()`.
 */
export function koamishinMiddleware(
    handlerOrOptions?: KoamishinMiddlewareHandler | KoamishinMiddlewareOptions,
    maybeOptions?: KoamishinMiddlewareOptions,
) {
    const handler =
        typeof handlerOrOptions === 'function' ? handlerOrOptions : undefined;
    const options =
        typeof handlerOrOptions === 'function'
            ? maybeOptions
            : handlerOrOptions;

    return async function proxy(request: NextRequest): Promise<Response> {
        const envConfig = requireServerConfig(options);
        const identifier = envConfig.publishableKey.trim() || envConfig.clientId.trim();
        const cookieToken = request.cookies.get(getSessionCookieName(envConfig.portalUrl, identifier))?.value;
        const authHeader = request.headers.get('authorization');
        let claims: SessionTokenClaims | null = null;

        if (envConfig.portalUrl) {
            try {
                const rawToken = selectSessionToken(cookieToken, authHeader);
                if (rawToken) {
                    claims = await verifySessionToken(rawToken, {
                        portalUrl: envConfig.portalUrl,
                        publishableKey: envConfig.publishableKey || undefined,
                        clientId: envConfig.clientId || undefined,
                        applicationId: envConfig.applicationId,
                        environment: envConfig.environment,
                    });
                }
            } catch {
                claims = null;
            }
        }

        const authObject: KoamishinAuthObject = {
            userId: claims?.sub ?? null,
            sessionId: claims?.sid ?? null,
            sessionClaims: claims,
            isAuthenticated: Boolean(claims?.sub),
            redirectToSignIn: (redirectOpts) =>
                buildSignInRedirect(
                    request,
                    options,
                    redirectOpts?.returnBackUrl,
                ),
        };

        const authFn = (async () => authObject) as KoamishinMiddlewareAuth;
        authFn.protect = async (protectOpts) => {
            if (!authObject.isAuthenticated) {
                const response = protectOpts?.unauthenticatedUrl
                    ? NextResponse.redirect(
                          new URL(protectOpts.unauthenticatedUrl, request.url),
                      )
                    : authObject.redirectToSignIn();
                throw new KoamishinRedirectError(response);
            }
            return authObject;
        };

        if (handler) {
            try {
                const customResponse = await handler(authFn, request);
                if (customResponse instanceof Response) {
                    return customResponse;
                }
            } catch (error) {
                if (error instanceof KoamishinRedirectError) {
                    return error.response;
                }
                throw error;
            }
        }

        const requestHeaders = new Headers(request.headers);
        requestHeaders.delete(HEADER_AUTH_STATUS);
        requestHeaders.delete(HEADER_USER_ID);
        requestHeaders.delete(HEADER_SESSION_ID);
        requestHeaders.delete(HEADER_CLAIMS);

        return NextResponse.next({
            request: {
                headers: requestHeaders,
            },
        });
    };
}

async function resolveAuth(options?: KoamishinMiddlewareOptions): Promise<{
    userId: string | null;
    sessionId: string | null;
    sessionClaims: SessionTokenClaims | null;
    isAuthenticated: boolean;
}> {
    const envConfig = requireServerConfig(options);
    const headerStore = await headers();
    const cookieStore = await cookies();
    const identifier = envConfig.publishableKey.trim() || envConfig.clientId.trim();
    const rawCookie = cookieStore.get(getSessionCookieName(envConfig.portalUrl, identifier))?.value;
    const authorization = headerStore.get('authorization');
    try {
        const rawToken = selectSessionToken(rawCookie, authorization);
        if (!rawToken) throw new Error('No session token.');
        const claims = await verifySessionToken(rawToken, {
            portalUrl: envConfig.portalUrl,
            publishableKey: envConfig.publishableKey || undefined,
            clientId: envConfig.clientId || undefined,
            applicationId: envConfig.applicationId,
            environment: envConfig.environment,
        });
        return {
            userId: claims.sub,
            sessionId: claims.sid,
            sessionClaims: claims,
            isAuthenticated: true,
        };
    } catch {
        return {
            userId: null,
            sessionId: null,
            sessionClaims: null,
            isAuthenticated: false,
        };
    }
}

/**
 * Read verified session claims inside Next.js Server Components, Route Handlers,
 * or Server Actions (Clerk-style `await auth()`).
 */
export async function auth(options?: KoamishinMiddlewareOptions): Promise<{
    userId: string | null;
    sessionId: string | null;
    sessionClaims: SessionTokenClaims | null;
    isAuthenticated: boolean;
}> {
    return resolveAuth(options);
}

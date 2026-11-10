import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { cookies, headers } from 'next/headers';
import {
    SESSION_COOKIE_NAME,
    SessionTokenClaims,
    decodeSessionToken,
    verifySessionToken,
} from '../index';

export { SESSION_COOKIE_NAME, decodeSessionToken, verifySessionToken };
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
    const applicationId =
        options?.applicationId ??
        process.env.NEXT_PUBLIC_KOAMISHIN_APPLICATION_ID ??
        process.env.KOAMISHIN_APPLICATION_ID;
    const environment =
        options?.environment ??
        process.env.NEXT_PUBLIC_KOAMISHIN_ENVIRONMENT ??
        process.env.KOAMISHIN_ENVIRONMENT;

    return {
        portalUrl,
        publishableKey,
        clientId,
        applicationId,
        environment,
    };
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
 * - By default leaves all routes public while verifying `__koamishin_session`
 *   offline against the Portal's JWKS document and forwarding claims to
 *   Server Components.
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
        const cookieToken = request.cookies.get(SESSION_COOKIE_NAME)?.value;
        const authHeader = request.headers.get('authorization');
        const bearerToken = authHeader?.startsWith('Bearer ')
            ? authHeader.slice(7).trim()
            : undefined;
        const rawToken = cookieToken
            ? decodeURIComponent(cookieToken)
            : bearerToken;

        const envConfig = resolveEnvConfig(options);
        let claims: SessionTokenClaims | null = null;

        if (rawToken && envConfig.portalUrl) {
            try {
                claims = await verifySessionToken(rawToken, {
                    portalUrl: envConfig.portalUrl,
                    publishableKey: envConfig.publishableKey || undefined,
                    clientId: envConfig.clientId || undefined,
                    applicationId: envConfig.applicationId,
                    environment: envConfig.environment,
                });
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
        requestHeaders.set(
            HEADER_AUTH_STATUS,
            authObject.isAuthenticated ? 'signed-in' : 'signed-out',
        );
        requestHeaders.set(HEADER_USER_ID, authObject.userId ?? '');
        requestHeaders.set(HEADER_SESSION_ID, authObject.sessionId ?? '');
        requestHeaders.set(HEADER_CLAIMS, claims ? JSON.stringify(claims) : '');

        return NextResponse.next({
            request: {
                headers: requestHeaders,
            },
        });
    };
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
    const headerStore = await headers();
    const status = headerStore.get(HEADER_AUTH_STATUS);
    const serializedClaims = headerStore.get(HEADER_CLAIMS);

    if (status === 'signed-in' && serializedClaims) {
        try {
            const parsed = JSON.parse(serializedClaims) as SessionTokenClaims;
            return {
                userId: parsed.sub,
                sessionId: parsed.sid,
                sessionClaims: parsed,
                isAuthenticated: true,
            };
        } catch {
            // Fall through to cookie verification
        }
    }

    const cookieStore = await cookies();
    const rawCookie = cookieStore.get(SESSION_COOKIE_NAME)?.value;
    if (!rawCookie) {
        return {
            userId: null,
            sessionId: null,
            sessionClaims: null,
            isAuthenticated: false,
        };
    }

    const envConfig = resolveEnvConfig(options);
    if (!envConfig.portalUrl) {
        return {
            userId: null,
            sessionId: null,
            sessionClaims: null,
            isAuthenticated: false,
        };
    }

    try {
        const claims = await verifySessionToken(decodeURIComponent(rawCookie), {
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

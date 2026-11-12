import { generatePkce, generateState } from './pkce';

export type KoamishinConfig = {
    portalUrl: string;
    redirectUri: string;
    scopes?: string[];
    onTransition?: AuthTransitionListener;
} & (
    | { publishableKey: string; clientId?: string }
    | { clientId: string; publishableKey?: string }
);

export interface KoamishinUser {
    sub: string;
    name: string;
    email: string;
    email_verified: boolean;
    picture?: string | null;
    roles: string[];
    permissions: string[];
    updated_at?: number;
    organization_id?: string;
    application_id?: string;
    environment?: 'development' | 'production' | string;
    public_metadata?: Record<string, unknown>;
}

export interface TokenResponse {
    token_type: string;
    expires_in: number;
    access_token: string;
    refresh_token?: string;
    revocation_token?: string;
    id_token?: string;
}

function isUsableTokenResponse(value: unknown): value is TokenResponse {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const token = value as Partial<TokenResponse>;
    return typeof token.access_token === 'string' && token.access_token.length > 0 &&
        (token.refresh_token === undefined || (typeof token.refresh_token === 'string' && token.refresh_token.length > 0)) &&
        (token.revocation_token === undefined || (typeof token.revocation_token === 'string' && token.revocation_token.length > 0));
}

export type SignOutResult =
    | { status: 'revoked' }
    | { status: 'reauthentication_required' }
    | { status: 'failed'; message: string };

export type AuthTransitionEvent =
    | {
          type: 'token_exchange';
          user: KoamishinUser;
          tokens: TokenResponse;
          generation: number;
      }
    | {
          type: 'token_refresh';
          tokens: TokenResponse;
          generation: number;
      }
    | {
          type: 'refresh_failure';
          error: unknown;
          generation: number;
      }
    | {
          type: 'sign_out';
          result: SignOutResult;
          generation: number;
      }
    | {
          type: 'session_invalidated';
          reason?: string;
          generation: number;
      }
    | {
          type: 'generation_change';
          from: number;
          to: number;
      };

export type AuthTransitionListener = (
    event: AuthTransitionEvent,
) => void | Promise<void>;

export class KoamishinRequestError extends Error {
    constructor(
        public readonly code: 'access_token_invalid' | 'invalid_grant' | 'unavailable',
        message: string,
    ) {
        super(message);
        this.name = 'KoamishinRequestError';
    }
}

const sessionGenerations = new Map<string, number>();
const refreshGenerations = new Map<string, number>();
const pendingSignOuts = new Map<string, Promise<SignOutResult>>();
const pendingCallbacks = new Map<string, number>();
const pendingRefreshes = new Map<string, number>();
const sessionMutationLocks = new Map<string, Promise<void>>();
const refreshFlights = new Map<string, Map<string, { generation: number; promise: Promise<TokenResponse> }>>();

async function withSessionLock<T>(key: string, action: () => Promise<T>): Promise<T> {
    const previous = sessionMutationLocks.get(key);
    let release!: () => void;
    const current = new Promise<void>((resolve) => { release = resolve; });
    sessionMutationLocks.set(key, current);
    if (previous) await previous;
    try {
        return await action();
    } finally {
        if (sessionMutationLocks.get(key) === current) sessionMutationLocks.delete(key);
        release();
    }
}

/** The mint response for a short-lived session token. */
export interface SessionToken {
    token: string;
    token_type: string;
    expires_in: number;
    expires_at: number;
}

/**
 * The claims carried by a session token, following Koamishin Auth's session
 * token version 2.
 */
export interface SessionTokenClaims {
    sub: string;
    iss: string;
    iat: number;
    nbf: number;
    exp: number;
    jti: string;
    sid: string;
    azp?: string;
    v: string;
    fva: [number, number];
    sts: 'active' | 'pending';
    tasks: string[];
    application_id?: string;
    environment?: string;
    o?: { id: string; slg: string; rol: string };
    act?: { iss: string; sid: string; sub: string };
}

/** Legacy unscoped cookie name. New clients never read or write this cookie. */
export const SESSION_COOKIE_NAME = '__koamishin_session';

function isLoopbackHostname(hostname: string): boolean {
    const host = hostname.toLowerCase().replace(/\.$/, '');
    return host === 'localhost' || host === '[::1]' ||
        /^127(?:\.\d{1,3}){3}$/.test(host);
}

/**
 * An injective, cookie-safe namespace for a Portal URL and OAuth client identifier.
 * Publishable keys are distinct per application environment; legacy client IDs
 * must likewise be unique within a Portal.
 */
export function normalizePortalUrl(portalUrl: string): string {
    try {
        const url = new URL(portalUrl.trim());
        if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
            throw new Error();
        }
        if (url.protocol === 'http:' && !isLoopbackHostname(url.hostname)) {
            throw new Error('insecure');
        }
        return `${url.origin}${url.pathname.replace(/\/+$/, '')}`;
    } catch (error) {
        if (error instanceof Error && error.message === 'insecure') {
            throw new Error('Koamishin Portal URL requires HTTPS unless the host is loopback.');
        }
        throw new Error('A valid Portal URL without credentials, query, or fragment is required for the session cookie.');
    }
}

export function getSessionCookieName(portalUrl: string, clientIdentifier: string): string {
    const identifier = clientIdentifier.trim();
    if (!identifier || identifier.startsWith('sk_')) {
        throw new Error('A Portal URL and client identifier are required for the session cookie.');
    }
    const portal = normalizePortalUrl(portalUrl);
    const bytes = new TextEncoder().encode(JSON.stringify([portal, identifier]));
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return `__Host-koamishin_session_${btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}`;
}

export interface JwksKey extends JsonWebKey {
    kty: string;
    alg?: string;
    use?: string;
    kid?: string;
    n?: string;
    e?: string;
}

export interface JwksDocument {
    keys: JwksKey[];
}

export interface VerifySessionTokenOptions {
    portalUrl: string;
    publishableKey?: string;
    clientId?: string;
    applicationId?: string;
    environment?: 'development' | 'production' | string;
    jwks?: JwksDocument;
    clockSkewSeconds?: number;
}

interface AuthenticationTransaction {
    verifier: string;
    createdAt: number;
}

export class KoamishinClient {
    protected portalUrl: string;
    protected clientId: string;
    protected publishableKey?: string;
    protected redirectUri: string;
    protected scopes: string[];
    protected transitionListeners: Set<AuthTransitionListener> = new Set();

    constructor(config: KoamishinConfig) {
        const publishableKey = config.publishableKey?.trim();
        const clientId = config.clientId?.trim();

        if (publishableKey && clientId && publishableKey !== clientId) {
            throw new Error(
                'Provide either publishableKey or clientId, or ensure both match.',
            );
        }

        const identifier = publishableKey || clientId || '';

        if (!identifier) {
            throw new Error(
                'A Koamishin publishableKey or clientId is required.',
            );
        }

        if (identifier.startsWith('sk_')) {
            throw new Error(
                'Secret keys (sk_...) must never be used in browser code. Use a publishableKey (pk_test_... or pk_live_...) instead.',
            );
        }

        this.portalUrl = normalizePortalUrl(config.portalUrl);
        this.clientId = identifier;
        this.publishableKey = identifier.startsWith('pk_')
            ? identifier
            : undefined;
        this.redirectUri = config.redirectUri;
        this.scopes = config.scopes ?? ['openid', 'profile', 'email', 'roles'];
        if (config.onTransition) {
            this.transitionListeners.add(config.onTransition);
        }
    }

    /**
     * Subscribe a listener to authentication lifecycle transitions.
     * Returns an unregister function.
     */
    onTransition(listener: AuthTransitionListener): () => void {
        this.transitionListeners.add(listener);
        return () => {
            this.transitionListeners.delete(listener);
        };
    }

    protected notifyTransition(event: AuthTransitionEvent): void {
        for (const listener of this.transitionListeners) {
            try {
                const res = listener(event);
                if (res && typeof (res as Promise<void>).catch === 'function') {
                    (res as Promise<void>).catch((err) => {
                        console.error('Error in auth transition listener:', err);
                    });
                }
            } catch (err) {
                console.error('Error in auth transition listener:', err);
            }
        }
    }

    protected incrementSessionGeneration(): number {
        const key = this.storageKey('session');
        const from = this.sessionGeneration();
        const to = from + 1;
        sessionGenerations.set(key, to);
        this.notifyTransition({
            type: 'generation_change',
            from,
            to,
        });
        return to;
    }

    /**
     * Return the target Portal environment inferred from a publishable key, or null for legacy client IDs.
     */
    getEnvironment(): 'development' | 'production' | null {
        if (this.clientId.startsWith('pk_test_')) {
            return 'development';
        }

        if (this.clientId.startsWith('pk_live_')) {
            return 'production';
        }

        return null;
    }

    /**
     * Redirect browser to Koamishin Portal authorization page with PKCE challenge.
     */
    async redirectToSignIn(): Promise<void> {
        return this.redirectToAuthentication(false);
    }

    /**
     * Open the hosted registration page for this application.
     */
    async redirectToSignUp(): Promise<void> {
        return this.redirectToAuthentication(true);
    }

    protected async redirectToAuthentication(signUp: boolean): Promise<void> {
        const generation = this.sessionGeneration();
        const { verifier, challenge } = await generatePkce();
        this.assertSessionGeneration(generation);
        const state = generateState();

        const transactions = Object.fromEntries(
            Object.entries(this.pendingTransactions()).slice(-9),
        );
        transactions[state] = { verifier, createdAt: Date.now() };
        sessionStorage.setItem(
            this.storageKey('oauth_transactions'),
            JSON.stringify(transactions),
        );

        const params = new URLSearchParams({
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            response_type: 'code',
            scope: this.scopes.join(' '),
            state,
            code_challenge: challenge,
            code_challenge_method: 'S256',
        });

        if (signUp) {
            params.set('screen_hint', 'signup');
        }

        window.location.href = `${this.portalUrl}/oauth/authorize?${params.toString()}`;
    }

    /**
     * Handle OAuth redirect callback on client app.
     */
    async handleRedirectCallback(shouldCommit?: () => boolean): Promise<{
        user: KoamishinUser;
        tokens: TokenResponse;
    }> {
        const key = this.storageKey('session');
        pendingCallbacks.set(key, (pendingCallbacks.get(key) ?? 0) + 1);
        try {
            return await this.completeRedirectCallback(shouldCommit);
        } finally {
            const remaining = (pendingCallbacks.get(key) ?? 1) - 1;
            if (remaining) pendingCallbacks.set(key, remaining);
            else pendingCallbacks.delete(key);
        }
    }

    protected async completeRedirectCallback(shouldCommit?: () => boolean): Promise<{
        user: KoamishinUser;
        tokens: TokenResponse;
    }> {
        const generation = this.sessionGeneration();
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');

        if (!code || !state) {
            throw new Error(
                'Callback URL missing code or state query parameters.',
            );
        }

        const transactions = this.pendingTransactions();
        const transaction = transactions[state];
        if (!transaction) {
            throw new Error('OAuth state mismatch. Request may be untrusted.');
        }
        delete transactions[state];
        sessionStorage.setItem(
            this.storageKey('oauth_transactions'),
            JSON.stringify(transactions),
        );

        let tokenResponse: Response;
        try {
            tokenResponse = await fetch(`${this.portalUrl}/oauth/token`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    grant_type: 'authorization_code',
                    client_id: this.clientId,
                    redirect_uri: this.redirectUri,
                    code_verifier: transaction.verifier,
                    code,
                }),
                redirect: 'error',
            });
        } catch {
            this.markRemoteOutcomeUnknown();
            throw new Error('Token exchange failed. Remote token issuance could not be confirmed.');
        }

        if (!tokenResponse.ok) {
            this.markRemoteOutcomeUnknown();
            throw new Error(`Token exchange failed (HTTP ${tokenResponse.status}). Remote token issuance could not be confirmed.`);
        }

        let responseBody: unknown;
        try {
            responseBody = await tokenResponse.json();
        } catch {
            this.markRemoteOutcomeUnknown();
            throw new Error('Token exchange response could not be read. Remote token issuance could not be confirmed.');
        }
        if (!isUsableTokenResponse(responseBody)) {
            this.markRemoteOutcomeUnknown();
            throw new Error('Token exchange response was invalid. Remote token issuance could not be confirmed.');
        }
        const tokens = responseBody;
        return withSessionLock(this.storageKey('session'), async () => {
        try {
            this.assertSessionGeneration(generation);
            if (shouldCommit && !shouldCommit()) throw new Error('Session changed during the request.');
            const user = await this.getUser(tokens.access_token, false);

            this.assertSessionGeneration(generation);
            if (shouldCommit && !shouldCommit()) throw new Error('Session changed during the request.');
            const previousCredential = sessionStorage.getItem(this.storageKey('revocation_token'));
            if (!previousCredential && this.getStoredAccessToken()) {
                this.markRemoteOutcomeUnknown();
            }
            if (previousCredential && previousCredential !== tokens.revocation_token) {
                if (!await this.revokeFamily(previousCredential)) {
                    throw new Error('Previous session revocation was not confirmed.');
                }
                this.assertSessionGeneration(generation);
                if (shouldCommit && !shouldCommit()) throw new Error('Session changed during the request.');
            }
            this.incrementSessionGeneration();
            this.clearSessionCookie();
            sessionStorage.setItem(
                this.storageKey('access_token'),
                tokens.access_token,
            );
            sessionStorage.setItem(this.storageKey('user'), JSON.stringify(user));
            sessionStorage.removeItem(this.storageKey('refresh_token'));
            sessionStorage.removeItem(this.storageKey('revocation_token'));
            if (tokens.refresh_token) {
                sessionStorage.setItem(
                    this.storageKey('refresh_token'),
                    tokens.refresh_token,
                );
            }
            if (tokens.revocation_token) {
                sessionStorage.setItem(this.storageKey('revocation_token'), tokens.revocation_token);
            }

            this.notifyTransition({
                type: 'token_exchange',
                user,
                tokens,
                generation: this.sessionGeneration(),
            });

            return { user, tokens };
        } catch (error) {
            const sessionChanged = this.sessionGeneration() !== generation;
            const revoked = tokens.revocation_token &&
                sessionStorage.getItem(this.storageKey('revocation_token')) !== tokens.revocation_token
                ? await this.revokeFamily(tokens.revocation_token)
                : false;
            if (!revoked) this.markRemoteOutcomeUnknown();
            const safeError = error instanceof Error && [
                'Userinfo environment does not match the configured publishable key.',
                'Previous session revocation was not confirmed.',
            ].includes(error.message) ? error.message : 'Authentication callback failed.';
            throw new Error(
                `${sessionChanged ? 'Session changed during the request.' : safeError} ${
                    revoked
                        ? 'The issued token family was revoked.'
                        : 'Revocation of the issued token family could not be confirmed.'
                }`,
            );
        }
        });
    }

    /**
     * Refresh the access token using a stored or provided refresh token.
     */
    refreshToken(token?: string): Promise<TokenResponse> {
        const key = this.storageKey('session');
        const stored = sessionStorage.getItem(this.storageKey('refresh_token'));
        const requestedToken = token ?? stored ?? '';
        try {
            this.assertRefreshTokenCompatible(token);
        } catch (error) {
            this.notifyTransition({
                type: 'refresh_failure',
                error,
                generation: this.sessionGeneration(),
            });
            return Promise.reject(error);
        }
        const generation = this.sessionGeneration();
        const flights = refreshFlights.get(key) ?? new Map<string, { generation: number; promise: Promise<TokenResponse> }>();
        const existing = flights.get(requestedToken);
        if (existing?.generation === generation) return existing.promise;
        if (!requestedToken) {
            const error = new Error('No refresh token available.');
            this.notifyTransition({
                type: 'refresh_failure',
                error,
                generation,
            });
            return Promise.reject(error);
        }
        pendingRefreshes.set(key, (pendingRefreshes.get(key) ?? 0) + 1);
        const request = withSessionLock(`refresh:${key}`, async () => {
            this.assertSessionGeneration(generation);
            this.assertRefreshTokenCompatible(token);
            return this.performRefreshToken(token);
        });
        flights.set(requestedToken, { generation, promise: request });
        refreshFlights.set(key, flights);
        void request.finally(() => {
            if (flights.get(requestedToken)?.promise === request) flights.delete(requestedToken);
            if (flights.size === 0) refreshFlights.delete(key);
            const remaining = (pendingRefreshes.get(key) ?? 1) - 1;
            if (remaining) pendingRefreshes.set(key, remaining);
            else pendingRefreshes.delete(key);
        }).catch(() => {});
        return request;
    }

    protected assertRefreshTokenCompatible(token?: string): void {
        const stored = sessionStorage.getItem(this.storageKey('refresh_token'));
        if (token && token !== stored &&
            (stored || this.getStoredAccessToken() || sessionStorage.getItem(this.storageKey('revocation_token')))) {
            throw new Error('Cannot replace an active session with a different refresh token. Sign in again instead.');
        }
    }

    protected async performRefreshToken(token: string | undefined): Promise<TokenResponse> {
        const generation = this.sessionGeneration();
        const refreshKey = this.storageKey('session');
        const refreshGeneration = refreshGenerations.get(refreshKey) ?? 0;
        const storedRefreshToken = sessionStorage.getItem(this.storageKey('refresh_token'));
        const refreshToken =
            token ?? storedRefreshToken;

        if (!refreshToken) {
            throw new Error('No refresh token available.');
        }

        let response: Response;
        try {
            response = await fetch(`${this.portalUrl}/oauth/token`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    grant_type: 'refresh_token',
                    client_id: this.clientId,
                    refresh_token: refreshToken,
                }),
                redirect: 'error',
            });
        } catch {
            this.markRemoteOutcomeUnknown();
            const error = new KoamishinRequestError('unavailable', 'Token refresh failed. Retry later.');
            this.notifyTransition({
                type: 'refresh_failure',
                error,
                generation,
            });
            throw error;
        }

        if (!response.ok) {
            let invalidGrant = false;
            if (response.status === 400) {
                try {
                    const body = await response.json();
                    invalidGrant = body?.error === 'invalid_grant';
                } catch {
                    // An unreadable error is not proof that the grant is invalid.
                }
            }
            if (!invalidGrant) this.markRemoteOutcomeUnknown();
            const error = new KoamishinRequestError(invalidGrant ? 'invalid_grant' : 'unavailable',
                invalidGrant ? 'The refresh grant is invalid. Sign in again.' : 'Token refresh failed. Retry later.');
            this.notifyTransition({
                type: 'refresh_failure',
                error,
                generation,
            });
            throw error;
        }

        let responseBody: unknown;
        try {
            responseBody = await response.json();
        } catch {
            this.markRemoteOutcomeUnknown();
            const error = new KoamishinRequestError('unavailable', 'Token refresh response could not be read. Retry later.');
            this.notifyTransition({
                type: 'refresh_failure',
                error,
                generation,
            });
            throw error;
        }
        if (!isUsableTokenResponse(responseBody)) {
            this.markRemoteOutcomeUnknown();
            const error = new KoamishinRequestError('unavailable', 'Token refresh response was invalid. Retry later.');
            this.notifyTransition({
                type: 'refresh_failure',
                error,
                generation,
            });
            throw error;
        }
        const tokens = responseBody;
        return withSessionLock(refreshKey, async () => {
        try {
            this.assertSessionGeneration(generation);
            if (
                sessionStorage.getItem(this.storageKey('refresh_token')) !== storedRefreshToken ||
                (refreshGenerations.get(refreshKey) ?? 0) !== refreshGeneration
            ) {
                throw new Error('Session changed during the request.');
            }
        } catch (error) {
            const hasCurrentSession = Boolean(this.getStoredAccessToken() ||
                sessionStorage.getItem(this.storageKey('refresh_token')) ||
                sessionStorage.getItem(this.storageKey('revocation_token')));
            const revoked = tokens.revocation_token &&
                !hasCurrentSession
                ? await this.revokeFamily(tokens.revocation_token)
                : false;
            if (!revoked) this.markRemoteOutcomeUnknown();
            const failureError = new Error(`Session changed during the request. ${revoked
                ? 'The issued token family was revoked.'
                : 'Revocation of the issued token family could not be confirmed.'}`);
            this.notifyTransition({
                type: 'refresh_failure',
                error: failureError,
                generation: this.sessionGeneration(),
            });
            throw failureError;
        }
        refreshGenerations.set(refreshKey, refreshGeneration + 1);
        sessionStorage.setItem(
            this.storageKey('access_token'),
            tokens.access_token,
        );
        if (tokens.refresh_token) {
            sessionStorage.setItem(
                this.storageKey('refresh_token'),
                tokens.refresh_token,
            );
        }
        if (tokens.revocation_token) {
            sessionStorage.setItem(this.storageKey('revocation_token'), tokens.revocation_token);
        }

        this.notifyTransition({
            type: 'token_refresh',
            tokens,
            generation: this.sessionGeneration(),
        });

        return tokens;
        });
    }

    /**
     * Mint a short-lived session token for the current session.
     *
     * Session tokens are sixty-second JWTs that application backends verify
     * offline against the JWKS document, instead of calling the userinfo
     * endpoint on every request. The claims are only trustworthy once a
     * backend has verified the signature.
     */
    async getSessionToken(token?: string): Promise<SessionToken> {
        const accessToken =
            token ?? sessionStorage.getItem(this.storageKey('access_token'));

        if (!accessToken) {
            throw new Error('No access token available.');
        }

        let response: Response;
        try {
            response = await fetch(`${this.portalUrl}/api/oauth/session-token`, {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                },
                redirect: 'error',
            });
        } catch {
            throw new Error('Session token mint failed.');
        }

        if (!response.ok) {
            throw new Error(`Session token mint failed (HTTP ${response.status}).`);
        }

        let minted: SessionToken;
        try {
            minted = await response.json();
        } catch {
            throw new Error('Invalid session token response.');
        }
        if (!minted || typeof minted.token !== 'string' || !minted.token ||
            typeof minted.token_type !== 'string' || !minted.token_type ||
            typeof minted.expires_in !== 'number' || !Number.isFinite(minted.expires_in) || minted.expires_in <= 0 ||
            typeof minted.expires_at !== 'number' || !Number.isFinite(minted.expires_at)) {
            throw new Error('Invalid session token response.');
        }
        return minted;
    }

    /**
     * Fetch user identity claims from Portal userinfo endpoint.
     */
    async getUser(token?: string, cache = true): Promise<KoamishinUser> {
        const generation = this.sessionGeneration();
        const storedAccessToken = sessionStorage.getItem(this.storageKey('access_token'));
        const accessToken = token ?? storedAccessToken;
        if (cache && token && token !== storedAccessToken) {
            throw new Error('Session changed during the request.');
        }

        if (!accessToken) {
            throw new Error('No access token available.');
        }

        let response: Response;
        try {
            response = await fetch(`${this.portalUrl}/api/oauth/userinfo`, {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                },
                redirect: 'error',
            });
        } catch {
            throw new KoamishinRequestError('unavailable', 'Failed to retrieve user claims. Retry later.');
        }

        this.assertSessionGeneration(generation);
        if (sessionStorage.getItem(this.storageKey('access_token')) !== storedAccessToken) {
            throw new Error('Session changed during the request.');
        }
        if (!response.ok) {
            throw new KoamishinRequestError(
                response.status === 401 ? 'access_token_invalid' : 'unavailable',
                response.status === 401 ? 'Access token is invalid.' : 'Failed to retrieve user claims. Retry later.',
            );
        }

        let user: KoamishinUser;
        try {
            user = await response.json();
        } catch {
            throw new KoamishinRequestError('unavailable', 'Failed to retrieve user claims. Retry later.');
        }
        const expectedEnvironment = this.getEnvironment();

        if (
            expectedEnvironment !== null &&
            (!user ||
                typeof user !== 'object' ||
                Array.isArray(user) ||
                user.environment !== expectedEnvironment)
        ) {
            throw new Error(
                'Userinfo environment does not match the configured publishable key.',
            );
        }

        this.assertSessionGeneration(generation);
        if (sessionStorage.getItem(this.storageKey('access_token')) !== storedAccessToken) {
            throw new Error('Session changed during the request.');
        }
        if (cache && typeof sessionStorage !== 'undefined') {
            sessionStorage.setItem(
                this.storageKey('user'),
                JSON.stringify(user),
            );
        }

        return user;
    }

    /**
     * Return the stored access token for this client, or null when signed out.
     */
    getStoredAccessToken(): string | null {
        if (typeof sessionStorage === 'undefined') {
            return null;
        }

        return sessionStorage.getItem(this.storageKey('access_token'));
    }

    /**
     * Clear an unusable local session only if it is still the expected one.
     * Retain its revocation credential for a later explicit sign-out.
     */
    invalidateSession(expectedAccessToken: string): boolean {
        if (typeof sessionStorage === 'undefined' ||
            sessionStorage.getItem(this.storageKey('access_token')) !== expectedAccessToken) {
            return false;
        }
        this.incrementSessionGeneration();
        if (!sessionStorage.getItem(this.storageKey('revocation_token'))) {
            this.markRemoteOutcomeUnknown();
        }
        sessionStorage.removeItem(this.storageKey('access_token'));
        sessionStorage.removeItem(this.storageKey('refresh_token'));
        sessionStorage.removeItem(this.storageKey('user'));
        this.clearSessionCookie();
        this.notifyTransition({
            type: 'session_invalidated',
            reason: 'access_token_invalidated',
            generation: this.sessionGeneration(),
        });
        return true;
    }

    /**
     * Return the cached user profile from sessionStorage, or null when unavailable.
     */
    getStoredUser(): KoamishinUser | null {
        if (typeof sessionStorage === 'undefined') {
            return null;
        }

        const raw = sessionStorage.getItem(this.storageKey('user'));
        if (!raw) {
            return null;
        }

        try {
            const parsed = JSON.parse(raw);
            return parsed &&
                typeof parsed === 'object' &&
                !Array.isArray(parsed)
                ? (parsed as KoamishinUser)
                : null;
        } catch {
            return null;
        }
    }

    /**
     * Mint a fresh short-lived session token and write it to this client's scoped cookie
     * so SSR frameworks and Next.js proxy/middleware can verify the session offline.
     */
    async syncSessionCookie(token?: string, shouldWrite?: () => boolean): Promise<SessionToken> {
        const generation = this.sessionGeneration();
        const storedAccessToken = this.getStoredAccessToken();
        if (!storedAccessToken || (token && token !== storedAccessToken)) {
            throw new Error('Session changed during the request.');
        }
        const sessionToken = await this.getSessionToken(token);

        this.assertSessionGeneration(generation);
        if (this.getStoredAccessToken() !== storedAccessToken) {
            throw new Error('Session changed during the request.');
        }
        if (shouldWrite && !shouldWrite()) {
            throw new Error('Session changed during the request.');
        }
        let tokenExpiresAt: number;
        try {
            const parts = sessionToken.token.split('.');
            if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part) || part.length % 4 === 1)) {
                throw new Error();
            }
            if (decodeBase64UrlBytes(parts[2]).length === 0) throw new Error();
            const header = JSON.parse(new TextDecoder().decode(decodeBase64UrlBytes(parts[0])));
            const claims = decodeSessionToken(sessionToken);
            const nowSeconds = Math.floor(Date.now() / 1000);
            if (header?.alg !== 'RS256' ||
                (header.kid !== undefined && (typeof header.kid !== 'string' || !header.kid)) ||
                typeof claims.iss !== 'string' || claims.iss !== this.portalUrl ||
                typeof claims.sub !== 'string' || !claims.sub ||
                typeof claims.sid !== 'string' || !claims.sid ||
                typeof claims.exp !== 'number' || !Number.isFinite(claims.exp) || claims.exp <= nowSeconds ||
                typeof claims.iat !== 'number' || !Number.isFinite(claims.iat) ||
                claims.iat > nowSeconds + 5 || claims.iat >= claims.exp || claims.exp - claims.iat > 65 ||
                typeof claims.nbf !== 'number' || !Number.isFinite(claims.nbf) ||
                claims.nbf > nowSeconds + 5 || claims.nbf >= claims.exp) {
                throw new Error();
            }
            tokenExpiresAt = claims.exp;
        } catch {
            throw new Error('Invalid minted session token.');
        }
        if (typeof document === 'undefined') {
            throw new Error('Session cookie is unavailable.');
        }
        if (typeof window !== 'undefined' && window.location?.protocol !== 'https:' &&
            !(window.location?.protocol === 'http:' &&
                isLoopbackHostname(window.location.hostname))) {
            throw new Error('Session cookies require HTTPS or a loopback development host.');
        }
        const maxAge = Math.floor(Math.min(sessionToken.expires_in, tokenExpiresAt - Date.now() / 1000, 60));
        if (maxAge < 1) {
            throw new Error('Session token expires too soon to write a cookie.');
        }
        const cookie = `${this.sessionCookieName()}=${encodeURIComponent(sessionToken.token)}`;
        document.cookie = `${cookie}; Path=/; Max-Age=${maxAge}; SameSite=Lax; Secure`;
        if (!document.cookie.split(/;\s*/).includes(cookie)) {
            throw new Error('Session cookie could not be written.');
        }

        return sessionToken;
    }

    /**
     * Clear local session immediately and report whether Portal confirmed revocation.
     */
    signOut(): Promise<SignOutResult> {
        const key = this.storageKey('session');
        const revocationToken = typeof sessionStorage !== 'undefined'
            ? sessionStorage.getItem(this.storageKey('revocation_token'))
            : null;
        const pending = pendingSignOuts.get(key);
        const hadAccessToken = Boolean(this.getStoredAccessToken());
        const reusePending = pending && !revocationToken && !hadAccessToken;
        const callbackInFlight = (pendingCallbacks.get(key) ?? 0) > 0 ||
            (pendingRefreshes.get(key) ?? 0) > 0;
        if (callbackInFlight || (pending && !reusePending)) this.markRemoteOutcomeUnknown();
        const outcomeUnknown = typeof sessionStorage !== 'undefined' &&
            sessionStorage.getItem(this.storageKey('remote_outcome_unknown')) === '1';
        if (!revocationToken && hadAccessToken) this.markRemoteOutcomeUnknown();
        this.incrementSessionGeneration();
        if (typeof sessionStorage !== 'undefined') {
            sessionStorage.removeItem(this.storageKey('access_token'));
            sessionStorage.removeItem(this.storageKey('refresh_token'));
            sessionStorage.removeItem(this.storageKey('revocation_token'));
            sessionStorage.removeItem(this.storageKey('user'));
            sessionStorage.removeItem(this.storageKey('oauth_state'));
            sessionStorage.removeItem(this.storageKey('code_verifier'));
            sessionStorage.removeItem(this.storageKey('oauth_transactions'));
        }

        this.clearSessionCookie();

        const callbackFailure: SignOutResult = {
            status: 'failed',
            message: 'Remote sign-out was not confirmed. An earlier token family may still be active.',
        };
        if (!revocationToken) {
            const result: SignOutResult = outcomeUnknown
                ? callbackFailure
                : { status: 'reauthentication_required' };
            this.notifyTransition({
                type: 'sign_out',
                result,
                generation: this.sessionGeneration(),
            });
            if (reusePending && !callbackInFlight && !outcomeUnknown) return pending;
            return Promise.resolve(result);
        }

        if (reusePending && !callbackInFlight && !outcomeUnknown) return pending;

        const request: Promise<SignOutResult> = (async () => {
            const revoked = await this.revokeFamily(revocationToken);
            if (!revoked) {
                this.markRemoteOutcomeUnknown();
                const result: SignOutResult = { status: 'failed', message: 'Remote sign-out was not confirmed due to a network error or Portal refusal.' };
                this.notifyTransition({
                    type: 'sign_out',
                    result,
                    generation: this.sessionGeneration(),
                });
                return result;
            }
            const result: SignOutResult = outcomeUnknown || (typeof sessionStorage !== 'undefined' &&
                sessionStorage.getItem(this.storageKey('remote_outcome_unknown')) === '1')
                ? callbackFailure : { status: 'revoked' };
            this.notifyTransition({
                type: 'sign_out',
                result,
                generation: this.sessionGeneration(),
            });
            return result;
        })();
        pendingSignOuts.set(key, request);
        void request.finally(() => {
            if (pendingSignOuts.get(key) === request) pendingSignOuts.delete(key);
        });
        return request;
    }

    protected async revokeFamily(revocationToken: string): Promise<boolean> {
        try {
            const response = await fetch(`${this.portalUrl}/api/oauth/revoke-family`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ revocation_token: revocationToken }),
                redirect: 'error',
            });
            return response.status === 204;
        } catch {
            return false;
        }
    }

    protected sessionCookieName(): string {
        return getSessionCookieName(this.portalUrl, this.clientId);
    }

    protected clearSessionCookie(): void {
        if (typeof document !== 'undefined') {
            document.cookie = `${this.sessionCookieName()}=; Path=/; Max-Age=0; SameSite=Lax; Secure`;
        }
    }

    protected markRemoteOutcomeUnknown(): void {
        if (typeof sessionStorage !== 'undefined') {
            sessionStorage.setItem(this.storageKey('remote_outcome_unknown'), '1');
        }
    }

    protected sessionGeneration(): number {
        return sessionGenerations.get(this.storageKey('session')) ?? 0;
    }

    protected assertSessionGeneration(generation: number): void {
        if (this.sessionGeneration() !== generation) {
            throw new Error('Session changed during the request.');
        }
    }

    protected storageKey(key: string): string {
        return `koamishin:${encodeURIComponent(this.portalUrl)}:${encodeURIComponent(this.clientId)}:${key}`;
    }

    protected pendingTransactions(): Record<string, AuthenticationTransaction> {
        let stored: unknown;
        try {
            stored = JSON.parse(
                sessionStorage.getItem(this.storageKey('oauth_transactions')) ??
                    '{}',
            );
        } catch {
            return {};
        }
        if (!stored || typeof stored !== 'object' || Array.isArray(stored)) {
            return {};
        }

        const now = Date.now();
        return Object.fromEntries(
            Object.entries(stored).filter(([state, value]) => {
                if (
                    !/^[A-Za-z0-9_-]{22}$/.test(state) ||
                    !value ||
                    typeof value !== 'object'
                ) {
                    return false;
                }
                const transaction = value as Partial<AuthenticationTransaction>;
                return (
                    typeof transaction.verifier === 'string' &&
                    /^[A-Za-z0-9_-]{43}$/.test(transaction.verifier) &&
                    typeof transaction.createdAt === 'number' &&
                    transaction.createdAt >= now - 600_000 &&
                    transaction.createdAt <= now
                );
            }),
        ) as Record<string, AuthenticationTransaction>;
    }
}

/**
 * Decode a session token's claims WITHOUT verifying the signature.
 *
 * Browser code cannot be trusted with verification anyway, so use this for
 * display and routing only. A backend must verify the token against the
 * Koamishin Auth JWKS document before trusting any claim on it.
 */
export function decodeSessionToken(
    sessionToken: string | SessionToken,
): SessionTokenClaims {
    const jwt =
        typeof sessionToken === 'string' ? sessionToken : sessionToken.token;
    const parts = jwt.split('.');
    if (parts.length !== 3) {
        throw new Error('The session token is not a JWT.');
    }

    let claims: unknown;
    try {
        const payload = new TextDecoder('utf-8', { fatal: true }).decode(
            decodeBase64UrlBytes(parts[1]),
        );
        claims = JSON.parse(payload);
    } catch {
        throw new Error('The session token payload is not valid JSON.');
    }

    if (
        !claims ||
        typeof claims !== 'object' ||
        Array.isArray(claims) ||
        typeof (claims as SessionTokenClaims).sub !== 'string' ||
        (claims as SessionTokenClaims).v !== '2'
    ) {
        throw new Error('The token is not a Koamishin session token.');
    }

    return claims as SessionTokenClaims;
}

const jwksCache = new Map<string, { fetchedAt: number; jwks: JwksDocument }>();
const jwksFetches = new Map<string, Promise<JwksDocument>>();
const jwksRefreshAttempts = new Map<string, number>();
const JWKS_UNKNOWN_KEY_REFRESH_INTERVAL_MS = 30_000;

function decodeBase64UrlBytes(input: string): Uint8Array {
    const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

async function resolveJwks(
    portalUrl: string,
    forceRefresh = false,
): Promise<JwksDocument> {
    const normalized = portalUrl.replace(/\/+$/, '');
    const cached = jwksCache.get(normalized);
    const now = Date.now();

    if (!forceRefresh && cached && now - cached.fetchedAt < 300_000) {
        return cached.jwks;
    }

    const pending = jwksFetches.get(normalized);
    if (pending) return pending;
    const request = (async () => {
        const response = await fetch(`${normalized}/oauth/jwks`, {
            headers: { Accept: 'application/json' },
        });
        if (!response.ok) {
            throw new Error('Failed to fetch Koamishin JWKS document.');
        }
        const document: unknown = await response.json();
        if (!document || typeof document !== 'object' ||
            !Array.isArray((document as JwksDocument).keys)) {
            throw new Error('Invalid Koamishin JWKS document.');
        }
        const keys: JwksKey[] = [];
        const identifiers = new Set<string>();
        for (const key of (document as JwksDocument).keys) {
            if (!key || typeof key !== 'object') {
                throw new Error('Invalid Koamishin JWKS document.');
            }
            if (key.kty !== 'RSA' || (key.alg && key.alg !== 'RS256') || (key.use && key.use !== 'sig')) continue;
            if ((key.kid !== undefined && (typeof key.kid !== 'string' || !key.kid)) ||
                typeof key.n !== 'string' || typeof key.e !== 'string' ||
                !/^[A-Za-z0-9_-]+$/.test(key.n) || !/^[A-Za-z0-9_-]+$/.test(key.e) ||
                key.n.length % 4 === 1 || key.e.length % 4 === 1 ||
                key.n.length > 16384 || key.e.length > 32 ||
                identifiers.has(key.kid ?? '')) {
                throw new Error('Invalid Koamishin JWKS document.');
            }
            try {
                const modulus = decodeBase64UrlBytes(key.n);
                const exponent = decodeBase64UrlBytes(key.e);
                if (modulus.length < 256 || modulus[0] === 0 ||
                    (modulus.length === 256 && modulus[0] < 128) ||
                    (modulus[modulus.length - 1] & 1) === 0 ||
                    exponent.length === 0 || exponent[0] === 0 ||
                    (exponent[exponent.length - 1] & 1) === 0 ||
                    (exponent.length === 1 && exponent[0] < 3)) {
                    throw new Error();
                }
                await crypto.subtle.importKey('jwk', {
                    kty: 'RSA', n: key.n, e: key.e, alg: 'RS256', ext: true,
                }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
            } catch {
                throw new Error('Invalid Koamishin JWKS document.');
            }
            identifiers.add(key.kid ?? '');
            keys.push(key);
        }
        if (keys.length === 0) {
            throw new Error('Invalid Koamishin JWKS document.');
        }
        const jwks: JwksDocument = { keys };
        jwksCache.set(normalized, { fetchedAt: Date.now(), jwks });
        return jwks;
    })();
    jwksFetches.set(normalized, request);
    try {
        return await request;
    } finally {
        if (jwksFetches.get(normalized) === request) jwksFetches.delete(normalized);
    }
}

/**
 * Cryptographically verify a Koamishin session token (RS256 JWT) against the
 * Portal's JWKS document and validate its issuer, lifetime, environment, and
 * optional application binding.
 */
export async function verifySessionToken(
    sessionToken: string | SessionToken,
    options: VerifySessionTokenOptions,
): Promise<SessionTokenClaims> {
    const jwt =
        typeof sessionToken === 'string' ? sessionToken : sessionToken.token;
    const parts = jwt.split('.');
    if (parts.length !== 3) {
        throw new Error('The session token is not a JWT.');
    }

    let header: { alg?: string; kid?: string; typ?: string };
    try {
        const headerBytes = decodeBase64UrlBytes(parts[0]);
        header = JSON.parse(new TextDecoder().decode(headerBytes));
    } catch {
        throw new Error('The session token header is not valid JSON.');
    }

    if (!header || header.alg !== 'RS256') {
        throw new Error('Unsupported session token algorithm.');
    }
    if (header.kid !== undefined && (typeof header.kid !== 'string' || !header.kid)) {
        throw new Error('Invalid session token key ID.');
    }

    const claims = decodeSessionToken(jwt);
    if (!claims.sub.trim() || typeof claims.sid !== 'string' || !claims.sid.trim()) {
        throw new Error('Session token must contain nonempty subject and session identifiers.');
    }
    const portalUrl = normalizePortalUrl(options.portalUrl);
    const skew = options.clockSkewSeconds ?? 5;
    if (!Number.isFinite(skew) || skew < 0) {
        throw new Error('Session token clock skew must be finite and nonnegative.');
    }
    const nowSeconds = Math.floor(Date.now() / 1000);

    if (claims.iss !== portalUrl) {
        throw new Error('Session token issuer does not match portalUrl.');
    }

    if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp) || nowSeconds - skew >= claims.exp) {
        throw new Error('Session token has expired.');
    }

    if (claims.iat !== undefined && (typeof claims.iat !== 'number' || !Number.isFinite(claims.iat))) {
        throw new Error('Session token issued-at time is invalid.');
    }
    if (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || !Number.isFinite(claims.nbf))) {
        throw new Error('Session token not-before time is invalid.');
    }
    if (typeof claims.nbf === 'number' && nowSeconds + skew < claims.nbf) {
        throw new Error('Session token is not active yet.');
    }

    if (options.publishableKey?.trim() && options.clientId?.trim() &&
        options.publishableKey.trim() !== options.clientId.trim()) {
        throw new Error('Koamishin publishableKey and clientId conflict.');
    }
    const keyIdentifier =
        options.publishableKey?.trim() || options.clientId?.trim() || '';
    const inferredEnvironment = keyIdentifier.startsWith('pk_test_')
        ? 'development'
        : keyIdentifier.startsWith('pk_live_')
          ? 'production'
          : null;
    if (options.environment?.trim() && inferredEnvironment &&
        options.environment.trim() !== inferredEnvironment) {
        throw new Error('Koamishin environment conflicts with the publishable key environment.');
    }
    const expectedEnvironment = options.environment?.trim() || inferredEnvironment;

    if (
        expectedEnvironment &&
        (typeof claims.environment !== 'string' ||
            claims.environment !== expectedEnvironment)
    ) {
        throw new Error(
            'Session token environment does not match the configured environment.',
        );
    }

    if (
        options.applicationId &&
        (typeof claims.application_id !== 'string' ||
            claims.application_id !== options.applicationId)
    ) {
        throw new Error(
            'Session token application_id does not match the configured applicationId.',
        );
    }

    let jwks = options.jwks ?? (await resolveJwks(portalUrl, false));
    let jwk = jwks.keys.find(
        (k) =>
            k && k.kty === 'RSA' && (!header.kid || k.kid === header.kid),
    );

    if (!jwk && !options.jwks) {
        const lastAttempt = jwksRefreshAttempts.get(portalUrl);
        const pending = jwksFetches.get(portalUrl);
        if (pending || lastAttempt === undefined || Date.now() - lastAttempt >= JWKS_UNKNOWN_KEY_REFRESH_INTERVAL_MS) {
            if (!pending) jwksRefreshAttempts.set(portalUrl, Date.now());
            jwks = pending ? await pending : await resolveJwks(portalUrl, true);
            jwk = jwks.keys.find(
                (k) =>
                    k && k.kty === 'RSA' &&
                    (!header.kid || k.kid === header.kid),
            );
        }
    }

    if (!jwk || !jwk.n || !jwk.e) {
        throw new Error('No matching RSA key found in JWKS document. If keys were rotated, retry shortly.');
    }

    const cryptoKey = await crypto.subtle.importKey(
        'jwk',
        {
            kty: 'RSA',
            n: jwk.n,
            e: jwk.e,
            alg: 'RS256',
            ext: true,
        },
        {
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-256',
        },
        false,
        ['verify'],
    );

    const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    const signature = decodeBase64UrlBytes(parts[2]);
    const valid = await crypto.subtle.verify(
        'RSASSA-PKCS1-v1_5',
        cryptoKey,
        signature as BufferSource,
        signingInput,
    );

    if (!valid) {
        throw new Error('Invalid session token signature.');
    }

    return claims;
}

export function createKoamishinClient(
    config: KoamishinConfig,
): KoamishinClient {
    return new KoamishinClient(config);
}

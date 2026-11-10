import { generatePkce, generateState } from './pkce';

export type KoamishinConfig = {
    portalUrl: string;
    redirectUri: string;
    scopes?: string[];
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
    id_token?: string;
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

export const SESSION_COOKIE_NAME = '__koamishin_session';

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

        this.portalUrl = config.portalUrl.replace(/\/+$/, '');
        this.clientId = identifier;
        this.publishableKey = identifier.startsWith('pk_')
            ? identifier
            : undefined;
        this.redirectUri = config.redirectUri;
        this.scopes = config.scopes ?? ['openid', 'profile', 'email', 'roles'];
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
        const { verifier, challenge } = await generatePkce();
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
    async handleRedirectCallback(): Promise<{
        user: KoamishinUser;
        tokens: TokenResponse;
    }> {
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

        const tokenResponse = await fetch(`${this.portalUrl}/oauth/token`, {
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
        });

        if (!tokenResponse.ok) {
            const err = await tokenResponse.text();
            throw new Error(`Token exchange failed: ${err}`);
        }

        const tokens: TokenResponse = await tokenResponse.json();
        const user = await this.getUser(tokens.access_token);

        sessionStorage.setItem(
            this.storageKey('access_token'),
            tokens.access_token,
        );
        sessionStorage.setItem(this.storageKey('user'), JSON.stringify(user));
        if (tokens.refresh_token) {
            sessionStorage.setItem(
                this.storageKey('refresh_token'),
                tokens.refresh_token,
            );
        }

        return { user, tokens };
    }

    /**
     * Refresh the access token using a stored or provided refresh token.
     */
    async refreshToken(token?: string): Promise<TokenResponse> {
        const refreshToken =
            token ?? sessionStorage.getItem(this.storageKey('refresh_token'));

        if (!refreshToken) {
            throw new Error('No refresh token available.');
        }

        const response = await fetch(`${this.portalUrl}/oauth/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                grant_type: 'refresh_token',
                client_id: this.clientId,
                refresh_token: refreshToken,
            }),
        });

        if (!response.ok) {
            const err = await response.text();
            throw new Error(`Token refresh failed: ${err}`);
        }

        const tokens: TokenResponse = await response.json();
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

        return tokens;
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

        const response = await fetch(
            `${this.portalUrl}/api/oauth/session-token`,
            {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                },
            },
        );

        if (!response.ok) {
            const err = await response.text();
            throw new Error(`Session token mint failed: ${err}`);
        }

        return (await response.json()) as SessionToken;
    }

    /**
     * Fetch user identity claims from Portal userinfo endpoint.
     */
    async getUser(token?: string): Promise<KoamishinUser> {
        const accessToken =
            token ?? sessionStorage.getItem(this.storageKey('access_token'));

        if (!accessToken) {
            throw new Error('No access token available.');
        }

        const response = await fetch(`${this.portalUrl}/api/oauth/userinfo`, {
            headers: {
                Authorization: `Bearer ${accessToken}`,
            },
        });

        if (!response.ok) {
            throw new Error('Failed to retrieve user claims.');
        }

        const user: KoamishinUser = await response.json();
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

        if (typeof sessionStorage !== 'undefined') {
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
     * Mint a fresh short-lived session token and write it to the `__koamishin_session` cookie
     * so SSR frameworks and Next.js proxy/middleware can verify the session offline.
     */
    async syncSessionCookie(token?: string): Promise<SessionToken> {
        const sessionToken = await this.getSessionToken(token);

        if (typeof document !== 'undefined') {
            const maxAge = Math.max(1, sessionToken.expires_in || 60);
            document.cookie = `${SESSION_COOKIE_NAME}=${encodeURIComponent(sessionToken.token)}; Path=/; Max-Age=${maxAge}; SameSite=Lax`;
        }

        return sessionToken;
    }

    /**
     * Clear session token and log user out.
     */
    signOut(): void {
        if (typeof sessionStorage !== 'undefined') {
            sessionStorage.removeItem(this.storageKey('access_token'));
            sessionStorage.removeItem(this.storageKey('refresh_token'));
            sessionStorage.removeItem(this.storageKey('user'));
            sessionStorage.removeItem(this.storageKey('oauth_state'));
            sessionStorage.removeItem(this.storageKey('code_verifier'));
            sessionStorage.removeItem(this.storageKey('oauth_transactions'));
        }

        if (typeof document !== 'undefined') {
            document.cookie = `${SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; SameSite=Lax`;
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

    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4);

    let claims: unknown;
    try {
        claims = JSON.parse(atob(padded));
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

    const response = await fetch(`${normalized}/oauth/jwks`, {
        headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
        throw new Error('Failed to fetch Koamishin JWKS document.');
    }

    const jwks = (await response.json()) as JwksDocument;
    if (!jwks || !Array.isArray(jwks.keys)) {
        throw new Error('Invalid Koamishin JWKS document.');
    }

    jwksCache.set(normalized, { fetchedAt: now, jwks });
    return jwks;
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

    const claims = decodeSessionToken(jwt);
    const portalUrl = options.portalUrl.replace(/\/+$/, '');
    const skew = options.clockSkewSeconds ?? 5;
    const nowSeconds = Math.floor(Date.now() / 1000);

    if (claims.iss.replace(/\/+$/, '') !== portalUrl) {
        throw new Error('Session token issuer does not match portalUrl.');
    }

    if (typeof claims.exp !== 'number' || nowSeconds - skew >= claims.exp) {
        throw new Error('Session token has expired.');
    }

    if (typeof claims.nbf === 'number' && nowSeconds + skew < claims.nbf) {
        throw new Error('Session token is not active yet.');
    }

    const keyIdentifier =
        options.publishableKey?.trim() || options.clientId?.trim() || '';
    const inferredEnvironment = keyIdentifier.startsWith('pk_test_')
        ? 'development'
        : keyIdentifier.startsWith('pk_live_')
          ? 'production'
          : null;
    const expectedEnvironment = options.environment ?? inferredEnvironment;

    if (
        expectedEnvironment &&
        claims.environment &&
        claims.environment !== expectedEnvironment
    ) {
        throw new Error(
            'Session token environment does not match the configured environment.',
        );
    }

    if (
        options.applicationId &&
        claims.application_id &&
        String(claims.application_id) !== String(options.applicationId)
    ) {
        throw new Error(
            'Session token application_id does not match the configured applicationId.',
        );
    }

    let jwks = options.jwks ?? (await resolveJwks(portalUrl, false));
    let jwk = jwks.keys.find(
        (k) =>
            k.kty === 'RSA' && (!header.kid || !k.kid || k.kid === header.kid),
    );

    if (!jwk && !options.jwks) {
        jwks = await resolveJwks(portalUrl, true);
        jwk = jwks.keys.find(
            (k) =>
                k.kty === 'RSA' &&
                (!header.kid || !k.kid || k.kid === header.kid),
        );
    }

    if (!jwk || !jwk.n || !jwk.e) {
        throw new Error('No matching RSA key found in JWKS document.');
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

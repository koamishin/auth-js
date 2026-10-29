import { generatePkce, generateState } from './pkce';

export interface KoamishinConfig {
    portalUrl: string;
    clientId: string;
    redirectUri: string;
    scopes?: string[];
}

export interface KoamishinUser {
    sub: string;
    name: string;
    email: string;
    email_verified: boolean;
    picture?: string | null;
    roles: string[];
    permissions: string[];
    updated_at?: number;
}

export interface TokenResponse {
    token_type: string;
    expires_in: number;
    access_token: string;
    refresh_token?: string;
    id_token?: string;
}

interface AuthenticationTransaction {
    verifier: string;
    createdAt: number;
}

export class KoamishinClient {
    protected portalUrl: string;
    protected clientId: string;
    protected redirectUri: string;
    protected scopes: string[];

    constructor(config: KoamishinConfig) {
        this.portalUrl = config.portalUrl.replace(/\/+$/, '');
        this.clientId = config.clientId;
        this.redirectUri = config.redirectUri;
        this.scopes = config.scopes ?? ['openid', 'profile', 'email', 'roles'];
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

        const user = await this.getUser(tokens.access_token);

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

        return response.json();
    }

    /**
     * Clear session token and log user out.
     */
    signOut(): void {
        if (typeof sessionStorage !== 'undefined') {
            sessionStorage.removeItem(this.storageKey('access_token'));
            sessionStorage.removeItem(this.storageKey('refresh_token'));
            sessionStorage.removeItem(this.storageKey('oauth_state'));
            sessionStorage.removeItem(this.storageKey('code_verifier'));
            sessionStorage.removeItem(this.storageKey('oauth_transactions'));
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

export function createKoamishinClient(
    config: KoamishinConfig,
): KoamishinClient {
    return new KoamishinClient(config);
}

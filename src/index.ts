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
    const { verifier, challenge } = await generatePkce();
    const state = generateState();

    sessionStorage.setItem('koamishin_code_verifier', verifier);
    sessionStorage.setItem('koamishin_oauth_state', state);

    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      response_type: 'code',
      scope: this.scopes.join(' '),
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });

    window.location.href = `${this.portalUrl}/oauth/authorize?${params.toString()}`;
  }

  /**
   * Handle OAuth redirect callback on client app.
   */
  async handleRedirectCallback(): Promise<{ user: KoamishinUser; tokens: TokenResponse }> {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');

    if (!code || !state) {
      throw new Error('Callback URL missing code or state query parameters.');
    }

    const savedState = sessionStorage.getItem('koamishin_oauth_state');
    if (!savedState || savedState !== state) {
      throw new Error('OAuth state mismatch. Request may be untrusted.');
    }

    const verifier = sessionStorage.getItem('koamishin_code_verifier');
    if (!verifier) {
      throw new Error('PKCE code verifier not found in session storage.');
    }

    const tokenResponse = await fetch(`${this.portalUrl}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: this.clientId,
        redirect_uri: this.redirectUri,
        code_verifier: verifier,
        code,
      }),
    });

    if (!tokenResponse.ok) {
      const err = await tokenResponse.text();
      throw new Error(`Token exchange failed: ${err}`);
    }

    const tokens: TokenResponse = await tokenResponse.json();

    sessionStorage.removeItem('koamishin_code_verifier');
    sessionStorage.removeItem('koamishin_oauth_state');
    sessionStorage.setItem('koamishin_access_token', tokens.access_token);
    if (tokens.refresh_token) {
      sessionStorage.setItem('koamishin_refresh_token', tokens.refresh_token);
    }

    const user = await this.getUser(tokens.access_token);

    return { user, tokens };
  }

  /**
   * Refresh the access token using a stored or provided refresh token.
   */
  async refreshToken(token?: string): Promise<TokenResponse> {
    const refreshToken = token ?? sessionStorage.getItem('koamishin_refresh_token');

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
    sessionStorage.setItem('koamishin_access_token', tokens.access_token);
    if (tokens.refresh_token) {
      sessionStorage.setItem('koamishin_refresh_token', tokens.refresh_token);
    }

    return tokens;
  }

  /**
   * Fetch user identity claims from Portal userinfo endpoint.
   */
  async getUser(token?: string): Promise<KoamishinUser> {
    const accessToken = token ?? sessionStorage.getItem('koamishin_access_token');

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
      sessionStorage.removeItem('koamishin_access_token');
      sessionStorage.removeItem('koamishin_refresh_token');
    }
  }
}

export function createKoamishinClient(config: KoamishinConfig): KoamishinClient {
  return new KoamishinClient(config);
}

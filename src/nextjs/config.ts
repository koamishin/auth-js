const defaultScopes = ['openid', 'profile', 'email', 'roles'];

/** A value-based dependency key, so equivalent arrays do not replace a client. */
export function scopesConfigurationKey(scopes?: string[]): string {
    return JSON.stringify(scopes ?? defaultScopes);
}

export function assertCompatibleClientIdentifiers(publishableKey?: string, clientId?: string): void {
    const key = publishableKey?.trim();
    const id = clientId?.trim();
    if (key && id && key !== id) {
        throw new Error('Koamishin publishableKey and clientId conflict; configure only one or matching values.');
    }
}

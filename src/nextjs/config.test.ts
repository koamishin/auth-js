import { expect, test } from 'vitest';
import { assertCompatibleClientIdentifiers, scopesConfigurationKey } from './config';

test('equivalent scope arrays have the same client configuration key', () => {
    expect(scopesConfigurationKey(['openid', 'email'])).toBe(
        scopesConfigurationKey(['openid', 'email']),
    );
    expect(scopesConfigurationKey(undefined)).toBe(
        scopesConfigurationKey(['openid', 'profile', 'email', 'roles']),
    );
    expect(scopesConfigurationKey(['openid', 'email'])).not.toBe(
        scopesConfigurationKey(['openid', 'roles']),
    );
});

test('provider configuration rejects conflicting nonblank identifiers', () => {
    expect(() => assertCompatibleClientIdentifiers('pk_live_a', 'other')).toThrow('conflict');
    expect(() => assertCompatibleClientIdentifiers('pk_live_a', 'pk_live_a')).not.toThrow();
    expect(() => assertCompatibleClientIdentifiers('pk_live_a', '')).not.toThrow();
});

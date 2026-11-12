import { expect, test } from 'vitest';
import { KoamishinRequestError } from '../index';
import { hydrationFailureAction } from './hydration';

test('hydration refreshes only after a definite invalid access token', () => {
    expect(hydrationFailureAction('userinfo', new KoamishinRequestError('access_token_invalid', 'invalid'))).toBe('refresh');
    expect(hydrationFailureAction('userinfo', new KoamishinRequestError('unavailable', 'offline'))).toBe('retry');
    expect(hydrationFailureAction('userinfo', new Error('network'))).toBe('retry');
});

test('only a definite invalid grant asks for reauthentication', () => {
    expect(hydrationFailureAction('refresh', new KoamishinRequestError('invalid_grant', 'invalid'))).toBe('reauthenticate');
    expect(hydrationFailureAction('refresh', new KoamishinRequestError('unavailable', 'offline'))).toBe('retry');
    expect(hydrationFailureAction('refresh', new Error('failure'))).toBe('retry');
});

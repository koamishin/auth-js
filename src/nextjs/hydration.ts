import { KoamishinRequestError } from '../index';

export function hydrationFailureAction(
    phase: 'userinfo' | 'refresh',
    error: unknown,
): 'refresh' | 'reauthenticate' | 'retry' {
    if (!(error instanceof KoamishinRequestError)) return 'retry';
    if (phase === 'userinfo' && error.code === 'access_token_invalid') return 'refresh';
    if (phase === 'refresh' && error.code === 'invalid_grant') return 'reauthenticate';
    return 'retry';
}

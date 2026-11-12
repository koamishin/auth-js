import { expect, test } from 'vitest';
import { claimCallbackNavigation, isCallbackEffectCurrent } from './callback-navigation';

test('unmounted and superseded callbacks cannot navigate or consume the navigation claim', () => {
    const completion = Promise.resolve();
    expect(claimCallbackNavigation(completion, false, true)).toBe(false);
    expect(claimCallbackNavigation(completion, true, false)).toBe(false);
    expect(claimCallbackNavigation(completion, true, true)).toBe(true);
    expect(claimCallbackNavigation(completion, true, true)).toBe(false);
    expect(claimCallbackNavigation(Promise.resolve(), true, true)).toBe(true);
});

test('obsolete effects cannot display callback errors', () => {
    expect(isCallbackEffectCurrent(false, true)).toBe(false);
    expect(isCallbackEffectCurrent(true, false)).toBe(false);
    expect(isCallbackEffectCurrent(true, true)).toBe(true);
});

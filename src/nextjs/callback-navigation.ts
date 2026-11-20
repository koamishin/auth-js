const claimed = new WeakSet<Promise<unknown>>();

export function isCallbackEffectCurrent(active: boolean, sessionCurrent: boolean): boolean {
    return active && sessionCurrent;
}

/** Claim a navigation only while the consuming effect and session are current. */
export function claimCallbackNavigation(
    completion: Promise<unknown>,
    active: boolean,
    sessionCurrent: boolean,
): boolean {
    if (!isCallbackEffectCurrent(active, sessionCurrent) || claimed.has(completion)) return false;
    claimed.add(completion);
    return true;
}

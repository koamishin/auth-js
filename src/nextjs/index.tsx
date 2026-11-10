'use client';

import React, {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useMemo,
    useRef,
    useState,
} from 'react';
import {
    KoamishinClient,
    KoamishinUser,
    SessionTokenClaims,
    createKoamishinClient,
    decodeSessionToken,
} from '../index';

const RETURN_TO_STORAGE_KEY = 'koamishin:return_to';

export interface KoamishinContextValue {
    client: KoamishinClient | null;
    user: KoamishinUser | null;
    sessionClaims: SessionTokenClaims | null;
    isLoaded: boolean;
    isSignedIn: boolean;
    error: string | null;
    signIn: (options?: { redirectUrl?: string }) => Promise<void>;
    signUp: (options?: { redirectUrl?: string }) => Promise<void>;
    signOut: (options?: { redirectUrl?: string }) => void;
    completeCallback: () => Promise<KoamishinUser>;
}

const KoamishinContext = createContext<KoamishinContextValue | undefined>(
    undefined,
);

export interface KoamishinProviderProps {
    children: React.ReactNode;
    portalUrl?: string;
    publishableKey?: string;
    clientId?: string;
    redirectUri?: string;
    scopes?: string[];
}

/**
 * Root authentication provider for Next.js applications.
 *
 * Mirrors Clerk's `<ClerkProvider>` in `app/layout.tsx`:
 * - Initializes the Koamishin PKCE client from `NEXT_PUBLIC_KOAMISHIN_*` env vars,
 * - Hydrates the signed-in user from sessionStorage and `/api/oauth/userinfo`,
 * - Mints and rotates the 60-second RS256 `__koamishin_session` cookie so
 *   Next.js `proxy.ts` (`koamishinMiddleware`) and Server Components (`auth()`)
 *   can verify the session offline against `/oauth/jwks`.
 */
export function KoamishinProvider({
    children,
    portalUrl,
    publishableKey,
    clientId,
    redirectUri,
    scopes,
}: KoamishinProviderProps) {
    const resolvedPortalUrl =
        portalUrl ?? process.env.NEXT_PUBLIC_KOAMISHIN_PORTAL_URL ?? '';
    const resolvedPublishableKey =
        publishableKey ??
        process.env.NEXT_PUBLIC_KOAMISHIN_PUBLISHABLE_KEY ??
        '';
    const resolvedClientId =
        clientId ?? process.env.NEXT_PUBLIC_KOAMISHIN_CLIENT_ID ?? '';
    const resolvedRedirectUri =
        redirectUri ??
        process.env.NEXT_PUBLIC_KOAMISHIN_REDIRECT_URI ??
        (typeof window !== 'undefined'
            ? `${window.location.origin}/auth/callback`
            : 'http://localhost:3000/auth/callback');

    const client = useMemo(() => {
        const key = resolvedPublishableKey || resolvedClientId;
        if (!resolvedPortalUrl || !key) {
            return null;
        }
        try {
            const baseConfig = {
                portalUrl: resolvedPortalUrl,
                redirectUri: resolvedRedirectUri,
                scopes: scopes ?? ['openid', 'profile', 'email', 'roles'],
            };
            return createKoamishinClient(
                resolvedPublishableKey
                    ? { ...baseConfig, publishableKey: resolvedPublishableKey }
                    : { ...baseConfig, clientId: resolvedClientId },
            );
        } catch (err) {
            console.error('Failed to initialize KoamishinClient:', err);
            return null;
        }
    }, [
        resolvedPortalUrl,
        resolvedPublishableKey,
        resolvedClientId,
        resolvedRedirectUri,
        scopes,
    ]);

    const [user, setUser] = useState<KoamishinUser | null>(null);
    const [sessionClaims, setSessionClaims] =
        useState<SessionTokenClaims | null>(null);
    const [isLoaded, setIsLoaded] = useState<boolean>(false);
    const [error, setError] = useState<string | null>(null);

    const syncCookieAndClaims = useCallback(
        async (activeClient: KoamishinClient, accessToken?: string) => {
            try {
                const minted =
                    await activeClient.syncSessionCookie(accessToken);
                setSessionClaims(decodeSessionToken(minted));
            } catch {
                // Session token endpoint is optional if offline
            }
        },
        [],
    );

    useEffect(() => {
        if (!client) {
            setIsLoaded(true);
            return;
        }

        // Skip automatic userinfo lookup while on the OAuth callback route
        // with a pending authorization code so the callback handler can exchange it first.
        if (typeof window !== 'undefined') {
            const params = new URLSearchParams(window.location.search);
            if (params.has('code') && params.has('state')) {
                const cached = client.getStoredUser();
                if (cached) {
                    setUser(cached);
                }
                setIsLoaded(true);
                return;
            }

            const authAction = params.get('auth');
            const redirectTarget = params.get('redirect_url');
            if (authAction === 'signin' || authAction === 'signup') {
                if (redirectTarget && typeof sessionStorage !== 'undefined') {
                    sessionStorage.setItem(
                        RETURN_TO_STORAGE_KEY,
                        redirectTarget,
                    );
                }
                params.delete('auth');
                params.delete('redirect_url');
                const cleanSearch = params.toString();
                const cleanUrl = `${window.location.pathname}${cleanSearch ? `?${cleanSearch}` : ''}${window.location.hash}`;
                window.history.replaceState({}, '', cleanUrl);

                if (authAction === 'signup') {
                    void client.redirectToSignUp();
                } else {
                    void client.redirectToSignIn();
                }
                return;
            }
        }

        const storedToken = client.getStoredAccessToken();
        const cachedUser = client.getStoredUser();

        if (!storedToken) {
            setUser(null);
            setSessionClaims(null);
            setIsLoaded(true);
            return;
        }

        if (cachedUser) {
            setUser(cachedUser);
        }

        let cancelled = false;

        (async () => {
            try {
                const freshUser = await client.getUser(storedToken);
                if (cancelled) return;
                setUser(freshUser);
                setError(null);
                await syncCookieAndClaims(client, storedToken);
            } catch {
                try {
                    const refreshed = await client.refreshToken();
                    const freshUser = await client.getUser(
                        refreshed.access_token,
                    );
                    if (cancelled) return;
                    setUser(freshUser);
                    setError(null);
                    await syncCookieAndClaims(client, refreshed.access_token);
                } catch (err) {
                    if (cancelled) return;
                    client.signOut();
                    setUser(null);
                    setSessionClaims(null);
                    setError(
                        err instanceof Error ? err.message : 'Session expired',
                    );
                }
            } finally {
                if (!cancelled) {
                    setIsLoaded(true);
                }
            }
        })();

        return () => {
            cancelled = true;
        };
    }, [client, syncCookieAndClaims]);

    // Rotate the 60-second session token cookie every 45 seconds while signed in
    useEffect(() => {
        if (!client || !user) {
            return;
        }

        const interval = window.setInterval(() => {
            void syncCookieAndClaims(client);
        }, 45_000);

        return () => window.clearInterval(interval);
    }, [client, user, syncCookieAndClaims]);

    const signIn = useCallback(
        async (options?: { redirectUrl?: string }) => {
            if (!client) {
                throw new Error(
                    'KoamishinClient is not configured. Check NEXT_PUBLIC_KOAMISHIN_PORTAL_URL and NEXT_PUBLIC_KOAMISHIN_PUBLISHABLE_KEY.',
                );
            }
            if (options?.redirectUrl && typeof sessionStorage !== 'undefined') {
                sessionStorage.setItem(
                    RETURN_TO_STORAGE_KEY,
                    options.redirectUrl,
                );
            }
            await client.redirectToSignIn();
        },
        [client],
    );

    const signUp = useCallback(
        async (options?: { redirectUrl?: string }) => {
            if (!client) {
                throw new Error(
                    'KoamishinClient is not configured. Check NEXT_PUBLIC_KOAMISHIN_PORTAL_URL and NEXT_PUBLIC_KOAMISHIN_PUBLISHABLE_KEY.',
                );
            }
            if (options?.redirectUrl && typeof sessionStorage !== 'undefined') {
                sessionStorage.setItem(
                    RETURN_TO_STORAGE_KEY,
                    options.redirectUrl,
                );
            }
            await client.redirectToSignUp();
        },
        [client],
    );

    const signOut = useCallback(
        (options?: { redirectUrl?: string }) => {
            client?.signOut();
            setUser(null);
            setSessionClaims(null);
            if (typeof window !== 'undefined') {
                window.location.href = options?.redirectUrl ?? '/';
            }
        },
        [client],
    );

    const completeCallback = useCallback(async (): Promise<KoamishinUser> => {
        if (!client) {
            throw new Error('KoamishinClient is not configured.');
        }

        const { user: authenticatedUser, tokens } =
            await client.handleRedirectCallback();
        await syncCookieAndClaims(client, tokens.access_token);
        setUser(authenticatedUser);
        setError(null);
        setIsLoaded(true);
        return authenticatedUser;
    }, [client, syncCookieAndClaims]);

    const value = useMemo<KoamishinContextValue>(
        () => ({
            client,
            user,
            sessionClaims,
            isLoaded,
            isSignedIn: Boolean(user),
            error,
            signIn,
            signUp,
            signOut,
            completeCallback,
        }),
        [
            client,
            user,
            sessionClaims,
            isLoaded,
            error,
            signIn,
            signUp,
            signOut,
            completeCallback,
        ],
    );

    return (
        <KoamishinContext.Provider value={value}>
            {children}
        </KoamishinContext.Provider>
    );
}

export function useKoamishin(): KoamishinContextValue {
    const context = useContext(KoamishinContext);
    if (!context) {
        throw new Error(
            'useKoamishin must be used within a <KoamishinProvider>',
        );
    }
    return context;
}

export function useAuth() {
    const {
        user,
        sessionClaims,
        isLoaded,
        isSignedIn,
        signIn,
        signUp,
        signOut,
    } = useKoamishin();

    return {
        isLoaded,
        isSignedIn,
        userId: user?.sub ?? null,
        sessionId: sessionClaims?.sid ?? null,
        sessionClaims,
        signIn,
        signUp,
        signOut,
    };
}

export function useUser() {
    const { user, isLoaded, isSignedIn } = useKoamishin();
    return {
        isLoaded,
        isSignedIn,
        user,
    };
}

export const useSession = useKoamishin;

/**
 * Conditional rendering component matching Clerk's `<Show when="signed-in" | "signed-out">`.
 */
export function Show({
    when,
    fallback = null,
    children,
}: {
    when: 'signed-in' | 'signed-out';
    fallback?: React.ReactNode;
    children: React.ReactNode;
}) {
    const { isLoaded, isSignedIn } = useKoamishin();

    if (!isLoaded) {
        return <>{fallback}</>;
    }

    if (when === 'signed-in') {
        return isSignedIn ? <>{children}</> : <>{fallback}</>;
    }

    return !isSignedIn ? <>{children}</> : <>{fallback}</>;
}

/**
 * Prebuilt Sign In trigger matching Clerk's `<SignInButton />`.
 */
export function SignInButton({
    children,
    redirectUrl,
    className,
}: {
    children?: React.ReactNode;
    redirectUrl?: string;
    className?: string;
}) {
    const { signIn } = useKoamishin();

    const handleClick = () => {
        void signIn({ redirectUrl });
    };

    if (children) {
        return (
            <span onClick={handleClick} className="inline-flex cursor-pointer">
                {children}
            </span>
        );
    }

    return (
        <button
            type="button"
            onClick={handleClick}
            className={
                className ??
                'text-sm sm:text-base font-medium text-gray-700 hover:text-gray-950 dark:text-gray-200 dark:hover:text-white px-3 py-2 cursor-pointer transition-colors'
            }
        >
            {children ?? 'Sign In'}
        </button>
    );
}

/**
 * Prebuilt Sign Up trigger matching Clerk's `<SignUpButton />`.
 */
export function SignUpButton({
    children,
    redirectUrl,
    className,
}: {
    children?: React.ReactNode;
    redirectUrl?: string;
    className?: string;
}) {
    const { signUp } = useKoamishin();

    const handleClick = () => {
        void signUp({ redirectUrl });
    };

    if (children) {
        return (
            <span onClick={handleClick} className="inline-flex cursor-pointer">
                {children}
            </span>
        );
    }

    return (
        <button
            type="button"
            onClick={handleClick}
            className={
                className ??
                'bg-purple-700 hover:bg-purple-600 text-white rounded-full font-medium text-sm sm:text-base h-10 sm:h-12 px-4 sm:px-5 cursor-pointer transition-colors'
            }
        >
            {children ?? 'Sign Up'}
        </button>
    );
}

/**
 * Prebuilt User Avatar & Account menu matching Clerk's `<UserButton />`.
 */
export function UserButton({
    afterSignOutUrl = '/',
}: {
    afterSignOutUrl?: string;
}) {
    const { user, signOut } = useKoamishin();
    const [open, setOpen] = useState(false);
    const containerRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const onClickOutside = (event: MouseEvent) => {
            if (
                containerRef.current &&
                !containerRef.current.contains(event.target as Node)
            ) {
                setOpen(false);
            }
        };
        document.addEventListener('mousedown', onClickOutside);
        return () => document.removeEventListener('mousedown', onClickOutside);
    }, []);

    if (!user) {
        return null;
    }

    const initials = (user.name || user.email || 'U')
        .split(/\s+/)
        .map((part) => part[0])
        .join('')
        .slice(0, 2)
        .toUpperCase();

    return (
        <div
            ref={containerRef}
            className="relative z-50 inline-block text-left"
        >
            <button
                type="button"
                onClick={() => setOpen((prev) => !prev)}
                aria-expanded={open}
                aria-label="Open user menu"
                className="flex h-10 w-10 items-center justify-center rounded-full bg-purple-700 text-sm font-semibold text-white shadow-sm ring-2 ring-purple-700/20 transition hover:bg-purple-600 cursor-pointer overflow-hidden"
            >
                {user.picture ? (
                    // eslint-disable-next-line @next/next/no-img-element
                    <img
                        src={user.picture}
                        alt={user.name}
                        className="h-full w-full object-cover"
                    />
                ) : (
                    <span>{initials}</span>
                )}
            </button>

            {open && (
                <div className="absolute right-0 z-50 mt-2 w-72 origin-top-right rounded-2xl border border-gray-200 bg-white p-4 shadow-xl dark:border-zinc-800 dark:bg-zinc-900">
                    <div className="flex items-center gap-3 border-b border-gray-100 pb-3 dark:border-zinc-800">
                        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-purple-700 text-sm font-semibold text-white">
                            {initials}
                        </div>
                        <div className="min-w-0 flex-1">
                            <p className="truncate text-sm font-semibold text-gray-900 dark:text-white">
                                {user.name}
                            </p>
                            <p className="truncate text-xs text-gray-500 dark:text-zinc-400">
                                {user.email}
                            </p>
                        </div>
                    </div>

                    <div className="py-2.5 text-xs text-gray-500 dark:text-zinc-400 space-y-1 border-b border-gray-100 dark:border-zinc-800">
                        {user.environment && (
                            <div className="flex items-center justify-between">
                                <span>Environment</span>
                                <span className="rounded-full bg-purple-50 px-2 py-0.5 font-medium text-purple-700 dark:bg-purple-950/60 dark:text-purple-300">
                                    {user.environment}
                                </span>
                            </div>
                        )}
                        {user.roles && user.roles.length > 0 && (
                            <div className="flex items-center justify-between">
                                <span>Role</span>
                                <span className="font-mono text-gray-700 dark:text-zinc-200">
                                    {user.roles.join(', ')}
                                </span>
                            </div>
                        )}
                    </div>

                    <div className="mt-2 space-y-1">
                        <a
                            href="/dashboard"
                            className="flex w-full items-center rounded-lg px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100 dark:text-zinc-200 dark:hover:bg-zinc-800"
                        >
                            Dashboard
                        </a>
                        <button
                            type="button"
                            onClick={() => {
                                setOpen(false);
                                signOut({ redirectUrl: afterSignOutUrl });
                            }}
                            className="flex w-full items-center rounded-lg px-3 py-2 text-sm font-medium text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-950/40 cursor-pointer"
                        >
                            Sign out
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
}

/**
 * Drop-in OAuth PKCE callback component for `app/auth/callback/page.tsx`.
 */
export function AuthenticateWithRedirectCallback({
    afterSignInUrl = '/dashboard',
}: {
    afterSignInUrl?: string;
}) {
    const { completeCallback } = useKoamishin();
    const [error, setError] = useState<string | null>(null);
    const hasRunRef = useRef(false);

    useEffect(() => {
        if (hasRunRef.current) {
            return;
        }
        hasRunRef.current = true;

        completeCallback()
            .then(() => {
                const returnTo =
                    typeof sessionStorage !== 'undefined'
                        ? sessionStorage.getItem(RETURN_TO_STORAGE_KEY)
                        : null;
                if (returnTo && typeof sessionStorage !== 'undefined') {
                    sessionStorage.removeItem(RETURN_TO_STORAGE_KEY);
                }
                window.location.replace(returnTo || afterSignInUrl);
            })
            .catch((err) => {
                setError(
                    err instanceof Error
                        ? err.message
                        : 'Authentication callback failed.',
                );
            });
    }, [afterSignInUrl, completeCallback]);

    return (
        <div className="flex min-h-[60vh] items-center justify-center font-sans">
            <div className="space-y-3 text-center">
                {!error ? (
                    <p className="text-sm font-medium text-gray-600 dark:text-gray-400 animate-pulse">
                        Completing secure sign-in with Koamishin...
                    </p>
                ) : (
                    <div className="space-y-3">
                        <p className="text-sm font-medium text-red-600 dark:text-red-400">
                            {error}
                        </p>
                        <a
                            href="/"
                            className="inline-block rounded-full bg-gray-900 px-4 py-2 text-xs font-medium text-white dark:bg-white dark:text-gray-900"
                        >
                            Return home
                        </a>
                    </div>
                )}
            </div>
        </div>
    );
}

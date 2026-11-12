/**
 * Accept only same-origin absolute paths, never absolute or protocol-relative URLs.
 */
export function safeReturnPath(value: string | null | undefined): string | null {
    if (!value || !value.startsWith('/') || value.startsWith('//') ||
        /[\\\u0000-\u001f\u007f]/.test(value)) {
        return null;
    }

    try {
        const url = new URL(value, 'https://return.invalid');
        return url.origin === 'https://return.invalid' &&
            !url.pathname.startsWith('//')
            ? `${url.pathname}${url.search}${url.hash}`
            : null;
    } catch {
        return null;
    }
}

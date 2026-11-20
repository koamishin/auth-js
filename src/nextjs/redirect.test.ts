import { expect, test } from 'vitest';
import { safeReturnPath } from './redirect';

test.each([
    ['https://evil.test/path', null],
    ['//evil.test/path', null],
    ['/\\evil.test/path', null],
    ['/\nevil.test', null],
    ['javascript:alert(1)', null],
    ['dashboard', null],
    ['/dashboard?view=1#section', '/dashboard?view=1#section'],
    ['/a/../dashboard', '/dashboard'],
    ['/a/..//evil.example/x', null],
    ['/a/%2e%2e//evil.example/x', null],
])('validates return path %s', (input, expected) => {
    expect(safeReturnPath(input)).toBe(expected);
});

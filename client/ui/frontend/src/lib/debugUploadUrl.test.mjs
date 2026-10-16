import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resolveDebugUploadUrl } from './debugUploadUrl.ts';

test('absent endpoint means no upload', () => {
    assert.equal(resolveDebugUploadUrl(undefined), '');
    assert.equal(resolveDebugUploadUrl(''), '');
    assert.equal(resolveDebugUploadUrl('  '), '');
});

test('explicit HTTPS destination is supported', () => {
    assert.equal(resolveDebugUploadUrl('https://support.example.test/upload-url'), 'https://support.example.test/upload-url');
});

test('inherited service domains are rejected', () => {
    for (const host of ['netbird.io', 'upload.debug.netbird.io', 'wiretrustee.com', 'netbird.cloud']) {
        assert.equal(resolveDebugUploadUrl(`https://${host}/upload-url`), '', host);
    }
});

test('invalid and credential-bearing endpoints are rejected', () => {
    for (const endpoint of ['http://support.example.test/upload', 'ftp://support.example.test/upload',
        'https://user:secret@support.example.test/upload', 'https://support.example.test/upload#fragment',
        'not a URL', '//support.example.test/upload']) {
        assert.equal(resolveDebugUploadUrl(endpoint), '', endpoint);
    }
});

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

test('debug UI cannot upload without affirmative consent and an endpoint', () => {
    const source = readFileSync(fileURLToPath(new URL('../contexts/DebugBundleContext.tsx', import.meta.url)), 'utf8');
    const view = readFileSync(fileURLToPath(new URL('../modules/settings/SettingsTroubleshooting.tsx', import.meta.url)), 'utf8');
    assert.match(source, /const \[upload, setUpload\] = useState\(false\)/);
    assert.match(source, /uploadUrl: upload && DEBUG_UPLOAD_URL \? DEBUG_UPLOAD_URL : ""/);
    assert.doesNotMatch(source, /upload\.debug\.netbird\.io/);
    assert.match(view, /disabled=\{!uploadAvailable\}/);
});

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const base = new URL("../", import.meta.url);
const source = (path) => readFileSync(new URL(path, base), "utf8");

test("fresh welcome never assumes hosted NetBird management", () => {
    const welcome = source("modules/welcome/WelcomeStepManagement.tsx");
    assert.match(welcome, /const startsCloud = Boolean\(initialUrl\.trim\(\)\) && isNetbirdCloud\(initialUrl\)/);
    assert.match(welcome, /startsCloud \? ManagementMode\.Cloud : ManagementMode\.SelfHosted/);
    assert.match(welcome, /\{startsCloud && \(\s*<div[^>]*>\s*<ManagementServerSwitch/s);
    assert.match(welcome, /!trimmedUrl \|\| !syntaxValid/);
});

test("new profile creation requires self-hosted address selection", () => {
    const modal = source("modules/profiles/ProfileCreationModal.tsx");
    assert.match(modal, /initial \? initialModeFromUrl\(initial\.managementUrl\) : ManagementMode\.SelfHosted/g);
    assert.match(modal, /\{isEdit && \(\s*<ManagementServerSwitch/s);
    assert.match(modal, /if \(!trimmed \|\| !isValidManagementUrl\(trimmed\)\)/);
    assert.match(modal, /if \(managedManagementUrl\)/);
});

test("unconfigured management in settings is not automatically hosted", () => {
    const hook = source("hooks/useManagementUrl.ts");
    assert.match(hook, /Boolean\(url\.trim\(\)\) && isNetbirdCloud\(url\)/);
    assert.match(hook, /ManagementMode\.Cloud : ManagementMode\.SelfHosted/);
    assert.match(hook, /if \(next === ManagementMode\.Cloud && !isNetbirdCloud\(config\.managementUrl\)\)/);
});

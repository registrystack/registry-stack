// SPDX-License-Identifier: Apache-2.0

import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';

import * as vscode from 'vscode';

suite('Registry Stack extension', () => {
  test('starts a language server for every trusted Registry Stack workspace folder', async () => {
    assert.strictEqual(vscode.workspace.isTrusted, true);
    assert.strictEqual(vscode.workspace.workspaceFolders?.length, 2);

    const extension = vscode.extensions.getExtension('registrystack.registry-stack');
    assert.ok(extension, 'Registry Stack extension is available in the Extension Host');
    assert.strictEqual(
      extension.packageJSON.capabilities?.untrustedWorkspaces?.supported,
      false,
    );
    assert.strictEqual(extension.packageJSON.capabilities?.virtualWorkspaces?.supported, false);
    await assertExtensionActivated(extension);

    await assertWorkspaceSymbol('alpha-registry');
    await assertWorkspaceSymbol('beta-registry');

    const alphaFolder = vscode.workspace.workspaceFolders?.find((folder) => folder.name === 'alpha');
    assert.ok(alphaFolder, 'alpha workspace folder is available');
    fs.writeFileSync(
      path.join(alphaFolder.uri.fsPath, 'registry-stack.yaml'),
      'version: 1\nregistry: { id: alpha-reloaded }\nservices: {}\n',
    );
    await assertWorkspaceSymbol('alpha-reloaded');

    const gammaPath = path.join(path.dirname(alphaFolder.uri.fsPath), 'project-gamma');
    fs.mkdirSync(gammaPath);
    fs.writeFileSync(
      path.join(gammaPath, 'registry-stack.yaml'),
      'version: 1\nregistry: { id: gamma-registry }\nservices: {}\n',
    );
    assert.strictEqual(
      vscode.workspace.updateWorkspaceFolders(2, 0, {
        uri: vscode.Uri.file(gammaPath),
        name: 'gamma',
      }),
      true,
    );
    await assertWorkspaceFolderCount(3);
    await assertWorkspaceSymbol('gamma-registry');

    assert.strictEqual(vscode.workspace.updateWorkspaceFolders(2, 1), true);
    await assertWorkspaceFolderCount(2);
    await assertWorkspaceSymbolAbsent('gamma-registry');
  });
});

async function assertExtensionActivated(extension: vscode.Extension<unknown>): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (extension.isActive) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.fail('Registry Stack extension did not activate for the workspace manifest');
}

async function assertWorkspaceFolderCount(expected: number): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (vscode.workspace.workspaceFolders?.length === expected) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.fail(`workspace folder count did not become ${expected}`);
}

async function assertWorkspaceSymbol(expected: string): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const symbols = await vscode.commands.executeCommand<vscode.SymbolInformation[]>(
      'vscode.executeWorkspaceSymbolProvider',
      expected,
    );
    if (symbols?.some((symbol) => symbol.name === expected)) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.fail(`workspace symbol ${expected} was not provided`);
}

async function assertWorkspaceSymbolAbsent(unexpected: string): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const symbols = await vscode.commands.executeCommand<vscode.SymbolInformation[]>(
      'vscode.executeWorkspaceSymbolProvider',
      unexpected,
    );
    if (!symbols?.some((symbol) => symbol.name === unexpected)) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.fail(`workspace symbol ${unexpected} remained after its folder was removed`);
}

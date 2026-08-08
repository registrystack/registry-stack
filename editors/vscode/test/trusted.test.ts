// SPDX-License-Identifier: Apache-2.0

import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';

import * as vscode from 'vscode';

suite('Registry Stack extension', () => {
  suiteTeardown(() => {
    fs.rmSync(path.resolve(__dirname, '../../dist/registry-stack-cli-path'), { force: true });
  });

  test('uses the installed registryctl or evidencectl for every trusted Registry Stack workspace folder', async () => {
    assert.strictEqual(vscode.workspace.isTrusted, true);
    assert.strictEqual(vscode.workspace.workspaceFolders?.length, 3);

    const extension = vscode.extensions.getExtension('registrystack.registry-stack');
    assert.ok(extension, 'Registry Stack extension is available in the Extension Host');
    assert.strictEqual(
      extension.packageJSON.capabilities?.untrustedWorkspaces?.supported,
      false,
    );
    assert.strictEqual(extension.packageJSON.capabilities?.virtualWorkspaces?.supported, false);
    await assertExtensionActivated(extension);

    // One client per workspace folder serves both the Relay and Evidence
    // project families; the alpha/beta folders are Relay manifests and
    // evidence is an Evidence authoring project, all discovered through the
    // same installer-selected registryctl.
    await assertWorkspaceSymbol('alpha-registry');
    await assertWorkspaceSymbol('beta-registry');
    await assertWorkspaceSymbol('smoke');

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
      vscode.workspace.updateWorkspaceFolders(3, 0, {
        uri: vscode.Uri.file(gammaPath),
        name: 'gamma',
      }),
      true,
    );
    await assertWorkspaceFolderCount(4);
    await assertWorkspaceSymbol('gamma-registry');

    assert.strictEqual(vscode.workspace.updateWorkspaceFolders(3, 1), true);
    await assertWorkspaceFolderCount(3);
    await assertWorkspaceSymbolAbsent('gamma-registry');

    // Deleting the installer metadata and restarting proves the PATH
    // fallback tier genuinely works: the registryctl that serves the metadata
    // route is kept off PATH, and the registryctl that is on PATH refuses the
    // subcommand, so once the packaged-CLI metadata is gone every folder can
    // only be served by the evidencectl standing behind it.
    fs.rmSync(path.resolve(__dirname, '../../dist/registry-stack-cli-path'), { force: true });
    await vscode.commands.executeCommand('registryStack.restartLanguageServer');
    await assertWorkspaceSymbol('alpha-reloaded');
    await assertWorkspaceSymbol('beta-registry');
    await assertWorkspaceSymbol('smoke');
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

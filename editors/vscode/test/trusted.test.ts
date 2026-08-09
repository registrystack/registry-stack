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
    for (const activationEvent of [
      'workspaceContains:**/registry-stack.yaml',
      'workspaceContains:**/evidence-project.yaml',
      'workspaceContains:**/source.openapi.yaml',
    ]) {
      assert.ok(
        extension.packageJSON.activationEvents?.includes(activationEvent),
        `${activationEvent} activates nested workspaces`,
      );
    }
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

    // Count real server starts from here on so the nested-folder behavior is
    // observable rather than inferred from a missing symbol. The three
    // declared roots each get one client after the configuration restart.
    const testRunDirectory = path.dirname(alphaFolder.uri.fsPath);
    const startLog = path.join(testRunDirectory, 'language-server-starts.log');
    const countingServer = path.join(testRunDirectory, 'counting-language-server');
    const languageServer = path.resolve(
      __dirname,
      '../../../../target/debug/registry-language-server',
    );
    fs.writeFileSync(
      countingServer,
      [
        '#!/bin/sh',
        `printf 'start\\n' >> ${shellQuote(startLog)}`,
        `exec ${shellQuote(languageServer)}`,
        '',
      ].join('\n'),
    );
    fs.chmodSync(countingServer, 0o755);
    const configuration = vscode.workspace.getConfiguration('registryStack');
    await configuration.update(
      'languageServer.path',
      countingServer,
      vscode.ConfigurationTarget.Workspace,
    );
    await assertLanguageServerStartCount(startLog, 3);

    const irrelevantPath = path.join(testRunDirectory, 'unrelated-yaml');
    fs.mkdirSync(irrelevantPath);
    const unrelatedDocumentPath = path.join(irrelevantPath, 'notes.yaml');
    fs.writeFileSync(unrelatedDocumentPath, 'notes: true\n');
    assert.strictEqual(
      vscode.workspace.updateWorkspaceFolders(3, 0, {
        uri: vscode.Uri.file(irrelevantPath),
        name: 'irrelevant',
      }),
      true,
    );
    await assertWorkspaceFolderCount(4);
    const unrelatedDocument = await vscode.workspace.openTextDocument(unrelatedDocumentPath);
    assert.strictEqual(unrelatedDocument.languageId, 'yaml');
    await assertLanguageServerStartCountStable(startLog, 3);

    assert.strictEqual(
      vscode.workspace.updateWorkspaceFolders(4, 0, {
        uri: vscode.Uri.parse('registry-test://example.invalid/remote'),
        name: 'remote',
      }),
      true,
    );
    await assertWorkspaceFolderCount(5);
    await assertLanguageServerStartCountStable(startLog, 3);

    // A parent folder is deliberately not scanned. Opening one YAML document
    // under its nested Evidence root is the bounded signal that starts the
    // single client for that workspace folder; the server then discovers the
    // project by walking upward from that document.
    const parentPath = path.join(testRunDirectory, 'evidence-parent');
    const nestedEvidencePath = path.join(parentPath, 'projects', 'evidence');
    const nestedSelectorsPath = path.join(nestedEvidencePath, 'selectors');
    fs.mkdirSync(nestedSelectorsPath, { recursive: true });
    fs.writeFileSync(
      path.join(nestedEvidencePath, 'evidence-project.yaml'),
      'version: 1\nproject: evidence-authoring\n',
    );
    const nestedSelectorPath = path.join(nestedSelectorsPath, 'nested-adopter.yaml');
    fs.writeFileSync(nestedSelectorPath, 'fields: {}\n');
    assert.strictEqual(
      vscode.workspace.updateWorkspaceFolders(5, 0, {
        uri: vscode.Uri.file(parentPath),
        name: 'evidence-parent',
      }),
      true,
    );
    await assertWorkspaceFolderCount(6);
    await assertLanguageServerStartCountStable(startLog, 3);
    await vscode.workspace.openTextDocument(nestedSelectorPath);
    await assertLanguageServerStartCount(startLog, 4);
    await assertWorkspaceSymbol('nested-adopter');

    const legacyEvidencePath = path.join(parentPath, 'legacy', 'evidence');
    const legacyQuestionsPath = path.join(legacyEvidencePath, 'questions');
    const legacySelectorsPath = path.join(legacyEvidencePath, 'selectors');
    fs.mkdirSync(legacyQuestionsPath, { recursive: true });
    fs.mkdirSync(legacySelectorsPath);
    fs.writeFileSync(
      path.join(legacyEvidencePath, 'source.openapi.yaml'),
      'openapi: 3.1.0\ninfo: { title: test, version: 1.0.0 }\npaths: {}\n',
    );
    const legacySelectorPath = path.join(legacySelectorsPath, 'legacy-selector.yaml');
    fs.writeFileSync(legacySelectorPath, 'fields: {}\n');
    await vscode.workspace.openTextDocument(legacySelectorPath);
    await assertWorkspaceSymbol('legacy-selector');
    await assertLanguageServerStartCountStable(startLog, 4);

    assert.strictEqual(vscode.workspace.updateWorkspaceFolders(3, 3), true);
    await assertWorkspaceFolderCount(3);

    // Deleting the installer metadata and restarting proves the PATH
    // fallback tier genuinely works: the registryctl that serves the metadata
    // route is kept off PATH, and the registryctl that is on PATH refuses the
    // subcommand, so once the packaged-CLI metadata is gone every folder can
    // only be served by the evidencectl standing behind it.
    fs.rmSync(path.resolve(__dirname, '../../dist/registry-stack-cli-path'), { force: true });
    await configuration.update(
      'languageServer.path',
      undefined,
      vscode.ConfigurationTarget.Workspace,
    );
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

async function assertLanguageServerStartCount(log: string, expected: number): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (languageServerStartCount(log) === expected) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.strictEqual(languageServerStartCount(log), expected);
}

async function assertLanguageServerStartCountStable(
  log: string,
  expected: number,
): Promise<void> {
  for (let attempt = 0; attempt < 10; attempt += 1) {
    assert.strictEqual(languageServerStartCount(log), expected);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

function languageServerStartCount(log: string): number {
  try {
    return fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).length;
  } catch {
    return 0;
  }
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

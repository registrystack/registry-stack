// SPDX-License-Identifier: Apache-2.0

import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';

import * as vscode from 'vscode';

suite('Registry Stack extension', () => {
  suiteTeardown(() => {
    fs.rmSync(path.resolve(__dirname, '../../dist/registry-stack-cli-path'), { force: true });
  });

  test('uses matching adopter CLIs and discovers current product folders', async () => {
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
      'workspaceContains:**/registry.yaml',
      'workspaceContains:**/evidence-project.yaml',
      'workspaceContains:**/source.openapi.yaml',
      'workspaceContains:**/casework.yaml',
      'workspaceContains:**/scheduling.yaml',
      'workspaceContains:**/messaging.yaml',
      'workspaceContains:**/origins.yaml',
      'workspaceContains:**/manifest.yaml',
      'workspaceContains:**/metadata.yaml',
      'workspaceContains:**/.registry-stack-editor/project.json',
    ]) {
      assert.ok(
        extension.packageJSON.activationEvents?.includes(activationEvent),
        `${activationEvent} activates nested workspaces`,
      );
    }
    await assertExtensionActivated(extension);

    // One client per workspace folder serves the BReg and Evidence
    // project families; alpha and beta are BReg, while evidence is an
    // Evidence authoring project, all discovered through the same
    // installer-selected evidencectl.
    await assertWorkspaceSymbol('alpha-registry');
    await assertWorkspaceSymbol('beta-registry');
    await assertWorkspaceSymbol('smoke');

    const productFixtures = [
      ['breg', 'registry.yaml', 'kind: RegistryProject\nentities:\n  - id: host-person\n', 'host-person'],
      ['casework', 'casework.yaml', 'kind: CaseworkProject\nqueues:\n  - id: host-queue\n', 'host-queue'],
      ['scheduling', 'scheduling.yaml', 'kind: SchedulingPolicyPackage\nservices:\n  - id: host-service\n', 'host-service'],
      ['messaging', 'messaging.yaml', 'kind: MessagingPackage\nproviders:\n  - id: host-provider\n', 'host-provider'],
      ['discovery', 'origins.yaml', 'schemaVersion: registry-discovery/origins/v1alpha1\norigins:\n  - originId: host-origin\n', 'host-origin'],
      ['render', 'manifest.yaml', 'kind: RenderBundle\ndocuments:\n  - id: host-document\n', 'host-document'],
      ['manifest', 'custom.yaml', 'schema_version: registry-manifest/v1\ncatalog:\n  id: host-catalog\n', 'host-catalog'],
      ['evidence-oid4vci', 'wallet-config.yml', 'issuer:\n  publicUrl: https://issuer.example.invalid\n', 'issuer'],
    ];
    const initialFolder = vscode.workspace.workspaceFolders?.[0];
    assert.ok(initialFolder);
    for (const [product, filename, content, symbol] of productFixtures) {
      const directory = path.join(path.dirname(initialFolder.uri.fsPath), `host-${product}`);
      fs.mkdirSync(directory);
      const documentPath = path.join(directory, filename);
      fs.writeFileSync(documentPath, content);
      if (product === 'manifest' || product === 'evidence-oid4vci') {
        fs.mkdirSync(path.join(directory, '.registry-stack-editor'));
        fs.writeFileSync(
          path.join(directory, '.registry-stack-editor/project.json'),
          JSON.stringify({ product, document: filename }),
        );
      }
      await changeWorkspaceFolders(3, 0, {
        uri: vscode.Uri.file(directory), name: product,
      });
      await assertWorkspaceFolderCount(4);
      await vscode.workspace.openTextDocument(documentPath);
      await assertWorkspaceSymbol(symbol, documentPath);
      await changeWorkspaceFolders(3, 1);
      await assertWorkspaceFolderCount(3);
    }

    const alphaFolder = vscode.workspace.workspaceFolders?.find((folder) => folder.name === 'alpha');
    assert.ok(alphaFolder, 'alpha workspace folder is available');
    fs.writeFileSync(
      path.join(alphaFolder.uri.fsPath, 'registry.yaml'),
      'apiVersion: registry.registrystack.org/v1alpha1\nkind: RegistryProject\nregistry: { id: alpha-reloaded }\n',
    );
    await assertWorkspaceSymbol('alpha-reloaded');

    const gammaPath = path.join(path.dirname(alphaFolder.uri.fsPath), 'project-gamma');
    fs.mkdirSync(gammaPath);
    fs.writeFileSync(
      path.join(gammaPath, 'registry.yaml'),
      'apiVersion: registry.registrystack.org/v1alpha1\nkind: RegistryProject\nregistry: { id: gamma-registry }\n',
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

    // A selected executable can be replaced after installation. The old
    // version must be passed over before serving any folder, and the matching
    // evidencectl on PATH still serves the real language-server session.
    const installedCli = fs.readFileSync(
      path.resolve(__dirname, '../../dist/registry-stack-cli-path'),
      'utf8',
    ).trim();
    fs.writeFileSync(installedCli, '#!/bin/sh\nif [ "$1" = "--version" ]; then echo "evidencectl 0.2.0"; exit 0; fi\nexit 64\n');
    await vscode.commands.executeCommand('registryStack.restartLanguageServer');
    await assertWorkspaceSymbol('alpha-reloaded');
    await assertWorkspaceSymbol('smoke');

    // Count real server starts from here on so the nested-folder behavior is
    // observable rather than inferred from a missing symbol. The three
    // declared roots each get one client after the configuration restart.
    const testRunDirectory = path.dirname(alphaFolder.uri.fsPath);
    const startLog = path.join(testRunDirectory, 'language-server-starts.log');
    const countingServer = path.join(testRunDirectory, 'counting-language-server');
    const languageServer = path.join(
      process.env.CARGO_TARGET_DIR ?? path.resolve(__dirname, '../../../..', 'target'),
      'debug/registry-language-server',
    );
    fs.writeFileSync(
      countingServer,
      [
        '#!/bin/sh',
        ...(process.platform === 'darwin' && process.env.REGISTRY_STACK_TEST_LIBRARY_PATH
          ? [`export DYLD_LIBRARY_PATH=${shellQuote(process.env.REGISTRY_STACK_TEST_LIBRARY_PATH)}`]
          : []),
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
    fs.writeFileSync(
      path.join(nestedEvidencePath, 'source.openapi.yaml'),
      'openapi: 3.1.0\ninfo: { title: test, version: 1.0.0 }\npaths: {}\n',
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
    // fallback tier genuinely works: the evidencectl that serves the metadata
    // route is kept off PATH, and the evidencectl that is on PATH refuses the
    // subcommand, so once the packaged-CLI metadata is gone every folder can
    // only be served by the matching Evidence copy standing behind it.
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

// VS Code requires the workspace-change event to finish before another
// updateWorkspaceFolders call, even when workspaceFolders already has its
// next value. Rapid product add/remove cycles must await that event.
async function changeWorkspaceFolders(
  start: number,
  deleteCount: number,
  ...folders: { uri: vscode.Uri; name: string }[]
): Promise<void> {
  let subscription: vscode.Disposable | undefined;
  const changed = new Promise<void>((resolve) => {
    subscription = vscode.workspace.onDidChangeWorkspaceFolders(() => resolve());
  });
  try {
    assert.strictEqual(vscode.workspace.updateWorkspaceFolders(start, deleteCount, ...folders), true);
    await changed;
  } finally {
    subscription?.dispose();
  }
}

async function assertWorkspaceSymbol(expected: string, documentPath?: string): Promise<void> {
  const expectedPath = documentPath === undefined ? undefined : fs.realpathSync(documentPath);
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const symbols = await vscode.commands.executeCommand<vscode.SymbolInformation[]>(
      'vscode.executeWorkspaceSymbolProvider',
      expected,
    );
    if (symbols?.some((symbol) =>
      symbol.name === expected &&
      (expectedPath === undefined || fs.realpathSync(symbol.location.uri.fsPath) === expectedPath)
    )) {
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

// SPDX-License-Identifier: Apache-2.0

import * as fs from 'node:fs';
import * as path from 'node:path';

import * as vscode from 'vscode';
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from 'vscode-languageclient/node';

const clients = new Map<string, LanguageClient>();
let lifecycle = Promise.resolve();

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  context.subscriptions.push(
    vscode.commands.registerCommand('registryStack.restartLanguageServer', async () => {
      await enqueueLifecycle(() => restart(context));
    }),
    vscode.workspace.onDidChangeConfiguration(async (event) => {
      if (event.affectsConfiguration('registryStack.languageServer.path')) {
        await enqueueLifecycle(() => restart(context));
      }
    }),
    vscode.workspace.onDidChangeWorkspaceFolders(async () => {
      await enqueueLifecycle(() => reconcileClients(context));
    }),
  );

  await enqueueLifecycle(() => reconcileClients(context));
}

export async function deactivate(): Promise<void> {
  await enqueueLifecycle(stopAll);
}

async function restart(context: vscode.ExtensionContext): Promise<void> {
  await stopAll();
  await reconcileClients(context);
}

function enqueueLifecycle(operation: () => Promise<void>): Promise<void> {
  lifecycle = lifecycle.then(operation, operation);
  return lifecycle;
}

async function reconcileClients(context: vscode.ExtensionContext): Promise<void> {
  const projectFolders = findProjectFolders();
  const desiredKeys = new Set(projectFolders.map(folderKey));
  for (const key of clients.keys()) {
    if (!desiredKeys.has(key)) {
      await stopClient(key);
    }
  }

  for (const projectFolder of projectFolders) {
    if (!clients.has(folderKey(projectFolder))) {
      await startClient(context, projectFolder);
    }
  }
}

async function startClient(
  context: vscode.ExtensionContext,
  projectFolder: vscode.WorkspaceFolder,
): Promise<void> {
  const key = folderKey(projectFolder);
  try {
    const server = resolveServerCommand(context, projectFolder);
    const serverOptions: ServerOptions = {
      run: {
        command: server.command,
        args: server.args,
        transport: TransportKind.stdio,
        options: { cwd: projectFolder.uri.fsPath },
      },
      debug: {
        command: server.command,
        args: server.args,
        transport: TransportKind.stdio,
        options: { cwd: projectFolder.uri.fsPath },
      },
    };
    const clientOptions: LanguageClientOptions = {
      documentSelector: [
        {
          scheme: 'file',
          language: 'yaml',
          pattern: {
            baseUri: projectFolder.uri.toString(),
            pattern: '**/*.yaml',
          },
        },
      ],
      workspaceFolder: projectFolder,
      outputChannelName: `Registry Stack Language Server (${projectFolder.name})`,
    };

    const client = new LanguageClient(
      `registry-stack:${key}`,
      `Registry Stack Language Server (${projectFolder.name})`,
      serverOptions,
      clientOptions,
    );
    clients.set(key, client);
    await client.start();
  } catch (error) {
    clients.delete(key);
    const detail = error instanceof Error ? error.message : String(error);
    void vscode.window.showErrorMessage(
      `Registry Stack language server failed to start for ${projectFolder.name}: ${detail}`,
    );
  }
}

async function stopClient(key: string): Promise<void> {
  const client = clients.get(key);
  clients.delete(key);
  await client?.dispose();
}

async function stopAll(): Promise<void> {
  const activeClients = [...clients.values()];
  clients.clear();
  await Promise.all(activeClients.map(async (client) => client.dispose()));
}

function findProjectFolders(): vscode.WorkspaceFolder[] {
  return (vscode.workspace.workspaceFolders ?? []).filter((folder) => {
    if (folder.uri.scheme !== 'file') {
      return false;
    }
    try {
      return fs.statSync(path.join(folder.uri.fsPath, 'registry-stack.yaml')).isFile();
    } catch {
      return false;
    }
  });
}

function folderKey(folder: vscode.WorkspaceFolder): string {
  return folder.uri.toString();
}

function resolveServerCommand(
  context: vscode.ExtensionContext,
  projectFolder: vscode.WorkspaceFolder,
): { command: string; args: string[] } {
  const configured = vscode.workspace
    .getConfiguration('registryStack', projectFolder.uri)
    .get<string>('languageServer.path', '')
    .trim();
  if (configured !== '') {
    const resolved = path.isAbsolute(configured)
      ? configured
      : path.resolve(projectFolder.uri.fsPath, configured);
    if (!isExecutableFile(resolved)) {
      throw new Error(`configured executable does not exist or is not a file: ${resolved}`);
    }
    return { command: resolved, args: [] };
  }

  const executable = process.platform === 'win32'
    ? 'registry-language-server.exe'
    : 'registry-language-server';
  const bundled = context.asAbsolutePath(path.join('bin', executable));
  if (isExecutableFile(bundled)) {
    return { command: bundled, args: [] };
  }
  const standalone = findExecutableOnPath(executable);
  if (standalone !== undefined) {
    return { command: standalone, args: [] };
  }
  const registryctl = findExecutableOnPath(
    process.platform === 'win32' ? 'registryctl.exe' : 'registryctl',
  );
  if (registryctl !== undefined) {
    return { command: registryctl, args: ['authoring', 'language-server'] };
  }
  throw new Error(
    'neither registry-language-server nor registryctl was found on PATH; install Registry Stack or configure registryStack.languageServer.path',
  );
}

function isExecutableFile(candidate: string): boolean {
  try {
    if (!fs.statSync(candidate).isFile()) {
      return false;
    }
    if (process.platform !== 'win32') {
      fs.accessSync(candidate, fs.constants.X_OK);
    }
    return true;
  } catch {
    return false;
  }
}

function findExecutableOnPath(executable: string): string | undefined {
  const pathEntries = process.env.PATH?.split(path.delimiter) ?? [];
  for (const entry of pathEntries) {
    if (entry === '') {
      continue;
    }
    const candidate = path.join(entry, executable);
    if (isExecutableFile(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

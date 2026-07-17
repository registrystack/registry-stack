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

let client: LanguageClient | undefined;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  context.subscriptions.push(
    vscode.commands.registerCommand('registryStack.restartLanguageServer', async () => {
      await restart(context);
    }),
    vscode.workspace.onDidChangeConfiguration(async (event) => {
      if (event.affectsConfiguration('registryStack.languageServer.path')) {
        await restart(context);
      }
    }),
  );

  await start(context);
}

export async function deactivate(): Promise<void> {
  await stop();
}

async function restart(context: vscode.ExtensionContext): Promise<void> {
  await stop();
  await start(context);
}

async function start(context: vscode.ExtensionContext): Promise<void> {
  if (client !== undefined) {
    return;
  }

  const projectFolder = findProjectFolder();
  if (projectFolder === undefined) {
    return;
  }

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
      outputChannelName: 'Registry Stack Language Server',
    };

    client = new LanguageClient(
      'registry-stack',
      'Registry Stack Language Server',
      serverOptions,
      clientOptions,
    );
    await client.start();
  } catch (error) {
    client = undefined;
    const detail = error instanceof Error ? error.message : String(error);
    void vscode.window.showErrorMessage(`Registry Stack language server failed to start: ${detail}`);
  }
}

async function stop(): Promise<void> {
  const activeClient = client;
  client = undefined;
  await activeClient?.dispose();
}

function findProjectFolder(): vscode.WorkspaceFolder | undefined {
  return vscode.workspace.workspaceFolders?.find((folder) =>
    fs.existsSync(path.join(folder.uri.fsPath, 'registry-stack.yaml')),
  );
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
    const candidate = path.join(entry === '' ? process.cwd() : entry, executable);
    if (isExecutableFile(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

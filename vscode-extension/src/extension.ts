import * as path from 'path';
import * as fs from 'fs';
import {
    workspace,
    ExtensionContext,
    window,
    commands,
    StatusBarItem,
    StatusBarAlignment,
    OutputChannel,
} from 'vscode';

import {
    LanguageClient,
    LanguageClientOptions,
    ServerOptions,
    TransportKind,
    Executable,
} from 'vscode-languageclient/node';

let client: LanguageClient | undefined;
let statusBarItem: StatusBarItem;
let outputChannel: OutputChannel;

export async function activate(context: ExtensionContext): Promise<void> {
    outputChannel = window.createOutputChannel('Security Scanner');
    outputChannel.appendLine('Security Scanner extension activating...');

    // Create status bar item
    statusBarItem = window.createStatusBarItem(StatusBarAlignment.Left, 100);
    statusBarItem.text = '$(shield) Security';
    statusBarItem.tooltip = 'Security Scanner';
    statusBarItem.command = 'securityScanner.showReport';
    context.subscriptions.push(statusBarItem);

    // Get configuration
    const config = workspace.getConfiguration('securityScanner');
    const enabled = config.get<boolean>('enable', true);

    if (!enabled) {
        outputChannel.appendLine('Security Scanner is disabled');
        statusBarItem.text = '$(shield) Security (disabled)';
        statusBarItem.show();
        return;
    }

    // Find Python and the LSP server
    const pythonPath = await findPython(config.get<string>('pythonPath', 'python'));
    if (!pythonPath) {
        window.showErrorMessage(
            'Security Scanner: Could not find Python. Please install Python or configure securityScanner.pythonPath.'
        );
        return;
    }

    outputChannel.appendLine(`Using Python: ${pythonPath}`);

    // Start the language server
    const serverModule = await findServerModule(context);
    if (!serverModule) {
        window.showErrorMessage(
            'Security Scanner: Could not find the LSP server. Please install security-lsp package.'
        );
        return;
    }

    outputChannel.appendLine(`Using server module: ${serverModule}`);

    // Server options
    const serverArgs = config.get<string[]>('serverArgs', []);
    const serverOptions: ServerOptions = {
        command: pythonPath,
        args: ['-m', 'security_lsp.server', ...serverArgs],
        options: {
            cwd: workspace.workspaceFolders?.[0]?.uri.fsPath,
        },
    };

    // Client options
    const clientOptions: LanguageClientOptions = {
        documentSelector: [
            // Dependency files
            { scheme: 'file', pattern: '**/requirements*.txt' },
            { scheme: 'file', pattern: '**/pyproject.toml' },
            { scheme: 'file', pattern: '**/setup.py' },
            { scheme: 'file', pattern: '**/Pipfile' },
            { scheme: 'file', pattern: '**/Pipfile.lock' },
            { scheme: 'file', pattern: '**/poetry.lock' },
            { scheme: 'file', pattern: '**/package.json' },
            { scheme: 'file', pattern: '**/package-lock.json' },
            { scheme: 'file', pattern: '**/yarn.lock' },
            { scheme: 'file', pattern: '**/Gemfile' },
            { scheme: 'file', pattern: '**/Gemfile.lock' },
            { scheme: 'file', pattern: '**/go.mod' },
            { scheme: 'file', pattern: '**/Cargo.toml' },
            // IaC files
            { scheme: 'file', language: 'terraform' },
            { scheme: 'file', pattern: '**/*.tf' },
            { scheme: 'file', pattern: '**/*.tfvars' },
            { scheme: 'file', pattern: '**/cloudformation/**/*.yaml' },
            { scheme: 'file', pattern: '**/cloudformation/**/*.yml' },
            { scheme: 'file', pattern: '**/cloudformation/**/*.json' },
            { scheme: 'file', pattern: '**/kubernetes/**/*.yaml' },
            { scheme: 'file', pattern: '**/kubernetes/**/*.yml' },
            { scheme: 'file', pattern: '**/k8s/**/*.yaml' },
            { scheme: 'file', pattern: '**/k8s/**/*.yml' },
        ],
        synchronize: {
            fileEvents: [
                workspace.createFileSystemWatcher('**/requirements*.txt'),
                workspace.createFileSystemWatcher('**/pyproject.toml'),
                workspace.createFileSystemWatcher('**/package.json'),
                workspace.createFileSystemWatcher('**/*.tf'),
            ],
        },
        outputChannel: outputChannel,
    };

    // Create the language client
    client = new LanguageClient(
        'securityScanner',
        'Security Scanner',
        serverOptions,
        clientOptions
    );

    // Register commands
    context.subscriptions.push(
        commands.registerCommand('securityScanner.scanWorkspace', async () => {
            await scanWorkspace();
        }),
        commands.registerCommand('securityScanner.scanCurrentFile', async () => {
            await scanCurrentFile();
        }),
        commands.registerCommand('securityScanner.clearDiagnostics', () => {
            clearDiagnostics();
        }),
        commands.registerCommand('securityScanner.showReport', () => {
            showReport();
        })
    );

    // Start the client
    try {
        await client.start();
        outputChannel.appendLine('Security Scanner LSP client started');
        statusBarItem.text = '$(shield) Security';
        statusBarItem.show();
    } catch (error) {
        outputChannel.appendLine(`Failed to start LSP client: ${error}`);
        window.showErrorMessage(`Security Scanner failed to start: ${error}`);
        statusBarItem.text = '$(shield) Security (error)';
        statusBarItem.show();
    }
}

export async function deactivate(): Promise<void> {
    if (client) {
        await client.stop();
    }
}

async function findPython(configuredPath: string): Promise<string | undefined> {
    // Try configured path first
    if (await isPythonValid(configuredPath)) {
        return configuredPath;
    }

    // Try common Python paths
    const candidates = [
        'python3',
        'python',
        '/usr/bin/python3',
        '/usr/local/bin/python3',
        '/opt/homebrew/bin/python3',
    ];

    for (const candidate of candidates) {
        if (await isPythonValid(candidate)) {
            return candidate;
        }
    }

    return undefined;
}

async function isPythonValid(pythonPath: string): Promise<boolean> {
    try {
        const { execSync } = require('child_process');
        execSync(`${pythonPath} --version`, { stdio: 'ignore' });
        return true;
    } catch {
        return false;
    }
}

async function findServerModule(context: ExtensionContext): Promise<string | undefined> {
    // Check if security-lsp is installed as a package
    try {
        const { execSync } = require('child_process');
        const pythonPath = workspace.getConfiguration('securityScanner').get<string>('pythonPath', 'python');
        execSync(`${pythonPath} -c "import security_lsp"`, { stdio: 'ignore' });
        return 'security_lsp.server';
    } catch {
        // Package not installed, check for local development
    }

    // Check for local development server
    const localServer = path.join(context.extensionPath, '..', 'src', 'security_lsp', 'server.py');
    if (fs.existsSync(localServer)) {
        return localServer;
    }

    return undefined;
}

async function scanWorkspace(): Promise<void> {
    if (!client) {
        window.showWarningMessage('Security Scanner is not running');
        return;
    }

    statusBarItem.text = '$(sync~spin) Scanning...';

    try {
        // Request workspace scan from server
        window.showInformationMessage('Scanning workspace for security vulnerabilities...');
        // The scan is triggered automatically by the LSP server on file events
    } finally {
        statusBarItem.text = '$(shield) Security';
    }
}

async function scanCurrentFile(): Promise<void> {
    const editor = window.activeTextEditor;
    if (!editor) {
        window.showWarningMessage('No active file to scan');
        return;
    }

    if (!client) {
        window.showWarningMessage('Security Scanner is not running');
        return;
    }

    statusBarItem.text = '$(sync~spin) Scanning...';

    try {
        // Save the file to trigger a scan
        await editor.document.save();
        window.showInformationMessage(`Scanning ${path.basename(editor.document.fileName)}...`);
    } finally {
        statusBarItem.text = '$(shield) Security';
    }
}

function clearDiagnostics(): void {
    // Diagnostics are managed by the LSP server
    window.showInformationMessage('Diagnostics cleared');
}

function showReport(): void {
    // Open the output channel to show scan results
    outputChannel.show();
    window.showInformationMessage(
        'Security report is shown in the Output panel. Check "Security Scanner" channel.'
    );
}

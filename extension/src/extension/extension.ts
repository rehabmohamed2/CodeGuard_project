import * as vscode from 'vscode';
import * as path from 'path';
import { AnalysisAPIClient } from '../api-client/index';
import dotenv from 'dotenv';

dotenv.config({ path: path.resolve(__dirname, '../../../../.env') });

// Global resources
let outputChannel: vscode.OutputChannel;
let apiClient: AnalysisAPIClient;
let currentAnalysisSession: {
  id: string;
  cancellationToken: vscode.CancellationTokenSource;
  poller?: NodeJS.Timeout;
} | undefined;

export async function activate(context: vscode.ExtensionContext) {
  // Create and register an output channel
  outputChannel = vscode.window.createOutputChannel("Secure Code Analyzer");
  context.subscriptions.push(outputChannel);
  outputChannel.appendLine('Secure Code Analyzer activated 🛡️');

  try {
    // Initialize secure API client
    apiClient = new AnalysisAPIClient({
      context,
      baseURL: 'https://localhost:3000/' //process.env.API_BASE_URL || 
    });
    
    // Check for first run
    const firstRun = true; //!(await context.secrets.get('authToken'));
    
    const firstAdminCreated = await apiClient.initialize(firstRun);

    if (firstAdminCreated) {
      vscode.window.showInformationMessage(
        'First admin account created successfully! You now have full privileges. 🔐'
      );
    }

    outputChannel.appendLine('Security components initialized 🔒');

    // Register commands and handlers
    registerEventHandlers(context);
    registerCommands(context);

  } catch (error: any) {
    vscode.window.showErrorMessage(`Initialization failed: ${error.message}`);
    outputChannel.appendLine(`Initialization error: ${error.message}`);
  }
}

function registerCommands(context: vscode.ExtensionContext) {
  context.subscriptions.push(
    vscode.commands.registerCommand('secure-code-analyzer.runAnalysis', 
      async () => await runAnalysis()
    ),
    vscode.commands.registerCommand('secure-code-analyzer.cancelAnalysis', 
      async () => await cancelAnalysis()
    ),
    vscode.commands.registerCommand('secure-code-analyzer.registerUser', 
      async () => await registerNewUser()
    )
  );
}

function registerEventHandlers(context: vscode.ExtensionContext) {
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(editor => {
      if (editor?.document.fileName.match(/\.(c|cpp)$/i)) {
        handleEditorChange(editor.document.fileName);
      }
    })
  );
}
async function registerNewUser() {
  try {
    const username = await vscode.window.showInputBox({
      prompt: 'Enter new username',
      ignoreFocusOut: true
    });
    
    const password = await vscode.window.showInputBox({
      prompt: 'Enter new password',
      password: true,
      ignoreFocusOut: true
    });

    const role = await vscode.window.showQuickPick(['user', 'admin'], {
      placeHolder: 'Select user role',
      ignoreFocusOut: true
    });

    if (username && password && role) {
      await apiClient.registerUser(username, password, role as 'admin' | 'user');
      vscode.window.showInformationMessage(`User ${username} created successfully`);
    }
  } catch (error: any) {
    vscode.window.showErrorMessage(`Registration failed: ${error.message}`);
  }
}

async function runAnalysis() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage('No active editor ⚠️');
    return;
  }
  
  const openedFile = editor.document.fileName;
  vscode.window.showInformationMessage(`Opened file: ${openedFile}`);
  
  if (!openedFile.match(/\.(c|cpp)$/i)) {
    vscode.window.showErrorMessage('Open a C/C++ file first ⚠️');
    return;
  }  

  cleanupAnalysisSession();
  const cppPath = editor.document.fileName;

  // Create both tokens/controllers
  const extensionToken = new vscode.CancellationTokenSource();
  const abortController = new AbortController();
  
  currentAnalysisSession = {
    id: `pending_${Date.now()}`,
    cancellationToken: extensionToken
  };

  try {
    outputChannel.appendLine(`Starting analysis on: ${cppPath} 🔍`);

    const progressOptions = {
      location: vscode.ProgressLocation.Notification,
      title: "Secure Code Analysis",
      cancellable: true
    };

    const analysisId = await vscode.window.withProgress(progressOptions, 
      async (progress, progressToken) => {
        // Link all cancellation systems
        progressToken.onCancellationRequested(() => {
          outputChannel.appendLine("User cancelled via progress UI");
          extensionToken.cancel();
          abortController.abort();
        });

        extensionToken.token.onCancellationRequested(() => {
          outputChannel.appendLine("Extension cancellation triggered");
          abortController.abort();
        });

        // Start analysis with abort capability
        progress.report({ message: "Encrypting and submitting file..." });
        const analysisId = await apiClient.analyzeFile(
          cppPath, 
          abortController.signal
        );
        
        if (currentAnalysisSession) {
          currentAnalysisSession.id = analysisId;
        }
        outputChannel.appendLine(`Analysis session started: ${analysisId}`);

        // Monitor analysis with progress updates
        return monitorAnalysisProgress(
          analysisId,
          progress,
          progressToken,
          extensionToken.token
        );
      }
    );

    // Final result handling
    if (currentAnalysisSession && currentAnalysisSession.id === analysisId) {
      await handleCompletedAnalysis(
        await apiClient.getAnalysisStatus(analysisId),
        cppPath
      );
    }
  } catch (error: any) {
    if (error.name === 'CanceledError' || error.message.includes('aborted')) {
      outputChannel.appendLine('Analysis cancelled during operation');
    } else {
      handleAnalysisError(error);
    }
  } finally {
    cleanupAnalysisSession();
  }
}

// Enhanced progress monitoring
async function monitorAnalysisProgress(
  analysisId: string,
  progress: vscode.Progress<{ message?: string; increment?: number }>,
  progressToken: vscode.CancellationToken,
  extensionToken: vscode.CancellationToken
): Promise<string> {
  while (!progressToken.isCancellationRequested && 
         !extensionToken.isCancellationRequested) {
    try {
      // NEW: Use typed status
      const status = await apiClient.getAnalysisStatus(analysisId);
      
      // Update progress based on state - now with type-safe crashes access
      switch (status.state) {
        case 'initializing':
          progress.report({ message: "Setting up fuzzing environment..." });
          break;
        case 'fuzzing':
          progress.report({ 
            message: `Fuzzing - ${status.crashes || 0} crashes found`,
            increment: 10
          });
          break;
        case 'analyzing':
          progress.report({ 
            message: `Analyzing ${status.crashes || 0} crashes...`,
            increment: 30
          });
          break;
        case 'completed':
          return analysisId;
        case 'failed':
          throw new Error(status.error || 'Analysis failed');
        case 'cancelled':
          throw new Error('Analysis cancelled by server');
      }
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (error: any) {
      if (error.message.includes('404')) {
        throw new Error('Analysis session expired');
      }
      throw error;
    }
  }
  throw new Error('Analysis cancelled by user');
}

async function pollAnalysisStatus(
  analysisId: string,
  cppPath: string,
  token: vscode.CancellationToken
) {
  if (token.isCancellationRequested) return;

  try {
    const status = await apiClient.getAnalysisStatus(analysisId);
    outputChannel.appendLine(`Status for ${analysisId}: ${status.state}`);

    if (status?.state === 'completed' || status?.state === 'failed') {
      clearInterval(currentAnalysisSession?.poller);
      
      if (status?.state === 'completed') {
        await handleCompletedAnalysis(status, cppPath);
      } 
      else if(status?.state === 'failed' && status.error?.includes('timed out')) {
        vscode.window.showErrorMessage('Analysis timed out');
      } else {
        handleFailedAnalysis(analysisId, status.error);
      }
      
      cleanupAnalysisSession();
    }
  } catch (error) {
    handlePollingError(error);
  }
}

async function handleCompletedAnalysis(status: any, cppPath: string) {
  try {
    if (status.results?.length > 0) {
      await generateSarifReport(status.results, cppPath);
      vscode.window.showInformationMessage('Vulnerabilities found! View SARIF report ⚠️');
      outputChannel.appendLine('Analysis completed with findings');
    } else {
      vscode.window.showInformationMessage('No vulnerabilities detected ✅');
      outputChannel.appendLine('Analysis completed successfully');
    }
  } catch (error: any) {
    vscode.window.showErrorMessage(`SARIF report failed: ${error.message}`);
    outputChannel.appendLine(`SARIF error: ${error.stack}`);
  }
}

function handleFailedAnalysis(analysisId: string, error?: string) {
  const message = error || 'Unknown error occurred';
  vscode.window.showErrorMessage(`Analysis failed: ${message}`);
  outputChannel.appendLine(`Analysis ${analysisId} failed: ${message}`);
}

async function cancelAnalysis() {
  if (!currentAnalysisSession) {
    vscode.window.showWarningMessage('No active analysis to cancel');
    return;
  }

  try {
    await apiClient.cancelAnalysis(currentAnalysisSession.id);
    vscode.window.showInformationMessage(`Analysis cancelled ✅`);
    outputChannel.appendLine(`User cancelled: ${currentAnalysisSession.id}`);
  } catch (error: any) {
    vscode.window.showErrorMessage(`Cancel failed: ${error.message}`);
    outputChannel.appendLine(`Cancel error: ${error.stack}`);
  } finally {
    cleanupAnalysisSession();
  }
}

function cleanupAnalysisSession() {
  if (currentAnalysisSession) {
    clearInterval(currentAnalysisSession.poller);
    currentAnalysisSession.cancellationToken.dispose();
    outputChannel.appendLine(`Cleaned up resources for ${currentAnalysisSession.id}`);
    currentAnalysisSession = undefined;
  }
}

function handleEditorChange(newFilePath: string) {
  if (currentAnalysisSession) {
    vscode.window.showInformationMessage('Analysis cancelled due to file change');
    cleanupAnalysisSession();
  }
}

function handleAnalysisError(error: any) {
  const message = error.response?.data?.error || error.message;
  vscode.window.showErrorMessage(`Analysis error: ${message}`);
  outputChannel.appendLine(`Analysis error: ${error.stack}`);
  cleanupAnalysisSession();
}

function handlePollingError(error: any) {
  if (error.message.includes('404')) {
    outputChannel.appendLine('Analysis session expired');
    cleanupAnalysisSession();
  } else {
    vscode.window.showErrorMessage(`Polling error: ${error.message}`);
    outputChannel.appendLine(`Polling error: ${error.stack}`);
  }
}

async function generateSarifReport(results: any[], cppPath: string) {
  const workspace = vscode.workspace.workspaceFolders?.[0];
  if (!workspace) throw new Error("No workspace open");

  const sarifExt = vscode.extensions.getExtension('MS-SarifVSCode.sarif-viewer');
  if (!sarifExt) throw new Error("SARIF Viewer not installed");

  try {
    await sarifExt.activate();
    
    const baseName = path.basename(cppPath, '.cpp');
    const reportPath = path.join(workspace.uri.fsPath, `${baseName}_analysis.sarif`);
    
    await vscode.workspace.fs.writeFile(
      vscode.Uri.file(reportPath),
      Buffer.from(JSON.stringify(results[0], null, 2))
    );

    await vscode.commands.executeCommand('sarif.showPanel', vscode.Uri.file(reportPath));
  } catch (error: any) {
    throw new Error(`SARIF failed: ${error.message}`);
  }
}

export function deactivate() {
  cleanupAnalysisSession();
  // apiClient?.dispose();
  
  if (outputChannel) {
    outputChannel.appendLine('Secure Code Analyzer deactivated 🔒');
    outputChannel.dispose();
  }
}
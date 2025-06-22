import { rejects, strict } from 'assert';
import { copyFileSync } from 'fs';
import { EventEmitter } from 'stream';
import { setFlagsFromString } from 'v8';
import * as vscode from 'vscode';
import { MessageChannel } from 'worker_threads';
import {DebugTypes, HighlightTypes, InferenceModes, InfoLevels, ProgressStages, DiagnosticInformation, FunctionsListType} from './config';
import { stdin } from 'process';
import { PythonShell } from 'python-shell';

// import class from files
import { LocalInference, RemoteInference } from './inference';
import { debugMessage, downloadEngine, Progress, progressHandler, removeBlankLines, removeComments } from './common';

// modules
export const axios = require('axios');
export const fs = require('fs');
export const path = require('path');
export const fsa = require('fs/promises');
// const formdata = require('form-data');
export const extract = require('extract-zip');
export const parser = require('xml2js');
export const dotenv = require('dotenv').config({ path: path.join(__dirname, '..', 'resources' , 'config') });

// export let config:DocumentConfig;
// export let inferenceMode: LocalInference | RemoteInference;

const parentDir = path.resolve(__dirname, '..');
export const progressEmitter = new Progress();
let statusBarItem: vscode.StatusBarItem;
let lock = false;
let diagnosticsQueue: VulDiagnostic[] = [];

export let config: Config;

// Implement Config as a class (fake singleton)
export class Config {

	inferenceMode: InferenceModes = InferenceModes.local;
	useCUDA: boolean = false;
	infoLevel: InfoLevels = InfoLevels.fluent;
	customDiagInfos: DiagnosticInformation | undefined;
	showDescription: boolean = true;
	diagnosticSeverity: vscode.DiagnosticSeverity = vscode.DiagnosticSeverity.Error;
	maxIndicatorLines: number = 1;
	typeWaitDelay: number = 1500;

	downloadPaths: {[key: string]: string} = {
		"lineModel": ".",
		"sevModel": ".",
		"cweModel": ".",
		"cweXMLZip": ".",
	};

	cweXMLFile: string = path.join(__dirname, ".." , "resources", "cwec_v4.8.xml");

	subDir: string = ".";
	localInferenceResDir: string = "./local";

	inferenceURLs: {[key: string]: string} = {
		onPremise: "http://localhost:5000",
		cloud: "https://0.0.0.0:5000", // Cloud inference not supported yet
	};

	// Endpoints as nested dictionaries
	endpoints: {[key: string]: {[key: string ]: string}} = {
		line:{
			cpu: "/api/v1/cpu/predict",
			gpu: "/api/v1/gpu/predict",
		},
		cwe:{
			cpu: "/api/v1/cpu/cwe",
			gpu: "/api/v1/gpu/cwe",
		},
		sev:{
			cpu: "/api/v1/cpu/sev",
			gpu: "/api/v1/gpu/sev",
		},
		repair:{
			cpu: "/api/v1/cpu/repair",
			gpu: "/api/v1/gpu/repair",
		}
	};

	downloadURLs: {[key: string]: string | undefined} = {
		lineModel: "",
		sevModel: "",
		cweModel: "",
		cweXML: "",
		inferencePack: ""
	};

	constructor(){
		this.loadConfig();
	}

	loadConfig(){
		const vsConfig = vscode.workspace.getConfiguration("AiBugHunter");

		this.inferenceMode = vsConfig.inference.inferenceMode;
		this.useCUDA = vsConfig.inference.useCUDA;
		this.infoLevel = vsConfig.diagnostics.informationLevel;
		this.customDiagInfos = vsConfig.diagnostics.diagnosticMessageInformation;
		this.showDescription = vsConfig.diagnostics.showDescription;
		this.maxIndicatorLines = vsConfig.diagnostics.maxNumberOfLines;
		this.typeWaitDelay = vsConfig.diagnostics.delayBeforeAnalysis;
		// Removed ability to specify download location for now
		// Everything should be downloaded to the extension directory and in the resources folder
		// this.downloadPaths.lineModel = vsConfig.model.downloadLocation;
		// this.downloadPaths.sevModel = vsConfig.model.downloadLocation;
		// this.downloadPaths.cweModel = vsConfig.model.downloadLocation;
		// this.downloadPaths.cweXML = vsConfig.cwe.downloadLocation;
		// this.subDir = vsConfig.resources.subDirectory;
		this.inferenceURLs.onPremise = vsConfig.inference.inferenceServerURL;

		switch(vsConfig.diagnostics.highlightSeverityType){
			case "Error": this.diagnosticSeverity = vscode.DiagnosticSeverity.Error; break;
			case "Warning": this.diagnosticSeverity = vscode.DiagnosticSeverity.Warning; break;
			case "Information": this.diagnosticSeverity = vscode.DiagnosticSeverity.Information; break;
			case "Hint": this.diagnosticSeverity = vscode.DiagnosticSeverity.Hint; break;
		}

		this.downloadURLs.lineModel = process.env.LINE_MODEL_URL;
		this.downloadURLs.sevModel = process.env.SEV_MODEL_URL;
		this.downloadURLs.cweModel = process.env.CWE_MODEL_URL;
		this.downloadURLs.cweXML = process.env.CWE_XML_URL;
		this.downloadURLs.inferencePack = process.env.INFERENCE_PACK_URL;
	}

}

export async function activate(context: vscode.ExtensionContext) {

	let statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
	context.subscriptions.push(statusBar);
	debugMessage(DebugTypes.info, "Extension initialised");

	config = new Config();

	const diagnosticCollection = vscode.languages.createDiagnosticCollection('Code-Guard');
	context.subscriptions.push(diagnosticCollection);

	// Register the Vulnerability Fix Provider
	context.subscriptions.push(
		vscode.languages.registerCodeActionsProvider(
			['c', 'cpp'],
			new VulnerabilityFixProvider(),
			{
				providedCodeActionKinds: VulnerabilityFixProvider.providedCodeActionKinds
			}
		)
	);

	// Register the fix vulnerability command
	context.subscriptions.push(
		vscode.commands.registerCommand('aibughunter.fixVulnerability', async (document: vscode.TextDocument, range: vscode.Range) => {
			try {
				debugMessage(DebugTypes.info, "Fixing vulnerability...");
				
				// Create progress notification with steps for a better UX
				await vscode.window.withProgress({
					location: vscode.ProgressLocation.Notification,
					title: "Fixing Vulnerability",
					cancellable: false
				}, async (progress) => {
					// Step 1: Extract function
					progress.report({ increment: 10, message: "Locating vulnerable function..." });
					const functionText = await extractVulnerableFunctionFromRange(document, range);
					if (!functionText) {
						vscode.window.showErrorMessage("Unable to determine the full function code.");
						return;
					}
					
					// Step 2: Analyze function and vulnerabilities
					progress.report({ increment: 30, message: "Analyzing vulnerabilities..." });
					
					// Identify vulnerabilities in the code for better reporting
					const vulnerabilityTypes = detectVulnerabilityTypes(functionText);
					
					// Step 3: Generate fix
					progress.report({ 
						increment: 30, 
						message: `Generating fixes for ${vulnerabilityTypes.length > 0 ? 
							vulnerabilityTypes.join(", ") : "identified vulnerabilities"}...` 
					});
					
					// Call the repair API
					const repaired = await callRepairAPI(functionText);
					if (!repaired || repaired.startsWith("Error")) {
						vscode.window.showErrorMessage("Failed to generate a fix: " + (repaired || "Unknown error"));
						return;
					}
					
					// Step 4: Apply fix
					progress.report({ increment: 30, message: "Applying security fixes..." });
					
					// Check if the repair actually made changes
					if (repaired.trim() === functionText.trim()) {
						vscode.window.showInformationMessage("No changes were needed or the repair API couldn't identify specific fixes.");
						return;
					}
					
					// Apply the fix
					const editor = vscode.window.activeTextEditor;
					if (editor && editor.document === document) {
						const functionRange = await getFunctionRangeFromPosition(document, range.start);
						if (functionRange) {
							await editor.edit(editBuilder => {
								editBuilder.replace(functionRange, repaired);
							});
							
							// Show success message with what was fixed
							if (vulnerabilityTypes.length > 0) {
								vscode.window.showInformationMessage(`Fixed vulnerabilities: ${vulnerabilityTypes.join(", ")}`);
							} else {
								vscode.window.showInformationMessage("Vulnerability fixed successfully.");
							}
							
							// Force re-analysis of the updated code after a short delay
							setTimeout(() => {
								progressEmitter.emit('init', ProgressStages.extensionInitStart);
							}, 1000);
						} else {
							vscode.window.showErrorMessage("Could not determine the function boundaries to apply the fix.");
						}
					}
				});
			} catch (error) {
				debugMessage(DebugTypes.error, "Error fixing vulnerability: " + error);
				vscode.window.showErrorMessage("Error fixing vulnerability: " + error);
			}
		})
	);

	progressEmitter.on('init', async (stage:ProgressStages) =>{

		progressHandler(stage);

		switch(stage){
			case ProgressStages.extensionInitStart:
				// Download models and CWE list if not found

				if(!lock){
					lock = true;

					let hasError = true;
					while(hasError){
						await init().then(() => {
							hasError = false;
						}
						).catch(err => {
							debugMessage(DebugTypes.error, err);
							debugMessage(DebugTypes.info, "Error occured during initialisation. Retrying...");
						}
						);
					}
					lock = false;
				} else {
					debugMessage(DebugTypes.info, "Extension initialisation already in progress");
				}
				progressEmitter.emit('init', ProgressStages.extensionInitEnd);
				progressEmitter.emit('init', ProgressStages.analysisStart);
				break;
			case ProgressStages.analysisStart:

				if (!lock){
					if (vscode.window.activeTextEditor?.document){

						// If there are duplicate requests, only show the result of the last request
						if (diagnosticsQueue.length > 0){
							diagnosticsQueue.forEach(element => {
								element.ignore = true;
							});
						}
						const vulDiagnostic = new VulDiagnostic(vscode.window.activeTextEditor?.document);
						diagnosticsQueue.push(vulDiagnostic);

						await vulDiagnostic.analysisSequence(diagnosticCollection).then(()=>{
							diagnosticsQueue.forEach( (item, index) => {
								if(item === vulDiagnostic) {
									diagnosticsQueue.splice(index,1);
								}
							  });
						}).catch(err => {
							debugMessage(DebugTypes.error, "Error occured during analysis");
							progressEmitter.emit("end", ProgressStages.error);
						});

					} else {
						debugMessage(DebugTypes.info, "No active text editor");
						progressEmitter.emit('end', ProgressStages.noDocument);
						break;
					}
				} else{
					debugMessage(DebugTypes.info, "Analysis already in progress");
				}
				break;
		}
	});

	progressEmitter.emit('init', ProgressStages.extensionInitStart);

	// When text document is modified
	let pause: NodeJS.Timeout;
	vscode.workspace.onDidChangeTextDocument((e) =>{

		if(e.contentChanges.length > 0){

			clearTimeout(pause);

			pause = setTimeout(() => {
				debugMessage(DebugTypes.info, "Typing stopped for " + config.typeWaitDelay + "ms");
				
				progressEmitter.emit('init', ProgressStages.extensionInitStart);

			}, config.typeWaitDelay);
	
		}
	});

	// When user changes settings
	vscode.workspace.onDidChangeConfiguration((e) => {
		debugMessage(DebugTypes.info, "Configuration Changed");
		config.loadConfig();
		progressEmitter.emit('init', ProgressStages.extensionInitStart);
	});

	// When user changes document
	vscode.window.onDidChangeActiveTextEditor((e) => {
		debugMessage(DebugTypes.info, "Active text editor changed");
		
		if (e?.document && (e.document.languageId === 'cpp' || e.document.languageId === 'c')) {
			const fileUri = e.document.uri.toString();
			if (VulDiagnostic.fileDecorations.has(fileUri) && VulDiagnostic.decorationRanges.has(fileUri)) {
				const decorations = VulDiagnostic.fileDecorations.get(fileUri)!;
				const ranges = VulDiagnostic.decorationRanges.get(fileUri)!;
				
				// Apply stored decorations with their ranges
				Object.entries(decorations).forEach(([severity, decoration]) => {
					if (ranges[severity] && ranges[severity].length > 0) {
						e.setDecorations(decoration, ranges[severity]);
					}
				});

				// Update status bar with the current file's vulnerability count
				const vulCount = VulDiagnostic.fileVulnerabilityCounts.get(fileUri) || 0;
				VulDiagnostic.updateStatusBar(vulCount);
			} else {
				// Only analyze if we haven't seen this file before
				progressEmitter.emit('init', ProgressStages.extensionInitStart);
			}
		} else {
			// If not a C/C++ file, show no vulnerabilities
			VulDiagnostic.updateStatusBar(0);
		}
	});

	// Manually restart analysis
	const restart = 'aibughunter.restart';
	const restartCommand = vscode.commands.registerCommand(restart, () => {
		debugMessage(DebugTypes.info, "Restarting extension");
		progressEmitter.emit('init', ProgressStages.extensionInitStart);
	}
	);
	context.subscriptions.push(restartCommand);

	// Initialize the status bar once during activation
	VulDiagnostic.initializeStatusBar();
}


/**
 * Initialises the extension by downloading the models and CWE list if not found on locally
 * @returns Promise that resolves when models and CWE list are loaded, rejects if error occurs
 */
 async function init() {
	var start = new Date().getTime();

	debugMessage(DebugTypes.info, "Config loaded, checking model and CWE list presence");

	var downloadCandidates = [downloadCWEXML(), downloadModels()];

	await Promise.all(downloadCandidates).then(() => {
		var end = new Date().getTime();
		debugMessage(DebugTypes.info, "Initialisation took " + (end - start) + "ms");
		debugMessage(DebugTypes.info, "Model and CWE list successfully loaded");
		progressEmitter.emit('end', ProgressStages.extensionInitEnd);
		return Promise.resolve();
	}
	).catch(err => {
		debugMessage(DebugTypes.error, err);
		return Promise.reject(err);
	}
	);
}

/**
 * Checks for presence of cwe list zip/xml file and downloads if not present
 * @returns Promise that resolves when CWE list is loaded
 */
async function downloadCWEXML() {

	progressEmitter.emit('update', ProgressStages.downloadCWEXMLStart);

	// const zipDownloadDir = (config.downloadPaths.cweXML === ".") ? parentDir + "/" + config.downloadPaths.cweXML : config.downloadPaths.cweXML;
	const zipDownloadDir = parentDir + "/resources";
	// const zipPath = path.resolve(zipDownloadDir, config.subDir, 'cwec_latest.xml.zip');
	const zipPath = path.resolve(zipDownloadDir, 'cwec_v4.8.xml.zip');
	// const extractTarget = path.resolve(zipDownloadDir, config.subDir);
	const extractTarget = path.resolve(zipDownloadDir);

	// Create subdirectory if specified and doesn't exist
	// if (config.subDir && !fs.existsSync(extractTarget)) {
	// 	fs.mkdirSync(path.join(zipDownloadDir, config.subDir), (err: any) => {
	// 		if (err) {
	// 			return console.error(err);
	// 		}
	// 		debugMessage(DebugTypes.info, "Directory created successfully at " + extractTarget);
	// 	}
	// 	);

	var files = fs.readdirSync(extractTarget).filter((file: string) => file.endsWith('.xml')).filter((file: string) => file.includes("cwec"));

	// Download if no xml file found
	if (!fs.existsSync(zipPath) || files.length === 0) { // If zip file doesn't exist or no xml files found
		debugMessage(DebugTypes.info, "cwec_v4.8.xml.zip not found, downloading...");
		await downloadEngine(fs.createWriteStream(zipPath), 'https://cwe.mitre.org/data/xml/cwec_v4.8.xml.zip').then(() => {
			debugMessage(DebugTypes.info, "cwec_v4.8.xml.zip downloaded");
		}
		).catch(err => {
			debugMessage(DebugTypes.error, "Error occured while downloading cwec_v4.8.xml.zip");
			return Promise.reject(err);
		}
		);
	} else if (files.length > 0) { // If xml file found
		debugMessage(DebugTypes.info, "xml file already exists, skipping download...");
		files = fs.readdirSync(extractTarget).filter((file: string) => file.endsWith('.xml')).filter((file: string) => file.includes("cwec"));
		// config.cweXMLFile = path.resolve(zipDownloadDir, config.subDir, files[0]);
		config.cweXMLFile = path.resolve(zipDownloadDir, files[0]);
		return Promise.resolve();
	};

	// Extract zip file
	debugMessage(DebugTypes.info, "Extracting cwec_v4.8.xml.zip");

	await extract(zipPath, { dir: extractTarget }).then(() => {
		debugMessage(DebugTypes.info, "cwec_v4.8.xml.zip extracted at " + extractTarget.toString());
		files = fs.readdirSync(extractTarget).filter((file: string) => file.endsWith('.xml')).filter((file: string) => file.includes("cwec"));
		// config.cweXMLFile = path.resolve(zipDownloadDir, config.subDir, files[0]);
		config.cweXMLFile = path.resolve(zipDownloadDir, files[0]);
		return Promise.resolve();
	}
	).catch((err: any) => {
		debugMessage(DebugTypes.error, "Error occured while extracting cwec_v4.8.xml.zip");
		return Promise.reject(err);
	}
	);
}

/**
 * Check if the model is downloaded and download if not
 */
 async function downloadModels(){

	progressEmitter.emit('update', ProgressStages.downloadModelStart);

	// const modelPath = (config.downloadPaths.lineModel === ".")? parentDir + "/" + config.downloadPaths.lineMode: config.downloadPaths.lineMode;

	let modelPath = parentDir + "/resources/local-inference/models";

	if(!fs.existsSync(path.join(modelPath))){
		fs.mkdirSync(path.join(modelPath), { recursive: true } ,(err: any) => {
			if (err) {
				return console.error(err);
			}
			debugMessage(DebugTypes.info, "Directory created successfully at " + (path.join(modelPath)));
		}
		);
	}

	// const lineModelPath = path.resolve(modelPath, config.resSubDir,'line_model.onnx');
	const lineModelPath = path.resolve(modelPath, 'line_model.onnx');
	// const sevModelPath = path.resolve(modelPath,config.resSubDir ,'sev_model.onnx');
	const sevModelPath = path.resolve(modelPath, 'sev_model.onnx');
	// const cweModelPath = path.resolve(modelPath,config.resSubDir ,'cwe_model.onnx');
	const cweModelPath = path.resolve(modelPath, 'cwe_model.onnx');

	// const localInferenceData = path.resolve(modelPath, config.resSubDir, 'local-inference-data.zip');
	const localInferenceData = path.resolve(modelPath, 'local-inference-data.zip');

	// Create subdirectory if specified and doesn't exist
	// if(config.resSubDir && !fs.existsSync(path.join(modelPath, config.resSubDir))){
	// 	fs.mkdirSync(path.join(modelPath, config.resSubDir), (err: any) => {
	// 		if (err) {
	// 			return console.error(err);
	// 		}
	// 		debugMessage(DebugTypes.info, "Directory created successfully at " + (path.join(modelPath, config.resSubDir)));
	// 	}
	// 	);

	var downloads = [];

	// const extractTarget = path.resolve(modelPath, config.resSubDir);
	const extractTarget = path.resolve(modelPath);

	if(!fs.existsSync(lineModelPath)){
		debugMessage(DebugTypes.info, "line_model not found, downloading...");
		downloads.push(downloadEngine(fs.createWriteStream(lineModelPath), config.downloadURLs.lineModel));
	} else {
		debugMessage(DebugTypes.info, "line_model found at " + lineModelPath + ", skipping download...");
	}
	
	if(!fs.existsSync(sevModelPath)){
		debugMessage(DebugTypes.info, "sve_model not found, downloading...");
		downloads.push(downloadEngine(fs.createWriteStream(sevModelPath), config.downloadURLs.sevModel));
	} else {
		debugMessage(DebugTypes.info, "sev_model found at " + sevModelPath + ", skipping download...");
	}

	if(!fs.existsSync(cweModelPath)){
		debugMessage(DebugTypes.info, "cwe_model not found, downloading...");
		downloads.push(downloadEngine(fs.createWriteStream(cweModelPath), config.downloadURLs.cweModel));
	} else {
		debugMessage(DebugTypes.info, "cwe_model found at " + cweModelPath + ", skipping download...");
	}

	await Promise.all(downloads).then(() => {	
		debugMessage(DebugTypes.info, "Completed model initialization");
		progressEmitter.emit('update', ProgressStages.downloadModelEnd);
		return Promise.resolve();
	}
	).catch(err => {
		debugMessage(DebugTypes.error, "Error occured while downloading models");
		return Promise.reject(err);
	}
	);
}


export function deactivate() {
	// Clean up any remaining diagnostics
	if (diagnosticsQueue && diagnosticsQueue.length > 0) {
		diagnosticsQueue.forEach((diagnostic: VulDiagnostic) => {
			diagnostic.dispose();
		});
	}
	// Clear the status bar
	if (VulDiagnostic.statusBarItem) {
		VulDiagnostic.statusBarItem.dispose();
	}
}

// Implement all above in class
export class VulDiagnostic {
	public static fileDecorations = new Map<string, {[key: string]: vscode.TextEditorDecorationType}>();
	public static decorationRanges = new Map<string, {[key: string]: vscode.Range[]}>();
	public static statusBarItem: vscode.StatusBarItem;
	public static fileVulnerabilityCounts = new Map<string, number>();
	targetDocument: vscode.TextDocument | undefined;
	ignore: boolean = false;
	
	// Add decoration types for different severity levels
	private vulnLineDecorationTypes: {[key: string]: vscode.TextEditorDecorationType} = {
		'High': vscode.window.createTextEditorDecorationType({
			backgroundColor: 'rgba(255, 0, 0, 0.15)',  // Softer red
			isWholeLine: true,
			borderWidth: '0 0 0 4px',
			borderStyle: 'solid',
			borderColor: 'rgba(255, 0, 0, 0.8)',  // Stronger red border
			after: {
				contentText: '  ⚠️High Risk',
				color: 'red',
				fontWeight: 'normal'
			}
		}),
		'Medium': vscode.window.createTextEditorDecorationType({
			backgroundColor: 'rgba(255, 165, 0, 0.15)', // Softer orange
			isWholeLine: true,
			borderWidth: '0 0 0 4px',
			borderStyle: 'solid',
			borderColor: 'rgba(255, 165, 0, 0.8)', // Stronger orange border
			after: {
				contentText: '  ⚠️Medium Risk',
				color: 'orange',
				fontWeight: 'normal'
			}
		}),
		'Low': vscode.window.createTextEditorDecorationType({
			backgroundColor: 'rgba(0, 191, 255, 0.15)', // Softer blue
			isWholeLine: true,
			borderWidth: '0 0 0 4px',
			borderStyle: 'solid',
			borderColor: 'rgba(0, 191, 255, 0.8)', // Stronger blue border
			after: {
				contentText: '  ⚠️Low Risk',
				color: 'blue',
				fontWeight: 'normal'
			}
		})
	};

	functionsList: FunctionsListType = {
		functions: [],
		vulnFunctions: [],
		shift: [],
		range: [],
	};

	predictions: { [key: string]: any } = {
		line: [],
		sev: [],
		cwe: [],
	};

	constructor(targetDocument?: vscode.TextDocument){
		this.targetDocument = targetDocument;
		// Restore decorations if they exist for this file
		if (targetDocument && VulDiagnostic.fileDecorations.has(targetDocument.uri.toString())) {
			this.vulnLineDecorationTypes = VulDiagnostic.fileDecorations.get(targetDocument.uri.toString())!;
		}
	}
	
	// extractFunctions, inference, and construct is implemented in this class

	async analysisSequence(diagnosticCollection: vscode.DiagnosticCollection) {

		await this.extractFunctions().then(() => {
			debugMessage(DebugTypes.info, "Finished extracting functions");
		}
		).catch(err => {
			debugMessage(DebugTypes.error, err);
			return Promise.reject(err);
		}
		);

		await this.inferenceSequence().then(() => {
			debugMessage(DebugTypes.info, "Finished extracting functions");
		}
		).catch(err => {
			debugMessage(DebugTypes.error, err);
			return Promise.reject(err);
		}
		);

		await this.constructDiagnostics(diagnosticCollection).then(() => {
			debugMessage(DebugTypes.info, "Finished constructing diagnostics");
		}
		).catch(err => {
			debugMessage(DebugTypes.error, err);
			return Promise.reject(err);
		}
		);
		
	}

	/**
	 * Extracts lists of functions from the current editor using DocumentSymbolProvider
	 * @returns Promise that rejects on error and resolves on success
	 */
	async extractFunctions(){
		
		// Exit if document is undefined or invalid
		const uri = vscode.window.activeTextEditor?.document.uri;
		if (!this.targetDocument || uri === undefined) {
			debugMessage(DebugTypes.error, "No document found");
			return Promise.reject("No document found");
		}

		var text = this.targetDocument.getText();
		var lines = text.split(/\r?\n/);

		if(lines.length === 0){
			debugMessage(DebugTypes.error, "Empty document");
			return Promise.reject("Empty document");
		}
		// ---
		
		// Extract functions from document
		debugMessage(DebugTypes.info, "Getting Symbols");
		progressEmitter.emit('update', ProgressStages.fetchSymbolStart);

		let symbols: vscode.DocumentSymbol[] = [];

		var attempts = 0;

		let start = new Date().getTime();
		var period = new Date().getTime();
		while (symbols === undefined || period - start < 3000) {
			symbols = await vscode.commands.executeCommand<vscode.DocumentSymbol[]>('vscode.executeDocumentSymbolProvider', uri);
			if (symbols !== undefined) {
				break;
			}
			period = new Date().getTime();
		}

		let end = new Date().getTime();

		if (symbols === undefined) {
			debugMessage(DebugTypes.error, "No symbols found after 3 seconds");
			return Promise.reject("No symbols found");
		} else {
			debugMessage(DebugTypes.info, "Found " + symbols.length + " symbols in " + (end - start) + " ms");
		}

		symbols.forEach(element => {
			if (element.kind === vscode.SymbolKind.Function) {

				// Formatting functions before storing
				var block: string = "";
				for (var i = element.range.start.line; i <= element.range.end.line; i++) {
					// Remove whitespace at the start of the line
					block += lines[i].replace(/^\s+/g, "");
					// block += lines[i];
					if (i !== element.range.end.line) {
						block += "\n";
					}
				}

				block = removeComments(block);
				const result = removeBlankLines(block);

				// Remove all "\n" characters
				// console.log(result[0].replace(/\n/g, ""));

				this.functionsList.functions.push(result[0]);
				this.functionsList.shift.push(result[1]);
				this.functionsList.range.push(element.range);
			}
		});
	}

	/**
	 * Runs inference on the extracted functions
	 * 1. Send list of functions to the inference engine to get vulnerability information and store it in predictions variable
	 * 2. Collect only the vulnerable functions and send them to CWE and Severity inference endpoints and store it in predictions variable
	 * @param document TextDocument to extract text/function from
	 * @returns 
	 */

	async inferenceSequence() {

		if (this.targetDocument?.getText() === "") {
			debugMessage(DebugTypes.error, "Document is empty, aborting analysis");
			return Promise.reject("Document is empty, aborting analysis");
		}

		var start = new Date().getTime();

		let inferenceEngine;

		switch(config.inferenceMode){
			case InferenceModes.local: inferenceEngine = new LocalInference(this); break;
			case InferenceModes.onpremise:inferenceEngine = new RemoteInference(this);break;
			case InferenceModes.cloud:inferenceEngine = new RemoteInference(this);break;
			default:inferenceEngine = new LocalInference(this);break;
		}

		progressEmitter.emit('update', ProgressStages.inferenceLineStart);

		await inferenceEngine.line(this.functionsList.functions).then(() => {
			debugMessage(DebugTypes.info, "Line vulnerabilities retrieved");

			this.predictions.line.batch_vul_pred.forEach((element: any, i: number) => {
				if (element === 1) {
					this.functionsList.vulnFunctions.push(this.functionsList.functions[i]);
				}
			});
		}
		).catch((err: string) => {
			debugMessage(DebugTypes.error, err);
			return Promise.reject(err);
		}
		);

		progressEmitter.emit('update', ProgressStages.inferenceCweStart);
		progressEmitter.emit('update', ProgressStages.inferenceSevStart);

		if (this.functionsList.vulnFunctions.length === 0) {
			debugMessage(DebugTypes.info, "No vulnerabilities found");
		} else {

			await Promise.all([
				inferenceEngine.cwe(this.functionsList.vulnFunctions),
				inferenceEngine.sev(this.functionsList.vulnFunctions)
			]).then(() => {
				debugMessage(DebugTypes.info, "CWE type and severity score retrieved");
			}
			).catch((err: string) => {
				debugMessage(DebugTypes.error, err);
				return Promise.reject(err);
			}
			);
		}

		progressEmitter.emit('end', ProgressStages.predictionEnd);

		var end = new Date().getTime();

		debugMessage(DebugTypes.info, "All inference completed in " + (end - start) + "ms");

		return Promise.resolve();
	}

	/**
	 * Takes all the predictions results and constructs diagnostics for each vulnerable function
	 * @param doc TextDocument to display diagnostic collection in
	 * @param diagnosticCollection DiagnosticCollection to set diagnostics for
	 */
	async constructDiagnostics(diagnosticCollection: vscode.DiagnosticCollection){

		if(this.targetDocument === undefined){
			debugMessage(DebugTypes.error, "No document found to construct diagnostics");
			return 1;
		}

		if(this.ignore){
			debugMessage(DebugTypes.info, "Ignoring diagnostics");
			progressEmitter.emit('end', ProgressStages.ignore);
			return 0;
		}

		let vulCount = 0;
		let diagnostics: vscode.Diagnostic[] = [];

		let cweList: any[] = [];

		if (this.predictions.line.batch_vul_pred && Array.isArray(this.predictions.line.batch_vul_pred)) {
			this.predictions.line.batch_vul_pred.forEach((element: any, i: number) => {
				if (element === 1) {
					cweList.push([this.predictions.cwe.cwe_type[vulCount], this.predictions.cwe.cwe_id[vulCount].substring(4)]);
					vulCount++;
				}
			});
		} else {
			debugMessage(DebugTypes.error, "batch_vul_pred is not defined or not an array");
		}

		await this.fetchCWEData(cweList);

		vulCount = 0;

		progressEmitter.emit('update', ProgressStages.constructDiagnosticsStart);

		// Create separate decoration ranges for each severity level
		let decorationRanges: {[key: string]: vscode.Range[]} = {
			'High': [],
			'Medium': [],
			'Low': []
		};

		this.functionsList.range.forEach((value: any, i: number) => {
			if(this.predictions.line.batch_vul_pred[i] === 1){
				debugMessage(DebugTypes.info, "Constructing diagnostic for function: " + i);

				// this.functionsList.* contains all functions
				// this.predictions.line contains line predcitions for all functions
				// this.predictions.cwe and predictions.sev contain only vulnerable functions

				const cweID = this.predictions.cwe.cwe_id[vulCount];
				const cweIDProb = this.predictions.cwe.cwe_id_prob[vulCount];
				const cweType = this.predictions.cwe.cwe_type[vulCount];
				const cweTypeProb = this.predictions.cwe.cwe_type_prob[vulCount];

				let cweDescription = this.predictions.cwe.descriptions[vulCount];
				const cweName = this.predictions.cwe.names[vulCount];

				const sevScore = this.predictions.sev.batch_sev_score[vulCount];
				const sevClass = this.predictions.sev.batch_sev_class[vulCount];

				const lineScores = this.predictions.line.batch_line_scores[i];
				
				let lineScoreShiftMapped: number[][] = [];

				this.functionsList.shift[i].forEach((element:number) =>{
					lineScores.splice(element, 0, 0);
				});

				let lineStart = this.functionsList.range[i].start.line;

				lineScores.forEach((element: number) => {
					lineScoreShiftMapped.push([lineStart, element]);
					lineStart++;
				});

				// Sort by prediction score
				lineScoreShiftMapped.sort((a: number[], b: number[]) => {
					return b[1] - a[1];
				}
				);

				const url = "https://cwe.mitre.org/data/definitions/" + cweID.substring(4) + ".html";

				for(var i = 0; i < config.maxIndicatorLines; i++){
					
					const vulnLine = lineScoreShiftMapped[i][0];

					const lines = this.targetDocument?.getText().split("\n") ?? [];

					let line = this.targetDocument?.lineAt(vulnLine);

					let diagMessage = "";

					cweDescription = this.predictions.cwe.descriptions[vulCount];

					const separator = " | ";

					switch(config.infoLevel){
						case InfoLevels.fluent: {
							// diagMessage = "Line: " + (vulnLine+1) + " | Severity: " + sevScore.toString().match(/^\d+(?:\.\d{0,2})?/) + " | CWE: " + cweID.substring(4) + " " + ((cweName === undefined || "") ? "" : ("(" + cweName + ") ") )  + "| Type: " + cweType;
							diagMessage = "[Severity: " + sevClass + " (" + sevScore.toString().match(/^\d+(?:\.\d{0,2})?/) + ")" + "] Line " + (vulnLine+1) + " may be vulnerable with " + cweID + " (" + cweName + " | Abstract Type: " + cweType + ")";  
							break;
						}
						case InfoLevels.verbose: {
							// diagMessage = "[" + lineScoreShiftMapped[i][1].toString().match(/^\d+(?:\.\d{0,2})?/) + "] Line: " + (vulnLine+1) + " | Severity: " + sevScore.toString().match(/^\d+(?:\.\d{0,2})?/) + " (" + sevClass +")" +" | " + "[" + cweIDProb.toString().match(/^\d+(?:\.\d{0,2})?/) + "] " +"CWE: " + cweID.substring(4) + " " + ((cweName === undefined || "") ? "" : ("(" + cweName + ") ") ) )  + "| " + "[" + cweTypeProb.toString().match(/^\d+(?:\.\d{0,2})?/) + "] " + "Type: " + cweType;
							diagMessage += (config.customDiagInfos?.includes(DiagnosticInformation.lineNumber))? "Line " + (vulnLine + 1) + separator : "";
							diagMessage += (config.customDiagInfos?.includes(DiagnosticInformation.cweID))? (config.customDiagInfos?.includes(DiagnosticInformation.confidenceScore)? "[" + cweIDProb.toString().match(/^\d+(?:\.\d{0,2})?/) + "] " + cweID: cweID) : "" ;
							diagMessage += ((config.customDiagInfos?.includes(DiagnosticInformation.cweID)) && config.customDiagInfos?.includes(DiagnosticInformation.cweSummary))? " (" + cweName + ")" + separator : "";
							diagMessage += (config.customDiagInfos?.includes(DiagnosticInformation.cweType))? (config.customDiagInfos?.includes(DiagnosticInformation.confidenceScore)?  "[" + cweTypeProb.toString().match(/^\d+(?:\.\d{0,2})?/) + "] " + "Abstract: " + cweType + separator: "Abstract: " + cweType + separator) : "";
							diagMessage += (config.customDiagInfos?.includes(DiagnosticInformation.severityLevel))? (config.customDiagInfos?.includes(DiagnosticInformation.severityScore))? "Severity: " + sevScore.toString().match(/^\d+(?:\.\d{0,2})?/) + " (" + sevClass + ")":  "Severity: " + sevClass : (config.customDiagInfos?.includes(DiagnosticInformation.severityScore))? "Severity: " + sevScore.toString().match(/^\d+(?:\.\d{0,2})?/):"";
							diagMessage = diagMessage.endsWith(separator)? diagMessage.substring(0, diagMessage.length - separator.length) : diagMessage;
							break;
						}
					};

					const range = new vscode.Range(vulnLine, this.targetDocument?.lineAt(vulnLine).firstNonWhitespaceCharacterIndex ?? 0, vulnLine, line?.text.length ?? 0);

					const diagnostic = new vscode.Diagnostic(
						range,
						diagMessage,
						config.diagnosticSeverity ?? vscode.DiagnosticSeverity.Error
					);

					diagnostic.code = {
						value: "More Details",
						target: vscode.Uri.parse(url)
					};

					diagnostic.source = "CodeGuard";

					// Get the text at the range
					const text = this.targetDocument?.getText(new vscode.Range(vulnLine, 0, vulnLine, line?.text.length ?? 0));
					
					if (diagMessage) {
						diagnostics.push(diagnostic);
					} else {
						debugMessage(DebugTypes.error, "Diagnostic message is not set");
					}

					if(config.showDescription){
						const diagnosticDescription = new vscode.Diagnostic(
							range,
							cweDescription,
							config.diagnosticSeverity ?? vscode.DiagnosticSeverity.Error
						);
		
						diagnosticDescription.code = {
							value: "More Details",
							target: vscode.Uri.parse(url)
						};
		
						diagnostics.push(diagnosticDescription);
					}

					// Add range for decoration based on severity
					const decorationRange = new vscode.Range(vulnLine, 0, vulnLine, line?.text.length ?? 0);
					if (sevScore >= 7.0) {
						decorationRanges['High'].push(decorationRange);
					} else if (sevScore >= 4.0) {
						decorationRanges['Medium'].push(decorationRange);
					} else {
						decorationRanges['Low'].push(decorationRange);
					}
					
				}
				vulCount++;
				
			}
		});

		// Store vulnerability count for this file
		if (this.targetDocument) {
			VulDiagnostic.fileVulnerabilityCounts.set(this.targetDocument.uri.toString(), vulCount);
		}

		// Update status bar with current file's vulnerability count
		VulDiagnostic.updateStatusBar(vulCount);

		// Apply decorations if there's an active text editor
		const activeEditor = vscode.window.activeTextEditor;
		if (activeEditor && activeEditor.document === this.targetDocument) {
			// Apply decorations for each severity level
			Object.keys(this.vulnLineDecorationTypes).forEach(severity => {
				activeEditor.setDecorations(this.vulnLineDecorationTypes[severity], decorationRanges[severity]);
			});
		}

		progressEmitter.emit("end", ProgressStages.analysisEnd);

		diagnosticCollection.delete(this.targetDocument.uri);
		diagnosticCollection.set(this.targetDocument.uri, diagnostics);
		
		// Store decorations and ranges separately
		if (this.targetDocument) {
			VulDiagnostic.fileDecorations.set(this.targetDocument.uri.toString(), this.vulnLineDecorationTypes);
			VulDiagnostic.decorationRanges.set(this.targetDocument.uri.toString(), decorationRanges);
		}

		return 0;
	}


	/**
	 * Takes a list of CWE Types and CWE IDs and fetches the CWE data from the CWE xml
	 * It stores the name and description into new fields in object: predictions.cwe.names and predictions.cwe.descriptions
	 * @param list List of CWE IDs ( [[CWE Type, CWE ID]] )
	 * @returns Promise that resolves when successfully retrieved CWE data from XML, rejects otherwise
	 */
	async fetchCWEData(list:any){
		progressEmitter.emit("update", ProgressStages.cweSearchStart);

		try{
			const data = await fsa.readFile(config.cweXMLFile); // replace config.xmlpath with manual path
			debugMessage(DebugTypes.info, "CWE XML file read");

			try{
				debugMessage(DebugTypes.info, "Parsing CWE XML file");
				
				const parsed:any = await new Promise((resolve, reject) => parser.parseString(data, (err: any, result: any) => {
					if (err) {reject(err); return Promise.reject(err);}
					else {resolve(result);}
				}));

				// Log the parsed XML structure
				console.log('Parsed XML Structure:', JSON.stringify(parsed, null, 2));

				if(!parsed){
					debugMessage(DebugTypes.error, "Error parsing CWE XML file");
					progressEmitter.emit("end", ProgressStages.error);
					return Promise.reject();
				} else{
					
					debugMessage(DebugTypes.info, "Parsed CWE XML file. Getting data");
					const weaknessDescriptions: any[] = [];
					const weaknessNames: any[] = [];

					list.forEach((element:any, i: number) => {
						let weakness: any;
						let weaknessDescription: string = "";
						let weaknessName: string = "";

						// Try Base path first
						try {
							weakness = parsed.Weakness_Catalog.Weaknesses[0].Weakness.find((obj:any) =>{
								return obj.$.ID === element[1].toString();
							});
							if (weakness && weakness.Description) {
								weaknessDescription = weakness.Description[0];
							}
						} catch (err) {
							// If Base path fails, silently continue to try Category path
						}

						// If Base path didn't work, try Category path
						if (!weaknessDescription) {
							try {
								weakness = parsed.Weakness_Catalog.Categories[0].Category.find((obj:any) =>{
									return obj.$.ID === element[1].toString();
								});
								if (weakness && weakness.Summary) {
									weaknessDescription = weakness.Summary[0];
								}
							} catch (err) {
								// If both paths fail, log the error but don't throw
								debugMessage(DebugTypes.error, `Could not find description for CWE ID: ${element[1]}`);
								console.log(`CWE ID: ${element[1]}`);
							}
						}

						// Get the name if we found a weakness
						if (weakness && weakness.$ && weakness.$.Name) {
							weaknessName = weakness.$.Name;
						} else {
							debugMessage(DebugTypes.error, `Name not found for CWE ID: ${element[1]}`);
							console.log(`CWE ID: ${element[1]}`);
						}

						weaknessDescriptions.push(weaknessDescription);
						weaknessNames.push(weaknessName);
					});
					
					this.predictions.cwe.descriptions = weaknessDescriptions;
					this.predictions.cwe.names = weaknessNames;

					return Promise.resolve();
				} 
			} catch(err){
				debugMessage(DebugTypes.error, "Error Parsing CWE XML file");
				progressEmitter.emit("end", ProgressStages.error);
				return Promise.reject(err);
			}
		
		} catch(err:any){
			debugMessage(DebugTypes.error, "Error while reading CWE XML file: " + err);
			progressEmitter.emit("end", ProgressStages.error);
			return Promise.reject(err);
		}
	}

	// Update dispose to clean up all decoration types
	dispose() {
		if (this.targetDocument) {
			// Don't delete the decorations when disposing unless explicitly clearing them
			// VulDiagnostic.fileDecorations.delete(this.targetDocument.uri.toString());
			Object.values(this.vulnLineDecorationTypes).forEach(decoration => {
				if (decoration.dispose) {
					decoration.dispose();
				}
			});
		}
	}

	// Add static method to initialize status bar
	public static initializeStatusBar() {
		if (!this.statusBarItem) {
			this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
			this.statusBarItem.command = 'aibughunter.restart';
			this.statusBarItem.name = 'CodeGuard';
			this.statusBarItem.text = 'Restart CodeGuard';
			this.statusBarItem.tooltip = 'Click to reinitialise CodeGuard';
			this.statusBarItem.show();
		}
	}

	// Add static method to update status bar
	public static updateStatusBar(vulCount: number) {
		if (!this.statusBarItem) {
			this.initializeStatusBar();
		}
		this.statusBarItem.text = `$(alert) ${vulCount} Vulnerabilities Found`;
		this.statusBarItem.tooltip = "Click to view details";

		if (vulCount > 10) {
			this.statusBarItem.color = "red";  // High-risk
		} else if (vulCount > 5) {
			this.statusBarItem.color = "orange";  // Medium-risk
		} else if (vulCount > 0) {
			this.statusBarItem.color = "yellow";  // Low-risk
		} else {
			this.statusBarItem.color = undefined; // No vulnerabilities
		}
	}
}

/**
 * Provides code actions for fixing vulnerabilities
 */
class VulnerabilityFixProvider implements vscode.CodeActionProvider {
    
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix
    ];

    async provideCodeActions(document: vscode.TextDocument, range: vscode.Range | vscode.Selection, context: vscode.CodeActionContext): Promise<vscode.CodeAction[] | null> {
        // Filter diagnostics to only those from our extension
        const diagnostics = context.diagnostics.filter(
            diagnostic => diagnostic.source === "CodeGuard"
        );
        
        if (!diagnostics.length) {
            return null;
        }
        
        const actions: vscode.CodeAction[] = [];
        
        // For each diagnostic, create a fix action
        for (const diagnostic of diagnostics) {
            // Skip description diagnostics (we only want to fix the main diagnostics)
            if (diagnostic.message.startsWith("The") || diagnostic.message.length > 200) {
                continue;
            }
            
            const fix = this.createFix(document, diagnostic.range, diagnostic);
            if (fix) {
                actions.push(fix);
            }
        }
        
        return actions;
    }
    
    private createFix(document: vscode.TextDocument, range: vscode.Range, diagnostic: vscode.Diagnostic): vscode.CodeAction | null {
        // Create a code action to fix the vulnerability
        const fix = new vscode.CodeAction('Fix Vulnerability', vscode.CodeActionKind.QuickFix);
        fix.diagnostics = [diagnostic];
        
        // Create a command that will be executed when the code action is selected
        fix.command = {
            title: 'Fix Vulnerability',
            command: 'aibughunter.fixVulnerability',
            arguments: [document, range]
        };
        
        return fix;
    }
}

/**
 * Extracts the vulnerable function's code from a given range
 * @param document The document containing the vulnerable code
 * @param range The range of the vulnerability
 * @returns The full function text or null if not found
 */
async function extractVulnerableFunctionFromRange(document: vscode.TextDocument, range: vscode.Range): Promise<string | null> {
	// Get the function range that contains this position
	const functionRange = await getFunctionRangeFromPosition(document, range.start);
	if (!functionRange) {
		return null;
	}
	
	// Extract the full function text
	return document.getText(functionRange);
}

/**
 * Gets the full range of a function from a position within it
 * @param document The document to search in
 * @param position A position within the function
 * @returns The full range of the function or null if not found
 */
async function getFunctionRangeFromPosition(document: vscode.TextDocument, position: vscode.Position): Promise<vscode.Range | null> {
	// Get document symbols
	const symbols = await vscode.commands.executeCommand<vscode.DocumentSymbol[]>(
		'vscode.executeDocumentSymbolProvider',
		document.uri
	);
	
	if (!symbols || symbols.length === 0) {
		return null;
	}
	
	// Find the function that contains this position
	for (const symbol of symbols) {
		if (symbol.kind === vscode.SymbolKind.Function && symbol.range.contains(position)) {
			return symbol.range;
		}
		
		// Check children (for nested functions/methods)
		if (symbol.children && symbol.children.length > 0) {
			for (const child of symbol.children) {
				if (child.kind === vscode.SymbolKind.Function && child.range.contains(position)) {
					return child.range;
				}
			}
		}
	}
	
	return null;
}

/**
 * Calls the repair API to fix vulnerable code
 * @param code The vulnerable code to fix
 * @returns The repaired code or an error message
 */
async function callRepairAPI(code: string): Promise<string | null> {
	try {
		debugMessage(DebugTypes.info, "Calling repair API...");
		
        // Show progress notification
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "Generating vulnerability fix...",
            cancellable: false
        }, async (progress) => {
            progress.report({ increment: 30, message: "Analyzing vulnerable code..." });
            
            // Add a small delay to show the progress
            await new Promise(resolve => setTimeout(resolve, 500));
            progress.report({ increment: 30, message: "Generating repair suggestions..." });
            
            // Add another small delay
            await new Promise(resolve => setTimeout(resolve, 500));
            progress.report({ increment: 40, message: "Finalizing repair..." });
        });
		
		// Determine the endpoint based on inference mode
		let repairEndpoint = "";
		let useAxios = false;
		
		if (config.inferenceMode === InferenceModes.local) {
			// For local inference, use PythonShell
			const scriptLocation = path.join(__dirname, "..", "resources", "local-inference");
			const shell = new PythonShell('local.py', {
				mode: 'text', 
				args: ["repair", (config.useCUDA ? "True" : "False")], 
				scriptPath: scriptLocation
			});
			
			// Send the code to repair
			shell.send(JSON.stringify([code]));
			
			return new Promise<string>((resolve, reject) => {
				shell.on('message', (message: any) => {
					try {
						// Try to parse as JSON first
						try {
							const result = JSON.parse(message);
							if (result && result.batch_repair && result.batch_repair.length > 0) {
								resolve(result.batch_repair[0]);
								return;
							}
						} catch {
							// If not JSON, it might be raw code
							if (message && message.length > 0) {
								resolve(message);
								return;
							}
						}
						reject("Invalid response format from repair API");
					} catch (err) {
						reject("Error parsing repair API response: " + err);
					}
				});
				
				shell.end((err: any) => {
					if (err) {
						reject("Error calling repair API: " + err);
					}
				});
			});
		} else {
			// For remote inference, use HTTP request
			const jsonObject = JSON.stringify([code]);
			const url = ((config.inferenceMode === InferenceModes.onpremise) ? 
				config.inferenceURLs.onPremise : 
				config.inferenceURLs.cloud) + 
				((config.useCUDA) ? config.endpoints.repair.gpu : config.endpoints.repair.cpu);
			
			debugMessage(DebugTypes.info, `Calling repair API at: ${url}`);
			
			const response = await axios({
				method: "post",
				url: url,
				data: jsonObject,
				headers: { "Content-Type": "application/json" },
                params: { raw: "true" } // Request raw code response instead of JSON wrapped
			});
			
			if (response && response.data) {
				// Handle both raw text and JSON responses
				if (typeof response.data === 'string') {
					try {
						// Try to parse as JSON
						const parsed = JSON.parse(response.data);
						if (parsed && parsed.batch_repair && parsed.batch_repair.length > 0) {
							return parsed.batch_repair[0];
						} else if (parsed && parsed.error) {
							throw new Error(parsed.error);
						}
					} catch (e) {
						// If it's not valid JSON, return it as raw code
						// But first check if it starts with "Error:"
						if (response.data.startsWith("Error:")) {
							throw new Error(response.data.substring(6));
						}
						return response.data;
					}
				} else if (typeof response.data === 'object') {
					// Already JSON object
					if (response.data.batch_repair && response.data.batch_repair.length > 0) {
						return response.data.batch_repair[0];
					} else if (response.data.error) {
						throw new Error(response.data.error);
					}
				}
			}
			
			return null;
		}
	} catch (error) {
		debugMessage(DebugTypes.error, "Error calling repair API: " + error);
		return "Error: " + error;
	}
}

/**
 * Detects potential vulnerability types in the given code
 * @param code The code to analyze
 * @returns An array of vulnerability type names
 */
function detectVulnerabilityTypes(code: string): string[] {
    const vulnerabilityTypes: string[] = [];
    
    // Buffer overflow vulnerabilities
    if (code.includes("gets(") || 
        code.includes("strcpy(") || 
        code.includes("strcat(") || 
        code.includes("sprintf(") ||
        code.includes("scanf(") && code.includes("%s") && !code.includes("%*s")) {
        vulnerabilityTypes.push("Buffer Overflow");
    }
    
    // Command injection vulnerabilities
    if ((code.includes("system(") || code.includes("popen(") || code.includes("exec(")) && 
        (code.includes("argv") || code.includes("gets") || code.includes("scanf") || 
         code.includes("sprintf(") || code.includes("strcat("))) {
        vulnerabilityTypes.push("Command Injection");
    }
    
    // Format string vulnerabilities
    if ((code.includes("printf(") || code.includes("sprintf(") || code.includes("fprintf(")) &&
        code.includes("argv")) {
        vulnerabilityTypes.push("Format String");
    }
    
    // Memory leak vulnerabilities
    if ((code.includes("malloc(") || code.includes("calloc(")) && 
        !code.includes("free(")) {
        vulnerabilityTypes.push("Memory Leak");
    }
    
    // Null pointer dereference
    if ((code.includes("malloc(") || code.includes("calloc(")) && 
        !code.includes("NULL")) {
        vulnerabilityTypes.push("Null Pointer Dereference");
    }
    
    // Integer overflow
    if ((code.includes("int ") || code.includes("long ") || code.includes("short ")) && 
        (code.includes("*") || code.includes("+")) && 
        !code.includes("INT_MAX") && !code.includes("LONG_MAX")) {
        vulnerabilityTypes.push("Integer Overflow");
    }
    
    // Use after free
    const hasFree = code.includes("free(");
    const hasPointerUsage = /\w+\s*->\s*\w+/.test(code);
    if (hasFree && hasPointerUsage) {
        vulnerabilityTypes.push("Use After Free");
    }
    
    // If no specific vulnerability type was identified
    if (vulnerabilityTypes.length === 0) {
        vulnerabilityTypes.push("Security Vulnerability");
    }
    
    return vulnerabilityTypes;
}


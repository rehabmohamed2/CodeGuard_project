"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.AnalysisCore = void 0;
const asan_1 = require("./asan");
const promises_1 = require("fs/promises");
const path = __importStar(require("path"));
class AnalysisCore {
    checkers;
    constructor(checkers) {
        this.checkers = checkers;
    }
    // File-based analysis flow
    async analyzeFile(cppPath, options) {
        // Generate the output file path in the current working directory.
        // (For example, "example.cpp" becomes "example")
        const outputPath = cppPath.replace(/\.cpp$/, '');
        try {
            // options.onProgress?.('Compiling with ASan...');
            await (0, asan_1.compileWithASan)(cppPath, outputPath);
            const sarifData = [];
            for (const checker of this.checkers) {
                if (options.cancellationToken?.isCancellationRequested) {
                    throw new Error('Analysis cancelled');
                }
                // options.onProgress?.(`Running ${checker.name} check...`);
                const asanOutput = await (0, asan_1.runWithASan)(outputPath, checker.testInput, checker.asanOptions);
                const vuln = checker.parse(asanOutput);
                if (vuln) {
                    sarifData.push(checker.generateSarif(vuln));
                }
            }
            if (sarifData.length > 0) {
                const sarifLog = [{
                        $schema: "http://json.schemastore.org/sarif-2.1.0",
                        version: "2.1.0",
                        runs: [{
                                tool: {
                                    driver: {
                                        name: "Secure Code Analyzer",
                                        rules: sarifData.map(d => d.rule),
                                        informationUri: "https://github.com/your-repo"
                                    }
                                },
                                results: sarifData.flatMap(d => d.result),
                            }]
                    }];
                return sarifLog;
            }
            else {
                return sarifData;
            }
        }
        finally {
            // Regardless of analysis outcome, delete the compiled file.
            try {
                await (0, promises_1.unlink)(outputPath);
            }
            catch (err) {
                // Log an error if deletion fails.
                console.error(`Failed to delete compiled file ${outputPath}:`, err);
            }
        }
    }
    // Fuzzing-based analysis flow
    async analyzeCrashes(executablePath, crashInputs, options) {
        const sarifData = [];
        try {
            for (const inputFile of crashInputs) {
                if (options.cancellationToken?.isCancellationRequested) {
                    throw new Error('Analysis cancelled');
                }
                options.onProgress?.(`Testing crash input: ${path.basename(inputFile)}`);
                for (const checker of this.checkers) {
                    // Run the crash input through ASan
                    const asanOutput = await (0, asan_1.runWithASan)(executablePath, inputFile, // pass the file path
                    checker.asanOptions);
                    const vuln = checker.parse(asanOutput);
                    if (vuln) {
                        sarifData.push(checker.generateSarif(vuln));
                    }
                }
            }
            // Build and return the SARIF log if we found any vulnerabilities
            if (sarifData.length > 0) {
                const sarifLog = [{
                        $schema: "http://json.schemastore.org/sarif-2.1.0",
                        version: "2.1.0",
                        runs: [{
                                tool: {
                                    driver: {
                                        name: "Secure Code Analyzer",
                                        rules: sarifData.map(d => d.rule),
                                        informationUri: "https://github.com/your-repo"
                                    }
                                },
                                results: sarifData.flatMap(d => d.result),
                            }]
                    }];
                return sarifLog;
            }
            else {
                // No vulnerabilities → return empty array
                return sarifData;
            }
        }
        finally {
        }
    }
}
exports.AnalysisCore = AnalysisCore;
//# sourceMappingURL=analysis-core.js.map
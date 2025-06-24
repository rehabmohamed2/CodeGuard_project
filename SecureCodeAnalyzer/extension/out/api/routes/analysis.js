"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const analysis_1 = require("../controllers/analysis");
const router = (0, express_1.Router)();
router.post('/analysis', analysis_1.startAnalysis);
router.get('/analysis/:id/status', analysis_1.getAnalysisStatus);
router.delete('/analysis/:id/cancel', analysis_1.cancelAnalysis);
exports.default = router;
//# sourceMappingURL=analysis.js.map
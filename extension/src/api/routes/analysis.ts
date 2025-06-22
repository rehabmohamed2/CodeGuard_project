import { Router } from 'express';
import { startAnalysis, getAnalysisStatus, cancelAnalysis } from '../controllers/analysis';

const router = Router();

router.post('/analysis', startAnalysis);
router.get('/analysis/:id/status', getAnalysisStatus);
router.delete('/analysis/:id/cancel', cancelAnalysis);

export default router;
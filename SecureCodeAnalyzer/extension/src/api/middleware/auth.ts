import { Request, Response, NextFunction  } from 'express';
import * as jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import path from 'path';

dotenv.config({ path: path.resolve(__dirname, '../../../../.env') });

export interface AuthenticatedRequest extends Request {
  user?: jwt.JwtPayload & { // Add JWT payload structure
    id: string;
    role: 'admin' | 'user';
  };
}

export const authenticate = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    // Validate JWT secret configuration
    if (!process.env.JWT_SECRET) {
      throw new Error('JWT_SECRET environment variable not configured');
    }

    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      res.sendStatus(401);
      return;
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
      ignoreExpiration: false
    }) as jwt.JwtPayload & { id: string; role: string };
    
    // Validate payload structure
    if (typeof decoded.id !== 'string' || !['admin', 'user'].includes(decoded.role)) {
      throw new Error('Invalid token payload');
    }

    req.user = {
      id: decoded.id,
      role: decoded.role as 'admin' | 'user',
      iat: decoded.iat!,
      exp: decoded.exp!
    };
    next();
  } catch (error) {
    res.status(401).json({
      error: error instanceof Error ? error.message : 'Invalid token',
      code: 'INVALID_CREDENTIALS'
    });
  }
};
import { describe, expect, test, beforeEach, vi } from 'vitest'
import { generateTokens, signup, login, logout } from './auth.controller'
import { User } from '../models/user.model.js';
import { Types } from 'mongoose';
import jwt from "jsonwebtoken";

describe('generateTokens', () => {
    // mock environment variables
    beforeEach(() => {
      vi.stubEnv('ACCESS_TOKEN_SECRET', 'test-access-secret');
      vi.stubEnv('REFRESH_TOKEN_SECRET', 'test-refresh-secret');
    });

    test('should generate tokens given {userId} @auth', () => {
      const userId = new Types.ObjectId();
      const { accessToken, refreshToken } = generateTokens(userId);
      const decodedAccessToken = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
      const decodedRefreshToken = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    
      // verify accessToken is defined
      expect(accessToken).toBeDefined();
      expect(decodedAccessToken.userId).toBe(userId.toString());
      // verify expiration is approximately 15 minutes (900 seconds)
      const accessExpirationDuration = decodedAccessToken.exp - decodedAccessToken.iat;
      expect(accessExpirationDuration).toBe(60*15); // 15 minutes in seconds

      // verify refreshToken is defined
      expect(refreshToken).toBeDefined();
      expect(decodedRefreshToken.userId).toBe(userId.toString());
      // verify expiration is approximately 7 days
      const refreshExpirationDuration = decodedRefreshToken.exp - decodedRefreshToken.iat;
      expect(refreshExpirationDuration).toBe(60*60*24*7);
    });
})
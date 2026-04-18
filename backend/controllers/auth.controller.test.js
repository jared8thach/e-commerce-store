import { describe, expect, test, beforeEach, vi } from 'vitest'
import { generateTokens, signup, login, logout } from './auth.controller.js'
import { User } from '../models/user.model.js';
import { Types } from 'mongoose';
import jwt from "jsonwebtoken";

describe('generateTokens(userId)', () => {
    // mock environment variables
    beforeEach(() => {
      vi.stubEnv('ACCESS_TOKEN_SECRET', 'test-access-secret');
      vi.stubEnv('REFRESH_TOKEN_SECRET', 'test-refresh-secret');
    });

    test('should generate tokens given {userId} @auth', () => {
      // define {userId} input
      const userId = new Types.ObjectId();

      // call generateTokens unit function
      const { accessToken, refreshToken } = generateTokens(userId);

      // prepare tokens for validation
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

    test('should generate tokens with {userId} as string', () => {
      const userId = '507f1f77bcf86cd799439011'; // valid ObjectId string
      const { accessToken, refreshToken } = generateTokens(userId);
      
      const decodedAccessToken = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
      const decodedRefreshToken = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
      
      expect(decodedAccessToken.userId).toBe(userId);
      expect(decodedRefreshToken.userId).toBe(userId);
    });

    test('should generate tokens with null {userId}', () => {
      const userId = null;
      const { accessToken, refreshToken } = generateTokens(userId);
      
      const decodedAccessToken = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
      const decodedRefreshToken = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
      
      expect(decodedAccessToken.userId).toBeNull();
      expect(decodedRefreshToken.userId).toBeNull();
    });

    test('should generate tokens with undefined {userId}', () => {
      const userId = undefined;
      const { accessToken, refreshToken } = generateTokens(userId);
      
      const decodedAccessToken = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
      const decodedRefreshToken = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
      
      expect(decodedAccessToken.userId).toBeUndefined();
      expect(decodedRefreshToken.userId).toBeUndefined();
    });

    test('should generate tokens with empty string {userId}', () => {
      const userId = '';
      const { accessToken, refreshToken } = generateTokens(userId);
      
      const decodedAccessToken = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
      const decodedRefreshToken = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
      
      expect(decodedAccessToken.userId).toBe('');
      expect(decodedRefreshToken.userId).toBe('');
    });

    test('should generate tokens with numeric {userId}', () => {
      const userId = 12345;
      const { accessToken, refreshToken } = generateTokens(userId);
      
      const decodedAccessToken = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
      const decodedRefreshToken = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
      
      expect(decodedAccessToken.userId).toBe(12345);
      expect(decodedRefreshToken.userId).toBe(12345);
    });

    test('should throw error when ACCESS_TOKEN_SECRET is missing', () => {
      vi.unstubAllEnvs();
      delete process.env.ACCESS_TOKEN_SECRET;
      
      const userId = new Types.ObjectId();
      expect(() => generateTokens(userId)).toThrow();
    });

    test('should throw error when REFRESH_TOKEN_SECRET is missing', () => {
      vi.unstubAllEnvs();
      delete process.env.REFRESH_TOKEN_SECRET;
      
      const userId = new Types.ObjectId();
      expect(() => generateTokens(userId)).toThrow();
    });

    test('should throw error when ACCESS_TOKEN_SECRET is empty', () => {
      vi.stubEnv('ACCESS_TOKEN_SECRET', '');
      
      const userId = new Types.ObjectId();
      expect(() => generateTokens(userId)).toThrow();
    });

    test('should throw error when REFRESH_TOKEN_SECRET is empty', () => {
      vi.stubEnv('REFRESH_TOKEN_SECRET', '');
      
      const userId = new Types.ObjectId();
      expect(() => generateTokens(userId)).toThrow();
    });

    test.todo('should generate unique tokens on each call', () => {
      const userId = new Types.ObjectId();
      const { accessToken: access1, refreshToken: refresh1 } = generateTokens(userId);
      const { accessToken: access2, refreshToken: refresh2 } = generateTokens(userId);
      
      expect(access1).not.toBe(access2);
      expect(refresh1).not.toBe(refresh2);
    });

    test('should include standard JWT claims', () => {
      const userId = new Types.ObjectId();
      const { accessToken, refreshToken } = generateTokens(userId);
      
      const decodedAccess = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
      const decodedRefresh = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
      
      // Check iat (issued at) is present and reasonable
      expect(decodedAccess.iat).toBeDefined();
      expect(typeof decodedAccess.iat).toBe('number');
      expect(decodedAccess.iat).toBeLessThanOrEqual(Date.now() / 1000);
      
      expect(decodedRefresh.iat).toBeDefined();
      expect(typeof decodedRefresh.iat).toBe('number');
      
      // Check exp is present
      expect(decodedAccess.exp).toBeDefined();
      expect(decodedRefresh.exp).toBeDefined();
    });

    test('should generate tokens in valid JWT format', () => {
      const userId = new Types.ObjectId();
      const { accessToken, refreshToken } = generateTokens(userId);
      
      // JWT format: header.payload.signature
      const accessParts = accessToken.split('.');
      const refreshParts = refreshToken.split('.');
      
      expect(accessParts).toHaveLength(3);
      expect(refreshParts).toHaveLength(3);
      
      // Each part should be base64url encoded
      accessParts.forEach(part => {
        expect(part).toMatch(/^[A-Za-z0-9_-]+$/);
      });
      refreshParts.forEach(part => {
        expect(part).toMatch(/^[A-Za-z0-9_-]+$/);
      });
    });

    test('should not decode access token with refresh secret', () => {
      const userId = new Types.ObjectId();
      const { accessToken } = generateTokens(userId);
      
      expect(() => jwt.verify(accessToken, process.env.REFRESH_TOKEN_SECRET)).toThrow();
    });

    test('should not decode refresh token with access secret', () => {
      const userId = new Types.ObjectId();
      const { refreshToken } = generateTokens(userId);
      
      expect(() => jwt.verify(refreshToken, process.env.ACCESS_TOKEN_SECRET)).toThrow();
    });

    test('should handle jwt.sign errors gracefully', () => {
      // Mock jwt.sign to throw an error
      const originalSign = jwt.sign;
      jwt.sign = vi.fn(() => { throw new Error('JWT signing failed'); });
      
      const userId = new Types.ObjectId();
      expect(() => generateTokens(userId)).toThrow('JWT signing failed');
      
      // Restore original function
      jwt.sign = originalSign;
    });
});
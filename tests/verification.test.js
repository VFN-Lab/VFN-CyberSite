const { generateToken, verifyDomain, isDomainVerified, normalizeDomain, verifiedDomains } = require('../scanners/verification/index');
const axios = require('axios');
const crypto = require('crypto');

// Mock axios
jest.mock('axios');

describe('Domain Ownership Verification Module', () => {
  
  beforeEach(() => {
    // Clear state
    verifiedDomains.clear();
    jest.clearAllMocks();
  });

  describe('normalizeDomain', () => {
    it('should extract hostname from http url', () => {
      expect(normalizeDomain('http://example.com')).toBe('example.com');
    });
    it('should extract hostname from https url', () => {
      expect(normalizeDomain('https://sub.example.com/path')).toBe('sub.example.com');
    });
    it('should assume https if no protocol provided', () => {
      expect(normalizeDomain('example.com/test')).toBe('example.com');
    });
  });

  describe('generateToken', () => {
    it('should generate a unique security token', () => {
      const token = generateToken('example.com');
      expect(token).toMatch(/^security-token-[0-9a-f]{16}$/);
    });

    it('should store the token', async () => {
      const token = generateToken('example.com');
      
      // Mock axios to return success
      axios.get.mockResolvedValue({
        data: `Security Scanner Verification\nDomain: example.com\nToken: ${token}`
      });

      const success = await verifyDomain('example.com', token);
      expect(success).toBe(true);
    });
  });

  describe('verifyDomain', () => {
    it('should return true for valid file content', async () => {
      const token = generateToken('test.com');
      
      axios.get.mockResolvedValue({
        data: `Security Scanner Verification\nDomain: test.com\nToken: ${token}`
      });

      const success = await verifyDomain('test.com', token);
      expect(success).toBe(true);
      expect(isDomainVerified('test.com')).toBe(true);
    });

    it('should return false if token mismatch', async () => {
      generateToken('test.com'); // stores one token
      
      const success = await verifyDomain('test.com', 'security-token-wrong');
      expect(success).toBe(false);
      expect(axios.get).not.toHaveBeenCalled(); // should fail before network request
    });

    it('should return false if domain in file is wrong', async () => {
      const token = generateToken('test.com');
      
      axios.get.mockResolvedValue({
        data: `Security Scanner Verification\nDomain: other.com\nToken: ${token}`
      });

      const success = await verifyDomain('test.com', token);
      expect(success).toBe(false);
    });

    it('should return false if header is missing', async () => {
      const token = generateToken('test.com');
      
      axios.get.mockResolvedValue({
        data: `Domain: test.com\nToken: ${token}`
      });

      const success = await verifyDomain('test.com', token);
      expect(success).toBe(false);
    });

    it('should try HTTP if HTTPS fails', async () => {
      const token = generateToken('test.com');
      
      axios.get.mockRejectedValueOnce(new Error('SSL Error')); // HTTPS fails
      axios.get.mockResolvedValueOnce({                        // HTTP succeeds
        data: `Security Scanner Verification\nDomain: test.com\nToken: ${token}`
      });

      const success = await verifyDomain('test.com', token);
      expect(success).toBe(true);
      expect(axios.get).toHaveBeenCalledTimes(2);
      expect(axios.get.mock.calls[0][0]).toBe('https://test.com/security-scanner-verification.txt');
      expect(axios.get.mock.calls[1][0]).toBe('http://test.com/security-scanner-verification.txt');
    });
  });
});

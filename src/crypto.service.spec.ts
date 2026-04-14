import { CryptoService } from './crypto.service';

describe('CryptoService', () => {
  let service: CryptoService;

  beforeEach(() => {
    service = new CryptoService();
  });

  describe('generateSalt', () => {
    it('should generate a salt', () => {
      const salt = service.generateSalt();
      expect(salt).toBeTruthy();
      expect(typeof salt).toBe('string');
    });

    it('should generate different salts', () => {
      const salt1 = service.generateSalt();
      const salt2 = service.generateSalt();
      expect(salt1).not.toBe(salt2);
    });

    it('should generate salt of specified length', () => {
      const salt = service.generateSalt(16);
      expect(salt).toBeTruthy();
    });
  });

  describe('hashPassword', () => {
    it('should hash password with generated salt', async () => {
      const password = 'TestPassword123!';
      const result = await service.hashPassword(password);

      expect(result.hash).toBeTruthy();
      expect(result.salt).toBeTruthy();
      expect(typeof result.hash).toBe('string');
      expect(typeof result.salt).toBe('string');
    });

    it('should hash password with provided salt', async () => {
      const password = 'TestPassword123!';
      const salt = service.generateSalt();
      const result = await service.hashPassword(password, salt);

      expect(result.salt).toBe(salt);
    });

    it('should produce same hash with same password and salt', async () => {
      const password = 'TestPassword123!';
      const salt = service.generateSalt();

      const result1 = await service.hashPassword(password, salt);
      const result2 = await service.hashPassword(password, salt);

      expect(result1.hash).toBe(result2.hash);
    });

    it('should produce different hash with different password', async () => {
      const salt = service.generateSalt();

      const result1 = await service.hashPassword('Password1!', salt);
      const result2 = await service.hashPassword('Password2!', salt);

      expect(result1.hash).not.toBe(result2.hash);
    });
  });

  describe('verifyPassword', () => {
    it('should verify correct password', async () => {
      const password = 'TestPassword123!';
      const { hash, salt } = await service.hashPassword(password);

      const isValid = await service.verifyPassword(password, hash, salt);
      expect(isValid).toBe(true);
    });

    it('should reject incorrect password', async () => {
      const password = 'TestPassword123!';
      const { hash, salt } = await service.hashPassword(password);

      const isValid = await service.verifyPassword('WrongPassword456!', hash, salt);
      expect(isValid).toBe(false);
    });
  });
});

/**
 * Tests for SecureFormsClient
 */

import { SecureFormsClient } from './secure-forms.client';
import { BunkorApiError } from './base.client';

const CONFIG = {
  apiUrl:   'https://lockbox-app-415633403824.us-central1.run.app',
  apiToken: 'sk_test_abc',
};

function mockOk(body: unknown, status = 200) {
  return jest.fn().mockResolvedValue({
    ok: true, status,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(''),
  });
}

function mockError(status: number, detail = 'error') {
  return jest.fn().mockResolvedValue({
    ok: false, status,
    json: () => Promise.resolve({ error: detail }),
    text: () => Promise.resolve(detail),
  });
}

describe('SecureFormsClient', () => {
  let client: SecureFormsClient;

  beforeEach(() => {
    client = new SecureFormsClient(CONFIG);
  });

  afterEach(() => jest.restoreAllMocks());

  // ─── Form CRUD ────────────────────────────────────────────────────────────

  describe('listForms()', () => {
    it('calls GET /api/v1/secure-forms/', async () => {
      global.fetch = mockOk([]);

      await client.listForms();

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/secure-forms/'),
        expect.objectContaining({ method: 'GET' }),
      );
    });

    it('passes include_inactive param', async () => {
      const fetchMock = mockOk([]);
      global.fetch = fetchMock;

      await client.listForms(true);

      const [url] = fetchMock.mock.calls[0];
      expect(url).toContain('include_inactive=true');
    });
  });

  describe('createForm()', () => {
    it('calls POST /api/v1/secure-forms/ with request body', async () => {
      const fetchMock = mockOk({ id: 'f1', token: 'tok', public_url: 'https://...', vault_id: 'v1', vault_name: 'Vault', title: 'Test', is_active: true, submission_count: 0, submission_status_counts: { new: 0, reviewed: 0, archived: 0 }, sections: [], created_at: '2024-01-01' }, 201);
      global.fetch = fetchMock;

      await client.createForm({
        vault_id: 'v1',
        title: 'Test Form',
        sections: [],
      });

      const [, init] = fetchMock.mock.calls[0];
      expect(JSON.parse(init.body as string)).toMatchObject({ vault_id: 'v1', title: 'Test Form' });
    });
  });

  describe('deactivateForm()', () => {
    it('calls DELETE /api/v1/secure-forms/{id}/', async () => {
      global.fetch = jest.fn().mockResolvedValue({ ok: true, status: 204 });

      await client.deactivateForm('f1');

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/secure-forms/f1/'),
        expect.objectContaining({ method: 'DELETE' }),
      );
    });
  });

  // ─── Submissions ──────────────────────────────────────────────────────────

  describe('listSubmissions()', () => {
    it('calls GET /api/v1/secure-forms/{id}/submissions/ with defaults', async () => {
      const fetchMock = mockOk({ count: 0, results: [] });
      global.fetch = fetchMock;

      await client.listSubmissions('f1');

      const [url] = fetchMock.mock.calls[0];
      expect(url).toContain('/api/v1/secure-forms/f1/submissions/');
      expect(url).toContain('page=1');
      expect(url).toContain('page_size=25');
    });

    it('passes status filter', async () => {
      const fetchMock = mockOk({ count: 0, results: [] });
      global.fetch = fetchMock;

      await client.listSubmissions('f1', { status: 'reviewed' });

      const [url] = fetchMock.mock.calls[0];
      expect(url).toContain('status=reviewed');
    });
  });

  describe('bulkUpdateSubmissionStatus()', () => {
    it('calls PATCH /api/v1/secure-forms/{id}/submissions/bulk-status/', async () => {
      const fetchMock = mockOk({ updated: 3, status: 'reviewed' });
      global.fetch = fetchMock;

      const result = await client.bulkUpdateSubmissionStatus('f1', {
        submission_ids: ['s1', 's2', 's3'],
        status: 'reviewed',
      });

      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toContain('bulk-status');
      expect(init.method).toBe('PATCH');
      expect(result.updated).toBe(3);
    });
  });

  // ─── Encryption Config ────────────────────────────────────────────────────

  describe('getEncryptionConfig()', () => {
    it('calls GET /api/v1/secure-forms/encryption-config/', async () => {
      global.fetch = mockOk({ organization_id: 'o1', mode: 'server_managed', public_key_pem: '...', has_keypair: true, encrypted_private_key_blob: null, kdf_params: null });

      await client.getEncryptionConfig();

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/secure-forms/encryption-config/'),
        expect.objectContaining({ method: 'GET' }),
      );
    });
  });

  describe('getPrivateKeyPem()', () => {
    it('calls GET /api/v1/secure-forms/decryption-key/', async () => {
      global.fetch = mockOk({ private_key_pem: '-----BEGIN RSA PRIVATE KEY-----' });

      const result = await client.getPrivateKeyPem();

      expect(result.private_key_pem).toContain('PRIVATE KEY');
    });

    it('propagates 403 as BunkorApiError', async () => {
      global.fetch = mockError(403, 'Forbidden');

      await expect(client.getPrivateKeyPem()).rejects.toMatchObject({ status: 403 });
    });
  });

  // ─── Public Form ──────────────────────────────────────────────────────────

  describe('getPublicForm()', () => {
    it('calls GET /api/v1/public-forms/{pageId}/', async () => {
      const fetchMock = mockOk({ page_id: 'p1', title: 'Form', requires_otp: false, send_submitter_confirmation: false, max_submissions_reached: false, is_expired: false, sections: [] });
      global.fetch = fetchMock;

      await client.getPublicForm('p1');

      const [url] = fetchMock.mock.calls[0];
      expect(url).toContain('/api/v1/public-forms/p1/');
    });
  });

  describe('submitForm()', () => {
    it('calls POST /api/v1/public-forms/{pageId}/submit/', async () => {
      const fetchMock = mockOk({ submission_id: 'sub1', message: 'ok', confirmation_email_sent: false });
      global.fetch = fetchMock;

      await client.submitForm('p1', {
        encryptedMetadata: 'abc',
        encryptedKeyData: { algorithm: 'RSA-OAEP', encrypted_cek: 'cek', iv: 'iv' },
        files: [],
      });

      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toContain('/api/v1/public-forms/p1/submit/');
      expect(init.method).toBe('POST');
    });
  });
});

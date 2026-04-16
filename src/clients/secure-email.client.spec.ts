/**
 * Tests for SecureEmailClient
 */

import { SecureEmailClient } from './secure-email.client';
import { BunkorApiError } from './base.client';
import { EmailStatus } from '../models/email.models';

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
    text: () => Promise.resolve(detail),
  });
}

describe('SecureEmailClient', () => {
  let client: SecureEmailClient;

  beforeEach(() => {
    client = new SecureEmailClient(CONFIG);
  });

  afterEach(() => jest.restoreAllMocks());

  // ─── Draft Lifecycle ──────────────────────────────────────────────────────

  describe('createDraft()', () => {
    it('calls POST /api/v1/secure-emails/drafts/', async () => {
      const fetchMock = mockOk({ email_id: 'e1', access_token: 'tok', access_link: 'https://...', subject: 'Hi', created_at: '2024-01-01', message: 'created' }, 201);
      global.fetch = fetchMock;

      await client.createDraft({ subject: 'Hi', recipients: ['bob@example.com'] });

      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toContain('/api/v1/secure-emails/drafts/');
      expect(init.method).toBe('POST');
      expect(JSON.parse(init.body as string)).toMatchObject({ subject: 'Hi' });
    });
  });

  describe('updateDraft()', () => {
    it('calls PUT /api/v1/secure-emails/{id}/', async () => {
      const fetchMock = mockOk({ message: 'updated' });
      global.fetch = fetchMock;

      await client.updateDraft('e1', { subject: 'Updated Subject' });

      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toContain('/api/v1/secure-emails/e1/');
      expect(init.method).toBe('PUT');
    });
  });

  describe('sendDraft()', () => {
    it('calls POST /api/v1/secure-emails/{id}/send/', async () => {
      const fetchMock = mockOk({ message: 'sent' });
      global.fetch = fetchMock;

      await client.sendDraft('e1');

      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toContain('/api/v1/secure-emails/e1/send/');
      expect(init.method).toBe('POST');
    });
  });

  // ─── Listings ─────────────────────────────────────────────────────────────

  describe('listInbox()', () => {
    it('calls GET /api/v1/secure-emails/inbox/', async () => {
      const fetchMock = mockOk({ emails: [], total_count: 0, page: 1, page_size: 25, total_pages: 0, filter_expired: null });
      global.fetch = fetchMock;

      await client.listInbox();

      const [url] = fetchMock.mock.calls[0];
      expect(url).toContain('/api/v1/secure-emails/inbox/');
    });

    it('passes pagination params', async () => {
      const fetchMock = mockOk({ emails: [], total_count: 0, page: 2, page_size: 10, total_pages: 5, filter_expired: null });
      global.fetch = fetchMock;

      await client.listInbox({ page: 2, page_size: 10 });

      const [url] = fetchMock.mock.calls[0];
      expect(url).toContain('page=2');
      expect(url).toContain('page_size=10');
    });
  });

  describe('getUnreadCount()', () => {
    it('calls GET /api/v1/secure-emails/unread-count/', async () => {
      global.fetch = mockOk({ unread_count: 3 });

      const result = await client.getUnreadCount();

      expect(result.unread_count).toBe(3);
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/secure-emails/unread-count/'),
        expect.anything(),
      );
    });
  });

  // ─── Email Actions ────────────────────────────────────────────────────────

  describe('trashEmail()', () => {
    it('calls POST /api/v1/secure-emails/{id}/trash/', async () => {
      const fetchMock = mockOk({ message: 'trashed' });
      global.fetch = fetchMock;

      await client.trashEmail('e1');

      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toContain('/api/v1/secure-emails/e1/trash/');
      expect(init.method).toBe('POST');
    });
  });

  describe('deleteEmail()', () => {
    it('calls DELETE /api/v1/secure-emails/{id}/', async () => {
      global.fetch = jest.fn().mockResolvedValue({ ok: true, status: 204 });

      await client.deleteEmail('e1');

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/secure-emails/e1/'),
        expect.objectContaining({ method: 'DELETE' }),
      );
    });
  });

  describe('markAsRead()', () => {
    it('calls POST /api/v1/secure-emails/{id}/mark-read/', async () => {
      const fetchMock = mockOk({ message: 'marked' });
      global.fetch = fetchMock;

      await client.markAsRead('e1');

      const [url] = fetchMock.mock.calls[0];
      expect(url).toContain('/api/v1/secure-emails/e1/mark-read/');
    });
  });

  // ─── Attachments ──────────────────────────────────────────────────────────

  describe('initiateAttachmentUpload()', () => {
    it('calls POST /api/v1/secure-emails/{id}/attachments/initiate-upload/', async () => {
      const fetchMock = mockOk({ attachment_id: 'a1', resumable_session_url: 'https://gcs/...', email_id: 'e1', message: 'ok' });
      global.fetch = fetchMock;

      await client.initiateAttachmentUpload('e1', { file_name: 'doc.pdf', size: 1024, content_type: 'application/pdf' });

      const [url] = fetchMock.mock.calls[0];
      expect(url).toContain('/api/v1/secure-emails/e1/attachments/initiate-upload/');
    });
  });

  describe('attachVaultFile()', () => {
    it('calls POST /api/v1/secure-emails/{id}/attachments/attach-vault-file/', async () => {
      const fetchMock = mockOk({ attachment_id: 'a2', email_id: 'e1', filename: 'file.pdf', content_type: 'application/pdf', encrypted_size_bytes: 2048, storage_url: 'https://...', is_vault_reference: true, message: 'ok' });
      global.fetch = fetchMock;

      await client.attachVaultFile('e1', {
        vault_id: 'v1',
        file_id: 'f1',
        wrapped_file_key: 'wrappedKey',
        iv: 'iv123',
        vault_file_iv: 'vaultIv',
      });

      const [url] = fetchMock.mock.calls[0];
      expect(url).toContain('/api/v1/secure-emails/e1/attachments/attach-vault-file/');
    });
  });

  // ─── Error propagation ────────────────────────────────────────────────────

  describe('error handling', () => {
    it('throws BunkorApiError on 422', async () => {
      global.fetch = mockError(422, 'Unprocessable Entity');

      await expect(client.createDraft({ subject: 'Test' })).rejects.toThrow(BunkorApiError);
      await expect(client.createDraft({ subject: 'Test' })).rejects.toMatchObject({ status: 422 });
    });

    it('throws BunkorApiError on network failure', async () => {
      global.fetch = jest.fn().mockRejectedValue(new TypeError('fetch failed'));

      await expect(client.listInbox()).rejects.toMatchObject({ status: 0 });
    });
  });
});

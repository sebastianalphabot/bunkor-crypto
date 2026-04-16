/**
 * Tests for VaultClient
 */

import { VaultClient } from './vault.client';
import { BunkorApiError } from './base.client';
import { Vault, ListVaultsResponse, FileListResponse } from '../models/vault.models';

const CONFIG = {
  apiUrl:   'https://lockbox-app-415633403824.us-central1.run.app',
  apiToken: 'sk_test_abc',
};

function mockOk(body: unknown) {
  return jest.fn().mockResolvedValue({
    ok: true, status: 200,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(''),
  });
}

function mockError(status: number, message = 'error') {
  return jest.fn().mockResolvedValue({
    ok: false, status,
    json: () => Promise.resolve({ error: message }),
    text: () => Promise.resolve(message),
  });
}

describe('VaultClient', () => {
  let client: VaultClient;

  beforeEach(() => {
    client = new VaultClient(CONFIG);
  });

  afterEach(() => jest.restoreAllMocks());

  // ─── Vault Lifecycle ─────────────────────────────────────────────────────

  describe('listVaults()', () => {
    it('calls GET /api/v1/vaults/ and returns vault list', async () => {
      const response: ListVaultsResponse = {
        vaults: [{ id: 'v1', name: 'My Vault', organization_id: 'o1', storage_provider: 'local', is_encrypted: false, is_locked: false, total_storage_bytes: 0, file_count: 0, created_at: '2024-01-01' }],
        total_count: 1,
      };
      global.fetch = mockOk(response);

      const result = await client.listVaults();

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/vaults/'),
        expect.objectContaining({ method: 'GET' }),
      );
      expect(result.vaults).toHaveLength(1);
      expect(result.vaults[0].id).toBe('v1');
    });
  });

  describe('createVault()', () => {
    it('calls POST /api/v1/vaults/ with the request body', async () => {
      const fetchMock = mockOk({ vault_id: 'v2', name: 'New Vault', organization_id: 'o1', storage_provider: 'gcs', created_at: '2024-01-01', message: 'created' });
      global.fetch = fetchMock;

      await client.createVault({ name: 'New Vault', storage_provider: 'gcs' });

      const [, init] = fetchMock.mock.calls[0];
      expect(JSON.parse(init.body as string)).toMatchObject({ name: 'New Vault', storage_provider: 'gcs' });
    });
  });

  describe('deleteVault()', () => {
    it('calls DELETE /api/v1/vaults/{id}/', async () => {
      global.fetch = jest.fn().mockResolvedValue({ ok: true, status: 204 });

      await expect(client.deleteVault('v1')).resolves.toEqual({});
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/vaults/v1/'),
        expect.objectContaining({ method: 'DELETE' }),
      );
    });
  });

  // ─── Files ───────────────────────────────────────────────────────────────

  describe('listFiles()', () => {
    it('calls GET /api/v1/vaults/{id}/files/', async () => {
      const response: FileListResponse = { files: [], folders: [], total_count: 0 };
      global.fetch = mockOk(response);

      await client.listFiles('v1');

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/vaults/v1/files/'),
        expect.anything(),
      );
    });

    it('appends folder_id param when provided', async () => {
      const fetchMock = mockOk({ files: [], folders: [], total_count: 0 });
      global.fetch = fetchMock;

      await client.listFiles('v1', 'f1');

      const [url] = fetchMock.mock.calls[0];
      expect(url).toContain('folder_id=f1');
    });
  });

  describe('initiateDownload()', () => {
    it('calls POST initiate-download endpoint', async () => {
      const fetchMock = mockOk({ method: 'provider', provider: 'gcs', download_url: 'https://gcs/...', file_size_bytes: 1024, file_name: 'doc.pdf', encryption: { algorithm: 'AES-256-GCM', iv: 'abc', salt: 'xyz', encrypted: true, zero_knowledge: true } });
      global.fetch = fetchMock;

      const result = await client.initiateDownload('v1', 'file1');

      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toContain('/api/v1/vaults/v1/files/file1/initiate-download/');
      expect(init.method).toBe('POST');
      expect(result.method).toBe('provider');
    });
  });

  // ─── Error propagation ────────────────────────────────────────────────────

  describe('error propagation', () => {
    it('propagates BunkorApiError on 404', async () => {
      global.fetch = mockError(404, 'Not found');

      await expect(client.getVault('missing')).rejects.toThrow(BunkorApiError);
      await expect(client.getVault('missing')).rejects.toMatchObject({ status: 404 });
    });

    it('propagates BunkorApiError on 403', async () => {
      global.fetch = mockError(403, 'Forbidden');

      await expect(client.listVaults()).rejects.toMatchObject({ status: 403 });
    });
  });

  // ─── Storage / Quota ─────────────────────────────────────────────────────

  describe('checkStorageQuota()', () => {
    it('calls POST /api/v1/storage/check-quota/', async () => {
      const fetchMock = mockOk({ can_upload: true, available_bytes: 1e9, quota_bytes: 2e9, used_bytes: 1e9 });
      global.fetch = fetchMock;

      const result = await client.checkStorageQuota({ file_size: 1024 });

      const [url] = fetchMock.mock.calls[0];
      expect(url).toContain('/api/v1/storage/check-quota/');
      expect(result.can_upload).toBe(true);
    });
  });
});

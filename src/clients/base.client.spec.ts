/**
 * Tests for BaseClient — auth injection, error handling, timeout
 */

import { BaseClient, BunkorApiError } from './base.client';
import { BunkorConfig } from '../config';

// Concrete subclass for testing the abstract class
class TestClient extends BaseClient {
  callGet<T>(endpoint: string, params?: Record<string, string | number | boolean>) {
    return this.get<T>(endpoint, params);
  }
  callPost<T>(endpoint: string, body?: unknown) {
    return this.post<T>(endpoint, body);
  }
  callPatch<T>(endpoint: string, body?: unknown) {
    return this.patch<T>(endpoint, body);
  }
  callDelete<T>(endpoint: string) {
    return this.delete<T>(endpoint);
  }
}

const BASE_CONFIG: BunkorConfig = {
  apiUrl:   'https://lockbox-app-415633403824.us-central1.run.app',
  apiToken: 'test-token',
  debug:    false,
};

function mockFetch(status: number, body: unknown, ok = status >= 200 && status < 300) {
  return jest.fn().mockResolvedValue({
    ok,
    status,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  });
}

describe('BaseClient', () => {
  let client: TestClient;

  beforeEach(() => {
    client = new TestClient(BASE_CONFIG);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('GET requests', () => {
    it('sends Authorization header with Bearer token', async () => {
      const fetchMock = mockFetch(200, { ok: true });
      global.fetch = fetchMock;

      await client.callGet('/api/v1/test/');

      const [, init] = fetchMock.mock.calls[0];
      expect((init.headers as Headers).get('Authorization')).toBe('Bearer test-token');
    });

    it('appends query params to the URL', async () => {
      const fetchMock = mockFetch(200, []);
      global.fetch = fetchMock;

      await client.callGet('/api/v1/items/', { page: 2, active: true });

      const [url] = fetchMock.mock.calls[0];
      expect(url).toContain('page=2');
      expect(url).toContain('active=true');
    });

    it('returns parsed JSON on success', async () => {
      const payload = { id: '123', name: 'test' };
      global.fetch = mockFetch(200, payload);

      const result = await client.callGet<typeof payload>('/api/v1/test/');
      expect(result).toEqual(payload);
    });
  });

  describe('POST requests', () => {
    it('sets Content-Type: application/json and serialises body', async () => {
      const fetchMock = mockFetch(201, { created: true });
      global.fetch = fetchMock;

      await client.callPost('/api/v1/items/', { name: 'foo' });

      const [, init] = fetchMock.mock.calls[0];
      expect((init.headers as Headers).get('Content-Type')).toBe('application/json');
      expect(init.body).toBe(JSON.stringify({ name: 'foo' }));
    });
  });

  describe('error handling', () => {
    it('throws BunkorApiError on non-2xx responses', async () => {
      global.fetch = mockFetch(404, { error: 'not found' }, false);

      await expect(client.callGet('/api/v1/missing/')).rejects.toThrow(BunkorApiError);
      await expect(client.callGet('/api/v1/missing/')).rejects.toMatchObject({ status: 404 });
    });

    it('throws BunkorApiError with status 0 on network failure', async () => {
      global.fetch = jest.fn().mockRejectedValue(new Error('Network unreachable'));

      await expect(client.callGet('/api/v1/test/')).rejects.toThrow(BunkorApiError);
      await expect(client.callGet('/api/v1/test/')).rejects.toMatchObject({ status: 0 });
    });

    it('returns empty object for 204 No Content', async () => {
      global.fetch = jest.fn().mockResolvedValue({ ok: true, status: 204 });

      const result = await client.callDelete('/api/v1/items/1/');
      expect(result).toEqual({});
    });
  });

  describe('X-Organization-ID header', () => {
    it('sets the org header when organizationId is provided', async () => {
      const orgClient = new TestClient({ ...BASE_CONFIG, organizationId: 'org-abc' });
      const fetchMock = mockFetch(200, {});
      global.fetch = fetchMock;

      await orgClient.callGet('/api/v1/test/');

      const [, init] = fetchMock.mock.calls[0];
      expect((init.headers as Headers).get('X-Organization-ID')).toBe('org-abc');
    });
  });
});

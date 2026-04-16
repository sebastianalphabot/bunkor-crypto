/**
 * @bunkor/crypto — BaseClient
 *
 * Abstract base class providing authenticated HTTP transport for all Bunkor
 * domain clients. Uses the native `fetch` API — zero framework dependencies.
 *
 * Design pattern: Template Method
 *   - Subclasses call `this.get<T>()`, `this.post<T>()`, etc.
 *   - Auth injection, error normalisation and debug logging live here.
 *
 * Licensed under the Apache License, Version 2.0
 */

import { BunkorConfig, DEFAULT_BUNKOR_CONFIG } from '../config';

// ─── Types ─────────────────────────────────────────────────────────────────

/** A resolved, fully-configured Bunkor config (no optional fields). */
export type ResolvedConfig = Required<Pick<BunkorConfig, 'apiUrl' | 'timeout'>> &
  Pick<BunkorConfig, 'apiToken' | 'organizationId' | 'debug'>;

/** Error thrown when the Bunkor server returns a non-2xx status. */
export class BunkorApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly endpoint: string,
    message: string,
  ) {
    super(message);
    this.name = 'BunkorApiError';
  }
}

// ─── BaseClient ─────────────────────────────────────────────────────────────

export abstract class BaseClient {
  protected readonly config: ResolvedConfig;

  constructor(config: BunkorConfig) {
    this.config = {
      apiUrl:         config.apiUrl         ?? DEFAULT_BUNKOR_CONFIG.apiUrl!,
      apiToken:       config.apiToken,
      organizationId: config.organizationId,
      debug:          config.debug          ?? DEFAULT_BUNKOR_CONFIG.debug ?? false,
      timeout:        config.timeout        ?? DEFAULT_BUNKOR_CONFIG.timeout!,
    };
  }

  // ─── HTTP helpers ──────────────────────────────────────────────────────────

  protected async get<T>(endpoint: string, params?: Record<string, string | number | boolean>): Promise<T> {
    const url = params ? `${endpoint}?${new URLSearchParams(this.stringifyParams(params))}` : endpoint;
    return this.request<T>(url, { method: 'GET' });
  }

  protected async post<T>(endpoint: string, body?: unknown): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  }

  protected async postForm<T>(endpoint: string, form: FormData): Promise<T> {
    // Do NOT set Content-Type — the browser/fetch sets it with the boundary.
    return this.request<T>(endpoint, { method: 'POST', body: form });
  }

  protected async put<T>(endpoint: string, body?: unknown): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  }

  protected async patch<T>(endpoint: string, body?: unknown): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  }

  protected async delete<T>(endpoint: string): Promise<T> {
    return this.request<T>(endpoint, { method: 'DELETE' });
  }

  // ─── Core request ─────────────────────────────────────────────────────────

  /**
   * Execute an authenticated fetch against the Bunkor API.
   *
   * @param endpoint  Path relative to `config.apiUrl` (must start with `/`).
   * @param init      Standard `RequestInit` — the method, body, and extra headers.
   */
  protected async request<T>(endpoint: string, init: RequestInit = {}): Promise<T> {
    const url = `${this.config.apiUrl}${endpoint}`;
    const headers = new Headers(init.headers as HeadersInit | undefined);

    if (this.config.apiToken) {
      headers.set('Authorization', `Bearer ${this.config.apiToken}`);
    }
    if (this.config.organizationId) {
      headers.set('X-Organization-ID', this.config.organizationId);
    }

    if (this.config.debug) {
      console.debug(`[BunkorClient] ${init.method ?? 'GET'} ${endpoint}`);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.timeout);

    let response: Response;
    try {
      response = await fetch(url, { ...init, headers, signal: controller.signal });
    } catch (err) {
      clearTimeout(timer);
      const msg = err instanceof Error ? err.message : String(err);
      throw new BunkorApiError(0, endpoint, `Network error: ${msg}`);
    }
    clearTimeout(timer);

    if (!response.ok) {
      let detail = '';
      try { detail = await response.text(); } catch { /* ignore */ }
      throw new BunkorApiError(
        response.status,
        endpoint,
        `Bunkor API error (${response.status}): ${detail}`,
      );
    }

    // 204 No Content — return empty object
    if (response.status === 204) {
      return {} as T;
    }

    return response.json() as Promise<T>;
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────

  private stringifyParams(params: Record<string, string | number | boolean>): Record<string, string> {
    return Object.fromEntries(
      Object.entries(params)
        .filter(([, v]) => v !== undefined && v !== null)
        .map(([k, v]) => [k, String(v)]),
    );
  }
}

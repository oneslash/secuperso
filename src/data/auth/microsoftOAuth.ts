import { Linking } from 'react-native';
import type { ProviderConnectionUpdate } from '@domain/models';
import type { SecureStore } from '@domain/protocols';
import { createDataError } from '../errors';

export interface MicrosoftOAuthConfiguration {
  clientID: string;
  tenantID: string;
  redirectURI: string;
  scopes: string[];
}

export interface MicrosoftOAuthToken {
  accessToken: string;
  refreshToken?: string;
  expiresIn: number;
  scope: string;
  tokenType: string;
}

interface StoredMicrosoftOAuthToken {
  token: MicrosoftOAuthToken;
  obtainedAt: number;
}

export class MicrosoftOAuthTokenStore {
  private secureStore: SecureStore;
  private key = 'com.secuperso.app.ms-oauth-token';

  constructor(secureStore: SecureStore) {
    this.secureStore = secureStore;
  }

  async read(): Promise<StoredMicrosoftOAuthToken | null> {
    const raw = await this.secureStore.read(this.key);
    if (!raw) return null;
    return JSON.parse(raw) as StoredMicrosoftOAuthToken;
  }

  async save(token: MicrosoftOAuthToken): Promise<void> {
    const stored: StoredMicrosoftOAuthToken = { token, obtainedAt: Date.now() };
    await this.secureStore.write(this.key, JSON.stringify(stored));
  }

  async clear(): Promise<void> {
    await this.secureStore.delete(this.key);
  }
}

function base64URLEncode(buffer: Uint8Array): string {
  return btoa(String.fromCharCode(...buffer))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function generateRandomString(length: number = 32): string {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return base64URLEncode(array);
}

async function sha256(input: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64URLEncode(new Uint8Array(hash));
}

async function exchangeMicrosoftCode(config: MicrosoftOAuthConfiguration, code: string, codeVerifier: string): Promise<MicrosoftOAuthToken> {
  const body = new URLSearchParams({
    client_id: config.clientID,
    scope: config.scopes.join(' '),
    code,
    redirect_uri: config.redirectURI,
    grant_type: 'authorization_code',
    code_verifier: codeVerifier,
  });

  const tokenURL = `https://login.microsoftonline.com/${config.tenantID}/oauth2/v2.0/token`;
  const response = await fetch(tokenURL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw createDataError('remoteRequestRejected', response.status, (errorBody as any).error_description ?? 'Token exchange failed');
  }

  const json = await response.json();
  return {
    accessToken: json.access_token,
    refreshToken: json.refresh_token,
    expiresIn: json.expires_in,
    scope: json.scope,
    tokenType: json.token_type,
  };
}

async function refreshMicrosoftToken(config: MicrosoftOAuthConfiguration, refreshToken: string): Promise<MicrosoftOAuthToken> {
  const body = new URLSearchParams({
    client_id: config.clientID,
    scope: config.scopes.join(' '),
    refresh_token: refreshToken,
    grant_type: 'refresh_token',
  });

  const tokenURL = `https://login.microsoftonline.com/${config.tenantID}/oauth2/v2.0/token`;
  const response = await fetch(tokenURL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!response.ok) {
    throw createDataError('remoteRequestRejected', response.status, 'Token refresh failed');
  }

  const json = await response.json();
  return {
    accessToken: json.access_token,
    refreshToken: json.refresh_token ?? refreshToken,
    expiresIn: json.expires_in,
    scope: json.scope,
    tokenType: json.token_type,
  };
}

export class MicrosoftOutlookOAuthService {
  private config: MicrosoftOAuthConfiguration;
  private tokenStore: MicrosoftOAuthTokenStore;

  constructor(config: MicrosoftOAuthConfiguration, tokenStore: MicrosoftOAuthTokenStore) {
    this.config = config;
    this.tokenStore = tokenStore;
  }

  async beginConnection(
    onUpdate: (update: ProviderConnectionUpdate) => void
  ): Promise<void> {
    const codeVerifier = generateRandomString(32);
    const codeChallenge = await sha256(codeVerifier);
    const state = generateRandomString(16);

    const params = new URLSearchParams({
      client_id: this.config.clientID,
      redirect_uri: this.config.redirectURI,
      response_type: 'code',
      scope: this.config.scopes.join(' '),
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
    });

    const authURL = `https://login.microsoftonline.com/${this.config.tenantID}/oauth2/v2.0/authorize?${params.toString()}`;

    onUpdate({ state: 'connecting', message: 'Opening Microsoft consent screen...' });

    try {
      const callbackURL = await new Promise<string>((resolve, reject) => {
        const subscription = Linking.addEventListener('url', (event) => {
          subscription.remove();
          resolve(event.url);
        });
        Linking.openURL(authURL).catch(reject);
        setTimeout(() => {
          subscription.remove();
          reject(new Error('OAuth timed out'));
        }, 300000);
      });

      const url = new URL(callbackURL);
      const returnedState = url.searchParams.get('state');
      if (returnedState !== state) {
        throw createDataError('invalidRemoteConfiguration', 'OAuth state mismatch');
      }

      const code = url.searchParams.get('code');
      if (!code) {
        throw createDataError('invalidRemoteConfiguration', 'No authorization code received');
      }

      onUpdate({ state: 'connecting', message: 'Granting permissions...' });

      const token = await exchangeMicrosoftCode(this.config, code, codeVerifier);
      await this.tokenStore.save(token);

      onUpdate({ state: 'connected', message: 'Outlook connected successfully.' });
    } catch (e: any) {
      onUpdate({ state: 'error', message: e.message ?? 'Outlook connection failed.' });
    }
  }

  async disconnect(): Promise<void> {
    await this.tokenStore.clear();
  }

  async loadAccessToken(): Promise<string | null> {
    const stored = await this.tokenStore.read();
    if (!stored) return null;

    const elapsed = (Date.now() - stored.obtainedAt) / 1000;
    if (elapsed < stored.token.expiresIn - 60) {
      return stored.token.accessToken;
    }

    if (!stored.token.refreshToken) return null;

    const refreshed = await refreshMicrosoftToken(this.config, stored.token.refreshToken);
    await this.tokenStore.save(refreshed);
    return refreshed.accessToken;
  }
}
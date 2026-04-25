import { Linking } from 'react-native';
import type { ProviderConnectionUpdate, ProviderID } from '@domain/models';
import type { ProviderConnectionService as IProviderConnectionService, SecureStore } from '@domain/protocols';
import { createDataError } from '../errors';

export interface GoogleOAuthConfiguration {
  clientID: string;
  clientSecret?: string;
  redirectURI: string;
  scopes: string[];
  accessType?: string;
}

export interface GoogleOAuthToken {
  accessToken: string;
  refreshToken?: string;
  expiresIn: number;
  scope: string;
  tokenType: string;
  idToken?: string;
}

interface StoredGoogleOAuthToken {
  token: GoogleOAuthToken;
  obtainedAt: number;
}

export class GoogleOAuthTokenStore {
  private secureStore: SecureStore;
  private key = 'com.secuperso.app.google-oauth-token';

  constructor(secureStore: SecureStore) {
    this.secureStore = secureStore;
  }

  async read(): Promise<StoredGoogleOAuthToken | null> {
    const raw = await this.secureStore.read(this.key);
    if (!raw) return null;
    return JSON.parse(raw) as StoredGoogleOAuthToken;
  }

  async save(token: GoogleOAuthToken): Promise<void> {
    const stored: StoredGoogleOAuthToken = { token, obtainedAt: Date.now() };
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

async function sha256(input: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64URLEncode(new Uint8Array(hash));
}

function generateRandomString(length: number = 32): string {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return base64URLEncode(array);
}

async function exchangeCode(config: GoogleOAuthConfiguration, code: string, codeVerifier: string): Promise<GoogleOAuthToken> {
  const body = new URLSearchParams({
    code,
    client_id: config.clientID,
    client_secret: config.clientSecret ?? '',
    redirect_uri: config.redirectURI,
    grant_type: 'authorization_code',
    code_verifier: codeVerifier,
  });

  const response = await fetch('https://oauth2.googleapis.com/token', {
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
    idToken: json.id_token,
  };
}

async function refreshGoogleToken(config: GoogleOAuthConfiguration, refreshToken: string): Promise<GoogleOAuthToken> {
  const body = new URLSearchParams({
    refresh_token: refreshToken,
    client_id: config.clientID,
    client_secret: config.clientSecret ?? '',
    grant_type: 'refresh_token',
  });

  const response = await fetch('https://oauth2.googleapis.com/token', {
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

export class GoogleOAuthService {
  private config: GoogleOAuthConfiguration;
  private tokenStore: GoogleOAuthTokenStore;

  constructor(config: GoogleOAuthConfiguration, tokenStore: GoogleOAuthTokenStore) {
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
      access_type: this.config.accessType ?? 'offline',
      prompt: 'consent',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
    });

    const authURL = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;

    onUpdate({ state: 'connecting', message: 'Opening consent screen...' });

    try {
      const callbackURL = await Linking.openURL(authURL).then(() => {
        return new Promise<string>((resolve, reject) => {
          const subscription = Linking.addEventListener('url', (event) => {
            subscription.remove();
            resolve(event.url);
          });
          setTimeout(() => {
            subscription.remove();
            reject(new Error('OAuth timed out'));
          }, 300000);
        });
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

      const token = await exchangeCode(this.config, code, codeVerifier);
      await this.tokenStore.save(token);

      onUpdate({ state: 'connected', message: 'Google connected successfully.' });
    } catch (e: any) {
      onUpdate({ state: 'error', message: e.message ?? 'Google connection failed.' });
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

    const refreshed = await refreshGoogleToken(this.config, stored.token.refreshToken);
    await this.tokenStore.save(refreshed);
    return refreshed.accessToken;
  }
}
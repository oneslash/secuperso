import type { SecureStore } from '@domain/protocols';
import { createDataError } from './errors';
import type { SecuPersoDataError } from './errors';

const KEY_IDENTIFIER = 'com.secuperso.app.db-key';
const KEY_LENGTH = 32;

function randomHex(length: number): string {
  const values = new Uint8Array(length)
  const cryptoApi = globalThis.crypto

  if (cryptoApi?.getRandomValues) {
    cryptoApi.getRandomValues(values)
  } else {
    for (let index = 0; index < values.length; index += 1) {
      values[index] = Math.floor(Math.random() * 256)
    }
  }

  return Array.from(values, (value) => value.toString(16).padStart(2, '0')).join('')
}

export class EncryptionKeyProvider {
  private secureStore: SecureStore;
  private keyIdentifier: string;
  private keyLength: number;

  constructor(secureStore: SecureStore, keyIdentifier: string = KEY_IDENTIFIER, keyLength: number = KEY_LENGTH) {
    this.secureStore = secureStore;
    this.keyIdentifier = keyIdentifier;
    this.keyLength = keyLength;
  }

  async loadOrCreateKeyData(): Promise<string> {
    const existing = await this.secureStore.read(this.keyIdentifier);
    if (existing) return existing;

    const hex = randomHex(this.keyLength);
    await this.secureStore.write(this.keyIdentifier, hex);
    return hex;
  }

  async loadExistingKeyData(): Promise<string> {
    const existing = await this.secureStore.read(this.keyIdentifier);
    if (!existing) throw createDataError('missingEncryptionKey');
    return existing;
  }
}

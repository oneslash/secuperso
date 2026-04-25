import type { SecureStore } from '@domain/protocols';
import * as Keychain from 'react-native-keychain';

export class KeychainSecureStore implements SecureStore {
  private service: string;

  constructor(service: string = 'com.secuperso.app') {
    this.service = service;
  }

  private serviceForKey(key: string): string {
    return `${this.service}.${key}`
  }

  async read(key: string): Promise<string | null> {
    try {
      const result = await Keychain.getGenericPassword(this.serviceForKey(key));
      if (!result) return null;
      return result.password;
    } catch {
      return null;
    }
  }

  async write(key: string, value: string): Promise<void> {
    await Keychain.setGenericPassword('secuperso', value, this.serviceForKey(key));
  }

  async delete(key: string): Promise<void> {
    await Keychain.resetGenericPassword(this.serviceForKey(key));
  }
}

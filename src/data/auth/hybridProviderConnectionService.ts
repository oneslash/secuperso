import type { ProviderID, ProviderConnectionUpdate, ProviderConnection } from '@domain/models';
import type { ProviderConnectionService, ProviderConnectionReadableService } from '@domain/protocols';
import { GoogleOAuthService } from './googleOAuth';
import { MicrosoftOutlookOAuthService } from './microsoftOAuth';
import { MockProviderConnectionService } from '../mockServices';

export class HybridProviderConnectionService implements ProviderConnectionService, ProviderConnectionReadableService {
  private fallbackService: MockProviderConnectionService;
  private googleService: GoogleOAuthService;
  private outlookService: MicrosoftOutlookOAuthService;
  private readableService: MockProviderConnectionService;

  constructor(
    fallbackService: MockProviderConnectionService,
    googleService: GoogleOAuthService,
    outlookService: MicrosoftOutlookOAuthService,
  ) {
    this.fallbackService = fallbackService;
    this.googleService = googleService;
    this.outlookService = outlookService;
    this.readableService = fallbackService;
  }

  async beginConnection(provider: ProviderID, onUpdate: (update: ProviderConnectionUpdate) => void): Promise<() => void> {
    if (provider === 'google') {
      await this.googleService.beginConnection(onUpdate);
      return () => {};
    }
    if (provider === 'outlook') {
      await this.outlookService.beginConnection(onUpdate);
      return () => {};
    }
    return this.fallbackService.beginConnection(provider, onUpdate);
  }

  async disconnect(provider: ProviderID): Promise<void> {
    if (provider === 'google') {
      return this.googleService.disconnect();
    }
    if (provider === 'outlook') {
      return this.outlookService.disconnect();
    }
    return this.fallbackService.disconnect(provider);
  }

  async connections(): Promise<ProviderConnection[]> {
    return this.readableService.connections();
  }
}
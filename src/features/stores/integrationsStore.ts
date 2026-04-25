import type { ProviderID, ConnectionState, ProviderDescriptor, ProviderConnectionUpdate } from '@domain/models';
import { create } from 'zustand';
import type { AccountCardSummary } from './securityConsoleStore';

interface IntegrationsState {
  accountCards: AccountCardSummary[];
  searchText: string;
  selectedProviderID: ProviderID | null;
  oauthSheetProvider: ProviderID | null;
  oauthState: ConnectionState | null;
  oauthStatusMessage: string;
}

export const useIntegrationsStore = create<IntegrationsState & {
  setAccountCards: (cards: AccountCardSummary[]) => void;
  setSearchText: (text: string) => void;
  setSelectedProviderID: (id: ProviderID | null) => void;
  beginConnectFlow: (provider: ProviderID) => void;
  dismissOAuthSheet: () => void;
}>((set, get) => ({
  accountCards: [],
  searchText: '',
  selectedProviderID: null,
  oauthSheetProvider: null,
  oauthState: null,
  oauthStatusMessage: '',

  setAccountCards: (cards) => set({ accountCards: cards }),
  setSearchText: (text) => set({ searchText: text }),
  setSelectedProviderID: (id) => set({ selectedProviderID: id }),
  beginConnectFlow: (provider) => set({ oauthSheetProvider: provider, oauthState: 'connecting', oauthStatusMessage: 'Starting connection...' }),
  dismissOAuthSheet: () => set({ oauthSheetProvider: null, oauthState: null, oauthStatusMessage: '' }),
}));
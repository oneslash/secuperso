import type { LoginEvent, IncidentCase, ProviderID, ConnectionState, ProviderConnectionUpdate, ProviderDescriptor, ExposureRecord } from '@domain/models';
import type { ProviderConnectionService, IncidentService, IncidentReadableService, ProviderConnectionReadableService, ProviderCatalogService, LoginEventActionService } from '@domain/protocols';
import { create } from 'zustand';

export interface ActivityFeedFilter { type: 'needsAttention' | 'all'; }

export interface PendingConfirmationAction {
  title: string;
  message: string;
  confirmTitle: string;
  isDestructive: boolean;
  onConfirm: () => void;
}

interface ActivityState {
  activityFeed: any[];
  loginEvents: LoginEvent[];
  incidents: IncidentCase[];
  activityFilter: 'needsAttention' | 'all';
  activitySearchText: string;
  selectedActivityItemID: string | null;
  isRefreshing: boolean;
  pendingConfirmationAction: PendingConfirmationAction | null;
}

export const useActivityStore = create<ActivityState & {
  setActivityFeed: (feed: any[]) => void;
  setLoginEvents: (events: LoginEvent[]) => void;
  setIncidents: (incidents: IncidentCase[]) => void;
  setActivityFilter: (filter: 'needsAttention' | 'all') => void;
  setActivitySearchText: (text: string) => void;
  setSelectedActivityItemID: (id: string | null) => void;
  setRefreshing: (v: boolean) => void;
  requestMarkAsMe: (login: LoginEvent) => void;
  requestCreateIncident: (login: LoginEvent) => void;
  requestResolveIncident: (incident: IncidentCase) => void;
  cancelPendingAction: () => void;
  confirmPendingAction: () => void;
}>((set, get) => ({
  activityFeed: [],
  loginEvents: [],
  incidents: [],
  activityFilter: 'needsAttention',
  activitySearchText: '',
  selectedActivityItemID: null,
  isRefreshing: false,
  pendingConfirmationAction: null,

  setActivityFeed: (feed) => set({ activityFeed: feed }),
  setLoginEvents: (events) => set({ loginEvents: events }),
  setIncidents: (incidents) => set({ incidents }),
  setActivityFilter: (filter) => set({ activityFilter: filter }),
  setActivitySearchText: (text) => set({ activitySearchText: text }),
  setSelectedActivityItemID: (id) => set({ selectedActivityItemID: id }),
  setRefreshing: (v) => set({ isRefreshing: v }),
  requestMarkAsMe: (login) => set({
    pendingConfirmationAction: {
      title: 'Mark sign-in as expected',
      message: `Confirm that the sign-in from ${login.location} (${login.device}) was you.`,
      confirmTitle: 'Mark as me',
      isDestructive: false,
      onConfirm: () => { /* handled in store */ },
    },
  }),
  requestCreateIncident: (login) => set({
    pendingConfirmationAction: {
      title: 'Create incident',
      message: `Create a security incident for the suspicious ${login.provider} sign-in from ${login.location}.`,
      confirmTitle: 'Create incident',
      isDestructive: false,
      onConfirm: () => {},
    },
  }),
  requestResolveIncident: (incident) => set({
    pendingConfirmationAction: {
      title: 'Resolve incident',
      message: `Are you sure you want to resolve "${incident.title}"?`,
      confirmTitle: 'Resolve',
      isDestructive: true,
      onConfirm: () => {},
    },
  }),
  cancelPendingAction: () => set({ pendingConfirmationAction: null }),
  confirmPendingAction: () => {
    const action = get().pendingConfirmationAction;
    if (action) action.onConfirm();
    set({ pendingConfirmationAction: null });
  },
}));
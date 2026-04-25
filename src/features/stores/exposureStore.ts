import type { MonitoredEmailAddress, ExposureSourceConfiguration, ProviderID } from '@domain/models';
import { create } from 'zustand';
import type { OperationFeedback } from './securityConsoleStore';

interface ExposureState {
  monitoredEmails: MonitoredEmailAddress[];
  exposureSourceConfiguration: ExposureSourceConfiguration;
  isUpdatingMonitoredEmails: boolean;
  monitoredEmailsFeedback: OperationFeedback | null;
  monitoredEmailComposerFocusToken: number;
}

export const useExposureStore = create<ExposureState & {
  setMonitoredEmails: (emails: MonitoredEmailAddress[]) => void;
  setExposureSourceConfiguration: (config: ExposureSourceConfiguration) => void;
  setUpdatingMonitoredEmails: (v: boolean) => void;
  setMonitoredEmailsFeedback: (feedback: OperationFeedback | null) => void;
  requestMonitoredEmailComposerFocus: () => void;
  addMonitoredEmail: (email: string, providerHint: ProviderID) => void;
  removeMonitoredEmail: (id: string) => void;
  setMonitoredEmailEnabled: (id: string, isEnabled: boolean) => void;
  clearMonitoredEmailsFeedback: () => void;
}>((set, get) => ({
  monitoredEmails: [],
  exposureSourceConfiguration: { apiKey: '', userAgent: 'SecuPersoApp/1.0' },
  isUpdatingMonitoredEmails: false,
  monitoredEmailsFeedback: null,
  monitoredEmailComposerFocusToken: 0,

  setMonitoredEmails: (emails) => set({ monitoredEmails: emails }),
  setExposureSourceConfiguration: (config) => set({ exposureSourceConfiguration: config }),
  setUpdatingMonitoredEmails: (v) => set({ isUpdatingMonitoredEmails: v }),
  setMonitoredEmailsFeedback: (feedback) => set({ monitoredEmailsFeedback: feedback }),
  requestMonitoredEmailComposerFocus: () => set((state) => ({ monitoredEmailComposerFocusToken: state.monitoredEmailComposerFocusToken + 1 })),
  addMonitoredEmail: (email, providerHint) => {
    set({ monitoredEmailsFeedback: { tone: 'info', message: 'Adding monitored email...' } });
  },
  removeMonitoredEmail: (id) => {
    set({ monitoredEmailsFeedback: { tone: 'info', message: 'Removing monitored email...' } });
  },
  setMonitoredEmailEnabled: (id, isEnabled) => {
    set((state) => ({
      monitoredEmails: state.monitoredEmails.map((e) => e.id === id ? { ...e, isEnabled } : e),
    }));
  },
  clearMonitoredEmailsFeedback: () => set({ monitoredEmailsFeedback: null }),
}));
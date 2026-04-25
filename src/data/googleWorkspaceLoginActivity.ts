import type { LoginEvent, ProviderID } from '@domain/models';
import type { LoginActivityService } from '@domain/protocols';
import { GoogleOAuthService } from './auth/googleOAuth';
import { StreamStore } from './streamStore';
import { createDataError } from './errors';

const ADMIN_REPORTS_SCOPE = 'https://www.googleapis.com/auth/admin.reports.audit.readonly';

interface GoogleWorkspaceActivity {
  id: { time: string; uniqueQualifier: string; applicationName: string; };
  actor: { email: string; };
  events: Array<{
    name: string;
    type: string;
    parameters?: Array<{ name: string; value?: string; boolValue?: boolean; }>;
  }>;
}

interface LoginHistoryConfig {
  lookbackDays: number;
  maxResultsPerPage: number;
  maxPages: number;
}

function normalizeConfig(raw: Partial<LoginHistoryConfig> = {}): LoginHistoryConfig {
  return {
    lookbackDays: Math.max(1, raw.lookbackDays ?? 30),
    maxResultsPerPage: Math.min(1000, Math.max(1, raw.maxResultsPerPage ?? 200)),
    maxPages: Math.min(10, Math.max(1, raw.maxPages ?? 5)),
  };
}

function generateStableID(provider: ProviderID, activityID: string, timestamp: string): string {
  const raw = `login-${provider}-${activityID}-${timestamp}`;
  let hash = 0;
  for (let i = 0; i < raw.length; i++) {
    hash = ((hash << 5) - hash + raw.charCodeAt(i)) | 0;
  }
  const hex = Math.abs(hash).toString(16).padStart(8, '0');
  return `${hex.slice(0, 8)}-${hex.slice(8 % 8, (8 % 8) + 4)}-${hex.slice(0, 4)}-b000-000000000000`;
}

function isLoginLike(event: { name: string; type: string }): boolean {
  return event.name === 'login' || event.type === 'login';
}

function isSuspicious(event: { parameters?: Array<{ name: string; value?: string; boolValue?: boolean }> }): boolean {
  if (!event.parameters) return false;
  return event.parameters.some(
    (p) => p.name === 'is_suspicious' && p.boolValue === true
  );
}

export class GoogleWorkspaceLoginActivityService implements LoginActivityService {
  private googleService: GoogleOAuthService;
  private fallbackService: LoginActivityService;
  private config: LoginHistoryConfig;
  private loginStream = new StreamStore<LoginEvent[]>([]);

  constructor(
    googleService: GoogleOAuthService,
    fallbackService: LoginActivityService,
    rawConfig?: Partial<LoginHistoryConfig>,
  ) {
    this.googleService = googleService;
    this.fallbackService = fallbackService;
    this.config = normalizeConfig(rawConfig);
  }

  async refresh(): Promise<LoginEvent[]> {
    try {
      const accessToken = await this.googleService.loadAccessToken();
      if (!accessToken) {
        const fallback = await this.fallbackService.refresh();
        this.loginStream.publish(fallback);
        return fallback;
      }

      const remoteEvents = await this.fetchRemoteEvents(accessToken);
      const fallbackEvents = await this.fallbackService.refresh();
      const merged = this.mergeEvents(fallbackEvents, remoteEvents);
      this.loginStream.publish(merged);
      return merged;
    } catch {
      const fallback = await this.fallbackService.refresh();
      this.loginStream.publish(fallback);
      return fallback;
    }
  }

  stream(callback: (values: LoginEvent[]) => void): () => void {
    return this.loginStream.subscribe(callback);
  }

  private async fetchRemoteEvents(accessToken: string): Promise<LoginEvent[]> {
    const now = new Date();
    const startTime = new Date(now.getTime() - this.config.lookbackDays * 24 * 60 * 60 * 1000);
    const allEvents: LoginEvent[] = [];
    let nextPageToken: string | undefined;
    let pageCount = 0;

    do {
      const params = new URLSearchParams({
        startTime: startTime.toISOString(),
        maxResults: this.config.maxResultsPerPage.toString(),
      });
      if (nextPageToken) params.set('pageToken', nextPageToken);

      const response = await fetch(
        `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?${params.toString()}`,
        { headers: { Authorization: `Bearer ${accessToken}` } },
      );

      if (!response.ok) throw createDataError('remoteRequestRejected', response.status, 'Google Workspace API error');

      const data = await response.json();
      const items: GoogleWorkspaceActivity[] = data.items ?? [];
      const token: string | undefined = data.nextPageToken;

      for (const activity of items) {
        for (const event of activity.events ?? []) {
          if (!isLoginLike(event)) continue;

          const suspicious = isSuspicious(event);
          const ipParam = event.parameters?.find((p) => p.name === 'ip_address');
          const locationParam = event.parameters?.find((p) => p.name === 'location');

          allEvents.push({
            id: generateStableID('google', activity.id.uniqueQualifier, activity.id.time),
            provider: 'google',
            providerAccountID: activity.id.uniqueQualifier,
            providerAccountEmail: activity.actor.email,
            occurredAt: activity.id.time,
            device: event.parameters?.find((p) => p.name === 'device_type')?.value ?? 'Unknown',
            ipAddress: ipParam?.value ?? 'Unknown',
            location: locationParam?.value ?? 'Unknown',
            reason: event.parameters?.find((p) => p.name === 'login_type')?.value ?? 'Sign-in detected',
            suspicious,
            expected: !suspicious,
          });
        }
      }

      nextPageToken = token;
      pageCount++;
    } while (nextPageToken && pageCount < this.config.maxPages);

    return allEvents;
  }

  private mergeEvents(fallbackEvents: LoginEvent[], remoteEvents: LoginEvent[]): LoginEvent[] {
    const remoteGoogleIDs = new Set(remoteEvents.filter((e) => e.provider === 'google').map((e) => e.id));
    const filtered = fallbackEvents.filter((e) => e.provider !== 'google' || !remoteGoogleIDs.has(e.id));
    return [...remoteEvents, ...filtered].sort(
      (a, b) => new Date(b.occurredAt).getTime() - new Date(a.occurredAt).getTime(),
    );
  }
}
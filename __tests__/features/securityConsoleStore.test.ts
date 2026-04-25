import { computeAllProjections, defaultNextAction, defaultOverviewSummary } from '@features/stores/securityConsoleStore';
import type { ExposureRecord, LoginEvent, IncidentCase, ProviderDescriptor, RiskSnapshot, RiskLevel, ConnectionState, ProviderID } from '@domain/models';

const fixedNow = new Date('2026-02-22T12:00:00Z');

function makeExposure(overrides: Partial<ExposureRecord> = {}): ExposureRecord {
  return {
    id: 'exposure-1',
    email: 'user@example.com',
    source: 'Test Breach',
    foundAt: fixedNow.toISOString(),
    severity: 'low',
    status: 'open',
    remediation: 'Change your password.',
    ...overrides,
  };
}

function makeLogin(overrides: Partial<LoginEvent> = {}): LoginEvent {
  return {
    id: 'login-1',
    provider: 'google',
    occurredAt: fixedNow.toISOString(),
    device: 'MacBook Pro',
    ipAddress: '203.0.113.10',
    location: 'San Francisco, US',
    reason: 'Known device',
    suspicious: false,
    expected: true,
    ...overrides,
  };
}

function makeIncident(overrides: Partial<IncidentCase> = {}): IncidentCase {
  return {
    id: 'incident-1',
    title: 'Test Incident',
    severity: 'medium',
    createdAt: fixedNow.toISOString(),
    status: 'open',
    linkedLoginEventID: 'login-1',
    notes: 'Test notes',
    resolvedAt: null,
    ...overrides,
  };
}

describe('SecurityConsoleStore projections', () => {
  it('computes default overview summary when empty', () => {
    const state = {
      exposures: [],
      loginEvents: [],
      incidents: [],
      providers: [],
      providerStates: {} as Record<ProviderID, ConnectionState>,
      riskSnapshot: { score: 0, level: 'low' as RiskLevel, lastUpdatedAt: fixedNow.toISOString() },
    };
    const projections = computeAllProjections(state);
    expect(projections.overviewSummary.stateLabel).toBe('Stable');
    expect(projections.overviewSummary.headline).toBe('No critical risks detected');
    expect(projections.exposureSummary.openCount).toBe(0);
    expect(projections.overviewRiskDrivers.length).toBeGreaterThan(0);
    expect(projections.overviewRiskDrivers[0].emphasis).toBe('calm');
  });

  it('computes high priority risk drivers for critical exposures', () => {
    const state = {
      exposures: [makeExposure({ severity: 'critical', status: 'open' })],
      loginEvents: [],
      incidents: [],
      providers: [{ id: 'google' as ProviderID, displayName: 'Google', details: 'Mock' }],
      providerStates: { google: 'connected' as ConnectionState },
      riskSnapshot: { score: 70, level: 'high' as RiskLevel, lastUpdatedAt: fixedNow.toISOString() },
    };
    const projections = computeAllProjections(state);
    expect(projections.overviewSummary.riskLevel).toBe('high');
    expect(projections.overviewRiskDrivers.some((d) => d.emphasis === 'critical')).toBe(true);
  });

  it('computes next action for suspicious login', () => {
    const state = {
      exposures: [],
      loginEvents: [makeLogin({ suspicious: true, expected: false })],
      incidents: [],
      providers: [],
      providerStates: {},
      riskSnapshot: { score: 15, level: 'low' as RiskLevel, lastUpdatedAt: fixedNow.toISOString() },
    };
    const projections = computeAllProjections(state);
    expect(projections.nextAction.kind.type).toBe('reviewSuspiciousLogin');
  });

  it('computes next action for critical exposure before suspicious login', () => {
    const state = {
      exposures: [makeExposure({ severity: 'critical', status: 'open' })],
      loginEvents: [makeLogin({ suspicious: true, expected: false })],
      incidents: [],
      providers: [],
      providerStates: {},
      riskSnapshot: { score: 50, level: 'medium' as RiskLevel, lastUpdatedAt: fixedNow.toISOString() },
    };
    const projections = computeAllProjections(state);
    expect(projections.nextAction.kind.type).toBe('reviewHighRiskExposure');
  });

  it('computes section badge counts', () => {
    const state = {
      exposures: [makeExposure({ severity: 'high', status: 'open' })],
      loginEvents: [makeLogin({ suspicious: true, expected: false })],
      incidents: [makeIncident()],
      providers: [],
      providerStates: {},
      riskSnapshot: { score: 50, level: 'medium' as RiskLevel, lastUpdatedAt: fixedNow.toISOString() },
    };
    const projections = computeAllProjections(state);
    expect(projections.sectionBadgeCounts.activity).toBeGreaterThan(0);
    expect(projections.sectionBadgeCounts.exposure).toBeGreaterThan(0);
  });
});
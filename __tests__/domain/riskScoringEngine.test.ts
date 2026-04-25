import { riskScoringEngine } from '@domain/riskScoringEngine';
import type { ExposureRecord, LoginEvent, IncidentCase } from '@domain/models';

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

describe('RiskScoringEngine', () => {
  it('returns low risk with no signals', () => {
    const result = riskScoringEngine.score([], [], [], fixedNow);
    expect(result.score).toBe(0);
    expect(result.level).toBe('low');
  });

  it('scores low severity exposure', () => {
    const result = riskScoringEngine.score(
      [makeExposure({ severity: 'low', status: 'open' })],
      [],
      [],
      fixedNow,
    );
    expect(result.score).toBe(5);
    expect(result.level).toBe('low');
  });

  it('scores medium severity exposure', () => {
    const result = riskScoringEngine.score(
      [makeExposure({ severity: 'medium', status: 'open' })],
      [],
      [],
      fixedNow,
    );
    expect(result.score).toBe(10);
    expect(result.level).toBe('low');
  });

  it('scores high severity exposure', () => {
    const result = riskScoringEngine.score(
      [makeExposure({ severity: 'high', status: 'open' })],
      [],
      [],
      fixedNow,
    );
    expect(result.score).toBe(20);
    expect(result.level).toBe('low');
  });

  it('scores critical severity exposure', () => {
    const result = riskScoringEngine.score(
      [makeExposure({ severity: 'critical', status: 'open' })],
      [],
      [],
      fixedNow,
    );
    expect(result.score).toBe(30);
    expect(result.level).toBe('medium');
  });

  it('ignores resolved exposures', () => {
    const result = riskScoringEngine.score(
      [makeExposure({ severity: 'critical', status: 'resolved' })],
      [],
      [],
      fixedNow,
    );
    expect(result.score).toBe(0);
    expect(result.level).toBe('low');
  });

  it('scores suspicious logins', () => {
    const result = riskScoringEngine.score(
      [],
      [makeLogin({ suspicious: true, expected: false })],
      [],
      fixedNow,
    );
    expect(result.score).toBe(15);
  });

  it('adds burst penalty for 2+ suspicious logins within 24h', () => {
    const result = riskScoringEngine.score(
      [],
      [
        makeLogin({ suspicious: true, expected: false, occurredAt: fixedNow.toISOString() }),
        makeLogin({ id: 'login-2', suspicious: true, expected: false, occurredAt: new Date(fixedNow.getTime() - 3600000).toISOString() }),
      ],
      [],
      fixedNow,
    );
    expect(result.score).toBe(40); // 15 + 15 + 10 burst
  });

  it('adds penalty for open incidents', () => {
    const result = riskScoringEngine.score(
      [],
      [],
      [makeIncident({ status: 'open' })],
      fixedNow,
    );
    expect(result.score).toBe(10);
  });

  it('does not add penalty for resolved incidents', () => {
    const result = riskScoringEngine.score(
      [],
      [],
      [makeIncident({ status: 'resolved' })],
      fixedNow,
    );
    expect(result.score).toBe(0);
  });

  it('clamps total to 100', () => {
    const manyCritical = Array.from({ length: 5 }, (_, i) =>
      makeExposure({ id: `exp-${i}`, severity: 'critical', status: 'open' }),
    );
    const result = riskScoringEngine.score(manyCritical, [], [], fixedNow);
    expect(result.score).toBe(100);
  });

  it('classifies 70+ as high risk', () => {
    const result = riskScoringEngine.score(
      [makeExposure({ severity: 'critical', status: 'open' }), makeExposure({ id: 'exp-2', severity: 'high', status: 'open' })],
      [],
      [],
      fixedNow,
    );
    expect(result.score).toBeGreaterThanOrEqual(50);
    expect(result.level).toBe('medium');
  });

  it('classifies 30-69 as medium risk', () => {
    const result = riskScoringEngine.score(
      [makeExposure({ severity: 'high', status: 'open' })],
      [],
      [makeIncident({ status: 'open' })],
      fixedNow,
    );
    expect(result.score).toBe(30);
    expect(result.level).toBe('medium');
  });
});
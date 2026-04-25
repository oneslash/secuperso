import type { ExposureRecord, LoginEvent, IncidentCase, RiskSnapshot, RiskLevel, ExposureSeverity } from './models';

const SEVERITY_WEIGHTS: Record<ExposureSeverity, number> = {
  critical: 30,
  high: 20,
  medium: 10,
  low: 5,
};

function severityWeight(severity: ExposureSeverity): number {
  return SEVERITY_WEIGHTS[severity];
}

function classifyRisk(total: number): RiskLevel {
  if (total >= 70) return 'high';
  if (total >= 30) return 'medium';
  return 'low';
}

export interface RiskScoringEngine {
  score(
    exposures: ExposureRecord[],
    logins: LoginEvent[],
    incidents: IncidentCase[],
    now?: Date,
  ): RiskSnapshot;
}

export const riskScoringEngine: RiskScoringEngine = {
  score(exposures, logins, incidents, now = new Date()) {
    const exposureScore = exposures
      .filter((e) => e.status === 'open')
      .reduce((sum, e) => sum + severityWeight(e.severity), 0);

    const suspiciousLogins = logins.filter((l) => l.suspicious || !l.expected);
    const loginScore = suspiciousLogins.length * 15;

    const burstThreshold = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const burstScore = suspiciousLogins.filter((l) => new Date(l.occurredAt) >= burstThreshold).length >= 2 ? 10 : 0;

    const unresolvedIncidents = incidents.filter((i) => i.status === 'open');
    const incidentPenalty = unresolvedIncidents.length * 10;

    const total = Math.min(100, Math.max(0, exposureScore + loginScore + burstScore + incidentPenalty));

    return {
      score: total,
      level: classifyRisk(total),
      lastUpdatedAt: now.toISOString(),
    };
  },
};
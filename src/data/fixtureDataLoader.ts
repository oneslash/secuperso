import type { ExposureRecord, LoginEvent, ProviderDescriptor, FixtureScenario } from '@domain/models';
import { createDataError } from './errors';

interface ScenarioFixture<T> {
  clean: T[];
  moderate: T[];
  critical: T[];
}

function unwrapJSONModule<T>(value: T | { default: T }): T {
  if (
    typeof value === 'object' &&
    value !== null &&
    'default' in value
  ) {
    return value.default
  }

  return value as T
}

function valuesForScenario<T>(fixture: ScenarioFixture<T>, scenario: FixtureScenario): T[] {
  switch (scenario) {
    case 'clean': return fixture.clean;
    case 'moderate': return fixture.moderate;
    case 'critical': return fixture.critical;
  }
}

export class FixtureDataLoader {
  private exposuresData: ScenarioFixture<ExposureRecord> | null = null;
  private loginEventsData: ScenarioFixture<LoginEvent> | null = null;
  private providersData: ProviderDescriptor[] | null = null;

  constructor(
    private exposuresJSON: string,
    private loginEventsJSON: string,
    private providersJSON: string,
  ) {}

  loadExposures(scenario: FixtureScenario): ExposureRecord[] {
    if (!this.exposuresData) {
      try {
        this.exposuresData = unwrapJSONModule(
          JSON.parse(this.exposuresJSON) as ScenarioFixture<ExposureRecord> | { default: ScenarioFixture<ExposureRecord> }
        )
      } catch {
        throw createDataError('fixtureDecodeFailure', 'exposures.json');
      }
    }
    return valuesForScenario(this.exposuresData!, scenario);
  }

  loadLoginEvents(scenario: FixtureScenario): LoginEvent[] {
    if (!this.loginEventsData) {
      try {
        this.loginEventsData = unwrapJSONModule(
          JSON.parse(this.loginEventsJSON) as ScenarioFixture<LoginEvent> | { default: ScenarioFixture<LoginEvent> }
        )
      } catch {
        throw createDataError('fixtureDecodeFailure', 'login_events.json');
      }
    }
    return valuesForScenario(this.loginEventsData!, scenario);
  }

  loadProviders(): ProviderDescriptor[] {
    if (!this.providersData) {
      try {
        this.providersData = unwrapJSONModule(
          JSON.parse(this.providersJSON) as ProviderDescriptor[] | { default: ProviderDescriptor[] }
        )
      } catch {
        throw createDataError('fixtureDecodeFailure', 'providers.json');
      }
    }
    return this.providersData!;
  }
}

import { FixtureDataLoader } from '@data/fixtureDataLoader';
import * as exposuresJSON from '../../Fixtures/exposures.json';
import * as loginEventsJSON from '../../Fixtures/login_events.json';
import * as providersJSON from '../../Fixtures/providers.json';

describe('FixtureDataLoader', () => {
  let loader: FixtureDataLoader;

  beforeEach(() => {
    loader = new FixtureDataLoader(
      JSON.stringify(exposuresJSON),
      JSON.stringify(loginEventsJSON),
      JSON.stringify(providersJSON),
    );
  });

  it('loads exposures for each scenario', () => {
    const clean = loader.loadExposures('clean');
    expect(clean.length).toBeGreaterThanOrEqual(1);
    expect(clean[0].severity).toBe('low');

    const moderate = loader.loadExposures('moderate');
    expect(moderate.length).toBeGreaterThanOrEqual(2);

    const critical = loader.loadExposures('critical');
    expect(critical.length).toBeGreaterThanOrEqual(2);
  });

  it('loads login events for each scenario', () => {
    const clean = loader.loadLoginEvents('clean');
    expect(clean.length).toBeGreaterThanOrEqual(1);

    const moderate = loader.loadLoginEvents('moderate');
    expect(moderate.length).toBeGreaterThanOrEqual(2);

    const critical = loader.loadLoginEvents('critical');
    expect(critical.length).toBeGreaterThanOrEqual(2);
  });

  it('loads provider catalog', () => {
    const providers = loader.loadProviders();
    expect(providers.length).toBe(3);
    expect(providers.map((p) => p.id)).toEqual(['google', 'outlook', 'other']);
  });
});
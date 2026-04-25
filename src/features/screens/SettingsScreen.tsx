import React, { useState } from 'react';
import { View, Text, TextInput, ScrollView, Pressable, StyleSheet, useWindowDimensions } from 'react-native';
import { Spacing, Colors, Typography, Dimensions } from '@ui/theme/designTokens';
import { SectionContainer } from '@ui/components/SectionContainer';
import type { FixtureScenario, ExposureSourceConfiguration } from '@domain/models';
import { FIXTURE_SCENARIOS, scenarioTitle } from '@domain/models';

const SCHEME = 'light';

interface SettingsScreenProps {
  configuration: ExposureSourceConfiguration;
  scenario: FixtureScenario;
  onSaveConfiguration: (config: ExposureSourceConfiguration) => void;
  onSetScenario: (scenario: FixtureScenario) => void;
}

export const SettingsScreen: React.FC<SettingsScreenProps> = ({
  configuration,
  scenario,
  onSaveConfiguration,
  onSetScenario,
}) => {
  const { width } = useWindowDimensions();
  const isStacked = width < 1120;
  const [apiKey, setApiKey] = useState(configuration.apiKey);
  const [userAgent, setUserAgent] = useState(configuration.userAgent);

  return (
    <ScrollView style={styles.container}>
      <View style={styles.content}>
        <View style={styles.hero}>
          <Text style={[Typography.overline, { color: Colors.textTertiary[SCHEME] }]}>On this device</Text>
          <Text style={[Typography.headlineLarge, { color: Colors.textPrimary[SCHEME] }]}>Privacy settings and demo controls</Text>
          <Text style={[Typography.body, { color: Colors.textSecondary[SCHEME] }]}>
            Adjust the data source details you want this app to use, and switch between demo scenarios while the desktop experience is still in mock mode.
          </Text>
        </View>

        <View style={[styles.grid, isStacked && styles.gridStacked]}>
          <SectionContainer
            title="Exposure configuration"
            subtitle="Provide the details used to check Have I Been Pwned in non-mock mode."
            style="elevated"
          >
          <Text style={[Typography.body, { color: Colors.textPrimary[SCHEME] }]}>API Key</Text>
          <TextInput
            style={styles.input}
            value={apiKey}
            onChangeText={setApiKey}
            placeholder="Enter your HIBP API key"
            placeholderTextColor={Colors.textTertiary[SCHEME]}
            autoCapitalize="none"
            secureTextEntry
          />
          <Text style={[Typography.body, { color: Colors.textPrimary[SCHEME] }]}>User Agent</Text>
          <TextInput
            style={styles.input}
            value={userAgent}
            onChangeText={setUserAgent}
            placeholder="SecuPersoApp/1.0"
            placeholderTextColor={Colors.textTertiary[SCHEME]}
          />
          <Pressable
            style={({ hovered, pressed }: any) => [
              styles.saveButton,
              hovered && styles.saveButtonHovered,
              pressed && styles.saveButtonPressed,
            ]}
            onPress={() => onSaveConfiguration({ apiKey, userAgent })}
          >
            <Text style={[Typography.captionStrong, { color: Colors.white }]}>Save configuration</Text>
          </Pressable>
        </SectionContainer>

          <SectionContainer
            title="Demo scenario"
            subtitle="Switch the desktop demo between clean, moderate, and critical account states."
            style="elevated"
          >
            <View style={styles.scenarioColumn}>
              {FIXTURE_SCENARIOS.map((s) => (
                <Pressable
                  key={s}
                  style={({ hovered, pressed }: any) => [
                    styles.scenarioButton,
                    scenario === s && styles.scenarioButtonActive,
                    hovered && styles.scenarioButtonHovered,
                    pressed && styles.scenarioButtonPressed,
                  ]}
                  onPress={() => onSetScenario(s)}
                >
                  <View style={styles.scenarioCopy}>
                    <Text style={[
                      Typography.bodyStrong,
                      { color: scenario === s ? Colors.brandTealDeep : Colors.textPrimary[SCHEME] },
                    ]}>
                      {scenarioTitle(s)}
                    </Text>
                    <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]}>
                      {s === 'clean'
                        ? 'Minimal risk, mostly calm signals.'
                        : s === 'moderate'
                          ? 'A realistic mix of reminders and open items.'
                          : 'A more urgent state with multiple issues to review.'}
                    </Text>
                  </View>
                </Pressable>
              ))}
            </View>
          </SectionContainer>
        </View>

        <SectionContainer
          title="Data security"
          subtitle="What this build is trying to guarantee."
          style="inset"
        >
          <Text style={[Typography.body, { color: Colors.textSecondary[SCHEME] }]}>
            All data is encrypted with AES-GCM before storage. Encryption keys are stored in the device keychain. No data leaves the device unencrypted.
          </Text>
        </SectionContainer>
      </View>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: Colors.canvas[SCHEME] },
  content: { padding: Spacing.xl, gap: Spacing.l },
  hero: {
    gap: Spacing.s,
    padding: Spacing.xl,
    borderRadius: Dimensions.panelCornerRadius,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  grid: {
    flexDirection: 'row',
    gap: Spacing.l,
  },
  gridStacked: {
    flexDirection: 'column',
  },
  input: {
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    borderRadius: 16,
    paddingHorizontal: Spacing.m,
    paddingVertical: Spacing.s,
    backgroundColor: Colors.surfaceSecondary[SCHEME],
    color: Colors.textPrimary[SCHEME],
    fontFamily: 'Mona Sans',
    fontSize: 15,
  },
  saveButton: {
    alignSelf: 'flex-start',
    backgroundColor: Colors.brandTealDeep,
    paddingHorizontal: Spacing.l,
    paddingVertical: Spacing.s,
    borderRadius: 999,
    marginTop: Spacing.s,
  },
  saveButtonHovered: {
    backgroundColor: Colors.brandTeal,
  },
  saveButtonPressed: {
    opacity: 0.9,
  },
  scenarioColumn: {
    gap: Spacing.s,
  },
  scenarioButton: {
    padding: Spacing.m,
    borderRadius: Dimensions.cardCornerRadius,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfaceSecondary[SCHEME],
  },
  scenarioButtonActive: {
    borderColor: '#B9DDD6',
    backgroundColor: Colors.surfaceAccent[SCHEME],
  },
  scenarioButtonHovered: {
    opacity: 0.95,
  },
  scenarioButtonPressed: {
    opacity: 0.88,
  },
  scenarioCopy: {
    gap: 4,
  },
});

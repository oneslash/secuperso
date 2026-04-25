import React, { useEffect, useState } from 'react';
import { View, Text, TextInput, FlatList, Pressable, Switch, StyleSheet, useWindowDimensions } from 'react-native';
import { Spacing, Colors, Typography, Dimensions } from '@ui/theme/designTokens';
import { StatusPill } from '@ui/components/StatusPill';
import type { ExposureFindingsProjectionRow } from '../stores/securityConsoleStore';
import type { MonitoredEmailAddress, ProviderID } from '@domain/models';

const SCHEME = 'light';

interface ExposureScreenProps {
  exposureFindingRows: ExposureFindingsProjectionRow[];
  exposureFilter: 'atRisk' | 'allOpen';
  exposureSearchText: string;
  selectedExposureFindingID: string | null;
  exposureSummary: { openCount: number; highRiskOpenCount: number; affectedEmailCount: number; headline: string; detail: string };
  monitoredEmails: MonitoredEmailAddress[];
  isUpdatingMonitoredEmails: boolean;
  monitoredEmailsFeedback: { tone: string; message: string } | null;
  onSetExposureFilter: (filter: 'atRisk' | 'allOpen') => void;
  onSetExposureSearchText: (text: string) => void;
  onSelectExposureFinding: (id: string | null) => void;
  onAddMonitoredEmail: (email: string, providerHint: ProviderID) => void;
  onRemoveMonitoredEmail: (id: string) => void;
  onSetMonitoredEmailEnabled: (id: string, isEnabled: boolean) => void;
  isRefreshing: boolean;
}

export const ExposureScreen: React.FC<ExposureScreenProps> = ({
  exposureFindingRows,
  exposureFilter,
  exposureSearchText,
  selectedExposureFindingID,
  exposureSummary,
  monitoredEmails,
  isUpdatingMonitoredEmails,
  monitoredEmailsFeedback,
  onSetExposureFilter,
  onSetExposureSearchText,
  onSelectExposureFinding,
  onAddMonitoredEmail,
  onRemoveMonitoredEmail,
  onSetMonitoredEmailEnabled,
  isRefreshing,
}) => {
  const { width } = useWindowDimensions();
  const isStacked = width < 1180;
  const [emailInput, setEmailInput] = useState('');
  const selectedItem = selectedExposureFindingID
    ? exposureFindingRows.find((r) => r.id === selectedExposureFindingID)
    : null;

  useEffect(() => {
    if (!selectedExposureFindingID && exposureFindingRows.length > 0) {
      onSelectExposureFinding(exposureFindingRows[0].id);
    }
  }, [exposureFindingRows, onSelectExposureFinding, selectedExposureFindingID]);

  return (
    <View style={styles.container}>
      <View style={[styles.hero, isStacked && styles.heroStacked]}>
        <View style={styles.heroCopy}>
          <Text style={[Typography.overline, { color: Colors.textTertiary[SCHEME] }]}>Exposure watch</Text>
          <Text style={[Typography.headlineLarge, { color: Colors.textPrimary[SCHEME] }]}>{exposureSummary.headline}</Text>
          <Text style={[Typography.body, { color: Colors.textSecondary[SCHEME] }]}>
            {exposureSummary.detail || 'Keep an eye on leaked credentials and watched email addresses in one place.'}
          </Text>
        </View>
        <View style={styles.summaryBadgeArea}>
          <StatusPill
            text={exposureSummary.highRiskOpenCount > 0 ? 'At risk' : exposureSummary.openCount > 0 ? 'Needs attention' : 'Stable'}
            tone={exposureSummary.highRiskOpenCount > 0 ? 'critical' : exposureSummary.openCount > 0 ? 'caution' : 'positive'}
          />
          <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]}>
            {isRefreshing ? 'Refreshing monitored findings…' : 'Updated whenever you run a new security check.'}
          </Text>
        </View>
      </View>

      <View style={[styles.metricsRow, isStacked && styles.metricsRowStacked]}>
        <View style={styles.metricItem}>
          <Text style={[Typography.micro, { color: Colors.textTertiary[SCHEME] }]}>Open alerts</Text>
          <Text style={[Typography.headlineMedium, { color: Colors.textPrimary[SCHEME] }]}>{exposureSummary.openCount}</Text>
          <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]}>Findings that still need a look</Text>
        </View>
        <View style={styles.metricItem}>
          <Text style={[Typography.micro, { color: Colors.textTertiary[SCHEME] }]}>High priority</Text>
          <Text style={[Typography.headlineMedium, { color: Colors.textPrimary[SCHEME] }]}>{exposureSummary.highRiskOpenCount}</Text>
          <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]}>The alerts worth reviewing first</Text>
        </View>
        <View style={styles.metricItem}>
          <Text style={[Typography.micro, { color: Colors.textTertiary[SCHEME] }]}>Affected emails</Text>
          <Text style={[Typography.headlineMedium, { color: Colors.textPrimary[SCHEME] }]}>{exposureSummary.affectedEmailCount}</Text>
          <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]}>Addresses showing up in open alerts</Text>
        </View>
      </View>

      <View style={[styles.workspace, isStacked && styles.workspaceStacked]}>
        <View style={styles.findingsPane}>
          <View style={styles.sectionHeader}>
            <View style={styles.sectionHeadingCopy}>
              <Text style={[Typography.overline, { color: Colors.textTertiary[SCHEME] }]}>Open findings</Text>
              <Text style={[Typography.headlineMedium, { color: Colors.textPrimary[SCHEME] }]}>Leaks and breach findings</Text>
            </View>
          </View>
          <View style={styles.filterRow}>
            <View style={styles.segmentedControl}>
              <Pressable
                style={({ hovered, pressed }: any) => [
                  styles.segment,
                  exposureFilter === 'atRisk' && styles.segmentActive,
                  hovered && styles.segmentHovered,
                  pressed && styles.segmentPressed,
                ]}
                onPress={() => onSetExposureFilter('atRisk')}
              >
                <Text style={[
                  Typography.captionStrong,
                  { color: exposureFilter === 'atRisk' ? Colors.brandTealDeep : Colors.textSecondary[SCHEME] },
                ]}>
                  At risk
                </Text>
              </Pressable>
              <Pressable
                style={({ hovered, pressed }: any) => [
                  styles.segment,
                  exposureFilter === 'allOpen' && styles.segmentActive,
                  hovered && styles.segmentHovered,
                  pressed && styles.segmentPressed,
                ]}
                onPress={() => onSetExposureFilter('allOpen')}
              >
                <Text style={[
                  Typography.captionStrong,
                  { color: exposureFilter === 'allOpen' ? Colors.brandTealDeep : Colors.textSecondary[SCHEME] },
                ]}>
                  All open
                </Text>
              </Pressable>
            </View>
            <TextInput
              style={styles.searchInput}
              placeholder="Search by email, source, or remediation"
              placeholderTextColor={Colors.textTertiary[SCHEME]}
              value={exposureSearchText}
              onChangeText={onSetExposureSearchText}
            />
          </View>
          <FlatList
            data={exposureFindingRows}
            keyExtractor={(item) => item.id}
            renderItem={({ item }) => (
              <Pressable
                style={({ hovered, pressed }: any) => [
                  styles.findingItem,
                  selectedExposureFindingID === item.id && styles.findingItemSelected,
                  hovered && styles.findingItemHovered,
                  pressed && styles.findingItemPressed,
                ]}
                onPress={() => onSelectExposureFinding(item.id)}
              >
                <View style={styles.findingHeader}>
                  <View style={styles.findingCopy}>
                    <Text style={[Typography.bodyStrong, { color: Colors.textPrimary[SCHEME] }]}>{item.email}</Text>
                    <Text style={[Typography.body, { color: Colors.textSecondary[SCHEME] }]} numberOfLines={2}>
                      {item.source}
                    </Text>
                  </View>
                  <StatusPill
                    text={item.severity.charAt(0).toUpperCase() + item.severity.slice(1)}
                    tone={item.severity === 'critical' || item.severity === 'high' ? 'critical' : item.severity === 'medium' ? 'caution' : 'neutral'}
                  />
                </View>
                <Text style={[Typography.caption, { color: Colors.textTertiary[SCHEME] }]} numberOfLines={2}>
                  {item.remediation}
                </Text>
              </Pressable>
            )}
            ListEmptyComponent={(
              <View style={styles.emptyState}>
                <Text style={[Typography.bodyStrong, { color: Colors.textPrimary[SCHEME] }]}>No open findings match this view.</Text>
                <Text style={[Typography.body, { color: Colors.textSecondary[SCHEME] }]}>
                  Adjust the filter or search to widen the results.
                </Text>
              </View>
            )}
          />
        </View>

        <View style={styles.inspectorPane}>
          <View style={styles.sectionHeader}>
            <View style={styles.sectionHeadingCopy}>
              <Text style={[Typography.overline, { color: Colors.textTertiary[SCHEME] }]}>Selected finding</Text>
              <Text style={[Typography.headlineMedium, { color: Colors.textPrimary[SCHEME] }]}>Context and remediation</Text>
            </View>
          </View>
          {selectedItem ? (
            <View style={styles.inspectorContent}>
              <StatusPill
                text={selectedItem.severity.charAt(0).toUpperCase() + selectedItem.severity.slice(1)}
                tone={selectedItem.severity === 'critical' || selectedItem.severity === 'high' ? 'critical' : selectedItem.severity === 'medium' ? 'caution' : 'neutral'}
              />
              <Text style={[Typography.headlineLarge, { color: Colors.textPrimary[SCHEME] }]}>{selectedItem.email}</Text>
              <Text style={[Typography.bodyStrong, { color: Colors.textPrimary[SCHEME] }]}>{selectedItem.source}</Text>
              <Text style={[Typography.body, { color: Colors.textSecondary[SCHEME] }]}>{selectedItem.remediation}</Text>
              <Text style={[Typography.caption, { color: Colors.textTertiary[SCHEME] }]}>
                Found {new Date(selectedItem.foundAt).toLocaleString()}
              </Text>
            </View>
          ) : (
            <View style={styles.emptyState}>
              <Text style={[Typography.bodyStrong, { color: Colors.textPrimary[SCHEME] }]}>Select a finding to review it.</Text>
              <Text style={[Typography.body, { color: Colors.textSecondary[SCHEME] }]}>
                This panel will explain what was exposed and what is worth doing next.
              </Text>
            </View>
          )}
        </View>
      </View>

      <View style={styles.monitoredSection}>
        <View style={styles.sectionHeader}>
          <View style={styles.sectionHeadingCopy}>
            <Text style={[Typography.overline, { color: Colors.textTertiary[SCHEME] }]}>Watched emails</Text>
            <Text style={[Typography.headlineMedium, { color: Colors.textPrimary[SCHEME] }]}>Addresses you want to monitor</Text>
          </View>
        </View>
        <View style={styles.addRow}>
          <View style={styles.metricItem}>
            <TextInput
              style={styles.emailInput}
              placeholder="Add an email address"
              placeholderTextColor={Colors.textTertiary[SCHEME]}
              value={emailInput}
              onChangeText={setEmailInput}
              autoCapitalize="none"
              keyboardType="email-address"
            />
          </View>
          <Pressable
            style={({ hovered, pressed }: any) => [
              styles.addButton,
              hovered && styles.addButtonHovered,
              pressed && styles.addButtonPressed,
              (isUpdatingMonitoredEmails || !emailInput.trim()) && styles.addButtonDisabled,
            ]}
            onPress={() => {
              onAddMonitoredEmail(emailInput, 'other');
              setEmailInput('');
            }}
            disabled={isUpdatingMonitoredEmails || !emailInput.trim()}
          >
            <Text style={[Typography.captionStrong, { color: Colors.white }]}>Add email</Text>
          </Pressable>
        </View>
        {monitoredEmailsFeedback && (
          <Text
            style={[
              Typography.caption,
              { color: monitoredEmailsFeedback.tone === 'error' ? Colors.riskRed : Colors.textSecondary[SCHEME] },
            ]}
          >
            {monitoredEmailsFeedback.message}
          </Text>
        )}
        {monitoredEmails.length === 0 ? (
          <View style={styles.emptyState}>
            <Text style={[Typography.bodyStrong, { color: Colors.textPrimary[SCHEME] }]}>No watched emails yet.</Text>
            <Text style={[Typography.body, { color: Colors.textSecondary[SCHEME] }]}>
              Add an address you care about so exposure alerts feel more personal and useful.
            </Text>
          </View>
        ) : (
          monitoredEmails.map((email) => (
            <View key={email.id} style={styles.emailRow}>
              <View style={styles.emailInfo}>
                <Text style={[Typography.bodyStrong, { color: Colors.textPrimary[SCHEME] }]}>{email.email}</Text>
                <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]}>
                  {email.lastCheckedAt ? `Checked ${new Date(email.lastCheckedAt).toLocaleString()}` : 'Not checked yet'}
                </Text>
              </View>
              <Switch value={email.isEnabled} onValueChange={(v) => onSetMonitoredEmailEnabled(email.id, v)} disabled={isUpdatingMonitoredEmails} />
              <Pressable onPress={() => onRemoveMonitoredEmail(email.id)}>
                <Text style={[Typography.captionStrong, { color: Colors.riskRed }]}>Remove</Text>
              </Pressable>
            </View>
          ))
        )}
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: Spacing.xl,
    gap: Spacing.l,
    backgroundColor: Colors.canvas[SCHEME],
  },
  hero: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    gap: Spacing.xl,
    padding: Spacing.xl,
    borderRadius: Dimensions.panelCornerRadius,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  heroStacked: {
    flexDirection: 'column',
  },
  heroCopy: {
    flex: 1,
    maxWidth: 700,
    gap: Spacing.s,
  },
  summaryBadgeArea: {
    alignItems: 'flex-end',
    gap: Spacing.s,
  },
  metricsRow: {
    flexDirection: 'row',
    gap: Spacing.l,
  },
  metricsRowStacked: {
    flexDirection: 'column',
  },
  metricItem: {
    flex: 1,
    gap: 6,
    padding: Spacing.m,
    borderRadius: Dimensions.cardCornerRadius,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  workspace: {
    flex: 1,
    flexDirection: 'row',
    gap: Spacing.l,
  },
  workspaceStacked: {
    flexDirection: 'column',
  },
  findingsPane: {
    flex: 1,
    minWidth: 360,
    padding: Spacing.l,
    gap: Spacing.m,
    borderRadius: Dimensions.panelCornerRadius,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  sectionHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-end',
    gap: Spacing.s,
  },
  sectionHeadingCopy: {
    flex: 1,
    gap: 4,
  },
  filterRow: {
    flexDirection: 'row',
    gap: Spacing.s,
  },
  segmentedControl: {
    flexDirection: 'row',
    padding: 4,
    backgroundColor: Colors.surfaceSecondary[SCHEME],
    borderRadius: 999,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
  },
  segment: {
    paddingHorizontal: Spacing.m,
    paddingVertical: Spacing.xs,
    borderRadius: 999,
  },
  segmentActive: {
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  segmentHovered: {
    opacity: 0.92,
  },
  segmentPressed: {
    opacity: 0.84,
  },
  searchInput: {
    flex: 1,
    minHeight: 44,
    paddingHorizontal: Spacing.m,
    paddingVertical: Spacing.xs,
    borderRadius: 16,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
    color: Colors.textPrimary[SCHEME],
    fontFamily: 'Mona Sans',
    fontSize: 15,
  },
  findingItem: {
    gap: Spacing.s,
    paddingVertical: Spacing.m,
    borderTopWidth: 1,
    borderTopColor: Colors.borderSubtle[SCHEME],
  },
  findingItemSelected: {
    backgroundColor: Colors.surfaceAccent[SCHEME],
    marginHorizontal: -Spacing.s,
    paddingHorizontal: Spacing.s,
    borderRadius: 16,
    borderTopColor: Colors.surfaceAccent[SCHEME],
  },
  findingItemHovered: {
    opacity: 0.94,
  },
  findingItemPressed: {
    opacity: 0.88,
  },
  findingHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    gap: Spacing.s,
  },
  findingCopy: {
    flex: 1,
    gap: 4,
  },
  inspectorPane: {
    flex: 1.05,
    padding: Spacing.l,
    gap: Spacing.m,
    borderRadius: Dimensions.panelCornerRadius,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  inspectorContent: {
    gap: Spacing.s,
  },
  monitoredSection: {
    gap: Spacing.m,
    padding: Spacing.l,
    borderRadius: Dimensions.panelCornerRadius,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  addRow: {
    flexDirection: 'row',
    gap: Spacing.s,
  },
  emailInput: {
    flex: 1,
    minHeight: 44,
    paddingHorizontal: Spacing.m,
    paddingVertical: Spacing.xs,
    borderRadius: 16,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfaceSecondary[SCHEME],
    color: Colors.textPrimary[SCHEME],
    fontFamily: 'Mona Sans',
    fontSize: 15,
  },
  addButton: {
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: Spacing.l,
    borderRadius: 999,
    backgroundColor: Colors.brandTealDeep,
  },
  addButtonHovered: {
    backgroundColor: Colors.brandTeal,
  },
  addButtonPressed: {
    opacity: 0.88,
  },
  addButtonDisabled: {
    opacity: 0.52,
  },
  emailRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.s,
    paddingVertical: Spacing.m,
    borderTopWidth: 1,
    borderTopColor: Colors.borderSubtle[SCHEME],
  },
  emailInfo: {
    flex: 1,
    gap: 4,
  },
  emptyState: {
    gap: Spacing.s,
    paddingVertical: Spacing.s,
  },
});

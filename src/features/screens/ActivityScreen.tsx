import React, { useEffect } from 'react';
import { View, Text, TextInput, Pressable, FlatList, StyleSheet, useWindowDimensions } from 'react-native';
import { Spacing, Colors, Typography, Dimensions } from '@ui/theme/designTokens';
import { StatusPill, type StatusPillTone } from '@ui/components/StatusPill';
import type { LoginEvent, IncidentCase } from '@domain/models';
import type { ActivityFeedItem } from '../stores/securityConsoleStore';

const SCHEME = 'light';

interface ActivityScreenProps {
  activityFeed: ActivityFeedItem[];
  loginEvents: LoginEvent[];
  incidents: IncidentCase[];
  activityFilter: 'needsAttention' | 'all';
  activitySearchText: string;
  selectedActivityItemID: string | null;
  isRefreshing: boolean;
  onSetActivityFilter: (filter: 'needsAttention' | 'all') => void;
  onSetActivitySearchText: (text: string) => void;
  onSelectActivityItem: (id: string | null) => void;
  onRequestMarkAsMe: (login: LoginEvent) => void;
  onRequestCreateIncident: (login: LoginEvent) => void;
  onRequestResolveIncident: (incident: IncidentCase) => void;
}

export const ActivityScreen: React.FC<ActivityScreenProps> = ({
  activityFeed,
  loginEvents,
  incidents,
  activityFilter,
  activitySearchText,
  selectedActivityItemID,
  isRefreshing,
  onSetActivityFilter,
  onSetActivitySearchText,
  onSelectActivityItem,
  onRequestMarkAsMe,
  onRequestCreateIncident,
  onRequestResolveIncident,
}) => {
  const { width } = useWindowDimensions();
  const isStacked = width < 1120;
  const searchQuery = activitySearchText.trim().toLowerCase();
  const filteredFeed = activityFeed.filter((item) => {
    const matchesFilter = activityFilter === 'needsAttention' ? item.needsAttention : true;
    const matchesSearch = searchQuery.length === 0
      || item.title.toLowerCase().includes(searchQuery)
      || item.detail.toLowerCase().includes(searchQuery);

    return matchesFilter && matchesSearch;
  });

  const selectedItem = selectedActivityItemID
    ? filteredFeed.find((i) => i.id === selectedActivityItemID) ?? activityFeed.find((i) => i.id === selectedActivityItemID)
    : null;

  useEffect(() => {
    if (!selectedActivityItemID && filteredFeed.length > 0) {
      onSelectActivityItem(filteredFeed[0].id);
    }
  }, [filteredFeed, onSelectActivityItem, selectedActivityItemID]);

  const handleAction = (action: ActivityFeedItem['actions'][number]) => {
    const { kind } = action;

    switch (kind.type) {
      case 'markLoginAsExpected': {
        const login = loginEvents.find((item) => item.id === kind.loginID);
        if (login) onRequestMarkAsMe(login);
        return;
      }
      case 'createIncident': {
        const login = loginEvents.find((item) => item.id === kind.loginID);
        if (login) onRequestCreateIncident(login);
        return;
      }
      case 'resolveIncident': {
        const incident = incidents.find((item) => item.id === kind.incidentID);
        if (incident) onRequestResolveIncident(incident);
      }
    }
  };

  return (
    <View style={styles.container}>
      <View style={[styles.filterRow, isStacked && styles.filterRowStacked]}>
        <View style={styles.segmentedControl}>
          <FilterSegment
            label="Needs attention"
            isActive={activityFilter === 'needsAttention'}
            onPress={() => onSetActivityFilter('needsAttention')}
          />
          <FilterSegment
            label="All activity"
            isActive={activityFilter === 'all'}
            onPress={() => onSetActivityFilter('all')}
          />
        </View>

        <TextInput
          style={styles.searchInput}
          placeholder="Search sign-ins, locations, or summaries"
          placeholderTextColor={Colors.textTertiary[SCHEME]}
          value={activitySearchText}
          onChangeText={onSetActivitySearchText}
        />

        <Text style={[Typography.captionStrong, styles.itemCount]}>
          {isRefreshing ? 'Refreshing' : `${filteredFeed.length} item${filteredFeed.length === 1 ? '' : 's'}`}
        </Text>
      </View>

      <View style={[styles.workspace, isStacked && styles.workspaceStacked]}>
        <View style={[styles.panel, styles.listPanel, isStacked && styles.stackedPanel]}>
          <View style={styles.panelHeader}>
            <View>
              <Text style={[Typography.bodyStrong, styles.panelTitle]}>Recent Alerts</Text>
              <Text style={[Typography.caption, styles.panelSubtitle]}>Sign-ins and exposure changes</Text>
            </View>
            {filteredFeed.some((item) => item.needsAttention) && (
              <StatusPill text="Needs review" tone="critical" style={styles.compactPill} />
            )}
          </View>

          <FlatList
            data={filteredFeed}
            keyExtractor={(item) => item.id}
            showsVerticalScrollIndicator={false}
            contentContainerStyle={filteredFeed.length === 0 ? styles.emptyListContent : undefined}
            renderItem={({ item }) => (
              <ActivityRow
                item={item}
                isSelected={selectedActivityItemID === item.id}
                onPress={() => onSelectActivityItem(item.id)}
              />
            )}
            ListEmptyComponent={(
              <View style={styles.emptyState}>
                <Text style={[Typography.bodyStrong, { color: Colors.textPrimary[SCHEME] }]}>Nothing matches this view.</Text>
                <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]}>
                  Clear the search or switch to all activity.
                </Text>
              </View>
            )}
          />
        </View>

        <View style={[styles.panel, styles.inspectorPanel, isStacked && styles.stackedPanel]}>
          {selectedItem ? (
            <View style={styles.inspectorContent}>
              <View style={styles.inspectorHeader}>
                <View style={styles.inspectorSeverity}>
                  <View style={[styles.severityDot, { backgroundColor: severityColor(selectedItem.severity) }]} />
                  <Text style={[Typography.captionStrong, { color: severityColor(selectedItem.severity) }]}>
                    {severityLabel(selectedItem.severity)}
                  </Text>
                </View>
                <Text style={[Typography.caption, { color: Colors.textTertiary[SCHEME] }]}>
                  {formatDate(selectedItem.date)}
                </Text>
              </View>

              <View style={styles.inspectorBlock}>
                <Text style={[Typography.overline, { color: Colors.textTertiary[SCHEME] }]}>Selected Event</Text>
                <Text style={[Typography.headlineMedium, styles.inspectorTitle]}>{selectedItem.title}</Text>
                <Text style={[Typography.body, styles.inspectorDetail]}>{selectedItem.detail}</Text>
              </View>

              <View style={styles.inspectorBlock}>
                <Text style={[Typography.overline, { color: Colors.textTertiary[SCHEME] }]}>Next Best Step</Text>
                <Text style={[Typography.caption, styles.inspectorNote]}>
                  {selectedItem.actions.length > 0
                    ? 'Choose the response that matches what you recognize about this event.'
                    : 'No immediate action is needed for this event.'}
                </Text>
              </View>

              {selectedItem.actions.length > 0 && (
                <View style={styles.actionRow}>
                  {selectedItem.actions.map((action) => (
                    <Pressable
                      key={action.id}
                      style={({ hovered, pressed }: any) => [
                        styles.actionButton,
                        hovered && styles.actionButtonHovered,
                        pressed && styles.actionButtonPressed,
                      ]}
                      onPress={() => handleAction(action)}
                    >
                      <Text style={[Typography.captionStrong, { color: Colors.brandTealDeep }]}>{action.title}</Text>
                    </Pressable>
                  ))}
                </View>
              )}
            </View>
          ) : (
            <View style={styles.emptyInspector}>
              <Text style={[Typography.bodyStrong, { color: Colors.textPrimary[SCHEME] }]}>Select an event</Text>
              <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]}>
                Event details and next steps will appear here.
              </Text>
            </View>
          )}
        </View>
      </View>
    </View>
  );
};

interface FilterSegmentProps {
  label: string;
  isActive: boolean;
  onPress: () => void;
}

const FilterSegment: React.FC<FilterSegmentProps> = ({ label, isActive, onPress }) => (
  <Pressable
    style={({ hovered, pressed }: any) => [
      styles.segment,
      isActive && styles.segmentActive,
      hovered && !isActive && styles.segmentHovered,
      pressed && styles.segmentPressed,
    ]}
    onPress={onPress}
  >
    <Text
      style={[
        Typography.captionStrong,
        { color: isActive ? Colors.brandBlue : Colors.textSecondary[SCHEME] },
      ]}
    >
      {label}
    </Text>
  </Pressable>
);

interface ActivityRowProps {
  item: ActivityFeedItem;
  isSelected: boolean;
  onPress: () => void;
}

const ActivityRow: React.FC<ActivityRowProps> = ({ item, isSelected, onPress }) => (
  <Pressable
    style={({ hovered, pressed }: any) => [
      styles.feedItem,
      isSelected && styles.feedItemSelected,
      hovered && !isSelected && styles.feedItemHovered,
      pressed && styles.feedItemPressed,
    ]}
    onPress={onPress}
  >
    <View style={[styles.severityDot, { backgroundColor: severityColor(item.severity) }]} />
    <View style={styles.feedItemCopy}>
      <View style={styles.feedItemHeader}>
        <Text style={[Typography.bodyStrong, styles.feedTitle]} numberOfLines={1}>{item.title}</Text>
        <Text style={[Typography.captionStrong, styles.feedDate]} numberOfLines={1}>{formatDate(item.date)}</Text>
      </View>
      <Text style={[Typography.caption, styles.feedDetail]} numberOfLines={2}>{item.detail}</Text>
    </View>
    <StatusPill
      text={severityLabel(item.severity)}
      tone={severityTone(item.severity)}
      style={styles.compactPill}
    />
  </Pressable>
);

function severityLabel(severity: ActivityFeedItem['severity']): string {
  switch (severity) {
    case 'warning': return 'Alert';
    case 'caution': return 'Review';
    case 'neutral': return 'Normal';
  }
}

function severityTone(severity: ActivityFeedItem['severity']): StatusPillTone {
  switch (severity) {
    case 'warning': return 'critical';
    case 'caution': return 'caution';
    case 'neutral': return 'neutral';
  }
}

function severityColor(severity: ActivityFeedItem['severity']): string {
  switch (severity) {
    case 'warning': return Colors.riskRed;
    case 'caution': return Colors.riskAmber;
    case 'neutral': return Colors.textTertiary[SCHEME];
  }
}

function formatDate(value: string): string {
  return new Date(value).toLocaleString(undefined, {
    month: 'numeric',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    gap: Spacing.l,
    padding: Spacing.xl,
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  filterRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.s,
  },
  filterRowStacked: {
    alignItems: 'stretch',
    flexWrap: 'wrap',
  },
  segmentedControl: {
    height: 38,
    flexDirection: 'row',
    alignItems: 'center',
    padding: 3,
    borderRadius: Dimensions.cardCornerRadius,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfaceSecondary[SCHEME],
  },
  segment: {
    minWidth: 112,
    height: 30,
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: Spacing.s,
    borderRadius: 6,
  },
  segmentActive: {
    backgroundColor: Colors.surfacePrimary[SCHEME],
    shadowColor: Colors.shadow[SCHEME],
    shadowOpacity: 0.06,
    shadowRadius: 4,
    shadowOffset: { width: 0, height: 1 },
  },
  segmentHovered: {
    backgroundColor: Colors.surfaceTertiary[SCHEME],
  },
  segmentPressed: {
    opacity: 0.82,
  },
  searchInput: {
    flex: 1,
    minWidth: 280,
    height: 38,
    paddingHorizontal: Spacing.m,
    paddingVertical: 0,
    borderRadius: Dimensions.cardCornerRadius,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
    color: Colors.textPrimary[SCHEME],
    fontFamily: 'Mona Sans',
    fontSize: 14,
  },
  itemCount: {
    minWidth: 86,
    color: Colors.textSecondary[SCHEME],
    textAlign: 'right',
  },
  workspace: {
    flex: 1,
    flexDirection: 'row',
    gap: Spacing.l,
    minHeight: 0,
  },
  workspaceStacked: {
    flexDirection: 'column',
  },
  panel: {
    borderRadius: Dimensions.panelCornerRadius,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
    overflow: 'hidden',
  },
  listPanel: {
    flex: 1,
    minWidth: 420,
  },
  inspectorPanel: {
    flex: 0.78,
    minWidth: 380,
    padding: Spacing.l,
  },
  stackedPanel: {
    minWidth: 0,
  },
  panelHeader: {
    minHeight: 64,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: Spacing.m,
    paddingHorizontal: Spacing.l,
    borderBottomWidth: 1,
    borderBottomColor: Colors.borderSubtle[SCHEME],
  },
  panelTitle: {
    color: Colors.textPrimary[SCHEME],
  },
  panelSubtitle: {
    color: Colors.textSecondary[SCHEME],
  },
  feedItem: {
    minHeight: 78,
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: Spacing.s,
    paddingHorizontal: Spacing.l,
    paddingVertical: Spacing.m,
    borderBottomWidth: 1,
    borderBottomColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  feedItemHovered: {
    backgroundColor: Colors.surfaceSecondary[SCHEME],
  },
  feedItemPressed: {
    opacity: 0.88,
  },
  feedItemSelected: {
    backgroundColor: Colors.brandBlueSoft,
  },
  feedItemCopy: {
    flex: 1,
    minWidth: 0,
    gap: 4,
  },
  feedItemHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.s,
  },
  feedTitle: {
    flex: 1,
    color: Colors.textPrimary[SCHEME],
  },
  feedDate: {
    color: Colors.textTertiary[SCHEME],
  },
  feedDetail: {
    color: Colors.textSecondary[SCHEME],
  },
  severityDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    marginTop: 7,
    flexShrink: 0,
  },
  compactPill: {
    paddingHorizontal: Spacing.xs,
    paddingVertical: 3,
  },
  inspectorContent: {
    gap: Spacing.l,
  },
  inspectorHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    gap: Spacing.s,
  },
  inspectorSeverity: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.xs,
  },
  inspectorBlock: {
    gap: Spacing.s,
  },
  inspectorTitle: {
    color: Colors.textPrimary[SCHEME],
  },
  inspectorDetail: {
    color: Colors.textSecondary[SCHEME],
  },
  inspectorNote: {
    maxWidth: 420,
    color: Colors.textPrimary[SCHEME],
  },
  actionRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: Spacing.s,
    paddingTop: Spacing.xs,
  },
  actionButton: {
    minHeight: 34,
    justifyContent: 'center',
    paddingHorizontal: Spacing.m,
    borderRadius: Dimensions.cardCornerRadius,
    borderWidth: 1,
    borderColor: '#B9DDD6',
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  actionButtonHovered: {
    backgroundColor: Colors.brandTealMist,
  },
  actionButtonPressed: {
    opacity: 0.86,
  },
  emptyListContent: {
    flexGrow: 1,
  },
  emptyState: {
    flex: 1,
    justifyContent: 'center',
    gap: Spacing.xs,
    padding: Spacing.l,
  },
  emptyInspector: {
    flex: 1,
    justifyContent: 'center',
    gap: Spacing.xs,
  },
});

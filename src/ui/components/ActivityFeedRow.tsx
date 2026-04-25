import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { Spacing, Typography, Colors, Dimensions } from '../theme/designTokens';
import type { ActivityFeedItem } from '@features/stores/securityConsoleStore';
import { StatusPill } from './StatusPill';

const SCHEME = 'light';

interface ActivityFeedRowProps {
  item: ActivityFeedItem;
}

const SEVERITY_COLORS: Record<string, string> = {
  warning: Colors.riskRed,
  caution: Colors.riskAmber,
  neutral: Colors.textSecondary[SCHEME],
};

export const ActivityFeedRow: React.FC<ActivityFeedRowProps> = ({ item }) => (
  <View style={styles.row}>
    <View style={[styles.indicator, { backgroundColor: SEVERITY_COLORS[item.severity] ?? Colors.textSecondary[SCHEME] }]} />
    <View style={styles.content}>
      <Text style={[Typography.bodyStrong, { color: Colors.textPrimary[SCHEME] }]} numberOfLines={1}>{item.title}</Text>
      <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]} numberOfLines={2}>{item.detail}</Text>
      <Text style={[Typography.micro, { color: Colors.textTertiary[SCHEME] }]}>
        {new Date(item.date).toLocaleString()}
      </Text>
    </View>
    {item.needsAttention && (
      <StatusPill
        text={item.severity === 'warning' ? 'Review now' : 'Take a look'}
        tone={item.severity === 'warning' ? 'critical' : 'caution'}
      />
    )}
  </View>
);

const styles = StyleSheet.create({
  row: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    paddingVertical: Spacing.m,
    gap: Spacing.s,
    borderTopWidth: 1,
    borderTopColor: Colors.borderSubtle[SCHEME],
  },
  indicator: {
    width: 9,
    height: 9,
    borderRadius: 5,
    marginTop: 7,
  },
  content: {
    flex: 1,
    gap: 4,
  },
});

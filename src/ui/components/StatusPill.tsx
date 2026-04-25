import React from 'react';
import { View, Text, StyleSheet, type ViewStyle } from 'react-native';
import { Spacing, Dimensions, Typography, Colors } from '../theme/designTokens';

export type StatusPillTone = 'neutral' | 'positive' | 'caution' | 'critical';

interface StatusPillProps {
  text: string;
  tone: StatusPillTone;
  style?: ViewStyle;
}

const SCHEME = 'light';

const TONE_CONFIG: Record<StatusPillTone, { foreground: string; background: string; border: string; dot: string }> = {
  neutral: {
    foreground: Colors.textSecondary[SCHEME],
    background: Colors.surfaceSecondary[SCHEME],
    border: Colors.borderSubtle[SCHEME],
    dot: Colors.textTertiary[SCHEME],
  },
  positive: {
    foreground: Colors.brandTealDeep,
    background: Colors.brandTealSoft,
    border: '#B9DDD6',
    dot: Colors.brandTeal,
  },
  caution: {
    foreground: '#6B3E00',
    background: Colors.riskAmberSoft,
    border: '#EAC885',
    dot: Colors.riskAmber,
  },
  critical: {
    foreground: Colors.riskRed,
    background: Colors.riskRedSoft,
    border: '#F0B9C1',
    dot: Colors.riskRed,
  },
};

export const StatusPill: React.FC<StatusPillProps> = ({ text, tone, style }) => {
  const config = TONE_CONFIG[tone];

  return (
    <View style={[styles.container, { backgroundColor: config.background, borderColor: config.border }, style]}>
      <View style={[styles.dot, { backgroundColor: config.dot }]} />
      <Text style={[Typography.captionStrong, { color: config.foreground }]}>{text}</Text>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: Spacing.s,
    paddingVertical: Spacing.xxs + 2,
    borderRadius: Dimensions.pillCornerRadius,
    borderWidth: Dimensions.borderWidth,
    overflow: 'hidden',
    gap: 6,
  },
  dot: {
    width: 7,
    height: 7,
    borderRadius: 4,
  },
});

import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { Spacing, Dimensions, Typography, Colors } from '../theme/designTokens';

const SCHEME = 'light';

interface MetricCardViewProps {
  title: string;
  value: string;
  subtitle: string;
}

export const MetricCardView: React.FC<MetricCardViewProps> = ({ title, value, subtitle }) => (
  <View style={styles.container}>
    <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]}>{title}</Text>
    <Text style={[Typography.headlineLarge, { color: Colors.textPrimary[SCHEME] }]}>{value}</Text>
    <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]} numberOfLines={2}>{subtitle}</Text>
  </View>
);

const styles = StyleSheet.create({
  container: {
    gap: 4,
    paddingHorizontal: Spacing.m,
    paddingVertical: Spacing.m,
    minHeight: 108,
    borderRadius: Dimensions.cardCornerRadius,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
});

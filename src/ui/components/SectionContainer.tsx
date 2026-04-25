import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { Spacing, Dimensions, Typography, Colors } from '../theme/designTokens';

export type SectionContainerStyleType = 'elevated' | 'flat' | 'inset';

interface SectionContainerProps {
  title?: string;
  subtitle?: string;
  style?: SectionContainerStyleType;
  children: React.ReactNode;
}

const SCHEME = 'light';

export const SectionContainer: React.FC<SectionContainerProps> = ({
  title,
  subtitle,
  style = 'elevated',
  children,
}) => {
  const bgColor = style === 'flat'
    ? Colors.canvas[SCHEME]
    : style === 'inset'
      ? Colors.surfaceSecondary[SCHEME]
      : Colors.surfacePrimary[SCHEME];
  const borderColor = style === 'flat' ? Colors.canvas[SCHEME] : Colors.borderSubtle[SCHEME];

  return (
    <View
      style={[
        styles.container,
        style === 'flat' && styles.flatContainer,
        style === 'elevated' && styles.elevatedContainer,
        { backgroundColor: bgColor, borderColor },
      ]}
    >
      {title && (
        <View style={styles.header}>
          <Text style={[Typography.overline, { color: Colors.textTertiary[SCHEME] }]}>{title}</Text>
          {subtitle && (
            <Text style={[Typography.body, { color: Colors.textSecondary[SCHEME] }]}>{subtitle}</Text>
          )}
        </View>
      )}
      {!title && subtitle && (
        <Text style={[Typography.body, { color: Colors.textSecondary[SCHEME] }]}>{subtitle}</Text>
      )}
      {children}
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    padding: Spacing.l,
    borderRadius: Dimensions.panelCornerRadius,
    borderWidth: Dimensions.borderWidth,
    gap: Spacing.m,
  },
  flatContainer: {
    paddingHorizontal: 0,
    paddingVertical: 0,
    borderWidth: 0,
    borderRadius: 0,
  },
  elevatedContainer: {
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  header: {
    gap: 4,
  },
});

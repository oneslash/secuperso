import { StyleSheet } from 'react-native';

export const Spacing = {
  xxs: 4,
  xs: 8,
  s: 12,
  m: 16,
  l: 24,
  xl: 32,
  xxl: 48,
  xxxl: 64,
} as const;

export const Colors = {
  brandTeal: '#12A872',
  brandTealDeep: '#0C7A55',
  brandTealSoft: '#DCFCE7',
  brandTealMist: '#F0FDF4',
  brandBlue: '#0A7AFF',
  brandBlueDeep: '#0057D8',
  brandBlueSoft: '#E8F1FF',
  riskAmber: '#F97316',
  riskAmberSoft: '#FFF2E7',
  riskRed: '#FF3B4D',
  riskRedSoft: '#FFE5E9',
  riskViolet: '#A855F7',
  riskVioletSoft: '#F3E8FF',
  canvas: { light: '#F4F4F5', dark: '#111412' },
  canvasSecondary: { light: '#EAEAEB', dark: '#171C1A' },
  surfacePrimary: { light: '#FFFFFF', dark: '#1D2320' },
  surfaceSecondary: { light: '#F7F7F8', dark: '#242B28' },
  surfaceTertiary: { light: '#EFEFF1', dark: '#303834' },
  surfaceAccent: { light: '#EAF3FF', dark: '#153A35' },
  surfaceWarm: { light: '#FFF8EE', dark: '#332719' },
  textPrimary: { light: '#17171A', dark: '#F4F7F5' },
  textSecondary: { light: '#5F636A', dark: '#C6D0CC' },
  textTertiary: { light: '#8A8F98', dark: '#95A09C' },
  borderSubtle: { light: '#E1E3E7', dark: '#303A36' },
  borderStrong: { light: '#C7CBD1', dark: '#4A5752' },
  overlay: { light: '#E1E3E7', dark: '#000000' },
  shadow: { light: '#000000', dark: '#000000' },
  white: '#FFFFFF',
} as const;

export const FontFamily = {
  sans: 'Mona Sans',
  display: 'Mona Sans',
} as const;

export const Typography = {
  overline: {
    fontFamily: FontFamily.sans,
    fontSize: 11,
    fontWeight: '600' as const,
    letterSpacing: 0,
    textTransform: 'uppercase' as const,
  },
  heroDisplay: {
    fontFamily: FontFamily.display,
    fontSize: 34,
    fontWeight: '700' as const,
    lineHeight: 41,
    letterSpacing: 0,
  },
  heroScore: {
    fontFamily: FontFamily.display,
    fontSize: 54,
    fontWeight: '700' as const,
    letterSpacing: 0,
  },
  headlineLarge: {
    fontFamily: FontFamily.display,
    fontSize: 28,
    fontWeight: '700' as const,
    lineHeight: 34,
    letterSpacing: 0,
  },
  headlineMedium: {
    fontFamily: FontFamily.sans,
    fontSize: 20,
    fontWeight: '600' as const,
    letterSpacing: 0,
  },
  title: {
    fontFamily: FontFamily.sans,
    fontSize: 17,
    fontWeight: '600' as const,
    letterSpacing: 0,
  },
  bodyStrong: {
    fontFamily: FontFamily.sans,
    fontSize: 16,
    fontWeight: '600' as const,
    lineHeight: 22,
  },
  body: {
    fontFamily: FontFamily.sans,
    fontSize: 15,
    fontWeight: '400' as const,
    lineHeight: 22,
  },
  caption: {
    fontFamily: FontFamily.sans,
    fontSize: 12,
    fontWeight: '500' as const,
    lineHeight: 17,
  },
  captionStrong: {
    fontFamily: FontFamily.sans,
    fontSize: 12,
    fontWeight: '600' as const,
    lineHeight: 16,
    letterSpacing: 0,
  },
  micro: {
    fontFamily: FontFamily.sans,
    fontSize: 11,
    fontWeight: '600' as const,
    lineHeight: 14,
    letterSpacing: 0,
  },
} as const;

export const Dimensions = {
  cardCornerRadius: 8,
  panelCornerRadius: 8,
  pillCornerRadius: 999,
  borderWidth: 1,
  railWidth: 280,
  contentMaxWidth: 1280,
  cardShadowRadius: 24,
  cardShadowYOffset: 12,
} as const;

export function useThemeColor(color: keyof typeof Colors, scheme: 'light' | 'dark' = 'light'): string {
  const value = Colors[color];
  if (typeof value === 'string') return value;
  return (value as any)[scheme] ?? value;
}

export const AppStyles = StyleSheet.create({
  container: {
    flex: 1,
  },
  card: {
    borderRadius: Dimensions.cardCornerRadius,
    padding: Spacing.l,
    overflow: 'hidden',
  },
  pill: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: Spacing.s,
    paddingVertical: Spacing.xxs + 2,
    borderRadius: Dimensions.pillCornerRadius,
    borderWidth: Dimensions.borderWidth,
  },
  section: {
    padding: Spacing.l,
    borderRadius: Dimensions.cardCornerRadius,
    borderWidth: Dimensions.borderWidth,
  },
});

import React from 'react';
import { View, StyleSheet, type ViewStyle } from 'react-native';

export type LineIconName =
  | 'activity'
  | 'alert-circle'
  | 'alert-triangle'
  | 'arrow-right'
  | 'bell'
  | 'box'
  | 'chevron-down'
  | 'chevron-right'
  | 'clipboard'
  | 'grid'
  | 'info'
  | 'log-in'
  | 'monitor'
  | 'refresh-cw'
  | 'shield'
  | 'users';

interface LineIconProps {
  name: LineIconName;
  size?: number;
  color: string;
  style?: ViewStyle;
}

export const LineIcon: React.FC<LineIconProps> = ({ name, size = 20, color, style }) => {
  const stroke = Math.max(2, Math.round(size * 0.1));
  const line = (extra: ViewStyle): ViewStyle => ({
    position: 'absolute',
    height: stroke,
    borderRadius: stroke,
    backgroundColor: color,
    ...extra,
  });
  const dot = (diameter: number, extra: ViewStyle): ViewStyle => ({
    position: 'absolute',
    width: diameter,
    height: diameter,
    borderRadius: diameter / 2,
    backgroundColor: color,
    ...extra,
  });
  const box = (extra: ViewStyle): ViewStyle => ({
    position: 'absolute',
    borderWidth: stroke,
    borderColor: color,
    ...extra,
  });

  const s = size;
  const render = () => {
    switch (name) {
      case 'grid': {
        const cell = Math.round(s * 0.32);
        const gap = Math.round(s * 0.14);
        const start = Math.round((s - cell * 2 - gap) / 2);
        return (
          <>
            {[0, 1, 2, 3].map((index) => (
              <View
                key={index}
                style={box({
                  left: start + (index % 2) * (cell + gap),
                  top: start + Math.floor(index / 2) * (cell + gap),
                  width: cell,
                  height: cell,
                  borderRadius: Math.max(2, Math.round(s * 0.08)),
                })}
              />
            ))}
          </>
        );
      }
      case 'activity':
        return (
          <>
            <View style={line({ left: s * 0.16, bottom: s * 0.2, width: stroke, height: s * 0.24 })} />
            <View style={line({ left: s * 0.44, bottom: s * 0.2, width: stroke, height: s * 0.48 })} />
            <View style={line({ right: s * 0.16, bottom: s * 0.2, width: stroke, height: s * 0.34 })} />
          </>
        );
      case 'users':
        return (
          <>
            <View style={box({ left: s * 0.2, top: s * 0.14, width: s * 0.28, height: s * 0.28, borderRadius: s * 0.14 })} />
            <View style={box({ right: s * 0.16, top: s * 0.24, width: s * 0.22, height: s * 0.22, borderRadius: s * 0.11 })} />
            <View style={box({ left: s * 0.1, bottom: s * 0.12, width: s * 0.52, height: s * 0.3, borderTopLeftRadius: s * 0.2, borderTopRightRadius: s * 0.2, borderBottomWidth: 0 })} />
            <View style={box({ right: s * 0.04, bottom: s * 0.12, width: s * 0.38, height: s * 0.24, borderTopLeftRadius: s * 0.16, borderTopRightRadius: s * 0.16, borderBottomWidth: 0 })} />
          </>
        );
      case 'alert-circle':
      case 'alert-triangle':
        return (
          <>
            <View style={box({ left: s * 0.12, top: s * 0.12, width: s * 0.76, height: s * 0.76, borderRadius: s * 0.38 })} />
            <View style={line({ left: s * 0.46, top: s * 0.28, width: stroke, height: s * 0.3 })} />
            <View style={dot(Math.max(3, s * 0.16), { left: s * 0.42, bottom: s * 0.24 })} />
          </>
        );
      case 'box':
        return (
          <>
            <View style={box({ left: s * 0.18, top: s * 0.18, width: s * 0.64, height: s * 0.64, borderRadius: s * 0.1 })} />
            <View style={line({ left: s * 0.3, top: s * 0.5, width: s * 0.4 })} />
          </>
        );
      case 'monitor':
        return (
          <>
            <View style={box({ left: s * 0.12, top: s * 0.16, width: s * 0.76, height: s * 0.52, borderRadius: s * 0.08 })} />
            <View style={line({ left: s * 0.45, top: s * 0.7, width: s * 0.1, height: s * 0.14 })} />
            <View style={line({ left: s * 0.3, bottom: s * 0.1, width: s * 0.4 })} />
          </>
        );
      case 'shield':
        return (
          <>
            <View style={box({ left: s * 0.18, top: s * 0.12, width: s * 0.64, height: s * 0.68, borderRadius: s * 0.16 })} />
            <View style={line({ left: s * 0.34, top: s * 0.5, width: s * 0.18, transform: [{ rotateZ: '45deg' }] })} />
            <View style={line({ left: s * 0.46, top: s * 0.47, width: s * 0.3, transform: [{ rotateZ: '-45deg' }] })} />
          </>
        );
      case 'bell':
        return (
          <>
            <View style={box({ left: s * 0.26, top: s * 0.18, width: s * 0.48, height: s * 0.5, borderTopLeftRadius: s * 0.24, borderTopRightRadius: s * 0.24, borderBottomWidth: 0 })} />
            <View style={line({ left: s * 0.18, top: s * 0.68, width: s * 0.64 })} />
            <View style={dot(Math.max(3, s * 0.14), { left: s * 0.43, bottom: s * 0.08 })} />
          </>
        );
      case 'clipboard':
        return (
          <>
            <View style={box({ left: s * 0.22, top: s * 0.16, width: s * 0.56, height: s * 0.7, borderRadius: s * 0.08 })} />
            <View style={box({ left: s * 0.36, top: s * 0.08, width: s * 0.28, height: s * 0.18, borderRadius: s * 0.06, backgroundColor: '#FFFFFF' })} />
          </>
        );
      case 'refresh-cw':
        return (
          <>
            <View style={box({ left: s * 0.16, top: s * 0.16, width: s * 0.68, height: s * 0.68, borderRadius: s * 0.34, borderLeftColor: 'transparent', borderBottomColor: 'transparent' })} />
            <View style={[styles.arrowHead, { right: s * 0.06, top: s * 0.16, borderLeftColor: color, borderTopWidth: s * 0.18, borderBottomWidth: s * 0.18, borderLeftWidth: s * 0.22 }]} />
          </>
        );
      case 'log-in':
        return (
          <>
            <View style={box({ right: s * 0.12, top: s * 0.2, width: s * 0.48, height: s * 0.6, borderRadius: s * 0.08, borderLeftWidth: 0 })} />
            <View style={line({ left: s * 0.16, top: s * 0.49, width: s * 0.45 })} />
            <View style={[styles.arrowHead, { left: s * 0.52, top: s * 0.36, borderLeftColor: color, borderTopWidth: s * 0.14, borderBottomWidth: s * 0.14, borderLeftWidth: s * 0.18 }]} />
          </>
        );
      case 'arrow-right':
        return (
          <>
            <View style={line({ left: s * 0.2, top: s * 0.48, width: s * 0.52 })} />
            <View style={[styles.arrowHead, { right: s * 0.12, top: s * 0.33, borderLeftColor: color, borderTopWidth: s * 0.16, borderBottomWidth: s * 0.16, borderLeftWidth: s * 0.2 }]} />
          </>
        );
      case 'chevron-right':
        return (
          <>
            <View style={line({ left: s * 0.42, top: s * 0.28, width: s * 0.34, transform: [{ rotateZ: '45deg' }] })} />
            <View style={line({ left: s * 0.42, top: s * 0.54, width: s * 0.34, transform: [{ rotateZ: '-45deg' }] })} />
          </>
        );
      case 'chevron-down':
        return (
          <>
            <View style={line({ left: s * 0.28, top: s * 0.44, width: s * 0.28, transform: [{ rotateZ: '45deg' }] })} />
            <View style={line({ right: s * 0.28, top: s * 0.44, width: s * 0.28, transform: [{ rotateZ: '-45deg' }] })} />
          </>
        );
      case 'info':
        return (
          <>
            <View style={box({ left: s * 0.12, top: s * 0.12, width: s * 0.76, height: s * 0.76, borderRadius: s * 0.38 })} />
            <View style={dot(Math.max(3, s * 0.14), { left: s * 0.43, top: s * 0.3 })} />
            <View style={line({ left: s * 0.46, top: s * 0.46, width: stroke, height: s * 0.26 })} />
          </>
        );
    }
  };

  return (
    <View style={[styles.root, { width: size, height: size }, style]}>
      {render()}
    </View>
  );
};

const styles = StyleSheet.create({
  root: {
    position: 'relative',
    flexShrink: 0,
  },
  arrowHead: {
    position: 'absolute',
    width: 0,
    height: 0,
    borderTopColor: 'transparent',
    borderBottomColor: 'transparent',
  },
});

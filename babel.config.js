module.exports = {
  presets: ['module:@react-native/babel-preset'],
  plugins: [
    [
      'module-resolver',
      {
        root: ['./src'],
        extensions: [
          '.macos.js',
          '.macos.ts',
          '.macos.tsx',
          '.ios.js',
          '.android.js',
          '.js',
          '.ts',
          '.tsx',
          '.json',
        ],
        alias: {
          '@domain': './src/domain',
          '@data': './src/data',
          '@ui': './src/ui',
          '@features': './src/features',
          '@app': './src/app',
        },
      },
    ],
  ],
}

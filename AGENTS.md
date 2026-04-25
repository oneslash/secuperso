# Repository Guidelines

## Build, Test, and Development Commands
- `npm start`: start Metro bundler.
- `npx react-native run-ios`: build and run on iOS simulator.
- `npx react-native run-android`: build and run on Android emulator.
- `npm test`: run Jest test suite.
- `npm run lint`: run ESLint across the project.
- `npm run typecheck`: run TypeScript type checking (`tsc --noEmit`).

## Coding Style & Naming Conventions
- Language/toolchain: TypeScript, React Native, strict mode enabled.
- Formatting: 2-space indentation, single quotes for strings, no semicolons.
- Naming: PascalCase for components/types/interfaces, camelCase for functions/variables, UPPER_SNAKE_CASE for constants.
- State management: Zustand stores in `src/features/stores/`.
- Keep module boundaries: `domain/` has no UI or data concerns; `data/` depends on `domain`; `features/` depends on `domain` and `ui`; `app/` wires everything together.
- Provider identifiers: `google`, `outlook`, `other` — keep aligned when adding provider logic.

## Testing Guidelines
- Framework: Jest (`__tests__/`).
- Conventions: files end with `.test.ts` or `.test.tsx`, test suites use `describe`/`it`.
- Favor deterministic fixtures and fixed timestamps to avoid flaky tests.
- Add or update tests whenever changing:
  - risk scoring/projections (`riskScoringEngine`, `securityConsoleStore`)
  - encryption/storage behavior (`encryptedDatabase`, key management)
  - remote integration flows (HIBP refresh/mapping, OAuth exchange/state handling)
  - fixture parsing/scenario behavior.

## Commit & Pull Request Guidelines
- Use Conventional Commits (for example, `feat(features): add provider risk weighting`).
- Keep commits focused and atomic; avoid mixing refactors with behavior changes.
- PRs should include: concise summary, linked issue/task, test evidence, and UI screenshots for component changes.

## Security & Configuration Tips
- Do not commit real credentials or production PII; keep `Fixtures/` synthetic.
- Preserve Keychain-backed encryption patterns in `src/data/` (`com.secuperso.app.db-key`, HIBP API key, OAuth token storage).
- Keep Microsoft OAuth protections intact (PKCE challenge, state validation, callback scheme validation).
- Treat `IS_MOCK_MODE` as default-safe configuration unless intentionally implementing a non-mock mode.
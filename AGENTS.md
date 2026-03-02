# Repository Guidelines

## Build, Test, and Development Commands
- `xcodegen generate`: regenerate Xcode project from `project.yml`.
- `xcodebuild -project SecuPerso.xcodeproj -scheme SecuPerso-Debug -destination 'platform=macOS' build`: compile app and tests.
- `xcodebuild -project SecuPerso.xcodeproj -scheme SecuPerso-Debug -destination 'platform=macOS' test`: run `SecuPersoTests`.
- `xcodebuild -project SecuPerso.xcodeproj -scheme SecuPerso-Release -destination 'platform=macOS' build`: release-scheme compile check.
- `for pkg in SecuPersoDomain SecuPersoData SecuPersoFeatures SecuPersoUI; do swift build --package-path Packages/$pkg; done`: package-level compile checks.
- If `xcodebuild` fails on CLI tools only setups, point developer tools to full Xcode: `xcode-select -s /Applications/Xcode.app/Contents/Developer`.

## Coding Style & Naming Conventions
- Language/toolchain: Swift 6, strict concurrency enabled.
- Formatting: 4-space indentation, clear line breaks for long initializers, minimal inline comments.
- Naming: UpperCamelCase for types/protocols (`MockProviderConnectionService`), lowerCamelCase for members (`databaseURL()`).
- Concurrency: prefer `actor`/`@MainActor` ownership boundaries and `Sendable`-safe APIs across module boundaries.
- Keep module boundaries explicit: `Domain` has no UI concerns; `UI` stays presentation-only; `Features` should depend on `Domain` abstractions rather than data-layer concrete types.
- Keep provider identifiers and fixture values aligned (`google`, `outlook`, `other`) when adding provider-related logic.

## Testing Guidelines
- Framework: XCTest (`Tests/SecuPersoTests`).
- Conventions: files end with `Tests.swift`, test classes end with `Tests`, test methods start with `test`.
- Favor deterministic fixtures and fixed timestamps (for example, a shared `fixedNow`) to avoid flaky tests.
- Add or update tests whenever changing:
  - risk scoring/projections (`RiskScoringEngine`, `SecurityConsoleViewModel`)
  - encryption/storage behavior (`EncryptedSQLiteDatabase`, key management, monitored email state)
  - remote integration flows (HIBP refresh/mapping, Microsoft OAuth exchange/state handling)
  - fixture parsing/scenario behavior.

## Commit & Pull Request Guidelines
- Use Conventional Commits (for example, `feat(domain): add provider risk weighting`).
- Keep commits focused and atomic; avoid mixing refactors with behavior changes.
- PRs should include: concise summary, linked issue/task, test evidence (`xcodebuild ... test`), and UI screenshots/gifs for SwiftUI changes.

## Security & Configuration Tips
- Do not commit real credentials or production PII; keep `Fixtures/` synthetic.
- Preserve Keychain-backed encryption patterns in `SecuPersoData` (`com.secuperso.app.db-key`, HIBP API key, OAuth token storage).
- Keep Microsoft OAuth protections intact (PKCE challenge, state validation, callback scheme validation).
- Treat `DATA_MODE`/`DATA_MODE_MOCK` as default-safe configuration unless intentionally implementing a non-mock mode.

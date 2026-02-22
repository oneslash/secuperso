# Repository Guidelines

## Project Structure & Module Organization
- `App/SecuPersoApp`: macOS SwiftUI entry point, app wiring (`AppContainer`), and notifications.
- `Packages/`: Swift Package modules.
  - `SecuPersoDomain`: core models, protocols, and risk scoring logic.
  - `SecuPersoData`: fixture loading, encrypted SQLite, Keychain key management, and mock services.
  - `SecuPersoFeatures`: feature-level presentation/view model orchestration.
  - `SecuPersoUI`: shared SwiftUI components and design tokens.
- `Fixtures/*.json`: bundled mock data used by default app runs.
- `Tests/SecuPersoTests`: XCTest suite.
- `project.yml`: XcodeGen source of truth. Regenerate `SecuPerso.xcodeproj` after edits.

## Build, Test, and Development Commands
- `xcodegen generate`: regenerate Xcode project from `project.yml`.
- `xcodebuild -project SecuPerso.xcodeproj -scheme SecuPerso-Debug -destination 'platform=macOS' build`: compile app and tests.
- `xcodebuild -project SecuPerso.xcodeproj -scheme SecuPerso-Debug -destination 'platform=macOS' test`: run `SecuPersoTests`.
- `swift build --package-path Packages/SecuPersoDomain`: quick compile check for one module (repeat for others).
- If `xcodebuild` fails on CLI tools only setups, point developer tools to full Xcode: `xcode-select -s /Applications/Xcode.app/Contents/Developer`.

## Coding Style & Naming Conventions
- Language/toolchain: Swift 6, strict concurrency enabled.
- Formatting: 4-space indentation, clear line breaks for long initializers, minimal inline comments.
- Naming: UpperCamelCase for types/protocols (`MockProviderConnectionService`), lowerCamelCase for members (`databaseURL()`).
- Keep module boundaries explicit: `Domain` has no UI concerns; `UI` stays presentation-only.

## Testing Guidelines
- Framework: XCTest (`Tests/SecuPersoTests`).
- Conventions: files end with `Tests.swift`, test classes end with `Tests`, test methods start with `test`.
- Favor deterministic fixtures and fixed timestamps (for example, a shared `fixedNow`) to avoid flaky tests.
- Add or update tests whenever changing risk scoring, encryption/storage behavior, or fixture parsing.

## Commit & Pull Request Guidelines
- Repository currently has no commit history; use Conventional Commits going forward (for example, `feat(domain): add provider risk weighting`).
- Keep commits focused and atomic; avoid mixing refactors with behavior changes.
- PRs should include: concise summary, linked issue/task, test evidence (`xcodebuild ... test`), and UI screenshots for SwiftUI changes.

## Security & Configuration Tips
- Do not commit real credentials or production PII; keep `Fixtures/` synthetic.
- Preserve Keychain-backed encryption patterns in `SecuPersoData`.
- Treat `DATA_MODE`/`DATA_MODE_MOCK` as default-safe configuration unless intentionally implementing a non-mock mode.

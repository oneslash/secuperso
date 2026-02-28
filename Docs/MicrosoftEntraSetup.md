# Microsoft Entra OAuth Setup (Outlook Provider)

SecuPerso uses OAuth 2.0 Authorization Code + PKCE for Microsoft sign-in.

## Required Entra Registration

1. Register a Microsoft Entra application for a native/public client.
2. Configure a redirect URI that matches this app's callback scheme, for example `secuperso://oauth`.
3. Do not create or store a client secret in the app.

## Runtime Configuration Keys

Provide these values via app Info.plist/build settings:

- `MS_ENTRA_CLIENT_ID` (required)
- `MS_ENTRA_TENANT_ID` (optional, defaults to `common`)
- `MS_ENTRA_REDIRECT_URI` (optional, defaults to `secuperso://oauth`)
- `MS_ENTRA_SCOPES` (optional, defaults to `openid profile offline_access User.Read`)

If `MS_ENTRA_CLIENT_ID` is missing, Outlook connect will return a setup-required error in the OAuth sheet.

import AppKit
import AuthenticationServices
import Foundation
import SecuPersoData

@MainActor
final class WebAuthenticationSessionAdapter: NSObject, OAuthAuthorizationSession, ASWebAuthenticationPresentationContextProviding {
    private var activeSession: ASWebAuthenticationSession?

    func authenticate(startURL: URL, callbackScheme: String) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: startURL,
                callbackURLScheme: callbackScheme
            ) { [weak self] callbackURL, error in
                self?.activeSession = nil

                if let callbackURL {
                    continuation.resume(returning: callbackURL)
                    return
                }

                if let authError = error as? ASWebAuthenticationSessionError, authError.code == .canceledLogin {
                    continuation.resume(throwing: OAuthAuthorizationSessionError.cancelled)
                    return
                }

                if let error {
                    continuation.resume(
                        throwing: OAuthAuthorizationSessionError.failed(message: error.localizedDescription)
                    )
                    return
                }

                continuation.resume(
                    throwing: OAuthAuthorizationSessionError.failed(message: "Missing OAuth callback URL.")
                )
            }

            session.presentationContextProvider = self
            session.prefersEphemeralWebBrowserSession = false
            activeSession = session

            if !session.start() {
                activeSession = nil
                continuation.resume(
                    throwing: OAuthAuthorizationSessionError.failed(message: "Unable to start OAuth session.")
                )
            }
        }
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        NSApplication.shared.keyWindow
            ?? NSApplication.shared.windows.first
            ?? NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 1, height: 1),
                styleMask: [],
                backing: .buffered,
                defer: false
            )
    }
}

import Foundation

/// Keeps the process running while a refresh-token exchange is on the wire and until its
/// result is saved.
///
/// Refresh tokens are single-use: the auth server rotates the moment it accepts the consuming
/// POST. If the system suspends the process before the successor is saved, storage keeps the
/// consumed token, the next refresh replays it, and the server revokes the whole token family —
/// a forced sign-out. Observed 2026-10-07 (Skeets 1.32.1, eurosky.social): the app went to the
/// background about four seconds after the consuming POST on a slow network, stayed suspended
/// for six minutes, and its first refresh on return got
/// `invalid_grant: "Refresh token replayed"`.
///
/// `ProcessInfo.performExpiringActivity` asks for background time in apps and app extensions
/// alike; the push and share extensions use this library too, and
/// `UIApplication.beginBackgroundTask` is not available to them. The system can still end the
/// activity early, or refuse it; it then calls the block with `expired` set, which is logged.
///
/// macOS does not suspend an app in the background (and the API is unavailable there), so the
/// activity is a no-op on macOS and on Linux.
enum RotationActivity {
    /// Begins the activity for an exchange on behalf of `did` and returns the call that ends it.
    static func begin(for did: String) -> @Sendable () -> Void {
        #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
            let finished = DispatchSemaphore(value: 0)
            ProcessInfo.processInfo.performExpiringActivity(withReason: "Saving a refreshed sign-in") { expired in
                guard !expired else {
                    LogManager.logError(
                        "ROTATION_TRACE background time refused or ran out during the exchange — the process may be suspended before the new token is saved did=\(LogManager.logDID(did))"
                    )
                    return
                }
                // The activity lasts exactly as long as this block runs.
                finished.wait()
            }
            return { finished.signal() }
        #else
            return {}
        #endif
    }
}

// Debug-only extensions for ATProtoClient
// This file provides test helpers used by PetrelLoad and demo apps.
#if DEBUG
    import Foundation

    public extension ATProtoClient {
        /// Debug helper to simulate an ambiguous refresh timeout scenario.
        /// Sleeps for the provided number of seconds and then triggers app-startup handling
        /// so the AuthenticationService can observe any interrupted refresh state.
        /// This is a no-op in release builds.
        func simulateAmbiguousRefreshTimeout(durationSeconds: Int) async {
            // Bound the duration to a reasonable maximum to avoid accidental long sleeps in tests.
            let bounded = max(0, min(durationSeconds, 60 * 60))
            let ns = UInt64(bounded) * 1_000_000_000
            do {
                try await Task.sleep(nanoseconds: ns)
            } catch {
                // Task was cancelled; just return
                return
            }

            // After sleeping, trigger the public activation hook so the auth service inspects state.
            applicationDidBecomeActive()
        }
    }

    /// Forces the *server-rejected token* path — a real `401` on a resource
    /// request, followed by a token refresh and a retry — without waiting for an
    /// access token to expire on its own.
    ///
    /// This is the reactive branch of `NetworkService.request` ("401 error is NOT
    /// 'use_dpop_nonce'. Will attempt standard token refresh"), which is otherwise
    /// only reachable by leaving the app closed for longer than the token's
    /// lifetime, and so is hard to measure or regression-test.
    ///
    /// Nothing persisted is modified. Requests are *signed* with a deliberately
    /// unverifiable access token — the DPoP proof binds that same value, so the
    /// authorization server answers `invalid_token` rather than complaining about
    /// the proof. The stored session, and in particular the refresh token, is
    /// untouched, so an armed run that goes wrong costs a refresh, not a session.
    ///
    /// The latch clears itself on the first successful refresh, so exactly one
    /// rejection happens no matter how many requests are in flight — including the
    /// DPoP-nonce retry a cold launch always performs first, which would otherwise
    /// consume a simple counter before the real request was ever signed.
    public enum PetrelDebugAuth {
        private static let lock = NSLock()
        private nonisolated(unsafe) static var rejectUntilNextRefresh = false

        /// Signs authenticated requests with an invalid access token until one
        /// refresh completes.
        public static func armAccessTokenRejection() {
            lock.withLock { rejectUntilNextRefresh = true }
            LogManager.logWarning(
                "DEBUG PetrelDebugAuth: armed — authenticated requests will be signed with an invalid access token until a refresh completes",
                category: .authentication
            )
        }

        /// Whether the next request should be signed with an invalid token.
        static var isArmed: Bool {
            lock.withLock { rejectUntilNextRefresh }
        }

        /// Called from the refresh success path; ends the simulation.
        static func disarmAfterRefresh() {
            let wasArmed = lock.withLock { () -> Bool in
                let was = rejectUntilNextRefresh
                rejectUntilNextRefresh = false
                return was
            }
            if wasArmed {
                LogManager.logWarning(
                    "DEBUG PetrelDebugAuth: disarmed — a refresh completed, requests resume signing normally",
                    category: .authentication
                )
            }
        }

        /// Returns a structurally well-formed but unverifiable variant of `token`.
        ///
        /// Only the signature segment is disturbed, so anything that parses the
        /// claims (expiry checks, the `sub` lookup) still behaves normally and the
        /// rejection comes from signature verification at the server, which is the
        /// failure an expired-but-well-formed token produces.
        static func invalidVariant(of token: String) -> String {
            let segments = token.split(separator: ".", omittingEmptySubsequences: false)
            guard segments.count == 3, let signature = segments.last, !signature.isEmpty else {
                return token + "invalid"
            }
            return "\(segments[0]).\(segments[1]).\(String(signature.reversed()))"
        }
    }
#endif

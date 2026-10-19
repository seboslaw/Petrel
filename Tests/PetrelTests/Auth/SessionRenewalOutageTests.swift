#if canImport(CryptoKit)
    import CryptoKit
#else
    @preconcurrency import Crypto
#endif
import Foundation
#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif
@testable import Petrel
import Synchronization
import Testing

// MARK: - Fixtures

private func makeAccount(did: String) -> Account {
    Account(did: did, handle: "outage.example", pdsURL: URL(string: "https://pds.outage.test")!)
}

/// A one-hour access token issued `age` seconds ago. Petrel renews inside the
/// last 15 minutes, so an age above 2700 s means "needs renewal now".
private func makeSession(did: String, age: TimeInterval) -> Session {
    Session(
        accessToken: "at-\(did)",
        refreshToken: "rt-\(did)",
        createdAt: Date().addingTimeInterval(-age),
        expiresIn: 3600,
        tokenType: .dpop,
        did: did
    )
}

private func makeCore(storage: KeychainStorage, did: String) -> OAuthCore {
    OAuthCore(
        storage: storage,
        accountManager: MockAccountManager(account: makeAccount(did: did)),
        networkService: NetworkService(baseURL: URL(string: "https://pds.outage.test")!),
        oauthConfig: OAuthConfig(clientId: "test-client", redirectUri: "test://callback", scope: "atproto"),
        didResolver: MockDIDResolver()
    )
}

private func withInMemoryBackend<T>(
    _ backend: InMemorySecureStorage,
    _ body: () async throws -> T
) async rethrows -> T {
    try await withSerializedStorageOverrideTest {
        KeychainManager._setStorageOverride(backend)
        defer { KeychainManager._setStorageOverride(nil) }
        return try await body()
    }
}

/// An auth provider whose session can't be renewed because the client
/// assertion backend is down — what every request met on 2026-10-18.
private struct AssertionBackendDownProvider: AuthenticationProvider {
    func prepareAuthenticatedRequest(_ request: URLRequest) async throws -> URLRequest { request }

    func prepareAuthenticatedRequestWithContext(_ request: URLRequest) async throws -> (URLRequest, AuthContext) {
        (request, AuthContext(did: "did:plc:outage-network", jkt: nil))
    }

    func refreshTokenIfNeeded() async throws -> TokenRefreshResult {
        throw ClientAssertionBackendUnavailable(statusCode: 502, transportError: nil)
    }

    func handleUnauthorizedResponse(_: HTTPURLResponse, data _: Data, for _: URLRequest) async throws -> (Data, HTTPURLResponse) {
        throw ClientAssertionBackendUnavailable(statusCode: 502, transportError: nil)
    }

    func updateDPoPNonce(for _: URL, from _: [String: String], did _: String?, jkt _: String?) async {}
}

// MARK: - Tests

/// What a client assertion backend outage does to session renewal.
///
/// On 2026-10-18 api.skeetsapp.com answered 502 for five hours. No session was
/// lost, but no session could be renewed, and every request failed as a bare
/// "Authentication failed." — the app could neither explain the outage nor tell
/// it apart from a broken sign-in, and users who signed out to fix it could not
/// sign back in.
@Suite("Session renewal during an assertion backend outage", .serialized)
struct SessionRenewalOutageTests {
    @Test("A token that is still valid is not blocked by an open circuit")
    func validTokenIgnoresOpenCircuit() async throws {
        let backend = InMemorySecureStorage()
        try await withInMemoryBackend(backend) {
            let did = "did:plc:outage-valid"
            let storage = KeychainStorage(namespace: "test.outage.valid")
            let core = makeCore(storage: storage, did: did)
            try await storage.saveAccountAndSession(makeAccount(did: did), session: makeSession(did: did, age: 0), for: did)
            for _ in 0 ..< 3 {
                await core.refreshCircuitBreaker.recordFailure(for: did, kind: .network)
            }
            #expect(await core.refreshCircuitBreaker.getState(for: did) == .open)

            let result = try await core.refreshTokenIfNeeded()
            #expect(result == .stillValid)
        }
    }

    @Test("A refresh that fails before reaching the server frees the half-open test")
    func unrecordedFailureReleasesHalfOpenTest() async throws {
        let backend = InMemorySecureStorage()
        try await withInMemoryBackend(backend) {
            let did = "did:plc:outage-halfopen"
            let storage = KeychainStorage(namespace: "test.outage.halfopen")
            let core = makeCore(storage: storage, did: did)
            // Inside the renewal window, so every call attempts a refresh.
            try await storage.saveAccountAndSession(makeAccount(did: did), session: makeSession(did: did, age: 3500), for: did)
            for _ in 0 ..< 3 {
                await core.refreshCircuitBreaker.recordFailure(for: did, kind: .network)
            }
            #expect(await core.refreshCircuitBreaker.forceHalfOpen(for: did))

            let attempts = Mutex(0)
            await core.setPerformActualRefresh { _, _ in
                attempts.withLock { $0 += 1 }
                throw ClientAssertionBackendUnavailable(statusCode: 502, transportError: nil)
            }

            await #expect(throws: ClientAssertionBackendUnavailable(statusCode: 502, transportError: nil)) {
                _ = try await core.refreshTokenIfNeeded()
            }
            // The backend is back: the next renewal must be allowed to try.
            await #expect(throws: ClientAssertionBackendUnavailable(statusCode: 502, transportError: nil)) {
                _ = try await core.refreshTokenIfNeeded()
            }
            #expect(attempts.withLock { $0 } == 2, "the second renewal must reach the exchange, not stop at the circuit breaker")
        }
    }

    @Test("A request whose renewal hits the outage says so")
    func requestReportsAssertionBackendUnavailable() async throws {
        let network = NetworkService(baseURL: URL(string: "https://pds.outage.test")!)
        await network.setAuthenticationProvider(AssertionBackendDownProvider())
        let request = URLRequest(url: URL(string: "https://pds.outage.test/xrpc/app.bsky.actor.getProfile?actor=outage.example")!)

        do {
            _ = try await network.performRequest(request, skipTokenRefresh: false)
            Issue.record("the request must fail while the session can't be renewed")
        } catch let NetworkError.clientAssertionBackendUnavailable(cause) {
            #expect(cause == ClientAssertionBackendUnavailable(statusCode: 502, transportError: nil))
        } catch {
            Issue.record("expected clientAssertionBackendUnavailable, got \(error)")
        }
    }
}

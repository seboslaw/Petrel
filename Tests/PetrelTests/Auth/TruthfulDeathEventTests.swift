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

// MARK: - Transport

/// Private to this suite so no other suite can ever fight over the handler.
private final class TruthfulDeathURLProtocol: URLProtocol {
    private static let handlerStorage = Mutex<(@Sendable (URLRequest) -> (HTTPURLResponse, Data))?>(nil)

    static func setHandler(_ new: (@Sendable (URLRequest) -> (HTTPURLResponse, Data))?) {
        handlerStorage.withLock { $0 = new }
    }

    override static func canInit(with _: URLRequest) -> Bool { true }
    override static func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = Self.handlerStorage.withLock({ $0 }) else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }
        let (response, data) = handler(request)
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

// MARK: - Fixtures

private let authHost = "https://auth.truthful.test"
private let cabHost = "https://cab.truthful.test"
private let pdsHost = "https://pds.truthful.test"

private let metadataJSON = """
{
  "issuer": "\(authHost)",
  "scopes_supported": ["atproto"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "authorization_endpoint": "\(authHost)/oauth/authorize",
  "token_endpoint": "\(authHost)/oauth/token",
  "pushed_authorization_request_endpoint": "\(authHost)/oauth/par"
}
"""

private func makeAccount(did: String) throws -> Account {
    let metadata = try JSONDecoder().decode(AuthorizationServerMetadata.self, from: Data(metadataJSON.utf8))
    return Account(
        did: did,
        handle: "truthful.example",
        pdsURL: URL(string: pdsHost)!,
        authorizationServerMetadata: metadata
    )
}

private func makeSession(did: String, refreshToken: String, createdAt: Date = Date()) -> Session {
    Session(
        accessToken: "access-\(refreshToken)",
        refreshToken: refreshToken,
        createdAt: createdAt,
        expiresIn: 3600,
        tokenType: .dpop,
        did: did
    )
}

private let assertionJSON = """
{"client_id":"\(cabHost)/oauth-client-metadata.json","client_assertion":"header.payload.sig"}
"""

private let invalidGrantJSON = """
{"error":"invalid_grant","error_description":"Refresh token replayed"}
"""

/// AccountManaging that records `clearCurrentAccount` calls — the observable
/// half of the truthful-death cleanup.
private actor RecordingAccountManager: AccountManaging {
    private let account: Account
    private(set) var clearCurrentAccountCalls = 0

    init(account: Account) {
        self.account = account
    }

    func addAccount(_: Account) async throws {}
    func getAccount(did: String) async -> Account? {
        did == account.did ? account : nil
    }

    func updateAccountFromStorage(did _: String) async throws {}
    func removeAccount(did _: String) async throws {}
    func setCurrentAccount(did _: String) async throws {}
    func getCurrentAccount() async -> Account? { account }
    func listAccounts() async -> [Account] { [account] }
    func clearCurrentAccount() async { clearCurrentAccountCalls += 1 }
    func updateServiceDIDs(bskyAppViewDID _: String, bskyChatDID _: String) async throws {}
}

private func withCABTransport<T>(
    _ backend: InMemorySecureStorage,
    handler: @escaping @Sendable (URLRequest) -> (HTTPURLResponse, Data),
    _ body: () async throws -> T
) async throws -> T {
    try await withSerializedStorageOverrideTest {
        KeychainManager._setStorageOverride(backend)
        TruthfulDeathURLProtocol.setHandler(handler)
        defer {
            TruthfulDeathURLProtocol.setHandler(nil)
            KeychainManager._setStorageOverride(nil)
        }
        // Task-scoped: cannot be clobbered by suites that mutate the global slot.
        return try await NetworkService.$taskLocalTestProtocolClasses.withValue(
            .init(classes: [TruthfulDeathURLProtocol.self])
        ) {
            try await body()
        }
    }
}

private func jsonResponse(url: URL, status: Int) -> HTTPURLResponse {
    HTTPURLResponse(
        url: url,
        statusCode: status,
        httpVersion: "HTTP/1.1",
        headerFields: ["Content-Type": "application/json"]
    )!
}

private func makeStrategy(
    storage: KeychainStorage,
    accountManager: RecordingAccountManager,
    networkService: NetworkService
) -> CABOAuthStrategy {
    let config = URLSessionConfiguration.ephemeral
    config.protocolClasses = [TruthfulDeathURLProtocol.self]
    return CABOAuthStrategy(
        backendURL: URL(string: cabHost)!,
        storage: storage,
        accountManager: accountManager,
        networkService: networkService,
        oauthConfig: OAuthConfig(
            clientId: "\(cabHost)/oauth-client-metadata.json",
            redirectUri: "https://client.example/callback",
            scope: "atproto"
        ),
        didResolver: MockDIDResolver(),
        urlSession: URLSession(configuration: config)
    )
}

// MARK: - Tests

/// The definitive-death signal comes from exactly one place: the strategy's
/// `invalid_grant` handling, after the rescue check. A genuine rejection cleans
/// local state so every storage-based check agrees with the event; a lost
/// cross-process race is rescued as `.stillValid` instead of reported as death.
@Suite("Truthful death events", .serialized)
struct TruthfulDeathEventTests {
    @Test("Genuine invalid_grant cleans local state and emits the one truthful event")
    func genuineInvalidGrantCleansUpAndEmits() async throws {
        let backend = InMemorySecureStorage()
        let did = "did:plc:truthful-death"
        let handler: @Sendable (URLRequest) -> (HTTPURLResponse, Data) = { request in
            let url = request.url!
            if url.host == "cab.truthful.test" {
                return (jsonResponse(url: url, status: 200), Data(assertionJSON.utf8))
            }
            if url.path == "/oauth/token" {
                return (jsonResponse(url: url, status: 400), Data(invalidGrantJSON.utf8))
            }
            return (jsonResponse(url: url, status: 404), Data("{}".utf8))
        }

        try await withCABTransport(backend, handler: handler) {
            let storage = KeychainStorage(namespace: "test.truthful.death")
            let account = try makeAccount(did: did)
            let accountManager = RecordingAccountManager(account: account)
            let strategy = makeStrategy(
                storage: storage,
                accountManager: accountManager,
                networkService: NetworkService(baseURL: URL(string: pdsHost)!)
            )

            try await storage.saveAccountAndSession(
                account, session: makeSession(did: did, refreshToken: "rt-dead"), for: did
            )
            try await storage.saveDPoPKeyRepresentation(
                P256.Signing.PrivateKey().x963Representation, for: did
            )

            // Captured at the emission site: the broadcaster's observer list is
            // process-global and other suites clear it wholesale mid-run.
            let events = Mutex<[AuthEvent]>([])
            LogManager.setOnAuthEventForTesting { event in
                events.withLock { $0.append(event) }
            }
            defer { LogManager.setOnAuthEventForTesting(nil) }

            var thrown: Error?
            do {
                _ = try await strategy.refreshTokenIfNeeded(forceRefresh: true)
            } catch {
                thrown = error
            }
            #expect(thrown as? AuthError == .invalidCredentials)

            // Storage agrees with the verdict: session, DPoP key and the
            // current-account pointer are gone, so persistedSessionState-style
            // checks reach the same conclusion the event announces.
            let session = try await storage.getSession(for: did)
            #expect(session == nil, "A dead family must not leave a session behind")
            let key = try? await storage.getDPoPKeyRepresentation(for: did)
            #expect(key == nil, "The DPoP key dies with the session")
            #expect(await accountManager.clearCurrentAccountCalls == 1)

            // Exactly one truthful death event, for this DID.
            let deathEvents = events.withLock { $0 }.filter {
                if case let .refreshTokenInvalid(eventDID, statusCode, error) = $0 {
                    return eventDID == did && statusCode == 400 && error == "invalid_grant"
                }
                return false
            }
            #expect(deathEvents.count == 1, "The genuine rejection must emit the refreshTokenInvalid event")
        }
    }

    @Test("applicationDidBecomeActiveAndWait completes the validation before returning")
    func awaitableForegroundValidation() async throws {
        let backend = InMemorySecureStorage()
        let handler: @Sendable (URLRequest) -> (HTTPURLResponse, Data) = { request in
            (jsonResponse(url: request.url!, status: 404), Data("{}".utf8))
        }
        try await withCABTransport(backend, handler: handler) {
            let client = try await ATProtoClient(
                oauthConfig: OAuthConfig(
                    clientId: "test-client",
                    redirectUri: "test://callback",
                    scope: "atproto"
                ),
                namespace: "test.truthful.foreground"
            )
            // The fire-and-forget applicationDidBecomeActive() races its own
            // verdict: callers that read auth state right after it observed the
            // PRE-validation state. The awaitable variant returns only after
            // validateAuthenticationState has completed — with no stored
            // account this is a no-op pass, and returning at all (rather than
            // detaching) is the contract under test.
            await client.applicationDidBecomeActiveAndWait()
        }
    }

    @Test("A lost cross-process race is rescued as stillValid, not reported as death")
    func lostRaceIsRescued() async throws {
        let backend = InMemorySecureStorage()
        let did = "did:plc:truthful-rescue"
        let namespace = "test.truthful.rescue"

        // The token endpoint answers invalid_grant — but before the verdict is
        // delivered, the WINNER's rotated session lands in shared storage, the
        // way a concurrent process persists its successor while our stale POST
        // is still on the wire.
        let handler: @Sendable (URLRequest) -> (HTTPURLResponse, Data) = { request in
            let url = request.url!
            if url.host == "cab.truthful.test" {
                return (jsonResponse(url: url, status: 200), Data(assertionJSON.utf8))
            }
            if url.path == "/oauth/token" {
                let winner = makeSession(did: did, refreshToken: "rt-winner", createdAt: Date())
                if let data = try? JSONEncoder().encode(winner) {
                    backend.plant(key: "session.\(did)", namespace: namespace, data: data)
                    KeychainManager.clearCache()
                }
                return (jsonResponse(url: url, status: 400), Data(invalidGrantJSON.utf8))
            }
            return (jsonResponse(url: url, status: 404), Data("{}".utf8))
        }

        try await withCABTransport(backend, handler: handler) {
            let storage = KeychainStorage(namespace: namespace)
            let account = try makeAccount(did: did)
            let accountManager = RecordingAccountManager(account: account)
            let strategy = makeStrategy(
                storage: storage,
                accountManager: accountManager,
                networkService: NetworkService(baseURL: URL(string: pdsHost)!)
            )

            try await storage.saveAccountAndSession(
                account, session: makeSession(did: did, refreshToken: "rt-loser"), for: did
            )
            try await storage.saveDPoPKeyRepresentation(
                P256.Signing.PrivateKey().x963Representation, for: did
            )

            let events = Mutex<[AuthEvent]>([])
            LogManager.setOnAuthEventForTesting { event in
                events.withLock { $0.append(event) }
            }
            defer { LogManager.setOnAuthEventForTesting(nil) }

            let result = try await strategy.refreshTokenIfNeeded(forceRefresh: true)
            #expect(result == .stillValid, "The session is alive — only our stale copy was condemned")

            // Nothing was torn down and no death was announced.
            let session = try await storage.getSession(for: did)
            #expect(session?.refreshToken == "rt-winner")
            let key = try? await storage.getDPoPKeyRepresentation(for: did)
            #expect(key != nil)
            #expect(await accountManager.clearCurrentAccountCalls == 0)

            let deathEvents = events.withLock { $0 }.filter {
                if case let .refreshTokenInvalid(eventDID, _, _) = $0 { return eventDID == did }
                return false
            }
            #expect(deathEvents.isEmpty, "A rescued race must not reach the UI as a death")
        }
    }
}

// MARK: - NetworkService silence

/// Minimal provider whose 401 handling fails the way a transient refresh
/// failure does — the case that must NOT be broadcast as an auto-logout.
private actor FailingRefreshProvider: AuthenticationProvider {
    func prepareAuthenticatedRequest(_ request: URLRequest) async throws -> URLRequest { request }
    func prepareAuthenticatedRequestWithContext(_ request: URLRequest) async throws -> (URLRequest, AuthContext) {
        (request, AuthContext(did: "did:plc:networkservice-silence", jkt: nil))
    }

    func refreshTokenIfNeeded() async throws -> TokenRefreshResult { .stillValid }
    func handleUnauthorizedResponse(_: HTTPURLResponse, data _: Data, for _: URLRequest) async throws -> (Data, HTTPURLResponse) {
        throw AuthError.tokenRefreshFailed
    }

    func updateDPoPNonce(for _: URL, from _: [String: String], did _: String?, jkt _: String?) async {}
}

/// NetworkService's non-nonce-401 fallbacks used to broadcast
/// `autoLogoutTriggered` — for plain network errors during the refresh,
/// rate-limit skips, an open circuit breaker, and expected stale-token
/// failures under `skipTokenRefresh`. None of those mean the session is dead;
/// after the fix, no broadcast leaves NetworkService for them.
@Suite("NetworkService auto-logout silence", .serialized)
struct NetworkServiceAutoLogoutSilenceTests {
    private static let watchedDID = "did:plc:networkservice-silence"

    private func collectAutoLogouts(
        during body: () async throws -> Void
    ) async rethrows -> [AuthEvent] {
        let events = Mutex<[AuthEvent]>([])
        await PetrelAuthEvents.addObserverAndWait { event in
            events.withLock { $0.append(event) }
        }
        try await body()
        // The removed broadcasts were fire-and-forget tasks; give any stray one
        // a bounded chance to land before asserting silence.
        await PetrelAuthEvents.drain()
        for _ in 0 ..< 50 { await Task.yield() }
        await PetrelAuthEvents.removeAllObservers()
        return events.withLock { $0 }.filter {
            if case let .autoLogoutTriggered(did, _) = $0 {
                return did == Self.watchedDID || did.isEmpty
            }
            return false
        }
    }

    @Test("A failed 401 refresh throws without broadcasting auto-logout")
    func failedRefreshDoesNotBroadcast() async throws {
        let backend = InMemorySecureStorage()
        let handler: @Sendable (URLRequest) -> (HTTPURLResponse, Data) = { request in
            (jsonResponse(url: request.url!, status: 401), Data(#"{"error":"InvalidToken"}"#.utf8))
        }
        try await withCABTransport(backend, handler: handler) {
            let networkService = NetworkService(baseURL: URL(string: pdsHost)!)
            await networkService.setAuthenticationProvider(FailingRefreshProvider())

            let autoLogouts = try await collectAutoLogouts {
                let request = URLRequest(url: URL(string: "\(pdsHost)/xrpc/app.bsky.actor.getProfile")!)
                // The two-parameter variant is the full path with non-nonce-401
                // handling (the single-argument one returns failed responses to
                // its caller instead).
                await #expect(throws: (any Error).self) {
                    _ = try await networkService.request(request, skipTokenRefresh: false)
                }
            }
            #expect(autoLogouts.isEmpty, "A transient refresh failure must not reach the UI as a logout")
        }
    }

    @Test("A stale-token 401 under skipTokenRefresh throws without broadcasting auto-logout")
    func skipRefresh401DoesNotBroadcast() async throws {
        let backend = InMemorySecureStorage()
        let handler: @Sendable (URLRequest) -> (HTTPURLResponse, Data) = { request in
            (jsonResponse(url: request.url!, status: 401), Data(#"{"error":"InvalidToken"}"#.utf8))
        }
        try await withCABTransport(backend, handler: handler) {
            let networkService = NetworkService(baseURL: URL(string: pdsHost)!)
            await networkService.setAuthenticationProvider(FailingRefreshProvider())

            let autoLogouts = try await collectAutoLogouts {
                let request = URLRequest(url: URL(string: "\(pdsHost)/xrpc/app.bsky.feed.getTimeline")!)
                await #expect(throws: (any Error).self) {
                    _ = try await networkService.request(request, skipTokenRefresh: true)
                }
            }
            #expect(autoLogouts.isEmpty, "Expected degradation on a stale token is not death")
        }
    }
}

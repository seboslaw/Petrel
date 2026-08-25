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
    Account(did: did, handle: "singleflight.example", pdsURL: URL(string: "https://pds.singleflight.test")!)
}

private func makeSession(
    did: String,
    accessToken: String,
    refreshToken: String,
    createdAt: Date = Date(),
    expiresIn: TimeInterval = 3600
) -> Session {
    Session(
        accessToken: accessToken,
        refreshToken: refreshToken,
        createdAt: createdAt,
        expiresIn: expiresIn,
        tokenType: .dpop,
        did: did
    )
}

private func makeCore(storage: KeychainStorage, did: String) -> OAuthCore {
    OAuthCore(
        storage: storage,
        accountManager: MockAccountManager(account: makeAccount(did: did)),
        networkService: NetworkService(baseURL: URL(string: "https://pds.singleflight.test")!),
        oauthConfig: OAuthConfig(
            clientId: "test-client",
            redirectUri: "test://callback",
            scope: "atproto"
        ),
        didResolver: MockDIDResolver()
    )
}

/// Runs `body` with an injected in-memory storage backend, always restoring the
/// platform default afterwards.
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

/// Waits (bounded) for a join on `did` to be observed by the process-wide
/// registry, so a test can release a gated exchange only once the second caller
/// has provably been absorbed into the running flight.
private func expectJoin(
    for did: String,
    while body: () async throws -> Void
) async throws {
    let joined = AsyncBarrier()
    await RefreshFlightRegistry.shared.setOnJoinForTesting { joinedDID in
        if joinedDID == did { joined.signal() }
    }
    try await body()
    try await joined.waitUntilSignaled()
    await RefreshFlightRegistry.shared.setOnJoinForTesting(nil)
}

// MARK: - Tests

/// The process-wide single-flight guarantee for refresh-token exchanges.
///
/// Refresh tokens are single-use, and the reference `@atproto/oauth-provider`
/// treats a replayed token as theft: it revokes the whole token family. So two
/// concurrent consuming POSTs of the same token — from actor reentrancy inside
/// one core, or from two core instances for the same account — permanently kill
/// the session. Observed in the field 2026-08-20: two exchanges 1 ms apart in
/// one process, the loser's `invalid_grant: "Refresh token replayed"` revoked
/// the family (Skeets SESSION_REVIEW_2.md F25 / incident #3).
@Suite("Refresh single-flight", .serialized)
struct RefreshSingleFlightTests {
    @Test("Concurrent forced refreshes share one exchange")
    func concurrentForcedRefreshesShareOneExchange() async throws {
        let backend = InMemorySecureStorage()
        try await withInMemoryBackend(backend) {
            let did = "did:plc:singleflight-concurrent"
            let storage = KeychainStorage(namespace: "test.singleflight.concurrent")
            let core = makeCore(storage: storage, did: did)
            try await storage.saveAccountAndSession(
                makeAccount(did: did),
                session: makeSession(did: did, accessToken: "at-1", refreshToken: "rt-1"),
                for: did
            )

            let exchangeCount = Mutex(0)
            let exchangeStarted = AsyncBarrier()
            let release = AsyncBarrier()
            await core.setPerformActualRefresh { _, _ in
                exchangeCount.withLock { $0 += 1 }
                exchangeStarted.signal()
                try await release.waitUntilSignaled()
                return .refreshedSuccessfully
            }

            let first = Task { try await core.refreshTokenIfNeeded(forceRefresh: true) }
            try await exchangeStarted.waitUntilSignaled()

            // The exchange is on the wire and gated open. A second caller must be
            // absorbed into it — wait for the registry to observe the join before
            // letting the exchange finish, so the test cannot pass by accident of
            // scheduling.
            var second: Task<TokenRefreshResult, Error>!
            try await expectJoin(for: did) {
                second = Task { try await core.refreshTokenIfNeeded(forceRefresh: true) }
            }
            release.signal()

            let firstResult = try await first.value
            let secondResult = try await second.value
            #expect(firstResult == .refreshedSuccessfully)
            #expect(secondResult == .refreshedSuccessfully)
            #expect(exchangeCount.withLock { $0 } == 1, "Both callers must share one consuming POST")
        }
    }

    @Test("A second core instance for the same DID joins the same flight")
    func secondCoreInstanceJoinsTheSameFlight() async throws {
        let backend = InMemorySecureStorage()
        try await withInMemoryBackend(backend) {
            let did = "did:plc:singleflight-crossinstance"
            let storage = KeychainStorage(namespace: "test.singleflight.crossinstance")
            let core1 = makeCore(storage: storage, did: did)
            let core2 = makeCore(storage: storage, did: did)
            try await storage.saveAccountAndSession(
                makeAccount(did: did),
                session: makeSession(did: did, accessToken: "at-1", refreshToken: "rt-1"),
                for: did
            )

            let exchangeCount = Mutex(0)
            let exchangeStarted = AsyncBarrier()
            let release = AsyncBarrier()
            let exchange: @Sendable (Account, Session) async throws -> TokenRefreshResult = { _, _ in
                exchangeCount.withLock { $0 += 1 }
                exchangeStarted.signal()
                try await release.waitUntilSignaled()
                return .refreshedSuccessfully
            }
            await core1.setPerformActualRefresh(exchange)
            await core2.setPerformActualRefresh(exchange)

            let first = Task { try await core1.refreshTokenIfNeeded(forceRefresh: true) }
            try await exchangeStarted.waitUntilSignaled()

            // An instance-local task map can never see this caller: it lives in a
            // different core (client rebuilt while the old instance still serves
            // requests). Only a process-wide registry absorbs it.
            var second: Task<TokenRefreshResult, Error>!
            try await expectJoin(for: did) {
                second = Task { try await core2.refreshTokenIfNeeded(forceRefresh: true) }
            }
            release.signal()

            #expect(try await first.value == .refreshedSuccessfully)
            #expect(try await second.value == .refreshedSuccessfully)
            #expect(exchangeCount.withLock { $0 } == 1, "Two instances must not each consume the token")
        }
    }

    @Test("A cancelled creator does not free the slot while the exchange is on the wire")
    func cancelledCreatorDoesNotFreeTheSlot() async throws {
        let backend = InMemorySecureStorage()
        try await withInMemoryBackend(backend) {
            let did = "did:plc:singleflight-cancel"
            let storage = KeychainStorage(namespace: "test.singleflight.cancel")
            let core = makeCore(storage: storage, did: did)
            try await storage.saveAccountAndSession(
                makeAccount(did: did),
                session: makeSession(did: did, accessToken: "at-1", refreshToken: "rt-1"),
                for: did
            )

            let exchangeCount = Mutex(0)
            let exchangeStarted = AsyncBarrier()
            let release = AsyncBarrier()
            let base = Date()
            // Rotates the persisted session like a real token endpoint, so the
            // follow-up call below consumes the successor instead of tripping the
            // consumed-token guard on the original.
            await core.setPerformActualRefresh { account, _ in
                let generation = exchangeCount.withLock { $0 += 1; return $0 }
                exchangeStarted.signal()
                try await release.waitUntilSignaled()
                let rotated = makeSession(
                    did: account.did,
                    accessToken: "at-\(generation + 1)",
                    refreshToken: "rt-\(generation + 1)",
                    createdAt: base.addingTimeInterval(TimeInterval(generation))
                )
                try await storage.saveSession(rotated, for: account.did)
                return .refreshedSuccessfully
            }

            let creator = Task { try await core.refreshTokenIfNeeded(forceRefresh: true) }
            try await exchangeStarted.waitUntilSignaled()

            // Cancel the caller that created the flight. Deregistration belongs to
            // the flight itself: were the creator's exit to free the slot, the next
            // caller would start a SECOND consuming POST of the same token.
            creator.cancel()

            var joiner: Task<TokenRefreshResult, Error>!
            try await expectJoin(for: did) {
                joiner = Task { try await core.refreshTokenIfNeeded(forceRefresh: true) }
            }
            release.signal()

            #expect(try await joiner.value == .refreshedSuccessfully)
            #expect(exchangeCount.withLock { $0 } == 1, "The cancelled creator must not have freed the slot mid-flight")

            // After completion the slot IS free: a fresh call runs its own exchange.
            let followUp = try await core.refreshTokenIfNeeded(forceRefresh: true)
            #expect(followUp == .refreshedSuccessfully)
            #expect(exchangeCount.withLock { $0 } == 2, "A completed flight must deregister itself")
        }
    }

    @Test("A 401 earned by an already-replaced access token refreshes nothing")
    func staleAccessTokenShortCircuitsWithoutConsuming() async throws {
        let backend = InMemorySecureStorage()
        try await withInMemoryBackend(backend) {
            let did = "did:plc:singleflight-stale401"
            let storage = KeychainStorage(namespace: "test.singleflight.stale401")
            let core = makeCore(storage: storage, did: did)
            try await storage.saveAccountAndSession(
                makeAccount(did: did),
                session: makeSession(did: did, accessToken: "at-current", refreshToken: "rt-current"),
                for: did
            )

            let exchangeCount = Mutex(0)
            await core.setPerformActualRefresh { _, _ in
                exchangeCount.withLock { $0 += 1 }
                return .refreshedSuccessfully
            }

            // The 401 was earned by an access token a rotation has since replaced:
            // stale evidence, no exchange.
            let shortCircuited = try await core.refreshTokenIfNeeded(
                forceRefresh: true, staleAccessToken: "at-replaced-by-rotation"
            )
            #expect(shortCircuited == .stillValid)
            #expect(exchangeCount.withLock { $0 } == 0, "A stale 401 must not consume a refresh token")

            // The same 401 against the CURRENT access token is real: refresh.
            let refreshed = try await core.refreshTokenIfNeeded(
                forceRefresh: true, staleAccessToken: "at-current"
            )
            #expect(refreshed == .refreshedSuccessfully)
            #expect(exchangeCount.withLock { $0 } == 1)
        }
    }

    @Test("A burst of forced refreshes never replays a refresh token")
    func burstOfForcedRefreshesNeverReplaysARefreshToken() async throws {
        let backend = InMemorySecureStorage()
        try await withInMemoryBackend(backend) {
            let did = "did:plc:singleflight-burst"
            let storage = KeychainStorage(namespace: "test.singleflight.burst")
            let core = makeCore(storage: storage, did: did)
            let base = Date()
            try await storage.saveAccountAndSession(
                makeAccount(did: did),
                session: makeSession(
                    did: did, accessToken: "at-0", refreshToken: "rt-0",
                    createdAt: base
                ),
                for: did
            )

            // The exchange behaves like a real token endpoint: it consumes the
            // refresh token it was handed and persists the rotated successor
            // before returning. Consuming the SAME token twice is the replay the
            // authorization server answers with family revocation — the one
            // outcome no interleaving may produce.
            let consumed = Mutex<[String]>([])
            await core.setPerformActualRefresh { account, session in
                let generation = consumed.withLock { list -> Int in
                    list.append(session.refreshToken ?? "<nil>")
                    return list.count
                }
                let rotated = makeSession(
                    did: account.did,
                    accessToken: "at-\(generation)",
                    refreshToken: "rt-\(generation)",
                    createdAt: base.addingTimeInterval(TimeInterval(generation))
                )
                try await storage.saveSession(rotated, for: account.did)
                return .refreshedSuccessfully
            }

            let results = try await withThrowingTaskGroup(of: TokenRefreshResult.self) { group in
                for _ in 0 ..< 8 {
                    group.addTask { try await core.refreshTokenIfNeeded(forceRefresh: true) }
                }
                var collected: [TokenRefreshResult] = []
                for try await result in group {
                    collected.append(result)
                }
                return collected
            }

            #expect(results.count == 8)
            #expect(results.allSatisfy { $0 == .refreshedSuccessfully })
            let tokens = consumed.withLock { $0 }
            #expect(
                Set(tokens).count == tokens.count,
                "No refresh token may be consumed twice — a replay revokes the token family. Consumed: \(tokens)"
            )
        }
    }
}

// MARK: - Strategy-level: the 401 handler feeds the failing token down

/// Serves the PDS resource endpoint and records what reaches the token endpoint
/// (nothing should, in these tests).
private final class SingleFlightURLProtocol: URLProtocol {
    private nonisolated(unsafe) static var handler: (@Sendable (URLRequest) -> (HTTPURLResponse, Data))?
    private static let handlerLock = NSLock()

    static func setHandler(_ new: (@Sendable (URLRequest) -> (HTTPURLResponse, Data))?) {
        handlerLock.withLock { handler = new }
    }

    override static func canInit(with _: URLRequest) -> Bool { true }
    override static func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = Self.handlerLock.withLock({ Self.handler }) else {
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

private func withStrategyTransport<T>(
    _ backend: InMemorySecureStorage,
    handler: @escaping @Sendable (URLRequest) -> (HTTPURLResponse, Data),
    _ body: () async throws -> T
) async throws -> T {
    try await withSerializedStorageOverrideTest {
        KeychainManager._setStorageOverride(backend)
        SingleFlightURLProtocol.setHandler(handler)
        NetworkService.setNetworkTestProtocolClasses([SingleFlightURLProtocol.self])
        defer {
            NetworkService.setNetworkTestProtocolClasses(nil)
            SingleFlightURLProtocol.setHandler(nil)
            KeychainManager._setStorageOverride(nil)
        }
        return try await body()
    }
}

private let strategyPDSHost = "https://pds.stale401.test"

private func strategyJSONResponse(url: URL, status: Int) -> HTTPURLResponse {
    HTTPURLResponse(
        url: url,
        statusCode: status,
        httpVersion: "HTTP/1.1",
        headerFields: ["Content-Type": "application/json"]
    )!
}

/// Both OAuth strategies hand the failing request's access token down to the
/// refresh path, so a 401 earned by an already-rotated token retries with the
/// stored session instead of consuming another single-use refresh token.
@Suite("401 handler stale-token short-circuit", .serialized)
struct StrategyStale401Tests {
    private func run(
        did: String,
        namespace: String,
        makeStrategy: @escaping @Sendable (KeychainStorage, NetworkService) -> any AuthStrategy
    ) async throws {
        let backend = InMemorySecureStorage()
        let tokenEndpointHits = Mutex(0)
        let retriedAuthorization = Mutex<String?>(nil)
        let handler: @Sendable (URLRequest) -> (HTTPURLResponse, Data) = { request in
            let url = request.url!
            if url.path.contains("/oauth/") || url.path.contains("/token") {
                tokenEndpointHits.withLock { $0 += 1 }
                return (strategyJSONResponse(url: url, status: 500), Data("{}".utf8))
            }
            retriedAuthorization.withLock { $0 = request.value(forHTTPHeaderField: "Authorization") }
            return (strategyJSONResponse(url: url, status: 200), Data("{}".utf8))
        }

        try await withStrategyTransport(backend, handler: handler) {
            // Everything is built inside the transport block: NetworkService
            // captures the test protocol classes into its URLSession at init, and
            // storage writes must land in the in-memory backend, never the real
            // keychain.
            let storage = KeychainStorage(namespace: namespace)
            let networkService = NetworkService(baseURL: URL(string: strategyPDSHost)!)
            let strategy = makeStrategy(storage, networkService)

            // Storage holds the CURRENT session; the failing request below carried
            // an access token a rotation has since replaced.
            try await storage.saveAccountAndSession(
                makeAccount(did: did),
                session: makeSession(did: did, accessToken: "at-fresh", refreshToken: "rt-fresh"),
                for: did
            )
            // The DPoP key that bound the session: request preparation correctly
            // refuses to mint a fresh key for an existing .dpop session.
            try await storage.saveDPoPKeyRepresentation(
                P256.Signing.PrivateKey().x963Representation, for: did
            )
            // The retry goes back out through NetworkService, whose authenticated
            // path requires a provider — in production the AuthManager, here the
            // strategy itself (same conformance).
            await networkService.setAuthenticationProvider(strategy)

            var failedRequest = URLRequest(url: URL(string: "\(strategyPDSHost)/xrpc/app.bsky.actor.getProfile")!)
            failedRequest.setValue("DPoP at-stale", forHTTPHeaderField: "Authorization")
            let failedResponse = strategyJSONResponse(url: failedRequest.url!, status: 401)

            let (_, retried) = try await strategy.handleUnauthorizedResponse(failedResponse, data: Data("{}".utf8), for: failedRequest)

            #expect(retried.statusCode == 200, "The healthy session must serve the retry")
            #expect(
                tokenEndpointHits.withLock { $0 } == 0,
                "A 401 earned by a replaced access token must not reach the token endpoint"
            )
            let authorization = retriedAuthorization.withLock { $0 }
            #expect(
                authorization == "DPoP at-fresh",
                "The retry must carry the stored (current) access token, got: \(authorization ?? "<none>")"
            )
        }
    }

    @Test("CABOAuthStrategy retries a stale 401 from storage without an exchange")
    func cabStrategyStale401() async throws {
        let did = "did:plc:stale401-cab"
        try await run(did: did, namespace: "test.stale401.cab") { storage, networkService in
            CABOAuthStrategy(
                backendURL: URL(string: "https://cab.stale401.test")!,
                storage: storage,
                accountManager: MockAccountManager(account: makeAccount(did: did)),
                networkService: networkService,
                oauthConfig: OAuthConfig(
                    clientId: "test-client",
                    redirectUri: "test://callback",
                    scope: "atproto"
                ),
                didResolver: MockDIDResolver()
            )
        }
    }

    @Test("PublicOAuthStrategy retries a stale 401 from storage without an exchange")
    func publicStrategyStale401() async throws {
        let did = "did:plc:stale401-public"
        try await run(did: did, namespace: "test.stale401.public") { storage, networkService in
            PublicOAuthStrategy(
                storage: storage,
                accountManager: MockAccountManager(account: makeAccount(did: did)),
                networkService: networkService,
                oauthConfig: OAuthConfig(
                    clientId: "test-client",
                    redirectUri: "test://callback",
                    scope: "atproto"
                ),
                didResolver: MockDIDResolver()
            )
        }
    }
}

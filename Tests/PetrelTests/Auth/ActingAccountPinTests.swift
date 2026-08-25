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

private final class ActingAccountURLProtocol: URLProtocol {
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

private let pdsHost = "https://pds.actingaccount.test"

private func makeAccount(did: String) -> Account {
    Account(did: did, handle: "acting.example", pdsURL: URL(string: pdsHost)!)
}

private func makeSession(did: String, accessToken: String, refreshToken: String) -> Session {
    Session(
        accessToken: accessToken,
        refreshToken: refreshToken,
        createdAt: Date(),
        expiresIn: 3600,
        tokenType: .dpop,
        did: did
    )
}

private func makeCore(storage: KeychainStorage, currentAccount: Account) -> OAuthCore {
    OAuthCore(
        storage: storage,
        accountManager: MockAccountManager(account: currentAccount),
        networkService: NetworkService(baseURL: URL(string: pdsHost)!),
        oauthConfig: OAuthConfig(
            clientId: "test-client",
            redirectUri: "test://callback",
            scope: "atproto"
        ),
        didResolver: MockDIDResolver()
    )
}

/// Seeds account + session + DPoP key for one DID.
private func seed(_ storage: KeychainStorage, did: String, accessToken: String, refreshToken: String) async throws {
    try await storage.saveAccountAndSession(
        makeAccount(did: did),
        session: makeSession(did: did, accessToken: accessToken, refreshToken: refreshToken),
        for: did
    )
    try await storage.saveDPoPKeyRepresentation(P256.Signing.PrivateKey().x963Representation, for: did)
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

// MARK: - Tests

/// `PetrelActingAccount.did` pins the account whose stored session signs the
/// requests made inside the binding task, without moving the current-account
/// pointer. Everything downstream — session, DPoP key, nonces, refresh
/// single-flight — is keyed by DID, so only account resolution changes.
@Suite("Acting-account pin", .serialized)
struct ActingAccountPinTests {
    @Test("A pinned request is signed with the pinned account's session and key")
    func pinSignsWithPinnedSession() async throws {
        let backend = InMemorySecureStorage()
        try await withInMemoryBackend(backend) {
            let didA = "did:plc:acting-current"
            let didB = "did:plc:acting-pinned"
            let storage = KeychainStorage(namespace: "test.acting.signing")
            let core = makeCore(storage: storage, currentAccount: makeAccount(did: didA))
            try await seed(storage, did: didA, accessToken: "at-A", refreshToken: "rt-A")
            try await seed(storage, did: didB, accessToken: "at-B", refreshToken: "rt-B")

            let request = URLRequest(url: URL(string: "\(pdsHost)/xrpc/com.atproto.repo.createRecord")!)

            // Unbound: the current account signs.
            let (plain, _) = try await core.prepareAuthenticatedRequestWithContext(request)
            #expect(plain.value(forHTTPHeaderField: "Authorization") == "DPoP at-A")

            // Pinned: the second account signs — while the current account is untouched.
            let (pinned, context) = try await PetrelActingAccount.$did.withValue(didB) {
                try await core.prepareAuthenticatedRequestWithContext(request)
            }
            #expect(pinned.value(forHTTPHeaderField: "Authorization") == "DPoP at-B")
            #expect(context.did == didB)

            // And after the binding ends, resolution reverts.
            let (after, _) = try await core.prepareAuthenticatedRequestWithContext(request)
            #expect(after.value(forHTTPHeaderField: "Authorization") == "DPoP at-A")
        }
    }

    @Test("An unknown pinned DID throws instead of falling back")
    func unknownPinThrows() async throws {
        let backend = InMemorySecureStorage()
        try await withInMemoryBackend(backend) {
            let didA = "did:plc:acting-fallback-current"
            let storage = KeychainStorage(namespace: "test.acting.unknown")
            let core = makeCore(storage: storage, currentAccount: makeAccount(did: didA))
            try await seed(storage, did: didA, accessToken: "at-A", refreshToken: "rt-A")

            let request = URLRequest(url: URL(string: "\(pdsHost)/xrpc/com.atproto.repo.createRecord")!)

            // Falling back to the current account would sign the request as the
            // wrong person — for a repo write, posting to the wrong repo.
            await #expect(throws: AuthError.noActiveAccount) {
                _ = try await PetrelActingAccount.$did.withValue("did:plc:acting-not-on-device") {
                    try await core.prepareAuthenticatedRequestWithContext(request)
                }
            }
        }
    }

    @Test("A pinned refresh rotates the pinned account's token, never the current one's")
    func pinRoutesRefresh() async throws {
        let backend = InMemorySecureStorage()
        try await withInMemoryBackend(backend) {
            let didA = "did:plc:acting-refresh-current"
            let didB = "did:plc:acting-refresh-pinned"
            let storage = KeychainStorage(namespace: "test.acting.refresh")
            let core = makeCore(storage: storage, currentAccount: makeAccount(did: didA))
            try await seed(storage, did: didA, accessToken: "at-A", refreshToken: "rt-A")
            try await seed(storage, did: didB, accessToken: "at-B", refreshToken: "rt-B")

            let consumed = Mutex<[(did: String, refreshToken: String?)]>([])
            await core.setPerformActualRefresh { account, session in
                consumed.withLock { $0.append((account.did, session.refreshToken)) }
                return .refreshedSuccessfully
            }

            let result = try await PetrelActingAccount.$did.withValue(didB) {
                try await core.refreshTokenIfNeeded(forceRefresh: true)
            }
            #expect(result == .refreshedSuccessfully)

            let exchanges = consumed.withLock { $0 }
            #expect(exchanges.count == 1)
            #expect(exchanges.first?.did == didB)
            #expect(exchanges.first?.refreshToken == "rt-B", "The pinned account's token rotates, not the active one's")
        }
    }

    @Test("performRequest(as:) pins end-to-end through the client's own stack")
    func clientPerformRequestAsPinsEndToEnd() async throws {
        let backend = InMemorySecureStorage()
        let namespace = "test.acting.client"
        let didA = "did:plc:acting-e2e-current"
        let didB = "did:plc:acting-e2e-pinned"
        let authorizations = Mutex<[String?]>([])
        let handler: @Sendable (URLRequest) -> (HTTPURLResponse, Data) = { request in
            authorizations.withLock { $0.append(request.value(forHTTPHeaderField: "Authorization")) }
            return (
                HTTPURLResponse(
                    url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1",
                    headerFields: ["Content-Type": "application/json"]
                )!,
                Data("{}".utf8)
            )
        }

        try await withSerializedStorageOverrideTest {
            KeychainManager._setStorageOverride(backend)
            ActingAccountURLProtocol.setHandler(handler)
            NetworkService.setNetworkTestProtocolClasses([ActingAccountURLProtocol.self])
            defer {
                NetworkService.setNetworkTestProtocolClasses(nil)
                ActingAccountURLProtocol.setHandler(nil)
                KeychainManager._setStorageOverride(nil)
            }

            let storage = KeychainStorage(namespace: namespace)
            try await seed(storage, did: didA, accessToken: "at-A", refreshToken: "rt-A")
            try await seed(storage, did: didB, accessToken: "at-B", refreshToken: "rt-B")
            try await storage.saveCurrentDID(didA)

            let client = try await ATProtoClient(
                baseURL: URL(string: pdsHost)!,
                oauthConfig: OAuthConfig(
                    clientId: "test-client",
                    redirectUri: "test://callback",
                    scope: "atproto"
                ),
                namespace: namespace
            )

            let request = URLRequest(url: URL(string: "\(pdsHost)/xrpc/com.atproto.repo.createRecord")!)

            // The task-local must survive the whole pipeline: client extension →
            // NetworkService → AuthManager → strategy → OAuthCore signing.
            let (_, pinnedResponse) = try await client.performRequest(request, as: didB)
            #expect(pinnedResponse.statusCode == 200)

            let (_, plainResponse) = try await client.performRequest(request, as: nil)
            #expect(plainResponse.statusCode == 200)

            let seen = authorizations.withLock { $0 }
            #expect(seen.contains("DPoP at-B"), "The pinned call must be signed as the pinned account, saw: \(seen)")
            #expect(seen.last == "DPoP at-A", "The unpinned call signs as the current account, saw: \(seen)")
        }
    }
}

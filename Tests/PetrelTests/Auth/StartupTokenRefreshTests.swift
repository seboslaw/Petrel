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

private final class StartupRefreshURLProtocol: URLProtocol {
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

private let authHost = "https://auth.startup.test"
private let pdsHost = "https://pds.startup.test"

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

private func jsonResponse(url: URL, status: Int) -> HTTPURLResponse {
    HTTPURLResponse(
        url: url,
        statusCode: status,
        httpVersion: "HTTP/1.1",
        headerFields: ["Content-Type": "application/json"]
    )!
}

/// Seeds a stored account whose access token is deep inside the expiry buffer,
/// so client initialization would normally rotate it proactively.
private func seedNearExpiryAccount(namespace: String, did: String) async throws {
    let storage = KeychainStorage(namespace: namespace)
    let metadata = try JSONDecoder().decode(AuthorizationServerMetadata.self, from: Data(metadataJSON.utf8))
    let account = Account(
        did: did,
        handle: "startup.example",
        pdsURL: URL(string: pdsHost)!,
        authorizationServerMetadata: metadata
    )
    let session = Session(
        accessToken: "at-near-expiry",
        refreshToken: "rt-near-expiry",
        createdAt: Date(timeIntervalSinceNow: -3500),
        expiresIn: 3600, // 100 s left — inside the 15-minute buffer
        tokenType: .dpop,
        did: did
    )
    try await storage.saveAccountAndSession(account, session: session, for: did)
    try await storage.saveDPoPKeyRepresentation(P256.Signing.PrivateKey().x963Representation, for: did)
    try await storage.saveCurrentDID(did)
}

private func withStartupTransport<T>(
    _ backend: InMemorySecureStorage,
    handler: @escaping @Sendable (URLRequest) -> (HTTPURLResponse, Data),
    _ body: () async throws -> T
) async throws -> T {
    try await withSerializedStorageOverrideTest {
        KeychainManager._setStorageOverride(backend)
        StartupRefreshURLProtocol.setHandler(handler)
        defer {
            StartupRefreshURLProtocol.setHandler(nil)
            KeychainManager._setStorageOverride(nil)
        }
        // Task-scoped: cannot be clobbered by suites that mutate the global slot.
        return try await NetworkService.$taskLocalTestProtocolClasses.withValue(
            .init(classes: [StartupRefreshURLProtocol.self])
        ) {
            try await body()
        }
    }
}

// MARK: - Tests

/// `startupTokenRefresh: false` keeps `initializeFromStoredAccount()` from
/// rotating a near-expiry token at client creation. App extensions need this:
/// a Notification Service Extension is reaped seconds after delivering its
/// content, and a rotation whose successor never reaches shared storage
/// permanently kills the session — the AS treats the inevitable replay of the
/// consumed token as theft and revokes the token family.
@Suite("Startup token refresh opt-out", .serialized)
struct StartupTokenRefreshTests {
    private func makeClient(namespace: String, startupTokenRefresh: Bool) async throws -> ATProtoClient {
        try await ATProtoClient(
            baseURL: URL(string: pdsHost)!,
            oauthConfig: OAuthConfig(
                clientId: "https://client.example/oauth-client-metadata.json",
                redirectUri: "https://client.example/callback",
                scope: "atproto"
            ),
            namespace: namespace,
            startupTokenRefresh: startupTokenRefresh
        )
    }

    @Test("Default startup keeps the proactive near-expiry rotation")
    func defaultStartupRotates() async throws {
        let backend = InMemorySecureStorage()
        let did = "did:plc:startup-default"
        let namespace = "test.startup.default"
        let tokenEndpointHits = Mutex(0)
        let tokenJSON = """
        {"access_token":"at-rotated","token_type":"DPoP","expires_in":3600,"refresh_token":"rt-rotated","scope":"atproto","sub":"\(did)"}
        """
        let handler: @Sendable (URLRequest) -> (HTTPURLResponse, Data) = { request in
            let url = request.url!
            if url.path == "/oauth/token" {
                tokenEndpointHits.withLock { $0 += 1 }
                return (jsonResponse(url: url, status: 200), Data(tokenJSON.utf8))
            }
            return (jsonResponse(url: url, status: 404), Data("{}".utf8))
        }

        try await withStartupTransport(backend, handler: handler) {
            try await seedNearExpiryAccount(namespace: namespace, did: did)
            _ = try await makeClient(namespace: namespace, startupTokenRefresh: true)
            #expect(
                tokenEndpointHits.withLock { $0 } >= 1,
                "The default path must still refresh a near-expiry token at startup"
            )
        }
    }

    @Test("startupTokenRefresh: false starts no rotation at client creation")
    func optOutStartsNoRotation() async throws {
        let backend = InMemorySecureStorage()
        let did = "did:plc:startup-optout"
        let namespace = "test.startup.optout"
        let tokenEndpointHits = Mutex(0)
        let handler: @Sendable (URLRequest) -> (HTTPURLResponse, Data) = { request in
            let url = request.url!
            if url.path == "/oauth/token" {
                tokenEndpointHits.withLock { $0 += 1 }
                return (jsonResponse(url: url, status: 500), Data("{}".utf8))
            }
            return (jsonResponse(url: url, status: 404), Data("{}".utf8))
        }

        try await withStartupTransport(backend, handler: handler) {
            try await seedNearExpiryAccount(namespace: namespace, did: did)
            let client = try await makeClient(namespace: namespace, startupTokenRefresh: false)

            #expect(
                tokenEndpointHits.withLock { $0 } == 0,
                "An extension process must never start an orphanable rotation at creation"
            )
            // The stored account is still loaded — the opt-out skips only the
            // proactive rotation, not initialization.
            let storedDID = try await client.getDid()
            #expect(storedDID == did)
        }
    }
}

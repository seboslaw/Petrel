#if DEBUG
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

    private final class DebugAuthURLProtocol: URLProtocol {
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

    private let authHost = "https://auth.debugauth.test"
    private let pdsHost = "https://pds.debugauth.test"

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

    /// JWT-shaped so only the signature segment is disturbed by the latch.
    private let storedAccessToken = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQifQ.c2lnbmF0dXJl"

    private func makeAccount(did: String, withMetadata: Bool = false) throws -> Account {
        let metadata: AuthorizationServerMetadata? = withMetadata
            ? try JSONDecoder().decode(AuthorizationServerMetadata.self, from: Data(metadataJSON.utf8))
            : nil
        return Account(
            did: did,
            handle: "debugauth.example",
            pdsURL: URL(string: pdsHost)!,
            authorizationServerMetadata: metadata
        )
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

    private func makeCore(storage: KeychainStorage, account: Account) -> OAuthCore {
        OAuthCore(
            storage: storage,
            accountManager: MockAccountManager(account: account),
            networkService: NetworkService(baseURL: URL(string: pdsHost)!),
            oauthConfig: OAuthConfig(
                clientId: "test-client",
                redirectUri: "test://callback",
                scope: "atproto"
            ),
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

    private func decodeProofPayload(_ compactJWS: String) throws -> [String: Any] {
        let parts = compactJWS.split(separator: ".")
        try #require(parts.count == 3)
        var payloadB64 = String(parts[1])
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while payloadB64.count % 4 != 0 { payloadB64 += "=" }
        let payloadData = try #require(Data(base64Encoded: payloadB64))
        return try #require(try JSONSerialization.jsonObject(with: payloadData) as? [String: Any])
    }

    private func base64URLSHA256(_ value: String) -> String {
        let hash = SHA256.hash(data: Data(value.utf8))
        return Data(hash).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    // MARK: - Tests

    /// `PetrelDebugAuth` forces the server-rejected-token path on demand: armed,
    /// requests are signed with an unverifiable variant of the access token whose
    /// hash the DPoP proof binds, so the server answers `invalid_token` — the same
    /// failure an expired-but-well-formed token produces. Nothing persisted is
    /// touched, and the latch clears on the first successful refresh.
    @Suite("PetrelDebugAuth", .serialized)
    struct PetrelDebugAuthTests {
        @Test("Armed, requests are signed with an unverifiable variant the proof binds")
        func armedSigningBindsTheCorruptedToken() async throws {
            let backend = InMemorySecureStorage()
            try await withInMemoryBackend(backend) {
                let did = "did:plc:debugauth-signing"
                let storage = KeychainStorage(namespace: "test.debugauth.signing")
                let account = try makeAccount(did: did)
                let core = makeCore(storage: storage, account: account)
                try await storage.saveAccountAndSession(
                    account,
                    session: makeSession(did: did, accessToken: storedAccessToken, refreshToken: "rt-1"),
                    for: did
                )
                try await storage.saveDPoPKeyRepresentation(
                    P256.Signing.PrivateKey().x963Representation, for: did
                )

                let request = URLRequest(url: URL(string: "\(pdsHost)/xrpc/app.bsky.actor.getProfile")!)

                PetrelDebugAuth.armAccessTokenRejection()
                defer { PetrelDebugAuth.disarmAfterRefresh() }

                let (armed, _) = try await core.prepareAuthenticatedRequestWithContext(request)
                let corrupted = PetrelDebugAuth.invalidVariant(of: storedAccessToken)
                #expect(corrupted != storedAccessToken)
                #expect(armed.value(forHTTPHeaderField: "Authorization") == "DPoP \(corrupted)")

                // The proof's ath must hash the SAME corrupted value the header
                // carries — otherwise the server rejects the proof instead of
                // answering invalid_token, and the wrong path gets exercised.
                let proof = try #require(armed.value(forHTTPHeaderField: "DPoP"))
                let payload = try decodeProofPayload(proof)
                #expect(payload["ath"] as? String == base64URLSHA256(corrupted))

                // Nothing persisted was modified.
                let stored = try await storage.getSession(for: did)
                #expect(stored?.accessToken == storedAccessToken)
                #expect(stored?.refreshToken == "rt-1")
            }
        }

        @Test("The latch clears on the first successful refresh")
        func latchClearsOnFirstSuccessfulRefresh() async throws {
            let backend = InMemorySecureStorage()
            try await withInMemoryBackend(backend) {
                let did = "did:plc:debugauth-latch"
                let storage = KeychainStorage(namespace: "test.debugauth.latch")
                let account = try makeAccount(did: did)
                let core = makeCore(storage: storage, account: account)
                try await storage.saveAccountAndSession(
                    account,
                    session: makeSession(did: did, accessToken: storedAccessToken, refreshToken: "rt-1"),
                    for: did
                )
                await core.setPerformActualRefresh { _, _ in .refreshedSuccessfully }

                PetrelDebugAuth.armAccessTokenRejection()
                #expect(PetrelDebugAuth.isArmed)

                _ = try await core.refreshTokenIfNeeded(forceRefresh: true)

                #expect(!PetrelDebugAuth.isArmed, "One completed refresh must end the simulation")
            }
        }

        @Test("An armed request drives the full 401 → refresh → retry sequence")
        func armedRequestDrivesRefreshAndRetry() async throws {
            let backend = InMemorySecureStorage()
            let did = "did:plc:debugauth-endtoend"
            let namespace = "test.debugauth.endtoend"
            let corrupted = PetrelDebugAuth.invalidVariant(of: storedAccessToken)

            let tokenEndpointHits = Mutex(0)
            let xrpcAuthorizations = Mutex<[String?]>([])
            let tokenJSON = """
            {"access_token":"at-rotated","token_type":"DPoP","expires_in":3600,"refresh_token":"rt-rotated","scope":"atproto","sub":"\(did)"}
            """
            let handler: @Sendable (URLRequest) -> (HTTPURLResponse, Data) = { request in
                let url = request.url!
                func response(_ status: Int) -> HTTPURLResponse {
                    HTTPURLResponse(
                        url: url, statusCode: status, httpVersion: "HTTP/1.1",
                        headerFields: ["Content-Type": "application/json"]
                    )!
                }
                if url.path == "/oauth/token" {
                    tokenEndpointHits.withLock { $0 += 1 }
                    return (response(200), Data(tokenJSON.utf8))
                }
                let authorization = request.value(forHTTPHeaderField: "Authorization")
                xrpcAuthorizations.withLock { $0.append(authorization) }
                // The server verdict on the unverifiable token: a real 401,
                // not a use_dpop_nonce dance.
                if authorization == "DPoP \(corrupted)" {
                    return (response(401), Data(#"{"error":"invalid_token"}"#.utf8))
                }
                return (response(200), Data("{}".utf8))
            }

            try await withSerializedStorageOverrideTest {
                KeychainManager._setStorageOverride(backend)
                DebugAuthURLProtocol.setHandler(handler)
                NetworkService.setNetworkTestProtocolClasses([DebugAuthURLProtocol.self])
                defer {
                    NetworkService.setNetworkTestProtocolClasses(nil)
                    DebugAuthURLProtocol.setHandler(nil)
                    KeychainManager._setStorageOverride(nil)
                    PetrelDebugAuth.disarmAfterRefresh()
                }

                let storage = KeychainStorage(namespace: namespace)
                let account = try makeAccount(did: did, withMetadata: true)
                let networkService = NetworkService(baseURL: URL(string: pdsHost)!)
                let strategy = PublicOAuthStrategy(
                    storage: storage,
                    accountManager: MockAccountManager(account: account),
                    networkService: networkService,
                    oauthConfig: OAuthConfig(
                        clientId: "test-client",
                        redirectUri: "test://callback",
                        scope: "atproto"
                    ),
                    didResolver: MockDIDResolver()
                )
                await networkService.setAuthenticationProvider(strategy)

                try await storage.saveAccountAndSession(
                    account,
                    session: makeSession(did: did, accessToken: storedAccessToken, refreshToken: "rt-1"),
                    for: did
                )
                try await storage.saveDPoPKeyRepresentation(
                    P256.Signing.PrivateKey().x963Representation, for: did
                )

                PetrelDebugAuth.armAccessTokenRejection()

                let request = URLRequest(url: URL(string: "\(pdsHost)/xrpc/app.bsky.actor.getProfile")!)
                let (_, response) = try await networkService.request(request, skipTokenRefresh: false)

                #expect((response as? HTTPURLResponse)?.statusCode == 200)
                #expect(tokenEndpointHits.withLock { $0 } == 1, "Exactly one real refresh serves the rejection")
                let authorizations = xrpcAuthorizations.withLock { $0 }
                #expect(
                    authorizations.first == "DPoP \(corrupted)",
                    "The first attempt must carry the unverifiable token"
                )
                #expect(
                    authorizations.last == "DPoP at-rotated",
                    "The retry must carry the freshly rotated token, saw: \(authorizations)"
                )
                #expect(!PetrelDebugAuth.isArmed, "The completed refresh disarms the latch")

                // The rotation persisted — the simulation cost one refresh, not a session.
                let stored = try await storage.getSession(for: did)
                #expect(stored?.refreshToken == "rt-rotated")
            }
        }
    }
#endif

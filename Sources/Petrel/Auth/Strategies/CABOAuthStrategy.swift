//
//  CABOAuthStrategy.swift
//  Petrel
//
//  Client Assertion Backend (CAB) OAuth strategy.
//  Fetches DPoP-bound client assertions from a backend before token
//  exchange and refresh, then includes them in the token request.
//

#if canImport(CryptoKit)
    import CryptoKit
#else
    @preconcurrency import Crypto
#endif
import Foundation
#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif
import JSONWebAlgorithms
import JSONWebKey
import JSONWebSignature

// MARK: - Client Assertion Response

struct ClientAssertionResponse: Decodable {
    let clientId: String
    let clientAssertion: String

    enum CodingKeys: String, CodingKey {
        case clientId = "client_id"
        case clientAssertion = "client_assertion"
    }
}

// MARK: - CABOAuthStrategy

/// Authentication strategy using Client Assertion Backend (CAB).
///
/// Identical to ``PublicOAuthStrategy`` for PAR, PKCE, and DPoP key
/// management, but injects a backend-issued `client_assertion` into
/// every token exchange and refresh request.
actor CABOAuthStrategy: AuthStrategy {
    // MARK: - Properties

    let core: OAuthCore
    let backendURL: URL

    /// Transport for backend assertion fetches — injectable for tests.
    let urlSession: URLSession

    static let clientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

    // Delegates
    private weak var progressDelegate: AuthProgressDelegate?
    private weak var failureDelegate: AuthFailureDelegate?

    // OAuth flow deduplication state
    private var oauthStartInProgress = false
    private var oauthStartTasks: [String: Task<URL, Error>] = [:]

    // MARK: - Initialization

    init(
        backendURL: URL,
        storage: KeychainStorage,
        accountManager: AccountManaging,
        networkService: NetworkService,
        oauthConfig: OAuthConfig,
        didResolver: DIDResolving,
        urlSession: URLSession = .shared
    ) {
        self.backendURL = backendURL
        self.urlSession = urlSession
        core = OAuthCore(
            storage: storage,
            accountManager: accountManager,
            networkService: networkService,
            oauthConfig: oauthConfig,
            didResolver: didResolver
        )
    }

    /// Must be called after init to wire up the strategy-specific refresh.
    private func setupRefreshClosure() async {
        await core.setPerformActualRefresh { [weak self] account, session in
            guard let self else { throw AuthError.tokenRefreshFailed }
            return try await self.performActualRefresh(for: account, session: session)
        }
    }

    // MARK: - AuthStrategy Implementation

    func startOAuthFlow(
        identifier: String?,
        bskyAppViewDID: String?,
        bskyChatDID: String?
    ) async throws -> URL {
        await ensureRefreshClosure()

        let key = identifier?.lowercased() ?? "__signup__"

        if let existing = oauthStartTasks[key] {
            return try await existing.value
        }

        let task = Task.detached(priority: .userInitiated) { [weak self] () throws -> URL in
            guard let self else { throw AuthError.invalidOAuthConfiguration }
            return try await self._startOAuthFlowImpl(
                identifier: identifier,
                bskyAppViewDID: bskyAppViewDID,
                bskyChatDID: bskyChatDID
            )
        }
        oauthStartTasks[key] = task
        defer { oauthStartTasks.removeValue(forKey: key) }
        return try await task.value
    }

    func startOAuthFlowForSignUp(
        pdsURL: URL?,
        bskyAppViewDID: String?,
        bskyChatDID: String?
    ) async throws -> URL {
        throw AuthError.invalidOAuthConfiguration
    }

    func handleOAuthCallback(url: URL) async throws -> (did: String, handle: String?, pdsURL: URL) {
        await emitProgress(.exchangingTokens)

        guard let code = await core.extractAuthorizationCode(from: url),
              let stateToken = await core.extractState(from: url)
        else { throw AuthError.invalidCallbackURL }

        let storage = core.storage
        guard let oauthState = try await storage.getOAuthState(for: stateToken) else {
            throw AuthError.invalidCallbackURL
        }

        guard let keyData = oauthState.ephemeralDPoPKey else { throw AuthError.dpopKeyError }
        let ephemeralKey = try P256.Signing.PrivateKey(rawRepresentation: keyData)

        try await storage.deleteOAuthState(for: stateToken)

        guard let pdsURL = oauthState.targetPDSURL else { throw AuthError.invalidOAuthConfiguration }
        let authServerURL = try await core.resolveAuthServer(for: pdsURL)
        let metadata = try await core.fetchAuthorizationServerMetadata(authServerURL: authServerURL)

        let tokenResponse = try await exchangeCodeForTokens(
            code: code,
            codeVerifier: oauthState.codeVerifier,
            tokenEndpoint: metadata.tokenEndpoint,
            issuer: metadata.issuer,
            authServerURL: authServerURL,
            ephemeralKey: ephemeralKey,
            initialNonce: oauthState.parResponseNonce,
            resourceURL: pdsURL
        )

        guard let did = tokenResponse.sub else { throw AuthError.invalidResponse }

        // Resolve real PDS
        let didResolver = core.didResolver
        let (handle, actualPDS) = try await didResolver.resolveDIDToHandleAndPDSURL(did: did)

        // Persist DPoP Key
        try await storage.saveDPoPKeyRepresentation(ephemeralKey.x963Representation, for: did)

        // Create Session
        let session = Session(
            accessToken: tokenResponse.accessToken,
            refreshToken: tokenResponse.refreshToken,
            createdAt: Date(),
            expiresIn: TimeInterval(tokenResponse.expiresIn),
            tokenType: .dpop,
            did: did
        )

        // Create/Update Account
        let account = Account(
            did: did,
            handle: handle,
            pdsURL: actualPDS,
            protectedResourceMetadata: nil,
            authorizationServerMetadata: metadata,
            bskyAppViewDID: oauthState.bskyAppViewDID ?? "",
            bskyChatDID: oauthState.bskyChatDID ?? ""
        )

        try await storage.saveAccountAndSession(account, session: session, for: did)
        let accountManager = core.accountManager
        try await accountManager.updateAccountFromStorage(did: did)
        try await accountManager.setCurrentAccount(did: did)
        let networkService = core.networkService
        await networkService.setBaseURL(actualPDS)

        return (did: did, handle: account.handle, pdsURL: actualPDS)
    }

    func loginWithPassword(
        identifier: String,
        password: String,
        bskyAppViewDID: String?,
        bskyChatDID: String?
    ) async throws -> (did: String, handle: String?, pdsURL: URL) {
        throw AuthError.invalidOAuthConfiguration
    }

    func logout() async throws {
        let accountManager = core.accountManager
        guard let did = await accountManager.getCurrentAccount()?.did else { return }

        let storage = core.storage
        // Revoke token if possible
        if let session = try? await storage.getSession(for: did),
           let refreshToken = session.refreshToken,
           let account = await accountManager.getAccount(did: did),
           let endpoint = account.authorizationServerMetadata?.revocationEndpoint
        {
            await core.revokeToken(refreshToken: refreshToken, endpoint: endpoint, did: did)
        }

        try await storage.deleteSession(for: did)
        try await storage.deleteDPoPKey(for: did)
        try await storage.saveDPoPNonces([:], for: did)

        await accountManager.clearCurrentAccount()
    }

    func cancelOAuthFlow() async {
        oauthStartTasks.values.forEach { $0.cancel() }
        oauthStartTasks.removeAll()
        oauthStartInProgress = false
    }

    func tokensExist() async -> Bool {
        await core.tokensExist()
    }

    func setProgressDelegate(_ delegate: AuthProgressDelegate?) async {
        progressDelegate = delegate
    }

    func setFailureDelegate(_ delegate: AuthFailureDelegate?) async {
        failureDelegate = delegate
    }

    func attemptRecoveryFromServerFailures(for did: String?) async throws {
        var targetDID = did
        if targetDID == nil {
            targetDID = await core.accountManager.getCurrentAccount()?.did
        }
        guard let did = targetDID else { return }
        await core.refreshCircuitBreaker.reset(for: did)
        _ = try await refreshTokenIfNeeded(forceRefresh: true)
    }

    // MARK: - AuthenticationProvider

    func prepareAuthenticatedRequest(_ request: URLRequest) async throws -> URLRequest {
        try await core.prepareAuthenticatedRequest(request)
    }

    func prepareAuthenticatedRequestWithContext(_ request: URLRequest) async throws -> (URLRequest, AuthContext) {
        try await core.prepareAuthenticatedRequestWithContext(request)
    }

    func refreshTokenIfNeeded() async throws -> TokenRefreshResult {
        await ensureRefreshClosure()
        return try await core.refreshTokenIfNeeded()
    }

    func refreshTokenIfNeeded(forceRefresh: Bool) async throws -> TokenRefreshResult {
        await ensureRefreshClosure()
        return try await core.refreshTokenIfNeeded(forceRefresh: forceRefresh)
    }

    func handleUnauthorizedResponse(
        _ response: HTTPURLResponse,
        data: Data,
        for request: URLRequest
    ) async throws -> (Data, HTTPURLResponse) {
        guard response.statusCode == 401 else { return (data, response) }

        let result = try await refreshTokenIfNeeded(forceRefresh: true)

        switch result {
        case .refreshedSuccessfully, .stillValid:
            // .stillValid after a 401 means another process already rotated (or
            // the invalid_grant rescue below fired): storage holds a fresh token
            // this request never used. Retry once with it instead of failing a
            // healthy session.
            let (newReq, _) = try await core.prepareAuthenticatedRequestWithContext(request)
            let networkService = core.networkService
            let result = try await networkService.request(newReq)
            guard let http = result.1 as? HTTPURLResponse else { throw AuthError.invalidResponse }
            return (result.0, http)
        default:
            throw AuthError.tokenRefreshFailed
        }
    }

    func updateDPoPNonce(for url: URL, from headers: [String: String], did: String?, jkt: String?) async {
        await core.updateDPoPNonce(for: url, from: headers, did: did, jkt: jkt)
    }

    // MARK: - Private Helpers (OAuth Flow)

    private var refreshClosureSet = false

    private func ensureRefreshClosure() async {
        if !refreshClosureSet {
            refreshClosureSet = true
            await setupRefreshClosure()
        }
    }

    private func _startOAuthFlowImpl(identifier: String?, bskyAppViewDID: String?, bskyChatDID: String?) async throws -> URL {
        if oauthStartInProgress {
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        oauthStartInProgress = true
        defer { oauthStartInProgress = false }

        let didResolver = core.didResolver
        let pdsURL: URL
        if let identifier {
            await emitProgress(.resolvingHandle(identifier))
            let did = try await didResolver.resolveHandleToDID(handle: identifier)
            pdsURL = try await didResolver.resolveDIDToPDSURL(did: did)
        } else {
            pdsURL = URL(string: "https://bsky.social")!
        }

        await emitProgress(.fetchingMetadata(url: pdsURL.absoluteString))
        let authServerURL = try await core.resolveAuthServer(for: pdsURL)
        let metadata = try await core.fetchAuthorizationServerMetadata(authServerURL: authServerURL)

        await emitProgress(.generatingParameters)
        let codeVerifier = await core.generateCodeVerifier()
        let codeChallenge = await core.generateCodeChallenge(from: codeVerifier)
        let stateToken = UUID().uuidString
        let ephemeralKey = P256.Signing.PrivateKey()

        let oauthConfig = core.oauthConfig

        // Confidential clients authenticate at PAR too. Assertions are
        // single-use (the AS replay-checks jti), so this one is fetched fresh
        // and used only for this PAR request.
        let parAssertion = try await fetchClientAssertion(
            aud: metadata.issuer, ephemeralKey: ephemeralKey
        )

        let (requestURI, parNonce) = try await core.pushAuthorizationRequest(
            codeChallenge: codeChallenge,
            identifier: identifier,
            endpoint: metadata.pushedAuthorizationRequestEndpoint,
            authServerURL: authServerURL,
            state: stateToken,
            ephemeralKeyRawRepresentation: ephemeralKey.rawRepresentation,
            additionalParameters: [
                "client_assertion": parAssertion.clientAssertion,
                "client_assertion_type": Self.clientAssertionTypeJWTBearer,
            ]
        )

        let oauthState = OAuthState(
            stateToken: stateToken,
            codeVerifier: codeVerifier,
            createdAt: Date(),
            initialIdentifier: identifier,
            targetPDSURL: pdsURL,
            ephemeralDPoPKey: ephemeralKey.rawRepresentation,
            parResponseNonce: parNonce,
            bskyAppViewDID: bskyAppViewDID,
            bskyChatDID: bskyChatDID
        )
        let storage = core.storage
        try await storage.saveOAuthState(oauthState)

        guard var components = URLComponents(string: metadata.authorizationEndpoint) else {
            throw AuthError.invalidOAuthConfiguration
        }
        components.queryItems = [
            URLQueryItem(name: "request_uri", value: requestURI),
            URLQueryItem(name: "client_id", value: oauthConfig.clientId),
            URLQueryItem(name: "redirect_uri", value: oauthConfig.redirectUri),
        ]

        guard let url = components.url else { throw AuthError.authorizationFailed }
        return url
    }

    // MARK: - Client Assertion Fetch

    /// Fetches a DPoP-bound client assertion for the given authorization
    /// server issuer. Retries exactly once when the backend answers
    /// 400 `use_dpop_nonce` with a `DPoP-Nonce` header.
    func fetchClientAssertion(
        aud: String,
        ephemeralKey: P256.Signing.PrivateKey? = nil,
        did: String? = nil
    ) async throws -> ClientAssertionResponse {
        try await fetchClientAssertionAttempt(
            aud: aud, ephemeralKey: ephemeralKey, did: did, nonce: nil, isRetry: false
        )
    }

    private func fetchClientAssertionAttempt(
        aud: String,
        ephemeralKey: P256.Signing.PrivateKey?,
        did: String?,
        nonce: String?,
        isRetry: Bool
    ) async throws -> ClientAssertionResponse {
        let assertionURL = backendURL.appendingPathComponent("oauth/client-assertion")

        let dpopProof: String
        if let key = ephemeralKey {
            dpopProof = try await core.createDPoPProof(
                for: "POST",
                url: assertionURL.absoluteString,
                type: .tokenRequest,
                did: did,
                ephemeralKeyRawRepresentation: key.rawRepresentation,
                nonce: nonce
            )
        } else if let did {
            dpopProof = try await core.createDPoPProof(
                for: "POST",
                url: assertionURL.absoluteString,
                type: .tokenRefresh,
                did: did,
                nonce: nonce
            )
        } else {
            throw AuthError.dpopKeyError
        }

        var request = URLRequest(url: assertionURL)
        request.httpMethod = "POST"
        request.setValue(dpopProof, forHTTPHeaderField: "DPoP")
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = await core.encodeFormData(["aud": aud])
        request.timeoutInterval = 30.0

        let (data, response) = try await urlSession.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw AuthError.invalidResponse
        }

        if (200 ..< 300).contains(httpResponse.statusCode) {
            return try JSONDecoder().decode(ClientAssertionResponse.self, from: data)
        }

        let oauthError = try? JSONDecoder().decode(OAuthErrorResponse.self, from: data)
        if !isRetry,
           oauthError?.error == "use_dpop_nonce",
           let serverNonce = await core.extractNonceFromHeaders(httpResponse.allHeaderFields)
        {
            return try await fetchClientAssertionAttempt(
                aud: aud, ephemeralKey: ephemeralKey, did: did, nonce: serverNonce, isRetry: true
            )
        }

        throw ClientAssertionBackendError(
            statusCode: httpResponse.statusCode,
            code: oauthError?.error
        )
    }

    // MARK: - Token Exchange (Strategy-Specific)

    private func exchangeCodeForTokens(
        code: String,
        codeVerifier: String,
        tokenEndpoint: String,
        issuer: String,
        authServerURL: URL,
        ephemeralKey: P256.Signing.PrivateKey?,
        initialNonce: String?,
        resourceURL: URL?
    ) async throws -> TokenResponse {
        guard let url = URL(string: tokenEndpoint) else {
            throw AuthError.invalidOAuthConfiguration
        }
        guard let key = ephemeralKey else {
            throw AuthError.dpopKeyError
        }

        // Fetch client assertion from backend
        // The AS's PAR nonce is deliberately NOT sent to the backend — backend
        // nonces come only from the backend's own challenge.
        let assertionResponse = try await fetchClientAssertion(aud: issuer, ephemeralKey: key)

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 30.0

        let oauthConfig = core.oauthConfig
        var params: [String: String] = [
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": oauthConfig.redirectUri,
            "client_id": assertionResponse.clientId,
            "code_verifier": codeVerifier,
            "client_assertion": assertionResponse.clientAssertion,
            "client_assertion_type": Self.clientAssertionTypeJWTBearer,
        ]
        if let resourceURL {
            params["resource"] = resourceURL.absoluteString
        }
        request.httpBody = await core.encodeFormData(params)

        return try await sendTokenRequestWithEphemeralKey(
            request: request,
            tokenEndpoint: tokenEndpoint,
            code: code,
            codeVerifier: codeVerifier,
            key: key,
            nonce: initialNonce,
            clientAssertion: assertionResponse.clientAssertion,
            clientId: assertionResponse.clientId
        )
    }

    private func sendTokenRequestWithEphemeralKey(
        request baseRequest: URLRequest,
        tokenEndpoint: String,
        code: String,
        codeVerifier: String,
        key: P256.Signing.PrivateKey,
        nonce: String?,
        clientAssertion: String,
        clientId: String
    ) async throws -> TokenResponse {
        var request = baseRequest
        request.timeoutInterval = 30.0

        let dpopProof = try await core.createDPoPProof(
            for: "POST",
            url: tokenEndpoint,
            type: .tokenRequest,
            did: nil,
            ephemeralKeyRawRepresentation: key.rawRepresentation,
            nonce: nonce
        )
        request.setValue(dpopProof, forHTTPHeaderField: "DPoP")

        do {
            let networkService = core.networkService
            let (data, urlResponse) = try await networkService.request(request, skipTokenRefresh: true)

            guard let httpResponse = urlResponse as? HTTPURLResponse else {
                throw AuthError.invalidResponse
            }

            if (200 ..< 300).contains(httpResponse.statusCode) {
                return try JSONDecoder().decode(TokenResponse.self, from: data)
            } else if httpResponse.statusCode == 400 && nonce == nil {
                // Handle use_dpop_nonce error
                let dpopNonceHeader = await core.extractNonceFromHeaders(httpResponse.allHeaderFields)
                var isNonceError = false
                if let errorResponse = try? JSONDecoder().decode(OAuthErrorResponse.self, from: data),
                   errorResponse.error == "use_dpop_nonce"
                {
                    isNonceError = true
                }

                if isNonceError, let receivedNonce = dpopNonceHeader {
                    let newDpopProof = try await core.createDPoPProof(
                        for: "POST",
                        url: tokenEndpoint,
                        type: .tokenRequest,
                        did: nil,
                        ephemeralKeyRawRepresentation: key.rawRepresentation,
                        nonce: receivedNonce
                    )

                    var retryRequest = baseRequest
                    retryRequest.setValue(newDpopProof, forHTTPHeaderField: "DPoP")

                    let (retryData, retryResponse) = try await networkService.request(retryRequest, skipTokenRefresh: true)
                    guard let retryHttpResponse = retryResponse as? HTTPURLResponse,
                          (200 ..< 300).contains(retryHttpResponse.statusCode)
                    else {
                        throw AuthError.tokenRefreshFailed
                    }
                    return try JSONDecoder().decode(TokenResponse.self, from: retryData)
                } else {
                    throw AuthError.invalidCredentials
                }
            } else {
                throw AuthError.tokenRefreshFailed
            }
        } catch let error as NetworkError {
            throw AuthError.networkError(error)
        } catch let error as AuthError {
            throw error
        } catch {
            throw AuthError.tokenRefreshFailed
        }
    }

    // MARK: - Token Refresh (Strategy-Specific)

    private func performActualRefresh(for account: Account, session: Session) async throws -> TokenRefreshResult {
        let data: Data
        let response: HTTPURLResponse
        do {
            (data, response) = try await performTokenRefresh(for: account.did, session: session)
        } catch let error as NetworkError {
            // Transport never reached a definitive answer: the refresh token may still be valid.
            await core.refreshCircuitBreaker.recordFailure(for: account.did, kind: .network)
            throw AuthError.networkError(error)
        }

        LogManager.logError(
            "ROTATION_TRACE 2/4 token endpoint answered status=\(response.statusCode) did=\(LogManager.logDID(account.did))"
        )
        if (200 ..< 300).contains(response.statusCode) {
            let tokenResponse = try JSONDecoder().decode(TokenResponse.self, from: data)
            let newSession = Session(
                accessToken: tokenResponse.accessToken,
                refreshToken: tokenResponse.refreshToken,
                createdAt: Date(),
                expiresIn: TimeInterval(tokenResponse.expiresIn),
                tokenType: session.tokenType,
                did: account.did
            )
            // A "3/4" without its "4/4" means the successor token WAS in this
            // process when it died — faster persistence would have saved the
            // session. A "1/4" with no "2/4" means the exchange was still in
            // flight when the process ended — no persistence fix can help that
            // case.
            LogManager.logError(
                "ROTATION_TRACE 3/4 new token pair decoded in-process — persisting did=\(LogManager.logDID(account.did))"
            )
            // The server has rotated the refresh token; persistence failures are handled
            // inside (retry + pending key + in-memory) and must not fail the refresh.
            await core.persistRefreshedSession(newSession, for: account)
            LogManager.logError(
                "ROTATION_TRACE 4/4 persist call returned did=\(LogManager.logDID(account.did))"
            )
            await core.refreshCircuitBreaker.recordSuccess(for: account.did)
            return .refreshedSuccessfully
        }

        // Distinguish a definitive rejection (token consumed/revoked — never retry it)
        // from transient server trouble (safe to retry with the same token).
        if response.statusCode == 400 || response.statusCode == 401,
           let errorResponse = try? JSONDecoder().decode(OAuthErrorResponse.self, from: data),
           errorResponse.error == "invalid_grant"
        {
            // Rescue: if storage now holds a DIFFERENT refresh token than the
            // one this attempt used, another process (e.g. a notification
            // extension) won a concurrent rotation — the session is alive and
            // the invalid_grant only condemns our stale copy. Report health,
            // not death.
            if let stored = try? await core.storage.getSession(for: account.did),
               let storedRefresh = stored.refreshToken,
               storedRefresh != session.refreshToken
            {
                LogManager.logError(
                    "ROTATION_TRACE rescue: invalid_grant on a stale token but storage holds a newer session — stillValid did=\(LogManager.logDID(account.did))"
                )
                await core.refreshCircuitBreaker.recordSuccess(for: account.did)
                return .stillValid
            }

            LogManager.logError(
                "Token refresh definitively rejected (invalid_grant) for DID: \(LogManager.logDID(account.did))"
            )
            await core.refreshCircuitBreaker.recordFailure(for: account.did, kind: .invalidGrant)

            // Truthful death: the token family is dead server-side — leave local
            // storage agreeing with the broadcast event so storage-based checks
            // reach the same verdict the app was just told. Same steps as
            // logout() minus the pointless revocation of a dead token; the
            // account record survives for login prefill, only the current
            // pointer clears.
            try? await core.storage.deleteSession(for: account.did)
            try? await core.storage.deleteDPoPKey(for: account.did)
            try? await core.storage.saveDPoPNonces([:], for: account.did)
            await core.accountManager.clearCurrentAccount()
            LogManager.logError(
                "AUTH_LOGOUT did=\(LogManager.logDID(account.did)) reason=invalid_grant"
            )
            LogManager.logAuthIncident(
                "RefreshInvalidGrant",
                details: [
                    "did": account.did,
                    "status": response.statusCode,
                    "error": errorResponse.error,
                ]
            )
            throw AuthError.invalidCredentials
        }

        let kind: RefreshCircuitBreaker.RefreshFailureKind = (500 ..< 600).contains(response.statusCode) ? .server : .other
        await core.refreshCircuitBreaker.recordFailure(for: account.did, kind: kind)
        throw AuthError.tokenRefreshFailed
    }

    private func performTokenRefresh(for did: String, session: Session) async throws -> (Data, HTTPURLResponse) {
        let accountManager = core.accountManager
        guard let account = await accountManager.getAccount(did: did),
              let metadata = account.authorizationServerMetadata,
              let refreshToken = session.refreshToken
        else {
            throw AuthError.tokenRefreshFailed
        }

        guard let endpointURL = URL(string: metadata.tokenEndpoint) else {
            throw AuthError.tokenRefreshFailed
        }

        // Fetch client assertion from backend
        let assertionResponse = try await fetchClientAssertion(aud: metadata.issuer, did: did)

        var request = URLRequest(url: endpointURL)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 30.0

        let params = [
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
            "client_id": assertionResponse.clientId,
            "client_assertion": assertionResponse.clientAssertion,
            "client_assertion_type": Self.clientAssertionTypeJWTBearer,
        ]
        request.httpBody = await core.encodeFormData(params)

        let proof = try await core.createDPoPProof(
            for: "POST", url: metadata.tokenEndpoint, type: .tokenRefresh, did: did
        )
        request.setValue(proof, forHTTPHeaderField: "DPoP")

        // ROTATION_TRACE: four error-level breadcrumbs bracket every rotation
        // so a device log pull shows exactly where an interrupted process lost
        // one (refresh tokens are single-use: a rotation that is consumed
        // server-side but never persisted client-side strands the session).
        // Deliberately logError — info-level does not persist on device.
        LogManager.logError(
            "ROTATION_TRACE 1/4 token-endpoint POST attempt=1 (token may be consumed from here) did=\(LogManager.logDID(did))"
        )
        let networkService = core.networkService
        let (data, response) = try await networkService.request(request, skipTokenRefresh: true)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw AuthError.invalidResponse
        }

        // Handle nonce mismatch with retry
        if httpResponse.statusCode == 400 {
            if let errorResponse = try? JSONDecoder().decode(OAuthErrorResponse.self, from: data),
               errorResponse.error == "use_dpop_nonce",
               let receivedNonce = await core.extractNonceFromHeaders(httpResponse.allHeaderFields)
            {
                // Update nonce and retry
                if let domain = endpointURL.host?.lowercased() {
                    await core.updateDPoPNonceInternal(domain: domain, nonce: receivedNonce, for: did)
                }

                let retryProof = try await core.createDPoPProof(
                    for: "POST", url: metadata.tokenEndpoint, type: .tokenRefresh, did: did
                )
                var retryRequest = request
                retryRequest.setValue(retryProof, forHTTPHeaderField: "DPoP")

                LogManager.logError(
                    "ROTATION_TRACE 1/4 token-endpoint POST attempt=2 (nonce retry — consuming attempt) did=\(LogManager.logDID(did))"
                )
                let (retryData, retryResponse) = try await networkService.request(retryRequest, skipTokenRefresh: true)
                guard let retryHttpResponse = retryResponse as? HTTPURLResponse else {
                    throw AuthError.invalidResponse
                }
                return (retryData, retryHttpResponse)
            }
        }

        return (data, httpResponse)
    }

    // MARK: - Progress Helpers

    private func emitProgress(_ event: AuthProgressEvent) async {
        await progressDelegate?.authenticationProgress(event)
    }
}

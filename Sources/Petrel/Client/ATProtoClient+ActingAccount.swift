//
//  ATProtoClient+ActingAccount.swift
//  Petrel
//

import Foundation

public extension ATProtoClient {
    /// Performs a request authenticated as `did` rather than as the current account.
    ///
    /// Intended for the case where a client must act for a second account without
    /// leaving the one the user is looking at — publishing a post from another
    /// identity, say. The current-account pointer is untouched, so requests running
    /// concurrently outside this call keep their own signing identity.
    ///
    /// `did` must already be stored on this device (logged in at some point and not
    /// removed since); an unknown DID throws `AuthError.noActiveAccount` rather than
    /// falling back to the current account. Passing `nil` is the same as calling
    /// `networkService.performRequest` directly.
    ///
    /// - Parameters:
    ///   - request: A fully-formed request. Its URL is used as given — point it at the
    ///     acting account's PDS, which is not necessarily the current account's.
    ///   - did: The account to authenticate as, or `nil` for the current account.
    ///   - skipTokenRefresh: Skips the prepare-side refresh, as on the plain call.
    func performRequest(
        _ request: URLRequest,
        as did: String?,
        skipTokenRefresh: Bool = false
    ) async throws -> (Data, HTTPURLResponse) {
        try await PetrelActingAccount.$did.withValue(did) {
            try await networkService.performRequest(request, skipTokenRefresh: skipTokenRefresh)
        }
    }
}

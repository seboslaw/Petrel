//
//  ActingAccount.swift
//  Petrel
//
//  Pins the account whose stored session authenticates the requests made inside a
//  task, independently of which account is currently *active*.
//

import Foundation

/// The account a request is authenticated as, for the duration of one task.
///
/// Petrel normally answers "who is this request from?" with `AccountManager`'s current
/// account — a process-wide pointer persisted in storage. That is right for a client
/// that shows one account at a time, but it cannot express "publish this post as a
/// second account while the app stays on the first": switching the pointer would
/// re-sign every *other* in-flight request as the wrong account, and a second
/// `ATProtoClient` is no escape because both instances share `saveCurrentDID`.
///
/// Binding this task-local pins account resolution for the calls made inside it —
/// request signing (DPoP proof, access token) and token refresh alike — while
/// leaving the current-account pointer untouched. Sessions, DPoP keys, nonces and
/// refresh coordinators are all keyed by DID already, so nothing downstream needs
/// to know which account it is serving.
///
/// Task-locals propagate across `await`s, actor hops and child tasks of the binding
/// task, which is exactly the reach a request needs. They do NOT propagate into
/// `Task.detached`; the request pipeline has none between `performRequest` and the
/// signing step.
///
/// ```swift
/// try await PetrelActingAccount.$did.withValue(otherDID) {
///     try await client.networkService.performRequest(request, skipTokenRefresh: false)
/// }
/// ```
///
/// A `nil` binding (the default) means "whichever account is current" — the
/// pre-existing behaviour.
public enum PetrelActingAccount {
    /// DID to authenticate as, or `nil` for the current account.
    @TaskLocal public static var did: String?
}

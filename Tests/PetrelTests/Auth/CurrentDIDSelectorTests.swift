//
//  CurrentDIDSelectorTests.swift
//  PetrelTests
//
//  Clearing the current-account selector has to actually clear it. Sign-out,
//  account removal and switching away from the last account all express "no
//  current account" by saving an empty DID.
//

import Foundation
@testable import Petrel
import Testing

private let selectorDID = "did:plc:selector"

@Suite("Current DID selector", .serialized)
struct CurrentDIDSelectorTests {
    @Test("Saving an empty DID clears the selector instead of storing an empty value")
    func emptyDIDClearsSelector() async throws {
        let backend = InMemorySecureStorage()
        try await withSerializedStorageOverrideTest {
            KeychainManager._setStorageOverride(backend)
            defer { KeychainManager._setStorageOverride(nil) }

            let storage = KeychainStorage(namespace: "test.currentdid.clear")
            try await storage.saveCurrentDID(selectorDID)
            #expect(try await storage.getCurrentDID() == selectorDID)

            // Storing zero bytes does not round-trip: the keychain returns no data for an
            // empty item, so the store's read-back verification threw and the previous DID
            // survived the sign-out. Clearing must delete.
            try await storage.saveCurrentDID("")

            #expect(try await storage.getCurrentDID() == nil)
        }
    }

    @Test("Clearing a selector that was never set is not an error")
    func clearingAbsentSelectorSucceeds() async throws {
        let backend = InMemorySecureStorage()
        try await withSerializedStorageOverrideTest {
            KeychainManager._setStorageOverride(backend)
            defer { KeychainManager._setStorageOverride(nil) }

            let storage = KeychainStorage(namespace: "test.currentdid.absent")
            try await storage.saveCurrentDID("")
            #expect(try await storage.getCurrentDID() == nil)
        }
    }
}

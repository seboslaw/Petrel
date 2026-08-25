import Foundation
#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif
@testable import Petrel
import Testing

// MARK: - Fixtures

private let testDID = "did:plc:backuplockstep"

private func makeAccount() -> Account {
    Account(did: testDID, handle: "lockstep.example", pdsURL: URL(string: "https://pds.test")!)
}

private func makeSession(refreshToken: String, createdAt: Date) -> Session {
    Session(
        accessToken: "access-\(refreshToken)",
        refreshToken: refreshToken,
        createdAt: createdAt,
        expiresIn: 3600,
        tokenType: .dpop,
        did: testDID
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

/// Removes an item behind the storage layer's back — the shape of the silent
/// keychain item loss observed on iOS-app-on-Mac, where persisted items became
/// unfindable with no delete ever issued.
private func silentlyLose(_ key: String, namespace: String, backend: InMemorySecureStorage) throws {
    try backend.delete(key: key, namespace: namespace, accessGroup: nil)
    KeychainManager.clearCache()
}

// MARK: - Tests

/// Session/account backups are kept in LOCKSTEP with every successful save
/// instead of being deleted on success.
///
/// The backups used to be rollback snapshots of the previous state, removed
/// once a save verified. When a primary item later vanished silently (observed
/// repeatedly on iOS-app-on-Mac), recovery could only ever find a STALE
/// session — and replaying its already-consumed single-use refresh token makes
/// the authorization server treat it as theft and revoke the whole token
/// family. A lockstep shadow turns that recovery into a genuine rescue.
@Suite("Session backup lockstep", .serialized)
struct SessionBackupLockstepTests {
    @Test("A successful save leaves a backup in place")
    func successfulSaveLeavesABackup() async throws {
        let backend = InMemorySecureStorage()
        try await withInMemoryBackend(backend) {
            let namespace = "test.lockstep.exists"
            let storage = KeychainStorage(namespace: namespace)
            let base = Date()

            try await storage.saveSession(makeSession(refreshToken: "rt-1", createdAt: base), for: testDID)

            // Before the lockstep change this was deleted as part of the
            // success cleanup, leaving silent primary loss unrecoverable.
            #expect(
                backend.peek(key: "session.backup.\(testDID)", namespace: namespace) != nil,
                "The backup must survive a successful save"
            )
        }
    }

    @Test("Silent primary loss recovers the CURRENT session, not a stale one")
    func silentPrimaryLossRecoversCurrentSession() async throws {
        let backend = InMemorySecureStorage()
        try await withInMemoryBackend(backend) {
            let namespace = "test.lockstep.silentloss"
            let storage = KeychainStorage(namespace: namespace)
            let base = Date()

            // Two rotations land normally…
            try await storage.saveSession(makeSession(refreshToken: "rt-1", createdAt: base), for: testDID)
            try await storage.saveSession(
                makeSession(refreshToken: "rt-2", createdAt: base.addingTimeInterval(60)), for: testDID
            )

            // …then the primary vanishes with no write and no delete.
            try silentlyLose("session.\(testDID)", namespace: namespace, backend: backend)

            let recovered = try await storage.getSession(for: testDID)
            #expect(
                recovered?.refreshToken == "rt-2",
                "Recovery must serve the CURRENT session — a stale one replays a consumed refresh token and the AS revokes the family"
            )
        }
    }

    @Test("Silent loss after an atomic account+session save recovers the current pair")
    func silentLossAfterAccountAndSessionSave() async throws {
        let backend = InMemorySecureStorage()
        try await withInMemoryBackend(backend) {
            let namespace = "test.lockstep.accountsession"
            let storage = KeychainStorage(namespace: namespace)
            let base = Date()
            let account = makeAccount()

            try await storage.saveAccountAndSession(
                account, session: makeSession(refreshToken: "rt-1", createdAt: base), for: testDID
            )
            try await storage.saveAccountAndSession(
                account, session: makeSession(refreshToken: "rt-2", createdAt: base.addingTimeInterval(60)),
                for: testDID
            )

            // Both backups are in lockstep with the just-verified state.
            #expect(backend.peek(key: "account.backup.\(testDID)", namespace: namespace) != nil)
            #expect(backend.peek(key: "session.backup.\(testDID)", namespace: namespace) != nil)

            try silentlyLose("session.\(testDID)", namespace: namespace, backend: backend)

            let recovered = try await storage.getSession(for: testDID)
            #expect(recovered?.refreshToken == "rt-2")
        }
    }

    @Test("A failed save still rolls back to the previous state")
    func failedSaveStillRollsBack() async throws {
        let backend = InMemorySecureStorage()
        try await withInMemoryBackend(backend) {
            let namespace = "test.lockstep.rollback"
            let storage = KeychainStorage(namespace: namespace)
            let base = Date()

            try await storage.saveSession(makeSession(refreshToken: "rt-1", createdAt: base), for: testDID)

            // The primary write fails mid-save; temp/backup/pending keys are
            // untouched by the script (exact-match on the primary key).
            backend.failStoreMatching = { $0 == "session.\(testDID)" }
            await #expect(throws: (any Error).self) {
                try await storage.saveSession(
                    makeSession(refreshToken: "rt-2", createdAt: base.addingTimeInterval(60)), for: testDID
                )
            }
            backend.failStoreMatching = nil
            KeychainManager.clearCache()

            // Rollback semantics are unchanged by the lockstep: the previous
            // session is what a read serves after the failed write.
            let current = try await storage.getSession(for: testDID)
            #expect(current?.refreshToken == "rt-1")
        }
    }

    @Test("A temp-write failure does not destroy the shadow")
    func tempWriteFailureKeepsTheShadow() async throws {
        let backend = InMemorySecureStorage()
        try await withInMemoryBackend(backend) {
            let namespace = "test.lockstep.tempfail"
            let storage = KeychainStorage(namespace: namespace)
            let base = Date()

            try await storage.saveSession(makeSession(refreshToken: "rt-1", createdAt: base), for: testDID)

            backend.failStoreMatching = { $0 == "session.temp.\(testDID)" }
            await #expect(throws: (any Error).self) {
                try await storage.saveSession(
                    makeSession(refreshToken: "rt-2", createdAt: base.addingTimeInterval(60)), for: testDID
                )
            }
            backend.failStoreMatching = nil
            KeychainManager.clearCache()

            // The shadow of the intact primary must survive the hiccup: it is the
            // copy that rescues a later silent primary loss.
            #expect(backend.peek(key: "session.backup.\(testDID)", namespace: namespace) != nil)
            try silentlyLose("session.\(testDID)", namespace: namespace, backend: backend)
            let recovered = try await storage.getSession(for: testDID)
            #expect(recovered?.refreshToken == "rt-1")
        }
    }

    @Test("Logout still removes the lockstep shadow")
    func logoutRemovesTheShadow() async throws {
        let backend = InMemorySecureStorage()
        try await withInMemoryBackend(backend) {
            let namespace = "test.lockstep.logout"
            let storage = KeychainStorage(namespace: namespace)

            try await storage.saveSession(makeSession(refreshToken: "rt-gone", createdAt: Date()), for: testDID)
            #expect(backend.peek(key: "session.backup.\(testDID)", namespace: namespace) != nil)

            try await storage.deleteSession(for: testDID)

            #expect(
                backend.peek(key: "session.backup.\(testDID)", namespace: namespace) == nil,
                "deleteSession must clear the shadow — no recovery path may resurrect a deleted session"
            )
            let resurrected = try await storage.getSession(for: testDID)
            #expect(resurrected == nil)
        }
    }
}

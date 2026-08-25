#if os(iOS) || os(macOS)

import Foundation
import Security
import Testing
@testable import Petrel

@Suite("Apple Keychain Store")
struct AppleKeychainStoreTests {
    @Test("replacement failure preserves the existing item without deleting")
    func replacementFailureIsAtomic() {
        let recorder = KeychainOperationRecorder(updateStatuses: [-50])
        let store = AppleKeychainStore(operations: recorder.operations)

        #expect(throws: KeychainError.self) {
            try store.store(key: "session", value: Data("new".utf8), namespace: "test", accessGroup: "group.test")
        }
        #expect(recorder.calls == [.update])
        #expect(recorder.lastUpdateData == Data("new".utf8))
    }

    @Test("absent item uses add")
    func absentItemUsesAdd() throws {
        let recorder = KeychainOperationRecorder(updateStatuses: [errSecItemNotFound], addStatuses: [errSecSuccess])
        let store = AppleKeychainStore(operations: recorder.operations)

        try store.store(key: "session", value: Data("new".utf8), namespace: "test", accessGroup: nil)

        #expect(recorder.calls == [.update, .add, .copy])
    }

    @Test("duplicate add retries update")
    func duplicateAddRetriesUpdate() throws {
        let recorder = KeychainOperationRecorder(updateStatuses: [errSecItemNotFound, errSecSuccess], addStatuses: [errSecDuplicateItem])
        let store = AppleKeychainStore(operations: recorder.operations)

        try store.store(key: "session", value: Data("new".utf8), namespace: "test", accessGroup: nil)

        #expect(recorder.calls == [.update, .add, .update, .copy])
    }

    @Test("successful replacement only updates, then verifies")
    func successfulReplacementOnlyUpdates() throws {
        let recorder = KeychainOperationRecorder(updateStatuses: [errSecSuccess])
        let store = AppleKeychainStore(operations: recorder.operations)

        try store.store(key: "session", value: Data("new".utf8), namespace: "test", accessGroup: nil)

        #expect(recorder.calls == [.update, .copy])
    }

    @Test("a write the store cannot read back fails loudly")
    func invisibleWriteFailsLoudly() {
        // The write reports success but the immediate read-back finds nothing —
        // the exact shape of the observed iOS-app-on-Mac silent item loss. A
        // store() that swallows this returns "saved" for a session that is
        // already gone.
        let recorder = KeychainOperationRecorder(updateStatuses: [errSecSuccess], copyStatuses: [errSecItemNotFound])
        let store = AppleKeychainStore(operations: recorder.operations)

        #expect(throws: KeychainError.self) {
            try store.store(key: "session", value: Data("new".utf8), namespace: "test", accessGroup: nil)
        }
        #expect(recorder.calls == [.update, .copy])
    }

    @Test("a read-back that returns different bytes fails loudly")
    func mismatchedReadBackFailsLoudly() {
        let recorder = KeychainOperationRecorder(updateStatuses: [errSecSuccess], copyData: Data("other".utf8))
        let store = AppleKeychainStore(operations: recorder.operations)

        #expect(throws: KeychainError.self) {
            try store.store(key: "session", value: Data("new".utf8), namespace: "test", accessGroup: nil)
        }
        #expect(recorder.calls == [.update, .copy])
    }
}

private final class KeychainOperationRecorder: @unchecked Sendable {
    enum Call: Equatable { case update, add, delete, copy }

    private(set) var calls: [Call] = []
    private(set) var lastUpdateData: Data?
    private var updateStatuses: [OSStatus]
    private var addStatuses: [OSStatus]
    private var copyStatuses: [OSStatus]
    /// What the read-back verification finds. Defaults to the last written data
    /// (an honest store); scripting something else simulates a store whose
    /// reads do not see its own writes.
    private var copyData: Data?
    private var lastWrittenData: Data?

    init(
        updateStatuses: [OSStatus] = [],
        addStatuses: [OSStatus] = [],
        copyStatuses: [OSStatus] = [],
        copyData: Data? = nil
    ) {
        self.updateStatuses = updateStatuses
        self.addStatuses = addStatuses
        self.copyStatuses = copyStatuses
        self.copyData = copyData
    }

    var operations: AppleKeychainStore.Operations {
        AppleKeychainStore.Operations(
            update: { [self] _, attributes in
                calls.append(.update)
                lastUpdateData = (attributes as NSDictionary)[kSecValueData as String] as? Data
                lastWrittenData = lastUpdateData
                return updateStatuses.isEmpty ? errSecSuccess : updateStatuses.removeFirst()
            },
            add: { [self] query, _ in
                calls.append(.add)
                lastWrittenData = (query as NSDictionary)[kSecValueData as String] as? Data
                return addStatuses.isEmpty ? errSecSuccess : addStatuses.removeFirst()
            },
            delete: { [self] _ in
                calls.append(.delete)
                return errSecSuccess
            },
            copyMatching: { [self] _, result in
                calls.append(.copy)
                let status = copyStatuses.isEmpty ? errSecSuccess : copyStatuses.removeFirst()
                if status == errSecSuccess, let data = copyData ?? lastWrittenData {
                    result?.pointee = data as CFData
                }
                return status
            }
        )
    }
}

#endif

import Foundation
@testable import Petrel
import Synchronization
import Testing

/// Records the background activity the registry holds for one DID, in order with the
/// exchange's own steps. Flights for other DIDs (other suites run in parallel against the
/// same process-wide registry) get a no-op activity and are not recorded.
private final class ActivityLog: Sendable {
    let did: String
    private let events = Mutex<[String]>([])

    init(did: String) {
        self.did = did
    }

    func record(_ event: String) {
        events.withLock { $0.append(event) }
    }

    var recorded: [String] {
        events.withLock { $0 }
    }

    var begin: @Sendable (String) -> @Sendable () -> Void {
        { [self] flightDID in
            guard flightDID == did else { return {} }
            record("activity begins")
            return { [self] in record("activity ends") }
        }
    }
}

private func withActivityLog(
    did: String, _ body: (ActivityLog) async throws -> Void
) async throws {
    let log = ActivityLog(did: did)
    await RefreshFlightRegistry.shared.setBeginActivityForTesting(log.begin)
    do {
        try await body(log)
    } catch {
        await RefreshFlightRegistry.shared.setBeginActivityForTesting(nil)
        throw error
    }
    await RefreshFlightRegistry.shared.setBeginActivityForTesting(nil)
}

private struct ExchangeFailed: Error {}

/// The background activity around refresh-token exchanges.
///
/// The auth server rotates the moment it accepts the consuming POST; if the process is
/// suspended before the successor is saved, the next refresh replays the consumed token and
/// the server revokes the whole token family. Observed 2026-10-07 (Skeets 1.32.1): the app was
/// backgrounded seconds after the POST and came back to `invalid_grant: "Refresh token
/// replayed"`. Each flight therefore holds a background activity from before the exchange
/// until it has finished.
@Suite("Refresh background activity", .serialized)
struct RotationActivityTests {
    @Test("The activity spans the whole exchange")
    func activitySpansTheExchange() async throws {
        try await withActivityLog(did: "did:plc:rotationactivity-spans") { log in
            let result = try await RefreshFlightRegistry.shared.run(for: log.did) {
                log.record("exchange starts")
                try await Task.sleep(for: .milliseconds(20))
                log.record("exchange saved")
                return .refreshedSuccessfully
            }
            #expect(result == .refreshedSuccessfully)
            #expect(log.recorded == ["activity begins", "exchange starts", "exchange saved", "activity ends"])
        }
    }

    @Test("The activity ends when the exchange fails")
    func activityEndsOnFailure() async throws {
        try await withActivityLog(did: "did:plc:rotationactivity-fails") { log in
            await #expect(throws: ExchangeFailed.self) {
                _ = try await RefreshFlightRegistry.shared.run(for: log.did) {
                    log.record("exchange starts")
                    throw ExchangeFailed()
                }
            }
            #expect(log.recorded == ["activity begins", "exchange starts", "activity ends"])
        }
    }

    @Test("A caller that joins a flight starts no second activity")
    func joinedCallerStartsNoActivity() async throws {
        try await withActivityLog(did: "did:plc:rotationactivity-join") { log in
            let started = AsyncBarrier()
            let release = AsyncBarrier()
            let joined = AsyncBarrier()
            await RefreshFlightRegistry.shared.setOnJoinForTesting { did in
                if did == log.did {
                    joined.signal()
                }
            }

            let first = Task {
                try await RefreshFlightRegistry.shared.run(for: log.did) {
                    log.record("exchange starts")
                    started.signal()
                    try await release.waitUntilSignaled()
                    return TokenRefreshResult.refreshedSuccessfully
                }
            }
            try await started.waitUntilSignaled()
            let second = Task {
                try await RefreshFlightRegistry.shared.run(for: log.did) {
                    log.record("second exchange")
                    return TokenRefreshResult.refreshedSuccessfully
                }
            }
            try await joined.waitUntilSignaled()
            await RefreshFlightRegistry.shared.setOnJoinForTesting(nil)
            release.signal()

            #expect(try await first.value == .refreshedSuccessfully)
            #expect(try await second.value == .refreshedSuccessfully)
            #expect(log.recorded == ["activity begins", "exchange starts", "activity ends"])
        }
    }

    @Test("Beginning the system activity does not hold up the caller, and it can be ended")
    func systemActivityBeginsAndEnds() async throws {
        // `performExpiringActivity` runs its block on a queue of its own; the caller only
        // waits for the exchange, never for the activity.
        for _ in 0 ..< 3 {
            let end = RotationActivity.begin(for: "did:plc:rotationactivity-system")
            try await Task.sleep(for: .milliseconds(10))
            end()
        }
    }
}

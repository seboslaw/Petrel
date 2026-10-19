// RefreshCircuitBreakerTests.swift
// Petrel

import Foundation
@testable import Petrel
import Testing

@Suite("RefreshCircuitBreaker Tests")
struct RefreshCircuitBreakerTests {
    @Test("Releasing an unresolved half-open test lets the next test through")
    func releaseUnresolvedHalfOpenTest() async {
        let breaker = RefreshCircuitBreaker()
        let did = "did:plc:halfopen-release"
        for _ in 0 ..< 3 {
            await breaker.recordFailure(for: did, kind: .network)
        }
        #expect(await breaker.forceHalfOpen(for: did))

        #expect(await breaker.canAttemptRefresh(for: did), "the first caller takes the test slot")
        #expect(await breaker.canAttemptRefresh(for: did) == false, "the slot is held while the test runs")

        await breaker.releaseUnresolvedHalfOpenTest(for: did)
        #expect(await breaker.canAttemptRefresh(for: did), "a released slot can be taken again")
        #expect(await breaker.getState(for: did) == .halfOpen)
    }

    @Test("Releasing after a recorded verdict changes nothing")
    func releaseAfterVerdictIsNoOp() async {
        let breaker = RefreshCircuitBreaker()
        let did = "did:plc:halfopen-verdict"
        for _ in 0 ..< 3 {
            await breaker.recordFailure(for: did, kind: .network)
        }
        _ = await breaker.forceHalfOpen(for: did)
        _ = await breaker.canAttemptRefresh(for: did)
        await breaker.recordFailure(for: did, kind: .network)

        await breaker.releaseUnresolvedHalfOpenTest(for: did)
        #expect(await breaker.getState(for: did) == .open)
        #expect(await breaker.canAttemptRefresh(for: did) == false, "a failed test re-opens the circuit and its backoff applies")
    }

    @Test("Reset for DID clears failure tracking and allows refresh")
    func resetForDIDAllowsRefresh() async {
        let breaker = RefreshCircuitBreaker()
        let did = "did:plc:test123"

        // Record enough failures to open circuit
        await breaker.recordFailure(for: did, kind: .invalidGrant) // +1
        await breaker.recordFailure(for: did, kind: .invalidGrant) // +1
        await breaker.recordFailure(for: did, kind: .network) // +1 = 3, circuit opens

        // Verify circuit is open
        let canRefreshBeforeReset = await breaker.canAttemptRefresh(for: did)
        #expect(canRefreshBeforeReset == false)

        // Reset the circuit
        await breaker.reset(for: did)

        // Verify circuit is now closed and allows refresh
        let canRefreshAfterReset = await breaker.canAttemptRefresh(for: did)
        #expect(canRefreshAfterReset == true)

        // Verify state is closed
        let state = await breaker.getState(for: did)
        #expect(state == .closed)
    }

    @Test("forceHalfOpen transitions open circuit to half-open for recovery test")
    func forceHalfOpenTransition() async {
        let breaker = RefreshCircuitBreaker()
        let did = "did:plc:test456"

        // Open the circuit (3 failures needed)
        await breaker.recordFailure(for: did, kind: .invalidGrant) // +1
        await breaker.recordFailure(for: did, kind: .invalidGrant) // +1
        await breaker.recordFailure(for: did, kind: .network) // +1 = 3

        // Verify circuit is open
        let initialState = await breaker.getState(for: did)
        #expect(initialState == .open)

        // Force transition to half-open
        let transitioned = await breaker.forceHalfOpen(for: did)
        #expect(transitioned == true)

        // Verify state is now half-open
        let newState = await breaker.getState(for: did)
        #expect(newState == .halfOpen)

        // Should now allow one refresh attempt
        let canRefresh = await breaker.canAttemptRefresh(for: did)
        #expect(canRefresh == true)
    }

    @Test("invalidGrant counts as 1 failure, not 2")
    func invalidGrantCountsAsOne() async {
        let breaker = RefreshCircuitBreaker()
        let did = "did:plc:weight-test"

        // Record 2 invalidGrant failures
        await breaker.recordFailure(for: did, kind: .invalidGrant)
        await breaker.recordFailure(for: did, kind: .invalidGrant)

        // Circuit should still be closed (need 3 failures)
        let stateAfterTwo = await breaker.getState(for: did)
        #expect(stateAfterTwo == .closed)

        // Can still attempt refresh
        let canRefresh = await breaker.canAttemptRefresh(for: did)
        #expect(canRefresh == true)

        // Third failure opens circuit
        await breaker.recordFailure(for: did, kind: .invalidGrant)
        let stateAfterThree = await breaker.getState(for: did)
        #expect(stateAfterThree == .open)
    }
}

# Provenance: @claude, 2026-09-18. These scenarios are written from the ask in
# issue #62 (measured on the appliance proving run of 2026-09-17: with the
# policy store stopped, /healthz answered 200, a policy write hung for eight
# seconds with no answer, and the log had no line about the store), in the
# operator language the issue used: a launcher check, a store that is down, a
# write that hangs. Decisions continuing from memory is the behaviour the
# issue names as right, and one scenario below holds it in place.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: A launcher check can tell "deciding from memory" from "healthy"

  Scenario: readiness says the store is unreachable when the store refuses
    Given wardryx is serving and its policy store refuses connections
    When a launcher asks GET /readyz with no credential
    Then the answer is 503 and the body names the store as unreachable
    # -> internal/api:TestReadyzAnswers503WhenTheStoreRefuses

  Scenario: readiness says the store is unreachable when the store hangs, within the deadline
    Given the policy store accepts connections but never answers
    When a launcher asks GET /readyz
    Then the answer is 503 within the store deadline, never a hang
    # -> internal/api:TestReadyzAnswers503WithinTheDeadlineWhenTheStoreHangs

  Scenario: readiness is 200 when the store answers
    Given the policy store answers its ping
    When a launcher asks GET /readyz
    Then the answer is 200 and the body says the store is ok
    # -> internal/api:TestReadyzAnswers200WhenTheStoreAnswers

  Scenario: liveness stays 200 and decisions continue from memory while the store is down
    Given the policy store is down
    When a launcher asks GET /healthz and an agent asks POST /v1/decide
    Then /healthz still answers 200
    And the decision is still answered from the policy set already in memory
    # -> internal/api:TestHealthzAndDecisionsStayUpWhileTheStoreIsDown

  Scenario: the readiness route ignores hostile input
    Given a caller sends the readiness route a wrong method, a body, a query string, or a garbage bearer header
    When each request is handled
    Then a wrong method is 405, the rest are answered by the store's state alone
    And no body echoes the input or carries the store's own error text
    # -> internal/api:TestReadyzIgnoresHostileInput

  Scenario: the built binary declares its ready path and answers it
    Given the built wardryx binary started with the in-memory store
    When the path components.json declares as ready_path is asked with no credential
    Then it answers 200
    # -> internal/manifest:TestItStartsAndRefusesUnauthenticatedCalls

Feature: A policy write against a store that is down is refused within seconds, never left hanging

  Scenario: a policy write on a store that hangs answers 503 within the deadline
    Given the policy store accepts connections but never answers
    When an admin sends PUT /v1/policies/{id} or DELETE /v1/policies/{id}
    Then the answer is 503 within the store deadline, with a reason naming the store
    And the policy set in force is unchanged
    # -> internal/api:TestAPolicyWriteOnAHangingStoreAnswers503InsteadOfHanging

  Scenario: a policy write on a store that refuses connections answers 503 with a reason
    Given the policy store refuses connections
    When an admin sends PUT /v1/policies/{id}
    Then the answer is 503 with a reason naming the store
    And the body carries none of the driver's own error text
    # -> internal/api:TestAPolicyWriteOnARefusingStoreAnswers503WithAReason

  Scenario: a write the store loses after the list leaves the live set and the store as they were
    Given the policy store lists its policies and then loses the connection on the write itself
    When an admin sends PUT /v1/policies/{id} or DELETE /v1/policies/{id}
    Then the answer is 503 with a reason naming the store
    And nothing is half-written: the policy set in force and the stored policies are unchanged
    # -> internal/api:TestAWriteThatFailsAfterTheListAnswers503AndLeavesTheLiveSetAlone

  Scenario: an outage is logged once, not once per request
    Given the policy store is down and several writes and readiness probes arrive
    When the log is read
    Then there is one line saying the store is unreachable
    And one line when it is reachable again, and nothing in between
    # -> internal/api:TestAStoreOutageIsLoggedOncePerOutageNotPerRequest

  Scenario: a store failure that is not about reachability is still a 500
    Given the policy store answers a write with a failure of its own, not a lost connection
    When an admin sends PUT /v1/policies/{id}
    Then the answer is 500 naming the operation, as before
    And no outage is logged
    # -> internal/api:TestAStoreFailureThatIsNotAnOutageIsStillA500

Feature: The Postgres store honours a deadline, proven on the driver rather than on a double

  Scenario: a ping or a policy write against a listener that never answers returns within the deadline
    Given a TCP listener that accepts connections and never speaks Postgres
    When the Postgres store is asked to ping, list, put and delete with a short deadline
    Then each call returns soon after the deadline, with an error the API classifies as unavailable
    # -> internal/store:TestPostgresCallsReturnWithinTheDeadlineAgainstAListenerThatNeverAnswers

  Scenario: a refused connection is classified as unavailable
    Given nothing is listening on the store's port
    When the Postgres store is asked to ping
    Then it fails at once with an error the API classifies as unavailable
    # -> internal/store:TestARefusedConnectionIsUnavailable

  Scenario: the in-memory store is always reachable
    Given the in-memory store
    When it is pinged
    Then it answers
    # -> internal/store:TestMemoryPingAlwaysAnswers

  Scenario: an ordinary store error is not an outage
    Given a not-found error, or a plain error the store composed itself
    When it is classified
    Then it is not unavailable
    # -> internal/store:TestAnOrdinaryStoreErrorIsNotUnavailable

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from ipaddress import IPv4Address

import pytest
from pydantic import ValidationError

from main import (
    DecisionStatus,
    IdempotencyConflict,
    ShieldOSGateway,
    TransactionPayload,
    demo_payloads,
    route_action,
    run_benchmark,
)


def test_three_reference_routes() -> None:
    with ShieldOSGateway() as gateway:
        decisions = [gateway.decide(payload) for payload in demo_payloads()]
    assert [decision.action for decision in decisions] == [
        DecisionStatus.APPROVED,
        DecisionStatus.TRIGGER_MFA,
        DecisionStatus.HARD_BLOCK,
    ]
    assert decisions[2].hard_stop is True
    assert decisions[2].agent_signals == []


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (39.99, DecisionStatus.APPROVED),
        (40.00, DecisionStatus.TRIGGER_MFA),
        (75.00, DecisionStatus.TRIGGER_MFA),
        (75.01, DecisionStatus.HARD_BLOCK),
    ],
)
def test_router_boundaries(score: float, expected: DecisionStatus) -> None:
    action, _, _ = route_action(
        score,
        hard_stop=False,
        degraded=False,
        imsi_status_changed=False,
    )
    assert action == expected


@pytest.mark.parametrize("score", [float("nan"), float("inf"), -0.01, 100.01])
def test_router_rejects_invalid_model_scores(score: float) -> None:
    with pytest.raises(ValueError, match="score must be finite"):
        route_action(
            score,
            hard_stop=False,
            degraded=False,
            imsi_status_changed=False,
        )


def test_imsi_change_sets_mfa_floor_without_hard_stop() -> None:
    action, status, _ = route_action(
        8.0,
        hard_stop=False,
        degraded=False,
        imsi_status_changed=True,
    )
    assert (action, status) == (DecisionStatus.TRIGGER_MFA, 202)


def test_idempotent_replay_and_conflict() -> None:
    payload = demo_payloads()[0]
    with ShieldOSGateway() as gateway:
        first = gateway.decide(payload)
        second = gateway.decide(payload)
        assert first == second

        changed = payload.model_copy(update={"amount": Decimal("99.00")})
        with pytest.raises(IdempotencyConflict):
            gateway.decide(changed)


def test_replay_cache_cannot_be_mutated_by_a_caller() -> None:
    payload = demo_payloads()[0]
    with ShieldOSGateway() as gateway:
        first = gateway.decide(payload)
        first.reason_codes.append("CALLER_TAMPER")
        first.agent_signals.clear()
        first.action = DecisionStatus.HARD_BLOCK

        replay = gateway.decide(payload)

    assert replay.action == DecisionStatus.APPROVED
    assert "CALLER_TAMPER" not in replay.reason_codes
    assert replay.agent_signals


def test_model_failure_falls_back_to_mfa() -> None:
    class FailingModel:
        def predict(self, *_: object) -> None:
            raise RuntimeError("simulated inference failure")

    with ShieldOSGateway() as gateway:
        gateway._model = FailingModel()  # type: ignore[assignment]
        decision = gateway.decide(demo_payloads()[0])

    assert decision.action == DecisionStatus.TRIGGER_MFA
    assert decision.http_status == 202
    assert decision.degraded is True
    assert decision.fraud_vector == "CONTROL_PLANE_DEGRADED"
    assert "MODEL_INFERENCE_FAILURE" in decision.reason_codes
    assert next(
        stage for stage in decision.trace if stage.stage == "ensemble_inference"
    ).outcome.value == "DEGRADED"


def test_invalid_model_score_falls_back_to_mfa() -> None:
    class InvalidScoreModel:
        def predict(self, *_: object) -> tuple[float, list[str], dict[str, float]]:
            return float("nan"), [], {}

    with ShieldOSGateway() as gateway:
        gateway._model = InvalidScoreModel()  # type: ignore[assignment]
        decision = gateway.decide(demo_payloads()[0])

    assert decision.action == DecisionStatus.TRIGGER_MFA
    assert decision.degraded is True
    assert "MODEL_INFERENCE_FAILURE" in decision.reason_codes


def test_agent_failure_emits_typed_fallback_and_forces_mfa() -> None:
    class FailingIdentityAgent:
        name = "identity_device_agent"

        def evaluate(self, *_: object) -> None:
            raise RuntimeError("simulated identity dependency failure")

    with ShieldOSGateway() as gateway:
        gateway._orchestrator._agents = (  # type: ignore[assignment]
            FailingIdentityAgent(),
            *gateway._orchestrator._agents[1:],
        )
        decision = gateway.decide(demo_payloads()[0])

    assert decision.action == DecisionStatus.TRIGGER_MFA
    assert decision.degraded is True
    assert "AGENT_FAILURE:identity_device_agent" in decision.reason_codes
    fallback = next(
        signal
        for signal in decision.agent_signals
        if signal.agent == "identity_device_agent"
    )
    assert fallback.risk_score == 65
    assert fallback.confidence == 0


def test_contract_rejects_malformed_event() -> None:
    with pytest.raises(ValidationError):
        TransactionPayload(
            transaction_id="bad_event_001",
            event_time=datetime(2026, 10, 14, 9, 0),
            user_id="u_1",
            amount=Decimal("-1.00"),
            device_id="device_1",
            network_ip="999.10.10.10",
            imsi_status_changed=False,
            hourly_velocity=1,
            unknown_field=True,
        )


def test_response_does_not_expose_raw_identity_or_ip() -> None:
    payload = TransactionPayload(
        transaction_id="privacy_event_001",
        event_time=datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc),
        user_id="real-customer-reference",
        amount=Decimal("10.00"),
        device_id="device_1",
        network_ip=IPv4Address("198.51.100.7"),
        imsi_status_changed=False,
        hourly_velocity=0,
    )
    with ShieldOSGateway() as gateway:
        response_json = gateway.decide(payload).model_dump_json()
    assert "real-customer-reference" not in response_json
    assert "198.51.100.7" not in response_json


def test_pseudonym_is_keyed_and_stable_for_an_injected_key() -> None:
    payload = demo_payloads()[0]
    key_a = b"a" * 32
    key_b = b"b" * 32
    with ShieldOSGateway(pseudonym_key=key_a) as gateway_a:
        reference_a = gateway_a.decide(payload).user_reference
    with ShieldOSGateway(pseudonym_key=key_a) as gateway_a_restarted:
        replay_reference_a = gateway_a_restarted.decide(payload).user_reference
    with ShieldOSGateway(pseudonym_key=key_b) as gateway_b:
        reference_b = gateway_b.decide(payload).user_reference

    assert reference_a == replay_reference_a
    assert reference_a != reference_b


def test_benchmark_contract() -> None:
    with ShieldOSGateway() as gateway:
        result = run_benchmark(gateway, request_count=100, concurrency=4)
    assert result.request_count == 100
    assert sum(result.action_counts.values()) == 100
    assert 0 < result.p50_ms <= result.p95_ms <= result.p99_ms <= result.max_ms


def test_repeated_benchmark_does_not_measure_cached_decisions() -> None:
    class CountingModel:
        def __init__(self, delegate: object) -> None:
            self.delegate = delegate
            self.calls = 0

        def predict(self, *args: object) -> object:
            self.calls += 1
            return self.delegate.predict(*args)  # type: ignore[attr-defined]

    with ShieldOSGateway() as gateway:
        counter = CountingModel(gateway._model)
        gateway._model = counter  # type: ignore[assignment]
        run_benchmark(gateway, request_count=20, concurrency=4)
        calls_after_first_run = counter.calls
        run_benchmark(gateway, request_count=20, concurrency=4)

    assert calls_after_first_run > 0
    assert counter.calls > calls_after_first_run

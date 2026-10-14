#!/usr/bin/env python3
"""ShieldOS real-time fraud and event decisioning gateway.

The online path is deliberately deterministic. Bounded specialist agents fan out
over already hydrated signals; no generative model can alter a settlement action.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import random
import secrets
import threading
import time
import uuid
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor, wait
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import StrEnum
from ipaddress import IPv4Address
from typing import Any, Protocol

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    field_validator,
)


DECISION_SLA_MS = 45.0
MODEL_VERSION = "fraud-ensemble-surrogate-2026.10"
POLICY_VERSION = "routing-policy-1.0"
AGENT_TIMEOUT_MS = 12.0


class DecisionStatus(StrEnum):
    APPROVED = "STATUS_APPROVED"
    TRIGGER_MFA = "STATUS_TRIGGER_MFA"
    HARD_BLOCK = "STATUS_HARD_BLOCK"


class TraceOutcome(StrEnum):
    PASS = "PASS"
    DEGRADED = "DEGRADED"
    BLOCK = "BLOCK"


class TransactionPayload(BaseModel):
    """Versioned public request contract for one authorization event."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        allow_inf_nan=False,
    )

    transaction_id: str = Field(
        default_factory=lambda: f"txn_{uuid.uuid4().hex[:18]}",
        min_length=8,
        max_length=96,
        pattern=r"^[A-Za-z0-9_.:-]+$",
    )
    event_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    user_id: str = Field(min_length=3, max_length=128)
    amount: Decimal = Field(gt=0, le=10_000_000, decimal_places=2)
    currency: str = Field(default="USD", min_length=3, max_length=3)
    device_id: str = Field(min_length=3, max_length=128)
    network_ip: IPvAnyAddress
    imsi_status_changed: bool
    hourly_velocity: int = Field(ge=0, le=500)

    # Hydrated or derived online features. In production these come from a
    # versioned feature snapshot rather than untrusted caller input.
    device_trust_score: int = Field(default=75, ge=0, le=100)
    ip_reputation_risk: int = Field(default=10, ge=0, le=100)
    geo_velocity_kmh: float = Field(default=0.0, ge=0, le=20_000)
    minutes_since_last_auth: int = Field(default=60, ge=0, le=10_080)
    payment_token_compromised: bool = False
    sensitive_transaction: bool = False

    @field_validator("event_time")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event_time must include a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("currency")
    @classmethod
    def normalize_currency(cls, value: str) -> str:
        if not value.isalpha():
            raise ValueError("currency must be a three-letter ISO code")
        return value.upper()


class AgentSignal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent: str
    risk_score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    reason_codes: list[str] = Field(default_factory=list)
    evidence: dict[str, float | int | bool | str] = Field(default_factory=dict)


class StageTrace(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stage: str
    duration_ms: float = Field(ge=0)
    outcome: TraceOutcome
    details: dict[str, float | int | bool | str] = Field(default_factory=dict)


class DecisionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transaction_id: str
    trace_id: str
    user_reference: str
    aggregate_risk_score: float = Field(ge=0, le=100)
    action: DecisionStatus
    http_status: int
    fraud_vector: str
    reason_codes: list[str]
    hard_stop: bool
    degraded: bool
    model_version: str
    policy_version: str
    feature_freshness_seconds: int
    agent_signals: list[AgentSignal]
    trace: list[StageTrace]
    audit_trace_hash: str
    downstream_route: str
    processing_time_ms: float
    sla_target_ms: float = DECISION_SLA_MS
    sla_met: bool


class BenchmarkResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_count: int
    concurrency: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    throughput_rps: float
    action_counts: dict[str, int]
    sla_target_ms: float
    p99_sla_met: bool
    benchmark_scope: str


class IdempotencyConflict(ValueError):
    """Raised when one transaction ID is reused with a different payload."""


class RiskAgent(Protocol):
    name: str

    def evaluate(self, payload: TransactionPayload) -> AgentSignal: ...


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return min(high, max(low, value))


def elapsed_ms(start_ns: int) -> float:
    return (time.perf_counter_ns() - start_ns) / 1_000_000


def unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


class IdentityDeviceAgent:
    name = "identity_device_agent"

    def evaluate(self, payload: TransactionPayload) -> AgentSignal:
        score = max(
            100 - payload.device_trust_score,
            90 if payload.imsi_status_changed else 0,
        )
        reasons: list[str] = []
        if payload.device_trust_score < 60:
            reasons.append("DEVICE_TRUST_LOW")
        if payload.imsi_status_changed:
            reasons.append("SIM_IDENTITY_CHANGED")
        return AgentSignal(
            agent=self.name,
            risk_score=round(score, 4),
            confidence=0.96,
            reason_codes=reasons,
            evidence={
                "device_trust_score": payload.device_trust_score,
                "imsi_status_changed": payload.imsi_status_changed,
            },
        )


class VelocityAgent:
    name = "velocity_agent"

    def evaluate(self, payload: TransactionPayload) -> AgentSignal:
        score = 100 * (1 - math.exp(-payload.hourly_velocity / 8))
        reasons = ["VELOCITY_BURST"] if payload.hourly_velocity >= 6 else []
        return AgentSignal(
            agent=self.name,
            risk_score=round(score, 4),
            confidence=0.93,
            reason_codes=reasons,
            evidence={"hourly_velocity": payload.hourly_velocity},
        )


class NetworkAgent:
    name = "network_agent"

    def evaluate(self, payload: TransactionPayload) -> AgentSignal:
        reasons = (
            ["NETWORK_REPUTATION_HIGH_RISK"]
            if payload.ip_reputation_risk >= 60
            else []
        )
        return AgentSignal(
            agent=self.name,
            risk_score=float(payload.ip_reputation_risk),
            confidence=0.90,
            reason_codes=reasons,
            evidence={"ip_reputation_risk": payload.ip_reputation_risk},
        )


class TransactionContextAgent:
    name = "transaction_context_agent"

    def evaluate(self, payload: TransactionPayload) -> AgentSignal:
        amount = float(payload.amount)
        amount_risk = 100 / (
            1 + math.exp(-1.25 * (math.log10(max(amount, 0.01)) - 3))
        )
        geo_risk = clamp((payload.geo_velocity_kmh - 120) / 8.8)
        recency = clamp((120 - payload.minutes_since_last_auth) / 120, 0, 1)
        score = 0.55 * amount_risk + 0.45 * (geo_risk * recency)
        reasons: list[str] = []
        if payload.geo_velocity_kmh >= 800 and payload.minutes_since_last_auth <= 30:
            reasons.append("IMPOSSIBLE_TRAVEL")
        if amount >= 5_000:
            reasons.append("HIGH_VALUE_TRANSACTION")
        return AgentSignal(
            agent=self.name,
            risk_score=round(score, 4),
            confidence=0.88,
            reason_codes=reasons,
            evidence={
                "amount_risk": round(amount_risk, 4),
                "geo_risk": round(geo_risk, 4),
                "authentication_recency": round(recency, 4),
            },
        )


class AgentOrchestrator:
    """Bounded deterministic fan-out with timeout and degraded fallbacks."""

    def __init__(self, max_workers: int = 32, timeout_ms: float = AGENT_TIMEOUT_MS):
        self._agents: tuple[RiskAgent, ...] = (
            IdentityDeviceAgent(),
            VelocityAgent(),
            NetworkAgent(),
            TransactionContextAgent(),
        )
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="shieldos-agent",
        )
        self._timeout_seconds = timeout_ms / 1_000

    def evaluate(self, payload: TransactionPayload) -> tuple[list[AgentSignal], bool]:
        futures: dict[Future[AgentSignal], RiskAgent] = {
            self._executor.submit(agent.evaluate, payload): agent
            for agent in self._agents
        }
        done, pending = wait(futures, timeout=self._timeout_seconds)
        signals: list[AgentSignal] = []
        degraded = False

        for future in done:
            agent = futures[future]
            try:
                signals.append(future.result())
            except Exception as exc:  # controlled fail-safe boundary
                degraded = True
                signals.append(
                    AgentSignal(
                        agent=agent.name,
                        risk_score=65,
                        confidence=0,
                        reason_codes=[f"AGENT_FAILURE:{agent.name}"],
                        evidence={"error_type": type(exc).__name__},
                    )
                )

        for future in pending:
            agent = futures[future]
            degraded = True
            future.cancel()
            signals.append(
                AgentSignal(
                    agent=agent.name,
                    risk_score=65,
                    confidence=0,
                    reason_codes=[f"AGENT_TIMEOUT:{agent.name}"],
                        evidence={
                            "timeout_ms": round(self._timeout_seconds * 1_000, 4)
                        },
                )
            )

        return sorted(signals, key=lambda signal: signal.agent), degraded

    def close(self) -> None:
        self._executor.shutdown(wait=True, cancel_futures=True)


class EnsembleRiskModel:
    """Explainable deterministic surrogate for a versioned boosted-tree model."""

    version = MODEL_VERSION

    def predict(
        self,
        payload: TransactionPayload,
        signals: list[AgentSignal],
    ) -> tuple[float, list[str], dict[str, float]]:
        by_name = {signal.agent: signal.risk_score for signal in signals}
        identity = by_name["identity_device_agent"]
        velocity = by_name["velocity_agent"]
        network = by_name["network_agent"]
        context = by_name["transaction_context_agent"]

        linear = (
            0.28 * identity
            + 0.28 * velocity
            + 0.18 * network
            + 0.26 * context
        )
        reasons: list[str] = []
        piecewise = 5.0

        def add(condition: bool, points: float, reason: str) -> None:
            nonlocal piecewise
            if condition:
                piecewise += points
                reasons.append(reason)

        add(payload.hourly_velocity >= 6, 20, "VELOCITY_ELEVATED")
        add(payload.hourly_velocity >= 12, 18, "VELOCITY_EXTREME")
        add(payload.device_trust_score < 60, 18, "DEVICE_TRUST_LOW")
        add(payload.device_trust_score < 25, 17, "DEVICE_TRUST_CRITICAL")
        add(payload.ip_reputation_risk >= 60, 18, "NETWORK_REPUTATION_HIGH_RISK")
        add(
            payload.geo_velocity_kmh >= 800
            and payload.minutes_since_last_auth <= 30,
            22,
            "IMPOSSIBLE_TRAVEL",
        )
        add(float(payload.amount) >= 5_000, 10, "HIGH_VALUE_TRANSACTION")
        add(payload.imsi_status_changed, 25, "SIM_IDENTITY_CHANGED")
        piecewise = min(100, piecewise)

        interaction = 0.0
        if payload.hourly_velocity >= 8 and payload.device_trust_score < 50:
            interaction += 8
            reasons.append("ATO_COMPOSITE_SIGNAL")
        if payload.geo_velocity_kmh >= 800 and payload.device_trust_score < 50:
            interaction += 7
            reasons.append("GEO_DEVICE_INTERACTION")

        score = clamp(0.62 * linear + 0.38 * piecewise + interaction)
        contributions = {
            "linear_component": round(linear, 4),
            "piecewise_component": round(piecewise, 4),
            "interaction_component": round(interaction, 4),
        }
        return round(score, 4), unique(reasons), contributions


def deterministic_hard_stop(payload: TransactionPayload) -> list[str]:
    reasons: list[str] = []
    if payload.payment_token_compromised:
        reasons.append("COMPROMISED_PAYMENT_TOKEN")
    if payload.imsi_status_changed and (
        payload.sensitive_transaction
        or float(payload.amount) >= 500
        or payload.hourly_velocity >= 5
    ):
        reasons.append("SIM_SWAP_ON_SENSITIVE_TRANSACTION")
    if (
        payload.geo_velocity_kmh >= 1_500
        and payload.minutes_since_last_auth <= 30
        and payload.device_trust_score <= 25
    ):
        reasons.append("HIGH_CONFIDENCE_ATO")
    return reasons


def route_action(
    score: float,
    *,
    hard_stop: bool,
    degraded: bool,
    imsi_status_changed: bool,
) -> tuple[DecisionStatus, int, str]:
    if not math.isfinite(score) or not 0 <= score <= 100:
        raise ValueError("score must be finite and within [0, 100]")
    if hard_stop or score > 75:
        return DecisionStatus.HARD_BLOCK, 403, "fraud-operations.manual-review.v1"
    if score >= 40 or degraded or imsi_status_changed:
        return DecisionStatus.TRIGGER_MFA, 202, "identity.step-up-mfa.v1"
    return DecisionStatus.APPROVED, 200, "payments.ledger-authorize.v1"


def infer_fraud_vector(reasons: list[str]) -> str:
    if any("SIM" in reason for reason in reasons):
        return "SIM_SWAP_ANOMALY"
    if any(reason in {"HIGH_CONFIDENCE_ATO", "ATO_COMPOSITE_SIGNAL"} for reason in reasons):
        return "ACCOUNT_TAKEOVER"
    if any("VELOCITY" in reason for reason in reasons):
        return "VELOCITY_BURST"
    if any("TOKEN" in reason for reason in reasons):
        return "TOKEN_COMPROMISE"
    if any("NETWORK" in reason or "GEO" in reason for reason in reasons):
        return "NETWORK_ANOMALY"
    if any(
        reason.startswith(("AGENT_FAILURE:", "AGENT_TIMEOUT:"))
        or reason in {"MODEL_INFERENCE_FAILURE", "CONTROL_PLANE_DEGRADED_STEP_UP"}
        for reason in reasons
    ):
        return "CONTROL_PLANE_DEGRADED"
    return "CLEAN_OR_LOW_RISK"


class ShieldOSGateway:
    """Single accountable decision service with replay-safe responses."""

    def __init__(self, *, pseudonym_key: bytes | None = None) -> None:
        if pseudonym_key is not None and len(pseudonym_key) < 32:
            raise ValueError("pseudonym_key must contain at least 32 bytes")
        self._orchestrator = AgentOrchestrator()
        self._model = EnsembleRiskModel()
        # The local sandbox uses an ephemeral key. A deployed service injects a
        # stable key from its secret manager so references remain joinable
        # without exposing dictionary-attackable hashes of customer IDs.
        self._pseudonym_key = pseudonym_key or secrets.token_bytes(32)
        self._cache: dict[str, tuple[str, DecisionResponse]] = {}
        self._cache_lock = threading.Lock()

    @staticmethod
    def _payload_fingerprint(payload: TransactionPayload) -> str:
        canonical = payload.model_dump_json(exclude={"transaction_id"})
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _user_reference(self, user_id: str) -> str:
        return "usr_" + hmac.new(
            self._pseudonym_key,
            user_id.encode(),
            hashlib.sha256,
        ).hexdigest()[:16]

    @staticmethod
    def _audit_hash(
        payload: TransactionPayload,
        action: DecisionStatus,
        score: float,
        reasons: list[str],
    ) -> str:
        envelope = {
            "transaction_id": payload.transaction_id,
            "action": action.value,
            "score": score,
            "reason_codes": reasons,
            "model_version": MODEL_VERSION,
            "policy_version": POLICY_VERSION,
        }
        canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def decide(self, payload: TransactionPayload) -> DecisionResponse:
        fingerprint = self._payload_fingerprint(payload)
        with self._cache_lock:
            cached = self._cache.get(payload.transaction_id)
        if cached:
            cached_fingerprint, response = cached
            if cached_fingerprint != fingerprint:
                raise IdempotencyConflict(
                    f"transaction_id {payload.transaction_id!r} was reused with a different payload"
                )
            # Keep callers from mutating lists or dictionaries held by the
            # idempotency cache and corrupting every subsequent replay.
            return response.model_copy(deep=True)

        decision_start = time.perf_counter_ns()
        trace: list[StageTrace] = []

        rules_start = time.perf_counter_ns()
        hard_stop_reasons = deterministic_hard_stop(payload)
        hard_stop = bool(hard_stop_reasons)
        trace.append(
            StageTrace(
                stage="deterministic_rules",
                duration_ms=round(elapsed_ms(rules_start), 6),
                outcome=TraceOutcome.BLOCK if hard_stop else TraceOutcome.PASS,
                details={"rule_hits": len(hard_stop_reasons)},
            )
        )

        signals: list[AgentSignal] = []
        degraded = False
        contributions: dict[str, float] = {}
        model_reasons: list[str] = []

        if hard_stop:
            score = 100.0
        else:
            orchestration_start = time.perf_counter_ns()
            signals, degraded = self._orchestrator.evaluate(payload)
            trace.append(
                StageTrace(
                    stage="agent_orchestration",
                    duration_ms=round(elapsed_ms(orchestration_start), 6),
                    outcome=(
                        TraceOutcome.DEGRADED if degraded else TraceOutcome.PASS
                    ),
                    details={"agents_completed": len(signals)},
                )
            )

            inference_start = time.perf_counter_ns()
            try:
                score, model_reasons, contributions = self._model.predict(
                    payload, signals
                )
                if not math.isfinite(score) or not 0 <= score <= 100:
                    raise ValueError("model returned an invalid risk score")
                inference_outcome = TraceOutcome.PASS
                inference_details = contributions
            except Exception as exc:  # controlled fail-safe boundary
                score = 65.0
                degraded = True
                model_reasons = ["MODEL_INFERENCE_FAILURE"]
                contributions = {}
                inference_outcome = TraceOutcome.DEGRADED
                inference_details = {"error_type": type(exc).__name__}
            trace.append(
                StageTrace(
                    stage="ensemble_inference",
                    duration_ms=round(elapsed_ms(inference_start), 6),
                    outcome=inference_outcome,
                    details=inference_details,
                )
            )

        routing_start = time.perf_counter_ns()
        action, http_status, downstream_route = route_action(
            score,
            hard_stop=hard_stop,
            degraded=degraded,
            imsi_status_changed=payload.imsi_status_changed,
        )
        agent_reasons = [
            reason for signal in signals for reason in signal.reason_codes
        ]
        reasons = unique(hard_stop_reasons + model_reasons + agent_reasons)
        if not reasons:
            reasons = ["NO_MATERIAL_RISK_SIGNAL"]
        if degraded:
            reasons.append("CONTROL_PLANE_DEGRADED_STEP_UP")
        trace.append(
            StageTrace(
                stage="action_routing",
                duration_ms=round(elapsed_ms(routing_start), 6),
                outcome=(
                    TraceOutcome.BLOCK
                    if action == DecisionStatus.HARD_BLOCK
                    else TraceOutcome.DEGRADED
                    if degraded
                    else TraceOutcome.PASS
                ),
                details={"http_status": http_status, "policy_version": POLICY_VERSION},
            )
        )

        processing_time_ms = elapsed_ms(decision_start)
        response = DecisionResponse(
            transaction_id=payload.transaction_id,
            trace_id=f"trc_{uuid.uuid4().hex}",
            user_reference=self._user_reference(payload.user_id),
            aggregate_risk_score=round(score, 4),
            action=action,
            http_status=http_status,
            fraud_vector=infer_fraud_vector(reasons),
            reason_codes=unique(reasons),
            hard_stop=hard_stop,
            degraded=degraded,
            model_version=MODEL_VERSION,
            policy_version=POLICY_VERSION,
            feature_freshness_seconds=0,
            agent_signals=signals,
            trace=trace,
            audit_trace_hash=self._audit_hash(payload, action, score, reasons),
            downstream_route=downstream_route,
            processing_time_ms=round(processing_time_ms, 6),
            sla_met=processing_time_ms <= DECISION_SLA_MS,
        )

        with self._cache_lock:
            existing = self._cache.setdefault(
                payload.transaction_id, (fingerprint, response)
            )
        if existing[0] != fingerprint:
            raise IdempotencyConflict(
                f"transaction_id {payload.transaction_id!r} raced with a different payload"
            )
        return existing[1].model_copy(deep=True)

    def close(self) -> None:
        self._orchestrator.close()

    def __enter__(self) -> "ShieldOSGateway":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


def percentile_nearest_rank(values_ns: list[int], quantile: float) -> float:
    if not values_ns:
        raise ValueError("values_ns must contain at least one observation")
    if not 0 < quantile <= 1:
        raise ValueError("quantile must be within (0, 1]")
    ordered = sorted(values_ns)
    rank = max(1, math.ceil(quantile * len(ordered)))
    return ordered[rank - 1] / 1_000_000


def generate_benchmark_payloads(
    count: int,
    seed: int = 42,
    transaction_namespace: str | None = None,
) -> list[TransactionPayload]:
    if count < 1:
        raise ValueError("count must be at least 1")
    rng = random.Random(seed)
    base_time = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)
    namespace = transaction_namespace or f"bench_{seed}"
    payloads: list[TransactionPayload] = []
    for index in range(count):
        imsi_changed = rng.random() < 0.012
        payloads.append(
            TransactionPayload(
                transaction_id=f"{namespace}_{index:06d}",
                event_time=base_time + timedelta(milliseconds=index * 7),
                user_id=f"user_{rng.randrange(1, 25_000):05d}",
                amount=Decimal(f"{min(rng.lognormvariate(4.2, 1.1), 25000):.2f}"),
                currency="GBP",
                device_id=f"dev_{rng.randrange(1, 40_000):05d}",
                network_ip=IPv4Address(f"198.51.100.{1 + index % 253}"),
                imsi_status_changed=imsi_changed,
                hourly_velocity=min(40, int(rng.expovariate(1 / 3.8))),
                device_trust_score=rng.randint(18, 100),
                ip_reputation_risk=rng.randint(0, 92),
                geo_velocity_kmh=max(0, rng.gauss(120, 360)),
                minutes_since_last_auth=rng.randint(0, 240),
                payment_token_compromised=rng.random() < 0.004,
                sensitive_transaction=rng.random() < 0.18,
            )
        )
    return payloads


def run_benchmark(
    gateway: ShieldOSGateway,
    request_count: int = 1_000,
    concurrency: int = 8,
) -> BenchmarkResult:
    if request_count < 1:
        raise ValueError("request_count must be at least 1")
    if concurrency < 1:
        raise ValueError("concurrency must be at least 1")

    # Distinct IDs ensure repeated runs on one gateway measure execution rather
    # than idempotency-cache retrieval while preserving seeded feature values.
    benchmark_run_id = uuid.uuid4().hex[:12]
    for warmup_payload in generate_benchmark_payloads(
        100,
        seed=7,
        transaction_namespace=f"warmup_{benchmark_run_id}",
    ):
        gateway.decide(warmup_payload)

    payloads = generate_benchmark_payloads(
        request_count,
        transaction_namespace=f"bench_{benchmark_run_id}",
    )

    def timed_decision(payload: TransactionPayload) -> tuple[int, DecisionStatus]:
        start_ns = time.perf_counter_ns()
        action = gateway.decide(payload).action
        return time.perf_counter_ns() - start_ns, action

    wall_start = time.perf_counter_ns()
    with ThreadPoolExecutor(
        max_workers=concurrency, thread_name_prefix="shieldos-load"
    ) as executor:
        observations = list(executor.map(timed_decision, payloads))
    wall_seconds = (time.perf_counter_ns() - wall_start) / 1_000_000_000

    durations = [duration for duration, _ in observations]
    actions = Counter(action.value for _, action in observations)
    p99 = percentile_nearest_rank(durations, 0.99)
    return BenchmarkResult(
        request_count=request_count,
        concurrency=concurrency,
        p50_ms=round(percentile_nearest_rank(durations, 0.50), 4),
        p95_ms=round(percentile_nearest_rank(durations, 0.95), 4),
        p99_ms=round(p99, 4),
        max_ms=round(max(durations) / 1_000_000, 4),
        throughput_rps=round(request_count / wall_seconds, 2),
        action_counts=dict(sorted(actions.items())),
        sla_target_ms=DECISION_SLA_MS,
        p99_sla_met=p99 <= DECISION_SLA_MS,
        benchmark_scope=(
            "In-process decision engine only; excludes TLS, network hops, "
            "external feature-store I/O, Kafka acknowledgement, and ledger latency."
        ),
    )


def demo_payloads() -> list[TransactionPayload]:
    common = {
        "event_time": datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc),
        "currency": "GBP",
        "network_ip": IPv4Address("198.51.100.42"),
    }
    return [
        TransactionPayload(
            **common,
            transaction_id="demo_clean_001",
            user_id="customer_clean",
            amount=Decimal("35.00"),
            device_id="trusted_device_01",
            imsi_status_changed=False,
            hourly_velocity=1,
            device_trust_score=98,
            ip_reputation_risk=5,
        ),
        TransactionPayload(
            **common,
            transaction_id="demo_stepup_001",
            user_id="customer_stepup",
            amount=Decimal("900.00"),
            device_id="device_stepup_01",
            imsi_status_changed=False,
            hourly_velocity=7,
            device_trust_score=58,
            ip_reputation_risk=35,
            geo_velocity_kmh=300,
            minutes_since_last_auth=18,
        ),
        TransactionPayload(
            **common,
            transaction_id="demo_simswap_001",
            user_id="customer_block",
            amount=Decimal("1200.00"),
            device_id="device_block_01",
            imsi_status_changed=True,
            hourly_velocity=5,
            device_trust_score=44,
            ip_reputation_risk=52,
            sensitive_transaction=True,
        ),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run ShieldOS decisions and the 1,000-request P99 validation."
    )
    parser.add_argument("--requests", type=int, default=1_000)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--skip-benchmark", action="store_true")
    args = parser.parse_args()

    with ShieldOSGateway() as gateway:
        print("\n=== Decision examples ===")
        for payload in demo_payloads():
            response = gateway.decide(payload)
            print(
                json.dumps(
                    response.model_dump(mode="json"),
                    indent=2,
                    sort_keys=True,
                )
            )

        if not args.skip_benchmark:
            print("\n=== Performance validation ===")
            benchmark = run_benchmark(
                gateway,
                request_count=args.requests,
                concurrency=args.concurrency,
            )
            print(json.dumps(benchmark.model_dump(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

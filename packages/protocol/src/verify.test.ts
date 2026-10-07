import { describe, expect, it } from "vitest";
import { createSignedEnvelope, hashSignedObjectBody } from "./crypto.js";
import {
  createSyntheticClosureFixture,
  createSyntheticNegativeClosureFixture,
  createSyntheticStepUpClosureFixture,
  signingInputFor,
} from "./testing.js";
import { verifyClosureProof } from "./verify.js";

function clone<T>(value: T): T {
  return structuredClone(value);
}

function resignLinkedDecision(
  fixture: ReturnType<typeof createSyntheticClosureFixture>,
  proof: ReturnType<typeof createSyntheticClosureFixture>["proof"],
) {
  const decisionHash = hashSignedObjectBody(proof.body.decision.body);
  proof.body.capsule.body.decision_hash = decisionHash;
  proof.body.capsule = createSignedEnvelope(proof.body.capsule.body, [signingInputFor(fixture, "capsule_authority")]);
  const capsuleHash = hashSignedObjectBody(proof.body.capsule.body);
  const consumptionBody = proof.body.consumption_records[0]!.body;
  consumptionBody.decision_hash = decisionHash;
  consumptionBody.capsule_hash = capsuleHash;
  proof.body.consumption_records[0] = createSignedEnvelope(consumptionBody, [signingInputFor(fixture, "executor")]);
  const consumptionHash = hashSignedObjectBody(proof.body.consumption_records[0]!.body);
  proof.body.receipt.body.decision_hash = decisionHash;
  proof.body.receipt.body.capsule_hash = capsuleHash;
  proof.body.receipt.body.consumption_hash = consumptionHash;
  proof.body.receipt = createSignedEnvelope(proof.body.receipt.body, [
    signingInputFor(fixture, "executor"),
    signingInputFor(fixture, "ledger"),
  ]);
  proof.body.ledger_observation.body.receipt_body_hash = hashSignedObjectBody(proof.body.receipt.body);
  proof.body.ledger_observation = createSignedEnvelope(proof.body.ledger_observation.body, [
    signingInputFor(fixture, "ledger"),
  ]);
}

describe("closure proof verifier", () => {
  it("accepts the synthetic happy-path fixture", () => {
    const fixture = createSyntheticClosureFixture();
    expect(verifyClosureProof(fixture.proof, fixture.trust_store)).toMatchObject({
      valid: true,
      code: "VALID",
      proof_id: "synthetic-proof-1",
    });
  });

  it("rejects schema-invalid trust stores and proofs", () => {
    const fixture = createSyntheticClosureFixture();
    expect(verifyClosureProof(fixture.proof, {}).code).toBe("TRUST_STORE_SCHEMA_INVALID");
    expect(verifyClosureProof({}, fixture.trust_store).code).toBe("PROOF_SCHEMA_INVALID");
  });

  it.each([0, 2])("rejects a success proof with %i consumption records at the schema boundary", (count) => {
    const fixture = createSyntheticClosureFixture();
    const proof = clone(fixture.proof);
    proof.body.consumption_records = Array.from(
      { length: count }, () => clone(fixture.proof.body.consumption_records[0]!),
    );
    expect(verifyClosureProof(proof, fixture.trust_store)).toMatchObject({
      valid: false,
      code: "PROOF_SCHEMA_INVALID",
    });
  });

  it("rejects an untrusted root", () => {
    const fixture = createSyntheticClosureFixture();
    const store = clone(fixture.trust_store);
    store.trusted_roots[0]!.public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    expect(verifyClosureProof(fixture.proof, store).code).toBe("TRUST_ROOT_NOT_TRUSTED");
  });

  it("rejects a broken hash link", () => {
    const fixture = createSyntheticClosureFixture();
    const proof = clone(fixture.proof);
    proof.body.decision.body.snapshot_hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const resigned = createSignedEnvelope(proof.body.decision.body, [signingInputFor(fixture, "decision_authority")]);
    proof.body.decision = resigned;
    const closed = createSignedEnvelope(proof.body, [signingInputFor(fixture, "closure_authority")]);
    expect(verifyClosureProof(closed, fixture.trust_store).code).toBe("OBJECT_HASH_LINK_INVALID");
  });

  it("rejects a replay mismatch and an illegal state path", () => {
    const fixture = createSyntheticClosureFixture();
    const replay = clone(fixture.proof);
    replay.body.decision_input.body.spendable_funds = "1";
    replay.body.decision_input = createSignedEnvelope(replay.body.decision_input.body, [
      signingInputFor(fixture, "snapshot_authority"),
    ]);
    replay.body.decision.body.snapshot_hash = hashSignedObjectBody(replay.body.decision_input.body);
    replay.body.decision = createSignedEnvelope(replay.body.decision.body, [
      signingInputFor(fixture, "decision_authority"),
    ]);
    resignLinkedDecision(fixture, replay);
    const replayProof = createSignedEnvelope(replay.body, [signingInputFor(fixture, "closure_authority")]);
    expect(verifyClosureProof(replayProof, fixture.trust_store).code).toBe("DECISION_REPLAY_MISMATCH");

    const pathProof = clone(fixture.proof);
    pathProof.body.state_path = ["PROPOSED", "AUTHORIZATION_DENIED", "CLOSED"];
    const resignedPath = createSignedEnvelope(pathProof.body, [signingInputFor(fixture, "closure_authority")]);
    expect(verifyClosureProof(resignedPath, fixture.trust_store).code).toBe("STATE_PATH_INVALID");
  });

  it("rejects an out-of-window capsule", () => {
    const fixture = createSyntheticClosureFixture();
    const proof = clone(fixture.proof);
    proof.body.receipt.body.executed_at = "2026-01-01T00:10:00.000Z";
    proof.body.receipt = createSignedEnvelope(proof.body.receipt.body, [
      signingInputFor(fixture, "executor"),
      signingInputFor(fixture, "ledger"),
    ]);
    proof.body.ledger_observation.body.receipt_body_hash = hashSignedObjectBody(proof.body.receipt.body);
    proof.body.ledger_observation.body.observed_at = "2026-01-01T00:10:00.000Z";
    proof.body.ledger_observation = createSignedEnvelope(proof.body.ledger_observation.body, [
      signingInputFor(fixture, "ledger"),
    ]);
    proof.body.closed_at = "2026-01-01T00:10:00.000Z";
    proof.body.issued_at = "2026-01-01T00:10:00.000Z";
    const closed = createSignedEnvelope(proof.body, [signingInputFor(fixture, "closure_authority")]);
    expect(verifyClosureProof(closed, fixture.trust_store).code).toBe("CAPSULE_TIME_INVALID");
  });

  it("accepts the synthetic step-up success fixture", () => {
    const fixture = createSyntheticStepUpClosureFixture();
    expect(verifyClosureProof(fixture.proof, fixture.trust_store)).toMatchObject({
      valid: true,
      code: "VALID",
      closure_kind: "success",
    });
  });

  it("rejects self-approval on a step-up proof", () => {
    const fixture = createSyntheticStepUpClosureFixture();
    const proof = clone(fixture.proof);
    proof.body.step_up_approval!.body.approver_id = proof.body.step_up_approval!.body.requester_id;
    proof.body.step_up_approval = createSignedEnvelope(proof.body.step_up_approval!.body, [
      signingInputFor(fixture, "approver"),
    ]);
    const closed = createSignedEnvelope(proof.body, [signingInputFor(fixture, "closure_authority")]);
    expect(verifyClosureProof(closed, fixture.trust_store).code).toBe("SEPARATION_FAILURE");
  });

  it("accepts a negative NSF closure and rejects a side-effect observation", () => {
    const fixture = createSyntheticNegativeClosureFixture();
    expect(verifyClosureProof(fixture.proof, fixture.trust_store)).toMatchObject({
      valid: true,
      code: "VALID",
      closure_kind: "negative",
      proof_id: "synthetic-negative-proof-1",
      receipt_body_hash: null,
      effect_hash: null,
    });

    const tainted = clone(fixture.proof);
    tainted.body.ledger_observation.body.mutation_count = "1";
    tainted.body.ledger_observation = createSignedEnvelope(tainted.body.ledger_observation.body, [
      signingInputFor(fixture, "ledger"),
    ]);
    const closed = createSignedEnvelope(tainted.body, [signingInputFor(fixture, "closure_authority")]);
    expect(verifyClosureProof(closed, fixture.trust_store).code).toBe("SIDE_EFFECT_PRESENT");
  });

  it("rejects a stale trust head and a compromised key after invalid_from", () => {
    const fixture = createSyntheticClosureFixture();
    const stale = clone(fixture.trust_store);
    stale.manifest_hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    expect(verifyClosureProof(fixture.proof, stale).code).toBe("STALE_TRUST_HEAD");

    const compromised = clone(fixture.trust_store);
    compromised.key_incidents = [
      {
        key_id: fixture.proof.body.key_id,
        issuer: fixture.proof.body.issuer,
        kind: "compromise",
        invalid_from: "2026-01-01T00:00:00.000Z",
      },
    ];
    expect(verifyClosureProof(fixture.proof, compromised).code).toBe("KEY_REVOKED");
  });

  it("rejects proofs that exceed the versioned resource limits", () => {
    const fixture = createSyntheticClosureFixture();
    const huge = { ...fixture.proof, padding: "x".repeat(1_048_577) };
    expect(verifyClosureProof(huge, fixture.trust_store).code).toBe("PROOF_LIMIT_EXCEEDED");
  });
});

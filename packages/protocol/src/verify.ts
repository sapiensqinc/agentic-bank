import {
  hashSignedObjectBody,
  hashTransferEffect,
  signaturesAreSorted,
  verifyObjectSignature,
  type SignableObject,
} from "./crypto.js";
import {
  deriveTransferEffect,
  evaluateKrwTransfer,
  isActionWithinMandate,
  isKrwTransferDescriptorCompatible,
  isMandateValidAtAuthorization,
} from "./evaluator.js";
import { proofExceedsLimits } from "./limits.js";
import { isNegativeClosedPath, isSuccessfulStatePath, isSuccessfulStepUpStatePath } from "./state.js";
import {
  ASSURANCE_PROFILE,
  KRW_TRANSFER_POLICY,
  type AuthorityBinding,
  type AuthorityRole,
  type ClosureFailureCode,
  type ClosureProof,
  type ClosureVerificationResult,
  type KeyIncident,
  type NegativeClosureProof,
  type SignedEnvelope,
  type TrustRootManifest,
  type TrustStore,
} from "./types.js";
import { validateObject } from "./validation.js";

const REQUIRED_ROLES: readonly AuthorityRole[] = [
  "trust_root",
  "mandate_authority",
  "action_proposer",
  "policy_authority",
  "interpreter_authority",
  "snapshot_authority",
  "decision_authority",
  "capsule_authority",
  "approver",
  "executor",
  "ledger",
  "closure_authority",
];

const SHARED_ENVELOPE_ROLES: Record<string, readonly AuthorityRole[]> = {
  manifest: ["trust_root"],
  mandate: ["mandate_authority"],
  action: ["action_proposer"],
  policy: ["policy_authority"],
  interpreter: ["interpreter_authority"],
  decision_input: ["snapshot_authority"],
  decision: ["decision_authority"],
  ledger_observation: ["ledger"],
  step_up_approval: ["approver"],
};

const SUCCESS_ENVELOPE_ROLES: Record<string, readonly AuthorityRole[]> = {
  ...SHARED_ENVELOPE_ROLES,
  capsule: ["capsule_authority"],
  receipt: ["executor", "ledger"],
};

function failure(code: ClosureFailureCode, path: string, message: string): ClosureVerificationResult {
  return { valid: false, code, path, message };
}

function firstMismatch(
  pairs: ReadonlyArray<readonly [string, unknown, unknown]>,
): readonly [string, unknown, unknown] | undefined {
  return pairs.find(([, left, right]) => left !== right);
}

function duplicateBinding(authorities: readonly AuthorityBinding[]): boolean {
  const seen = new Set<string>();
  for (const binding of authorities) {
    const key = `${binding.role}\0${binding.issuer}\0${binding.key_id}`;
    if (seen.has(key) || [...seen].some((item) => item.startsWith(`${binding.role}\0`))) {
      return true;
    }
    seen.add(key);
  }
  return false;
}

function bindingByRole(
  authorities: readonly AuthorityBinding[],
  role: AuthorityRole,
): AuthorityBinding | undefined {
  return authorities.find((binding) => binding.role === role);
}

function trustedRootMatches(store: TrustStore, manifest: TrustRootManifest): boolean {
  return store.trusted_roots.some(
    (root) =>
      root.role === "trust_root" &&
      root.issuer === manifest.issuer &&
      root.key_id === manifest.key_id &&
      root.algorithm === "Ed25519" &&
      root.public_key === bindingByRole(manifest.authorities, "trust_root")?.public_key,
  );
}

type SignedBody = SignableObject & { issuer: string; key_id: string };
type ManifestPinned = {
  protocol_version: string;
  schema_version: string;
  manifest_version: string;
  manifest_hash: string;
  trust_epoch: string;
};

function verifyEnvelope(
  envelope: SignedEnvelope<SignedBody>,
  roles: readonly AuthorityRole[],
  authorities: readonly AuthorityBinding[],
  path: string,
): ClosureVerificationResult | undefined {
  if (!signaturesAreSorted(envelope.signatures)) {
    return failure("SIGNATURE_ORDER_INVALID", `${path}/signatures`, "signatures must be in canonical order");
  }
  if (envelope.signatures.length !== roles.length) {
    return failure(
      "AUTHORITY_BINDING_INVALID",
      `${path}/signatures`,
      "signature set does not match the required authority roles",
    );
  }
  for (const role of roles) {
    const signature = envelope.signatures.find((item) => item.role === role);
    const binding = bindingByRole(authorities, role);
    /* v8 ignore if -- @preserve required roles are already checked on the manifest */
    if (!binding) {
      return failure("UNKNOWN_KEY", `${path}/signatures`, `missing ${role} binding`);
    }
    if (!signature) {
      return failure("AUTHORITY_BINDING_INVALID", `${path}/signatures`, `missing ${role} signature or binding`);
    }
    if (signature.issuer !== binding.issuer || signature.key_id !== binding.key_id) {
      return failure(
        "AUTHORITY_BINDING_INVALID",
        `${path}/signatures`,
        `${role} signature does not match the trust manifest binding`,
      );
    }
    if (role === roles[0] && (envelope.body.issuer !== binding.issuer || envelope.body.key_id !== binding.key_id)) {
      return failure(
        "AUTHORITY_BINDING_INVALID",
        `${path}/body`,
        "object issuer and key_id must match the primary authority",
      );
    }
    if (!verifyObjectSignature(envelope.body, signature, binding.public_key)) {
      return failure("SIGNATURE_INVALID", `${path}/signatures`, `${role} signature is invalid`);
    }
  }
  return undefined;
}

function verifyTrustAndPins(
  body: ClosureProof["body"] | NegativeClosureProof["body"],
  proof: SignedEnvelope<SignedBody>,
  trustStore: TrustStore,
  extraPinned: Array<[string, ManifestPinned]>,
  envelopeRoles: Record<string, readonly AuthorityRole[]>,
): ClosureVerificationResult | undefined {
  const manifest = body.manifest.body;
  const authorities = manifest.authorities;

  if (duplicateBinding(authorities) || REQUIRED_ROLES.some((role) => !bindingByRole(authorities, role))) {
    return failure(
      "TRUST_MANIFEST_BINDING_INVALID",
      "/body/manifest/body/authorities",
      "trust manifest must bind each required authority role exactly once",
    );
  }

  if (!trustedRootMatches(trustStore, manifest)) {
    return failure("TRUST_ROOT_NOT_TRUSTED", "/trust_store/trusted_roots", "manifest trust root is not in the trust store");
  }

  if (
    trustStore.manifest_version !== manifest.manifest_version ||
    trustStore.trust_epoch !== manifest.trust_epoch ||
    trustStore.manifest_hash !== hashSignedObjectBody(manifest)
  ) {
    return failure("STALE_TRUST_HEAD", "/trust_store", "trust store pin does not match the proof manifest");
  }

  const revoked = findRevokedKey(trustStore.key_incidents ?? [], body);
  if (revoked) return revoked;

  const manifestSignature = verifyEnvelope(body.manifest, ["trust_root"], authorities, "/body/manifest");
  if (manifestSignature) {
    return manifestSignature.code === "SIGNATURE_INVALID"
      ? failure("TRUST_MANIFEST_SIGNATURE_INVALID", "/body/manifest/signatures", manifestSignature.message)
      : manifestSignature;
  }

  /* v8 ignore start -- schema already constrains the v0 assurance profile */
  if (
    body.assurance_profile !== ASSURANCE_PROFILE ||
    trustStore.expected_assurance_profile !== ASSURANCE_PROFILE ||
    manifest.assurance_profile !== ASSURANCE_PROFILE
  ) {
    return failure("ASSURANCE_PROFILE_MISMATCH", "/body/assurance_profile", "assurance profile is not single_process_simulation");
  }
  /* v8 ignore stop */

  const pin = {
    protocol_version: manifest.protocol_version,
    schema_version: manifest.schema_version,
    manifest_version: manifest.manifest_version,
    manifest_hash: hashSignedObjectBody(manifest),
    trust_epoch: manifest.trust_epoch,
  };

  const pinnedObjects: Array<[string, ManifestPinned]> = [
    ["/body", body],
    ["/body/mandate/body", body.mandate.body],
    ["/body/action/body", body.action.body],
    ["/body/policy/body", body.policy.body],
    ["/body/interpreter/body", body.interpreter.body],
    ["/body/decision_input/body", body.decision_input.body],
    ["/body/decision/body", body.decision.body],
    ["/body/ledger_observation/body", body.ledger_observation.body],
    ...extraPinned,
  ];
  for (const [path, object] of pinnedObjects) {
    const mismatch = firstMismatch([
      [`${path}/protocol_version`, object.protocol_version, pin.protocol_version],
      [`${path}/schema_version`, object.schema_version, pin.schema_version],
      [`${path}/manifest_version`, object.manifest_version, pin.manifest_version],
      [`${path}/manifest_hash`, object.manifest_hash, pin.manifest_hash],
      [`${path}/trust_epoch`, object.trust_epoch, pin.trust_epoch],
    ]);
    if (mismatch) {
      return failure("MANIFEST_PIN_MISMATCH", mismatch[0], "object is not pinned to the trusted manifest");
    }
  }

  for (const [field, roles] of Object.entries(envelopeRoles)) {
    const envelope = (body as unknown as Record<string, SignedEnvelope<SignedBody> | null | undefined>)[field];
    if (!envelope) continue;
    const invalid = verifyEnvelope(envelope, roles, authorities, `/body/${field}`);
    if (invalid) return invalid;
  }
  return verifyEnvelope(proof, ["closure_authority"], authorities, "");
}

function verifySharedDecisionSemantics(
  body: ClosureProof["body"] | NegativeClosureProof["body"],
): ClosureVerificationResult | undefined {
  if (!isActionWithinMandate(body.mandate.body, body.action.body)) {
    return failure("MANDATE_SCOPE_INVALID", "/body/action/body", "proposed action is outside the signed mandate");
  }
  if (!isMandateValidAtAuthorization(body.mandate.body, body.action.body, body.decision.body.authorized_at)) {
    if (body.object_type !== "NegativeClosureProof" || body.terminal_reason !== "EXPIRED") {
      return failure(
        "AUTHORIZATION_TIME_INVALID",
        "/body/decision/body/authorized_at",
        "authorization time is outside the mandate window",
      );
    }
  }

  const actionHash = hashSignedObjectBody(body.action.body);
  const mandateHash = hashSignedObjectBody(body.mandate.body);
  const policyHash = hashSignedObjectBody(body.policy.body);
  const interpreterHash = hashSignedObjectBody(body.interpreter.body);
  const snapshotHash = hashSignedObjectBody(body.decision_input.body);
  const hashMismatch = firstMismatch([
    ["/body/decision_input/body/action_hash", body.decision_input.body.action_hash, actionHash],
    ["/body/decision_input/body/mandate_hash", body.decision_input.body.mandate_hash, mandateHash],
    ["/body/decision_input/body/policy_hash", body.decision_input.body.policy_hash, policyHash],
    ["/body/decision_input/body/interpreter_hash", body.decision_input.body.interpreter_hash, interpreterHash],
    ["/body/decision/body/action_hash", body.decision.body.action_hash, actionHash],
    ["/body/decision/body/mandate_hash", body.decision.body.mandate_hash, mandateHash],
    ["/body/decision/body/policy_hash", body.decision.body.policy_hash, policyHash],
    ["/body/decision/body/interpreter_hash", body.decision.body.interpreter_hash, interpreterHash],
    ["/body/decision/body/snapshot_hash", body.decision.body.snapshot_hash, snapshotHash],
  ]);
  if (hashMismatch) {
    return failure("OBJECT_HASH_LINK_INVALID", hashMismatch[0], "hash-linked objects do not form a closed chain");
  }

  const manifest = body.manifest.body;
  if (
    body.policy.body.policy_type !== KRW_TRANSFER_POLICY ||
    !manifest.supported_policy_ids.includes(body.policy.body.policy_id)
  ) {
    return failure("POLICY_UNSUPPORTED", "/body/policy/body", "policy is not supported by the trust manifest");
  }
  if (
    !isKrwTransferDescriptorCompatible(body.interpreter.body) ||
    body.interpreter.body.policy_id !== body.policy.body.policy_id ||
    !manifest.supported_interpreter_ids.includes(body.interpreter.body.interpreter_id)
  ) {
    return failure("INTERPRETER_UNSUPPORTED", "/body/interpreter/body", "interpreter is not supported for this policy");
  }

  const replayed = evaluateKrwTransfer(body.mandate.body, body.action.body, body.policy.body, body.decision_input.body);
  if (replayed.outcome !== body.decision.body.outcome || replayed.reason_code !== body.decision.body.reason_code) {
    return failure(
      "DECISION_REPLAY_MISMATCH",
      "/body/decision/body",
      "authorization decision does not replay from the attested snapshot",
    );
  }

  const derivedEffect = deriveTransferEffect(body.action.body);
  if (
    derivedEffect.action_id !== body.effect.action_id ||
    derivedEffect.from_account_id !== body.effect.from_account_id ||
    derivedEffect.to_account_id !== body.effect.to_account_id ||
    derivedEffect.amount !== body.effect.amount ||
    derivedEffect.currency !== body.effect.currency
  ) {
    return failure("EFFECT_MISMATCH", "/body/effect", "transfer effect does not match the proposed action");
  }
  return undefined;
}

function verifyStepUpApproval(
  body: ClosureProof["body"] | NegativeClosureProof["body"],
  actionHash: string,
  decisionHash: string,
  effectHash: string,
  required: boolean,
): ClosureVerificationResult | undefined {
  const approval = body.step_up_approval;
  if (!approval) {
    return required
      ? failure("STEP_UP_MISSING", "/body/step_up_approval", "step-up success requires a signed approval")
      : undefined;
  }
  if (approval.body.requester_id === approval.body.approver_id) {
    return failure(
      "SEPARATION_FAILURE",
      "/body/step_up_approval/body/approver_id",
      "requester and approver must be distinct",
    );
  }
  const mismatch = firstMismatch([
    ["/body/step_up_approval/body/action_hash", approval.body.action_hash, actionHash],
    ["/body/step_up_approval/body/decision_hash", approval.body.decision_hash, decisionHash],
    ["/body/step_up_approval/body/approved_effect_hash", approval.body.approved_effect_hash, effectHash],
  ]);
  if (mismatch) {
    return failure("OBJECT_HASH_LINK_INVALID", mismatch[0], "step-up approval is not linked to the pending effect");
  }
  return undefined;
}

function verifyProofSemantics(proof: ClosureProof, trustStore: TrustStore): ClosureVerificationResult | undefined {
  const body = proof.body;
  const extraPinned: Array<[string, ManifestPinned]> = [
    ["/body/capsule/body", body.capsule.body],
    ["/body/receipt/body", body.receipt.body],
  ];
  if (body.step_up_approval) {
    extraPinned.push(["/body/step_up_approval/body", body.step_up_approval.body]);
  }
  for (const record of body.consumption_records) {
    extraPinned.push(["/body/consumption_records/0/body", record.body]);
  }

  const trust = verifyTrustAndPins(body, proof, trustStore, extraPinned, SUCCESS_ENVELOPE_ROLES);
  if (trust) return trust;

  /* v8 ignore if -- @preserve schema already requires exactly one consumption record */
  if (body.consumption_records.length !== 1) {
    return failure(
      "CONSUMPTION_CARDINALITY_INVALID",
      "/body/consumption_records",
      "success proofs must contain exactly one consumption record",
    );
  }
  const consumptionEnvelope = body.consumption_records[0]!;
  const consumptionSig = verifyEnvelope(
    consumptionEnvelope,
    ["executor"],
    body.manifest.body.authorities,
    "/body/consumption_records/0",
  );
  if (consumptionSig) return consumptionSig;

  const shared = verifySharedDecisionSemantics(body);
  if (shared) return shared;

  const actionHash = hashSignedObjectBody(body.action.body);
  const decisionHash = hashSignedObjectBody(body.decision.body);
  const capsuleHash = hashSignedObjectBody(body.capsule.body);
  const consumptionHash = hashSignedObjectBody(consumptionEnvelope.body);
  const receiptHash = hashSignedObjectBody(body.receipt.body);
  const effectHash = hashTransferEffect(body.effect);
  const stepUp = body.decision.body.outcome === "STEP_UP";

  if (stepUp) {
    if (body.decision.body.reason_code !== "STEP_UP_REQUIRED" || body.decision.body.approved_effect_hash !== effectHash) {
      return failure(
        "DECISION_NOT_ALLOWED",
        "/body/decision/body",
        "step-up closure requires STEP_UP and a pending approved effect hash",
      );
    }
    const approval = verifyStepUpApproval(body, actionHash, decisionHash, effectHash, true);
    if (approval) return approval;
    if (!isSuccessfulStepUpStatePath(body.state_path)) {
      return failure(
        "STATE_PATH_INVALID",
        "/body/state_path",
        "closure state path is not the exact legal step-up success path",
      );
    }
  } else {
    if (body.decision.body.outcome !== "ALLOW" || body.decision.body.approved_effect_hash !== effectHash) {
      return failure(
        "DECISION_NOT_ALLOWED",
        "/body/decision/body",
        "ALLOW closure requires an ALLOW decision and matching effect hash",
      );
    }
    if (body.step_up_approval) {
      return failure("STEP_UP_MISSING", "/body/step_up_approval", "ALLOW proofs must not carry a step-up approval");
    }
    if (!isSuccessfulStatePath(body.state_path) || isSuccessfulStepUpStatePath(body.state_path)) {
      return failure(
        "STATE_PATH_INVALID",
        "/body/state_path",
        "closure state path is not the exact legal Stage 1 success path",
      );
    }
  }

  const capsuleMismatch = firstMismatch([
    ["/body/capsule/body/action_hash", body.capsule.body.action_hash, actionHash],
    ["/body/capsule/body/decision_hash", body.capsule.body.decision_hash, decisionHash],
    ["/body/capsule/body/approved_effect_hash", body.capsule.body.approved_effect_hash, effectHash],
  ]);
  if (capsuleMismatch) {
    return failure("CAPSULE_LINK_INVALID", capsuleMismatch[0], "execution capsule is not linked to the approved decision");
  }

  const consumption = consumptionEnvelope.body;
  const consumptionMismatch = firstMismatch([
    ["/body/consumption_records/0/body/capsule_hash", consumption.capsule_hash, capsuleHash],
    ["/body/consumption_records/0/body/action_hash", consumption.action_hash, actionHash],
    ["/body/consumption_records/0/body/decision_hash", consumption.decision_hash, decisionHash],
  ]);
  if (consumptionMismatch) {
    return failure("CONSUMPTION_LINK_INVALID", consumptionMismatch[0], "consumption record is not linked to the capsule");
  }

  const receipt = body.receipt.body;
  const authorities = body.manifest.body.authorities;
  const receiptMismatch = firstMismatch([
    ["/body/receipt/body/capsule_hash", receipt.capsule_hash, capsuleHash],
    ["/body/receipt/body/consumption_hash", receipt.consumption_hash, consumptionHash],
    ["/body/receipt/body/action_hash", receipt.action_hash, actionHash],
    ["/body/receipt/body/decision_hash", receipt.decision_hash, decisionHash],
    ["/body/receipt/body/effect_hash", receipt.effect_hash, effectHash],
    ["/body/receipt/body/executor_issuer", receipt.executor_issuer, bindingByRole(authorities, "executor")?.issuer],
    ["/body/receipt/body/executor_key_id", receipt.executor_key_id, bindingByRole(authorities, "executor")?.key_id],
    ["/body/receipt/body/ledger_issuer", receipt.ledger_issuer, bindingByRole(authorities, "ledger")?.issuer],
    ["/body/receipt/body/ledger_key_id", receipt.ledger_key_id, bindingByRole(authorities, "ledger")?.key_id],
  ]);
  if (receiptMismatch) {
    return failure("RECEIPT_LINK_INVALID", receiptMismatch[0], "execution receipt is not linked to the consumed capsule");
  }

  const observation = body.ledger_observation.body;
  if (observation.status !== "POSTED" || observation.mutation_count !== "1") {
    return failure(
      "LEDGER_OBSERVATION_INVALID",
      "/body/ledger_observation/body",
      "success closure requires a POSTED observation with mutation_count 1",
    );
  }
  const observationMismatch = firstMismatch([
    ["/body/ledger_observation/body/receipt_body_hash", observation.receipt_body_hash, receiptHash],
    ["/body/ledger_observation/body/effect_hash", observation.effect_hash, effectHash],
    ["/body/ledger_observation/body/action_id", observation.action_id, body.action.body.action_id],
    ["/body/ledger_observation/body/issuer", observation.issuer, receipt.ledger_issuer],
    ["/body/ledger_observation/body/key_id", observation.key_id, receipt.ledger_key_id],
    ["/body/ledger_observation/body/ledger_id", observation.ledger_id, receipt.ledger_id],
  ]);
  if (observationMismatch) {
    return failure(
      "LEDGER_OBSERVATION_INVALID",
      observationMismatch[0],
      "positive ledger observation does not match receipt and effect",
    );
  }

  const timelineIsValid = [
    Date.parse(body.decision.body.authorized_at) <= Date.parse(body.capsule.body.issued_at),
    Date.parse(body.capsule.body.not_before) <= Date.parse(consumption.consumed_at),
    Date.parse(consumption.consumed_at) <= Date.parse(receipt.executed_at),
    Date.parse(receipt.executed_at) < Date.parse(body.capsule.body.expires_at),
  ].every(Boolean);
  if (!timelineIsValid) {
    return failure(
      "CAPSULE_TIME_INVALID",
      "/body/capsule/body",
      "capsule was not consumed and executed within its validity window",
    );
  }
  if (body.step_up_approval) {
    const approval = body.step_up_approval.body;
    if (
      Date.parse(approval.not_before) > Date.parse(body.capsule.body.issued_at) ||
      Date.parse(receipt.executed_at) >= Date.parse(approval.expires_at)
    ) {
      return failure("CAPSULE_TIME_INVALID", "/body/step_up_approval/body", "step-up approval was outside its validity window");
    }
  }

  const closureTimelineIsValid = [
    Date.parse(receipt.executed_at) <= Date.parse(observation.observed_at),
    Date.parse(observation.observed_at) <= Date.parse(body.closed_at),
    Date.parse(body.closed_at) <= Date.parse(body.issued_at),
  ].every(Boolean);
  if (!closureTimelineIsValid) {
    return failure(
      "CLOSURE_TIME_INVALID",
      "/body/closed_at",
      "ledger observation, closure, and proof issuance are out of order",
    );
  }
  return undefined;
}

function verifyNegativeProofSemantics(
  proof: NegativeClosureProof,
  trustStore: TrustStore,
): ClosureVerificationResult | undefined {
  const body = proof.body;
  const extraPinned: Array<[string, ManifestPinned]> = [];
  if (body.step_up_approval) {
    extraPinned.push(["/body/step_up_approval/body", body.step_up_approval.body]);
  }
  const trust = verifyTrustAndPins(body, proof, trustStore, extraPinned, SHARED_ENVELOPE_ROLES);
  if (trust) return trust;

  const shared = verifySharedDecisionSemantics(body);
  if (shared) return shared;

  const actionHash = hashSignedObjectBody(body.action.body);
  const decisionHash = hashSignedObjectBody(body.decision.body);
  const effectHash = hashTransferEffect(body.effect);
  const observation = body.ledger_observation.body;

  if (observation.status !== "ABSENT" || observation.mutation_count !== "0") {
    return failure(
      observation.mutation_count !== "0" ? "SIDE_EFFECT_PRESENT" : "LEDGER_OBSERVATION_INVALID",
      "/body/ledger_observation/body",
      "negative closure requires an ABSENT observation with mutation_count 0",
    );
  }
  const observationMismatch = firstMismatch([
    ["/body/ledger_observation/body/receipt_body_hash", observation.receipt_body_hash, null],
    ["/body/ledger_observation/body/effect_hash", observation.effect_hash, null],
    ["/body/ledger_observation/body/action_id", observation.action_id, body.action.body.action_id],
  ]);
  if (observationMismatch) {
    return failure(
      "LEDGER_OBSERVATION_INVALID",
      observationMismatch[0],
      "negative ledger observation must omit receipt and effect hashes",
    );
  }

  if (body.terminal_reason === "AUTHORIZATION_DENIED") {
    if (body.decision.body.outcome !== "DENY" || body.decision.body.approved_effect_hash !== null) {
      return failure(
        "DECISION_NOT_ALLOWED",
        "/body/decision/body",
        "denied closure requires a DENY decision without an approved effect",
      );
    }
  }
  if (body.terminal_reason === "REVOKED" && !body.state_path.includes("REVOKED")) {
    return failure("MANDATE_REVOKED", "/body/state_path", "revoked closure must include REVOKED");
  }
  if (body.decision.body.outcome === "STEP_UP") {
    const approval = verifyStepUpApproval(body, actionHash, decisionHash, effectHash, false);
    if (approval) return approval;
  } else if (body.step_up_approval) {
    return failure("STEP_UP_MISSING", "/body/step_up_approval", "non-step-up negative proofs must not carry an approval");
  }

  if (!isNegativeClosedPath(body.state_path, body.terminal_reason)) {
    return failure(
      "STATE_PATH_INVALID",
      "/body/state_path",
      "negative closure state path is not a legal terminal path for the stated reason",
    );
  }

  const closureTimelineIsValid = [
    Date.parse(body.decision.body.authorized_at) <= Date.parse(observation.observed_at),
    Date.parse(observation.observed_at) <= Date.parse(body.closed_at),
    Date.parse(body.closed_at) <= Date.parse(body.issued_at),
  ].every(Boolean);
  if (!closureTimelineIsValid) {
    return failure(
      "CLOSURE_TIME_INVALID",
      "/body/closed_at",
      "ledger observation, closure, and proof issuance are out of order",
    );
  }
  return undefined;
}

function findRevokedKey(
  incidents: readonly KeyIncident[],
  body: ClosureProof["body"] | NegativeClosureProof["body"],
): ClosureVerificationResult | undefined {
  const objects: Array<{ path: string; issued_at: string; issuer: string; key_id: string }> = [
    { path: "/body", issued_at: body.issued_at, issuer: body.issuer, key_id: body.key_id },
    { path: "/body/decision/body", issued_at: body.decision.body.issued_at, issuer: body.decision.body.issuer, key_id: body.decision.body.key_id },
  ];
  for (const object of objects) {
    for (const incident of incidents) {
      if (incident.key_id !== object.key_id || incident.issuer !== object.issuer) continue;
      const cutoff = incident.kind === "compromise" ? incident.invalid_from : incident.revoked_at;
      if (cutoff && Date.parse(object.issued_at) >= Date.parse(cutoff)) {
        return failure("KEY_REVOKED", object.path, "signing key is revoked or compromised at the object issued_at");
      }
    }
  }
  return undefined;
}

function proofObjectType(input: unknown): string | undefined {
  if (!input || typeof input !== "object" || !("body" in input)) return undefined;
  const body = (input as { body?: { object_type?: unknown } }).body;
  return body && typeof body === "object" && typeof body.object_type === "string" ? body.object_type : undefined;
}

export function verifyClosureProof(proofInput: unknown, trustStoreInput: unknown): ClosureVerificationResult {
  try {
    const limit = proofExceedsLimits(proofInput, trustStoreInput);
    if (limit) {
      return failure("PROOF_LIMIT_EXCEEDED", "/", limit);
    }
    const trustStore = validateObject("TrustStore", trustStoreInput);
    if (!trustStore.valid) {
      return failure(
        "TRUST_STORE_SCHEMA_INVALID",
        /* v8 ignore next */
        trustStore.issues[0]?.path || "/",
        "trust store does not match the protocol schema",
      );
    }

    const objectType = proofObjectType(proofInput);
    if (objectType === "NegativeClosureProof") {
      const proof = validateObject("NegativeClosureProof", proofInput);
      if (!proof.valid) {
        return failure(
          "PROOF_SCHEMA_INVALID",
          /* v8 ignore next */
          proof.issues[0]?.path || "/",
          "closure proof does not match the protocol schema",
        );
      }
      const semantic = verifyNegativeProofSemantics(proof.value, trustStore.value);
      if (semantic) return semantic;
      return {
        valid: true,
        code: "VALID",
        proof_id: proof.value.body.proof_id,
        closure_kind: "negative",
        manifest_hash: hashSignedObjectBody(proof.value.body.manifest.body),
        receipt_body_hash: null,
        effect_hash: null,
      };
    }

    const proof = validateObject("ClosureProof", proofInput);
    if (!proof.valid) {
      return failure(
        "PROOF_SCHEMA_INVALID",
        /* v8 ignore next */
        proof.issues[0]?.path || "/",
        "closure proof does not match the protocol schema",
      );
    }
    const semantic = verifyProofSemantics(proof.value, trustStore.value);
    if (semantic) return semantic;
    return {
      valid: true,
      code: "VALID",
      proof_id: proof.value.body.proof_id,
      closure_kind: "success",
      manifest_hash: hashSignedObjectBody(proof.value.body.manifest.body),
      receipt_body_hash: hashSignedObjectBody(proof.value.body.receipt.body),
      effect_hash: hashTransferEffect(proof.value.body.effect),
    };
  } catch {
    return failure("INTERNAL_VERIFICATION_ERROR", "/", "verification failed unexpectedly");
  }
}

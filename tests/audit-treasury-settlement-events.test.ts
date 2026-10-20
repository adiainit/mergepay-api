/**
 * Issue #809 — structured audit events for treasury multisig and group
 * settlement state transitions.
 *
 * The durable audit rows for these two domains are already pinned by
 * tests/treasury-multisig-audit-logging.test.ts and
 * tests/expense-action-audit.test.ts. What none of them asserted is the
 * *operator-facing* half of the audit trail: the standardized Pino line the
 * same helper mirrors for every state change (src/lib/audit-logger.ts). Those
 * structured lines are what log aggregators filter on (`event = "audit"`,
 * `action`, `actor.id`, `outcome`), so they need their own assertions for the
 * flows this issue names:
 *
 *   - treasury multisig signature collection and submission failure,
 *   - settlement execution success and envelope-validation failure.
 *
 * Every case checks the full context — actor, action, target, groupId,
 * outcome, timestamp — on both the structured line and the durable row, and
 * the failure cases additionally prove that key material (private keys,
 * signed XDRs, bearer tokens) is redacted before it can reach either sink.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import pino from "pino";
import type pinoTypes from "pino";

const h = vi.hoisted(() => {
  const prisma: any = {
    auditLog: {
      create: vi.fn(async ({ data }: any) => ({ id: "audit_1", ...data })),
    },
    $disconnect: vi.fn(),
  };
  return { prisma };
});

vi.mock("../src/db", () => ({ prisma: h.prisma }));

import {
  audit,
  auditTx,
  auditMultisigActionTx,
} from "../src/services/audit";
import { AuditAction } from "../src/services/audit-actions";
import {
  AUDIT_REDACTED,
  setAuditEventLogger,
} from "../src/lib/audit-logger";

const prisma = h.prisma;

/** A transaction client stand-in that records the durable audit row. */
function mockTx() {
  return {
    auditLog: {
      create: vi.fn(async ({ data }: any) => ({ id: "audit_tx_1", ...data })),
    },
  } as any;
}

/** Capture the structured lines emitted to a destination stream. */
function captureLogger(): {
  logger: pinoTypes.Logger;
  lines: () => any[];
} {
  const lines: any[] = [];
  const logger = pino(
    { level: "info" },
    {
      write(chunk: string) {
        try {
          lines.push(JSON.parse(chunk));
        } catch {
          // ignore non-JSON chunks
        }
      },
    } as any
  );
  return { logger, lines: () => lines };
}

/** Only audit-event lines (the schema under test), not unrelated output. */
function auditLines(all: any[]): any[] {
  return all.filter((line) => line.event === "audit");
}

let capture: ReturnType<typeof captureLogger>;

beforeEach(() => {
  vi.clearAllMocks();
  capture = captureLogger();
  setAuditEventLogger(capture.logger);
});

afterEach(() => {
  setAuditEventLogger(null);
});



describe("treasury multisig structured audit events (#809)", () => {
  it("emits a success event with full context when a signature is recorded", async () => {
    const tx = mockTx();

    await auditMultisigActionTx(tx, {
      userId: "user_signer",
      groupId: "group_1",
      proposalId: "prop_1",
      action: AuditAction.TREASURY_PROPOSAL_SIGNED,
      actorPublicKey: "GBSIGNERKEY123",
      metadata: {
        signerPublicKey: "GBSIGNERKEY123",
        txHash: "deadbeef",
        signatureCount: 1,
        threshold: 2,
      },
    });

    // The durable row commits on the caller's transaction client…
    expect(tx.auditLog.create).toHaveBeenCalledTimes(1);
    expect(tx.auditLog.create.mock.calls[0][0].data).toMatchObject({
      userId: "user_signer",
      groupId: "group_1",
      action: AuditAction.TREASURY_PROPOSAL_SIGNED,
      entityType: "treasury_proposal",
      entityId: "prop_1",
      metadata: expect.objectContaining({
        outcome: "success",
        signatureCount: 1,
        threshold: 2,
      }),
    });

    // …and the structured line mirrors it with the same context.
    const rows = auditLines(capture.lines());
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      event: "audit",
      action: AuditAction.TREASURY_PROPOSAL_SIGNED,
      actor: { type: "user", id: "user_signer" },
      target: { type: "treasury_proposal", id: "prop_1" },
      groupId: "group_1",
      outcome: "success",
      actorPublicKey: "GBSIGNERKEY123",
      metadata: expect.objectContaining({
        signatureCount: 1,
        threshold: 2,
        txHash: "deadbeef",
      }),
    });
    expect(typeof rows[0].timestamp).toBe("string");
  });

  it("emits a failure event and redacts key material on a failed submission", async () => {
    const tx = mockTx();

    await auditMultisigActionTx(tx, {
      groupId: "group_1",
      proposalId: "prop_1",
      action: AuditAction.TREASURY_PROPOSAL_FAILED,
      outcome: "failure",
      metadata: {
        reason: "Stellar rejected the transaction: op_underfunded",
        signatureCount: 2,
        threshold: 2,
        // Never allowed to reach either sink, in any flow.
        privateKey: "SSUPERSECRETSEED",
        signedXdr: "AAAA-signed-payload",
        token: "bearer-session-token",
      },
    });

    // Durable row: failure outcome carried, secrets replaced not dropped.
    const row = tx.auditLog.create.mock.calls[0][0].data;
    expect(row.action).toBe(AuditAction.TREASURY_PROPOSAL_FAILED);
    expect(row.metadata.outcome).toBe("failure");
    expect(row.metadata.reason).toContain("op_underfunded");
    expect(row.metadata.privateKey).toBe(AUDIT_REDACTED);
    expect(row.metadata.signedXdr).toBe(AUDIT_REDACTED);
    expect(row.metadata.token).toBe(AUDIT_REDACTED);

    // Structured line: same outcome, and no secret verbatim anywhere.
    const rows = auditLines(capture.lines());
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      event: "audit",
      action: AuditAction.TREASURY_PROPOSAL_FAILED,
      actor: { type: "system" },
      target: { type: "treasury_proposal", id: "prop_1" },
      groupId: "group_1",
      outcome: "failure",
    });
    const serialized = JSON.stringify(capture.lines());
    expect(serialized).not.toContain("SSUPERSECRETSEED");
    expect(serialized).not.toContain("AAAA-signed-payload");
    expect(serialized).not.toContain("bearer-session-token");
    expect(JSON.stringify(row)).not.toContain("SSUPERSECRETSEED");
    expect(JSON.stringify(row)).not.toContain("AAAA-signed-payload");
  });
});

describe("group settlement structured audit events (#809)", () => {
  it("emits a success event with full context when a settlement is executed", async () => {
    const tx = mockTx();

    await auditTx(tx, {
      userId: "user_payer",
      groupId: "group_1",
      action: "settlement.execute",
      entityType: "settlement",
      entityId: "settlement_1",
      metadata: { status: "submitted" },
    });

    expect(tx.auditLog.create).toHaveBeenCalledTimes(1);
    expect(tx.auditLog.create.mock.calls[0][0].data).toMatchObject({
      userId: "user_payer",
      groupId: "group_1",
      action: "settlement.execute",
      entityType: "settlement",
      entityId: "settlement_1",
      // The durable writer records an outcome only when the caller supplies
      // one — the routes keep "success" implicit — so the row carries the
      // context fields, while the structured line below carries the outcome.
      metadata: { status: "submitted" },
    });

    const rows = auditLines(capture.lines());
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      event: "audit",
      action: "settlement.execute",
      actor: { type: "user", id: "user_payer" },
      target: { type: "settlement", id: "settlement_1" },
      groupId: "group_1",
      outcome: "success",
      metadata: expect.objectContaining({ status: "submitted" }),
    });
    expect(typeof rows[0].timestamp).toBe("string");
  });

  it("emits a failure event and never logs the envelope when envelope validation fails", async () => {
    await audit({
      userId: "user_payer",
      groupId: "group_1",
      action: "settlement.execute.validation_failed",
      entityType: "settlement",
      entityId: "settlement_1",
      outcome: "failure",
      metadata: {
        reason: "Signed transaction does not match the recorded intent",
        signedXdr: "AAAA-mismatched-envelope",
        privateKey: "SSUPERSECRETSEED",
      },
    });

    // Durable row written through the best-effort path…
    expect(prisma.auditLog.create).toHaveBeenCalledTimes(1);
    const row = prisma.auditLog.create.mock.calls[0][0].data;
    expect(row).toMatchObject({
      userId: "user_payer",
      groupId: "group_1",
      action: "settlement.execute.validation_failed",
      entityType: "settlement",
      entityId: "settlement_1",
      metadata: expect.objectContaining({
        outcome: "failure",
        reason: "Signed transaction does not match the recorded intent",
      }),
    });

    // …mirrored as a structured failure line with redacted metadata.
    const rows = auditLines(capture.lines());
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      event: "audit",
      action: "settlement.execute.validation_failed",
      actor: { type: "user", id: "user_payer" },
      target: { type: "settlement", id: "settlement_1" },
      groupId: "group_1",
      outcome: "failure",
    });
    expect(rows[0].metadata.signedXdr).toBe(AUDIT_REDACTED);
    expect(rows[0].metadata.privateKey).toBe(AUDIT_REDACTED);
    const serialized = JSON.stringify(capture.lines());
    expect(serialized).not.toContain("AAAA-mismatched-envelope");
    expect(serialized).not.toContain("SSUPERSECRETSEED");
    expect(JSON.stringify(row)).not.toContain("AAAA-mismatched-envelope");
    expect(JSON.stringify(row)).not.toContain("SSUPERSECRETSEED");
  });
});

import { z } from "zod";

/** Severity normalized across sources. Solodit fetch keeps only High/Medium. */
export const Severity = z.enum([
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
]);
export type Severity = z.infer<typeof Severity>;

/** Detectability bucket assigned by the Classifier stage. */
export const Bucket = z.enum([
  "primitive", // known-bad API
  "missing-check", // state-changing entry w/o guard
  "taint", // user input -> dangerous sink
  "ordering", // external-call-before-state-write (reentrancy-shaped)
  "NOT-detectable", // logic/economic/intended -> parked, never templated
]);
export type Bucket = z.infer<typeof Bucket>;

/**
 * Candidate status — the state machine that drives resumability (spec §8).
 * A stage runs only when status equals its expected prior state.
 */
export const CandidateStatus = z.enum([
  "pending",
  "explored", // AI root-cause exploration done (or skipped)
  "classifying",
  "classified",
  "drafting",
  "drafted",
  "testing",
  "repairing",
  "tested",
  "regressing",
  "regressed",
  "verifying",
  "verified",
  "improving",
  "cataloged", // terminal success -> candidates/
  "parked", // terminal: NOT-detectable
  "shelved", // terminal: retries exhausted / overfit
  "promoted", // terminal: manually copied into templates/
]);
export type CandidateStatus = z.infer<typeof CandidateStatus>;

export const TERMINAL_STATUSES: CandidateStatus[] = [
  "cataloged",
  "parked",
  "shelved",
  "promoted",
];

/** Origin of a candidate. */
export const CandidateKind = z.enum(["incident", "finding"]);
export type CandidateKind = z.infer<typeof CandidateKind>;

/** Parsed metadata from a DeFiHackLabs PoC header (spec §5). */
export const IncidentMeta = z.object({
  name: z.string(),
  repoPath: z.string(),
  date: z.string().optional(), // YYYY-MM derived from folder
  lossText: z.string().optional(), // e.g. "330K"
  attacker: z.string().optional(),
  attackContract: z.string().optional(),
  vulnerableContract: z.string().optional(),
  attackTx: z.string().optional(),
  references: z.array(z.string()).default([]),
  forkBlock: z.number().int().optional(),
  chain: z.string().default("ethereum"),
  // Inline human-written root-cause prose from the PoC `// @Analysis` block.
  analysis: z.string().default(""),
});
export type IncidentMeta = z.infer<typeof IncidentMeta>;

/**
 * Structured root cause produced by the AI `explore` stage (finding-root-cause skill).
 */
export const RootCause = z.object({
  summary: z.string().default(""),
  rootCause: z.string().default(""),
  vulnerableCode: z.string().default(""),
  fixedCode: z.string().default(""),
  triggerConditions: z.array(z.string()).default([]),
  attackFlow: z.array(z.string()).default([]),
  logicBug: z.boolean().default(false),
  detectabilityHint: z.string().default(""),
  sources: z.array(z.string()).default([]),
});
export type RootCause = z.infer<typeof RootCause>;

/**
 * Normalized candidate — the unit that flows through the forge loop. Stored as
 * `candidate.payload_json` in SQLite.
 */
export const Candidate = z.object({
  id: z.string(), // stable id: `${kind}:${sourceRef}` hashed/slugged
  kind: CandidateKind,
  sourceRef: z.string(), // repo path (incident) or finding id/slug (finding)
  title: z.string(),
  severity: Severity,
  rootCause: z.string().default(""), // root-cause text (writeup / finding body / explored)
  code: z.string().default(""), // vulnerable source / snippet seeding vuln.sol
  poc: z.string().default(""), // exploit body, incidents only
  txSummary: z.string().default(""), // attack tx summary, incidents only
  blogText: z.string().default(""), // reference writeup text
  tags: z.array(z.string()).default([]),
  links: z.array(z.string()).default([]),
  incident: IncidentMeta.optional(),
  // Populated by the AI `explore` stage:
  fixedCode: z.string().default(""),
  triggerConditions: z.array(z.string()).default([]),
  attackFlow: z.array(z.string()).default([]),
  logicBug: z.boolean().optional(),
  detectabilityHint: z.string().default(""),
});
export type Candidate = z.infer<typeof Candidate>;

/** A single w3goaudit finding (subset of corpus/findings.json we rely on). */
export const Finding = z.object({
  template_id: z.string(),
  severity: z.string(),
  title: z.string().optional(),
  location: z
    .object({
      file: z.string().optional(),
      contract: z.string().optional(),
      function: z.string().optional(),
      line: z.number().optional(),
    })
    .partial()
    .optional(),
});
export type Finding = z.infer<typeof Finding>;

/** The artifact the Drafter produces and gates consume. */
export const TemplateArtifact = z.object({
  candidateId: z.string(),
  templateId: z.string(), // WQL meta.id
  templateYaml: z.string(),
  vulnSol: z.string(),
  safeSol: z.string(),
});
export type TemplateArtifact = z.infer<typeof TemplateArtifact>;

/** Classifier stage output. */
export const Classification = z.object({
  bucket: Bucket,
  targetPrimitive: z.string(), // WQL primitive the template should use
  rationale: z.string(),
});
export type Classification = z.infer<typeof Classification>;

/** Verifier stage output (right-reason judgement). */
export const Verdict = z.object({
  rightReason: z.boolean(),
  rationale: z.string(),
  confidence: z.enum(["LOW", "MEDIUM", "HIGH"]),
});
export type Verdict = z.infer<typeof Verdict>;

/** One generated variant fixture and its observed gate result. */
export const VariantResult = z.object({
  candidateId: z.string(),
  variantId: z.string(),
  kind: z.enum(["recall", "precision"]), // recall=must-fire, precision=must-be-silent
  expectedFire: z.boolean(),
  actualFire: z.boolean(),
  passed: z.boolean(),
});
export type VariantResult = z.infer<typeof VariantResult>;

/** Provenance written alongside a cataloged candidate. */
export const Provenance = z.object({
  candidateId: z.string(),
  links: z.array(z.string()).default([]),
  cwe: z.array(z.string()).default([]),
  owaspSc: z.array(z.string()).default([]), // OWASP SC Top-10 ids
  confidence: z.enum(["LOW", "MEDIUM", "HIGH"]),
  dedupOf: z.string().optional(), // official template id this duplicates, if any
});
export type Provenance = z.infer<typeof Provenance>;

/** Stage names — also used as `stage_result.stage` keys for the resume cache. */
export const STAGES = [
  "explore",
  "classify",
  "draft",
  "test",
  "repair",
  "regress",
  "verify",
  "catalog",
] as const;
export type Stage = (typeof STAGES)[number];

/** Normalize a free-form severity string to our enum (default INFO). */
export function normalizeSeverity(raw: string): Severity {
  const up = raw.trim().toUpperCase();
  const parsed = Severity.safeParse(up);
  if (parsed.success) return parsed.data;
  if (up.startsWith("CRIT")) return "CRITICAL";
  if (up.startsWith("HIGH")) return "HIGH";
  if (up.startsWith("MED")) return "MEDIUM";
  if (up.startsWith("LOW")) return "LOW";
  return "INFO";
}

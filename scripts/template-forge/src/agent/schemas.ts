import { z } from "zod";

/** Drafter / Repair stage output (becomes a TemplateArtifact + candidateId). */
export const DraftOutput = z.object({
  templateId: z.string(),
  templateYaml: z.string(),
  vulnSol: z.string(),
  safeSol: z.string(),
});
export type DraftOutput = z.infer<typeof DraftOutput>;

/** Variants stage output (recall + precision fixtures). */
export const VariantsOutput = z.object({
  variants: z.array(
    z.object({
      variantId: z.string(),
      kind: z.enum(["recall", "precision"]),
      expectedFire: z.boolean(),
      sol: z.string(),
    }),
  ),
});
export type VariantsOutput = z.infer<typeof VariantsOutput>;

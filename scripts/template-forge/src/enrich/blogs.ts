import { cached } from "../util/cache.js";

/**
 * Fetch a reference URL and reduce it to readable text (very light HTML strip).
 * Best-effort + cached. Twitter/X links are skipped (no useful static text).
 */
export async function fetchBlogText(url: string): Promise<string | undefined> {
  if (/(?:twitter\.com|x\.com|t\.co)\//.test(url)) return undefined;
  try {
    return await cached("blog", url, async () => {
      const res = await fetch(url, {
        headers: { "User-Agent": "template-forge" },
      });
      if (!res.ok) throw new Error(`blog ${res.status}`);
      const html = await res.text();
      return htmlToText(html).slice(0, 12000);
    });
  } catch {
    return undefined;
  }
}

/** Strip scripts/styles/tags and collapse whitespace. Not a full readability pass. */
export function htmlToText(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<\/(p|div|li|h[1-6]|br)>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

/** Pick the most useful reference (post-mortem/analysis) from a list. */
export function pickPrimaryReference(refs: string[]): string | undefined {
  const ranked = [...refs].sort((a, b) => score(b) - score(a));
  return ranked[0];
}

function score(url: string): number {
  if (/blog|post-mortem|postmortem|analysis|rekt|medium\.com|mirror\.xyz/i.test(url))
    return 3;
  if (/(?:twitter\.com|x\.com|t\.co)\//.test(url)) return 0;
  return 1;
}

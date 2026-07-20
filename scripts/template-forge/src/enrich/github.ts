import { cached } from "../util/cache.js";

/**
 * Given a finding's reference links, fetch the most relevant GitHub source file
 * to deep-understand the finding. Converts a blob URL to its raw equivalent and
 * caches the body. Returns undefined when no GitHub source link is present.
 */
export async function fetchFindingSource(
  links: string[],
): Promise<string | undefined> {
  const blob = links.find((l) => /github\.com\/[^/]+\/[^/]+\/blob\//.test(l));
  if (!blob) return undefined;
  const raw = blob
    .replace("github.com", "raw.githubusercontent.com")
    .replace("/blob/", "/");
  const url = raw.split("#")[0]!; // strip line anchor
  try {
    return await cached("finding-source", url, async () => {
      const res = await fetch(url, {
        headers: { "User-Agent": "template-forge" },
      });
      if (!res.ok) throw new Error(`github source ${res.status}`);
      return await res.text();
    });
  } catch {
    return undefined;
  }
}

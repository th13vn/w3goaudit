import { cached } from "./cache.js";
import type { GitHubClient } from "../sources/defihacklabs.js";

const API = "https://api.github.com";
const RAW = "https://raw.githubusercontent.com";

/**
 * GitHub client backed by the contents API (listing) + raw.githubusercontent
 * (file bodies). Directory listings and file bodies are disk-cached, so a
 * resumed run does not re-hit the API. `GITHUB_TOKEN` raises rate limits.
 */
export class HttpGitHubClient implements GitHubClient {
  constructor(
    private readonly repo: string,
    private readonly token = "",
    private readonly branch = "main",
  ) {}

  private headers(): Record<string, string> {
    const h: Record<string, string> = {
      Accept: "application/vnd.github+json",
      "User-Agent": "template-forge",
    };
    if (this.token) h.Authorization = `Bearer ${this.token}`;
    return h;
  }

  async listDir(
    repoPath: string,
  ): Promise<{ name: string; type: string; path: string }[]> {
    const url = `${API}/repos/${this.repo}/contents/${repoPath}?ref=${this.branch}`;
    const body = await cached("github-list", url, async () => {
      const res = await fetch(url, { headers: this.headers() });
      if (!res.ok)
        throw new Error(`GitHub listDir ${repoPath} failed: ${res.status}`);
      return await res.text();
    });
    const json = JSON.parse(body) as {
      name: string;
      type: string;
      path: string;
    }[];
    return json.map((e) => ({ name: e.name, type: e.type, path: e.path }));
  }

  async getRaw(repoPath: string): Promise<string> {
    const url = `${RAW}/${this.repo}/${this.branch}/${repoPath}`;
    return cached("github-raw", url, async () => {
      const res = await fetch(url, {
        headers: { "User-Agent": "template-forge" },
      });
      if (!res.ok)
        throw new Error(`GitHub getRaw ${repoPath} failed: ${res.status}`);
      return await res.text();
    });
  }
}

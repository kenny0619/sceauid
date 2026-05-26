type SceauIDFetchResponse = {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
};

type SceauIDFetch = (
  url: string,
  init?: {
    credentials?: "include" | "omit" | "same-origin";
  }
) => Promise<SceauIDFetchResponse>;

declare const fetch: SceauIDFetch;

export type SceauIDClientOptions = {
  baseUrl: string;
  fetch?: SceauIDFetch;
};

export class SceauIDClient {
  private readonly baseUrl: string;
  private readonly fetcher: SceauIDFetch;

  constructor(options: SceauIDClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.fetcher = options.fetch ?? fetch;
  }

  async meta(): Promise<unknown> {
    const response = await this.fetcher(`${this.baseUrl}/v1/meta`, {
      credentials: "include"
    });

    if (!response.ok) {
      throw new Error(`SceauID request failed with status ${response.status}`);
    }

    return response.json();
  }
}

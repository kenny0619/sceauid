export type SceauIDClientOptions = {
  baseUrl: string;
  fetch?: typeof fetch;
};

export class SceauIDClient {
  private readonly baseUrl: string;
  private readonly fetcher: typeof fetch;

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

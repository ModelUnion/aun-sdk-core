export type ClientHost = Record<string, any>;

export class ClientRuntime {
  readonly client: ClientHost;

  constructor(client: unknown) {
    this.client = client as ClientHost;
  }
}

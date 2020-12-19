// TypeScript Version: 3.3
// see https://github.com/Microsoft/dtslint#specify-a-typescript-version for more information

declare module '@scrypta/core';

export class ScryptaCore {
    constructor(isBrowser: boolean, nodes: [])

    returnNodes(): Promise<[]>;
    post(endpoint: string, params: object, node?: string): Promise<object | boolean>;
    get(endpoint: string, node?: string): Promise<object | boolean>;
    testnet(value: boolean): void;
    checkNode(node: string): Promise<object | boolean>;
}

// TypeScript Version: 3.3
// see https://github.com/Microsoft/dtslint#specify-a-typescript-version for more information

declare module '@scrypta/core';

declare class ScryptaCore {
    staticnodes: boolean;
    testnet: boolean;
    nodes: string[];

    constructor(isBrowser: boolean, nodes?: string[])
    returnNodes(): Promise<[]>;
    post(endpoint: string, params: any, node?: string): Promise<any>;
    get(endpoint: string, node?: string): Promise<any>;
    checkNode(node: string): Promise<any>;
    connectNode(): Promise<any>;
    returnLastChecksum(version: string): Promise<string | false>;
    returnFirstNode(): Promise<any>;
    clearCache(force?: boolean): Promise<boolean>;
    returnTXIDCache(): Promise<string[]>;
    returnUTXOCache(): Promise<string[]>;
    pushUTXOtoCache(utxo: string): Promise<boolean>;
    returnSXIDCache(): Promise<string[]>;
    pushSXIDtoCache(sxid: string): Promise<boolean>;
    returnUSXOCache(): Promise<string[]>;
    pushUSXOtoCache(usxo: string): Promise<boolean>;
    sleep(ms: number): Promise<any>;
    hash(text: string): Promise<string>;
    hashtopath(hash: string, hardened?: boolean): string;
    gettime(): Promise<number>;
    cryptData(data: string, password: string): Promise<string>;
    decryptData(data: string, password: string, buffer?: boolean): Promise<string | Buffer>;
    cryptFile(file: Buffer, password: string): Promise<string>;
    decryptFile(file: Buffer, password: string): Promise<Buffer>;
    generateMnemonic(language?: string): Promise<string>;
    buildxSid(password: string, language?: string, saveKey?: boolean, mnemonic?: string, label?: string): Promise<any>;
    returnxKey(xpub: string): Promise<any>;
    readxKey(password: string, key: string): Promise<any>;
    returnXKeysFromSeed(seed: string): Promise<any>;
    deriveKeyFromMnemonic(mnemonic: string, index: string): Promise<any>;
    deriveKeyFromSeed(seed: string, index: string): Promise<any>;
    deriveKeyFromXPrv(xprv: string, index: string): Promise<any>;
    deriveKeyfromXPub(xpub: string, index: string): Promise<any>;
    createAddress(password: string, saveKey?: boolean, label?: boolean): Promise<any>;
    buildWallet(password: string, pub: string, wallet: object, saveKey?: boolean, label?: string): Promise<any>;
    saveWallet(sid: object, label?: string): Promise<any>;
    initAddress(address: string): Promise<any>;
    getPublicKey(privateWif: string): string;
    getAddressFromPubKey(pubKey: string): Promise<string>;
    importBrowserSID(): boolean;
    importPrivateKey(key: string, password: string, save?: boolean): Promise<any>;
    returnKey(address: string): Promise<any>;
    readKey(password: string, key: string): Promise<any>;
    fundAddress(privkey: string, to: string, amount: number): Promise<any>;
    listUnspent(address: string): Promise<object[]>;
    sendRawTransaction(rawtransaction: string): Promise<string>;
    decodeRawTransaction(rawtransaction: string): Promise<any>;
    createRawTransaction(from: string, outputs?: object, metadata?: string, fees?: number): Promise<any>;
    signRawTransaction(rawtransaction: string, privatekey: string): Promise<string>;
    build(key: string, password: string, send: boolean, to: string, amount: number, metadata?: string, fees?: number): Promise<any>;
    send(key: string, password: string, to: string, amount: number, metadata?: string): Promise<any>;
    usePlanum(sidechain: string): boolean;
    verifyPlanum(): Promise<any>;
    listPlanumUnspent(address: string, safe?: boolean): Promise<object[]>;
    sendPlanumAsset(key: string, password: string, to: string, amount: number, changeaddress?: string, memo?: string, time?: number, safe?: boolean, inputs?: string[]): Promise<any>;
    returnPlanumBalance(address: string): Promise<any>;
    returnPlanumTransactions(address: string): Promise<string[]>;
    write(key: string, password: string, metadata: string, collection?: string, refID?: string, protocol?: string, uuid?: string, contract?: string): Promise<any>;
    update(key: string, password: string, metadata: string, uuid: string, collection?: string, refID?: string, protocol?: string): Promise<any>;
    invalidate(key: string, password: string, uuid: string): Promise<any>;
    signMessage(privatekey: string, message: string): Promise<object>;
    verifyMessage(pubkey: string, signature: string, message: string): Promise<any>;
    createContractRequest(key: string, password: string, request: object): Promise<any>;
    sendContractRequest(request: object, node?: string): Promise<any>;
    connectP2P(callback: any): any;
    broadcast(key: string, password: string, protocol: string, message: string, socketID?: string, nodeID?: string): Promise<any>;
    returnIdentities(): Promise<object[]>;
    returnIdentity(address: string): Promise<any>;
    createRSAKeys(address: string, password: string): Promise<any>;
    setDefaultIdentity(address: string): Promise<boolean>;
    returnDefaultIdentity(): Promise<any>;
    returnDefaultxSid(): Promise<any>;
    setDefaultxIdentity(xpub: string): Promise<any>;
    fetchIdentities(address: string): Promise<any>;
}

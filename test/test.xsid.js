let ScryptaCore = require('../src/index.js')
let scrypta = new ScryptaCore
var assert = require('assert')
const password = '123456'

describe('Addresses', async function () {
    it('Should create an extended ScryptaID', async function () {
        this.timeout(35000)
        let xsid = await scrypta.buildxSid('123456', 'latin', false)
        console.log('GENERATING', xsid)
        let checksid = await scrypta.readxKey('123456', xsid.walletstore)
        console.log('READING', checksid)
        let derive = await scrypta.deriveKeyFromSeed(checksid.seed, "m/0'/0/1")
        console.log('DERIVING', derive)
    })

    it('Should create an extended testnet ScryptaID', async function () {
        this.timeout(35000)
        scrypta.testnet = true
        let xsid = await scrypta.buildxSid('123456', 'latin', false)
        console.log(xsid)
        let derive = await scrypta.deriveKeyFromSeed(xsid.seed, "m/0/0/1")
        console.log(derive)
    })

    it('Should generate same key from xpub or xprv', async function () {
        this.timeout(35000)
        scrypta.testnet = false
        let xsid = await scrypta.buildxSid('123456', false)
        let derivexpriv = await scrypta.deriveKeyFromXPrv(xsid.xprv, "m/0/0/2")
        console.log(derivexpriv)
        let derive = await scrypta.deriveKeyfromXPub(xsid.xpub, "m/0/0/2")
        console.log(derive)
    })

    it('Should return same xpub and xprv', async function () {
        this.timeout(35000)
        scrypta.testnet = false
        let xsid = await scrypta.buildxSid('123456', false)
        console.log(xsid)
        let xkeys = await scrypta.returnXKeysFromSeed(xsid.seed)
        console.log(xkeys)
    })

    it('Should derive same address from seed or xprv or xpub', async function () {
        this.timeout(35000)
        scrypta.testnet = false
        let xsid = await scrypta.buildxSid('123456', false)
        console.log(xsid)
        let deriveseed = await scrypta.deriveKeyFromSeed(xsid.seed, "m/0/0/2")
        console.log(deriveseed)
        let derivexpriv = await scrypta.deriveKeyFromXPrv(xsid.xprv, "m/0/0/2")
        console.log(derivexpriv)
        let derive = await scrypta.deriveKeyfromXPub(xsid.xpub, "m/0/0/2")
        console.log(derive)
    })
});
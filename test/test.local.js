let ScryptaCore = require('../src/index.js')
let scrypta = new ScryptaCore
var assert = require('assert')
const password = '123456'

describe('Addresses', async function() {
    it('Address should be length 34 bytes', async function(){
        let address = await scrypta.createAddress(password, true)
        assert.equal(34, address.pub.length);
    })
    it('PubKey should be length 66 bytes', async function(){
        let address = await scrypta.createAddress(password, true)
        assert.equal(66, address.key.length);
    })
    it('PrivKey should be length 52 bytes', async function(){
        let address = await scrypta.createAddress(password, true)
        assert.equal(52, address.prv.length);
    })
    it('Wallet store shuold be decryptable and address should be the same', async function(){
        let address = await scrypta.createAddress(password, true)
        let readed = await scrypta.readKey(password, address.walletstore)
        assert.equal(readed.key, address.key);
    })
    it('Should import a private key', async function(){
        let address = await scrypta.createAddress(password, true)
        let key = await scrypta.importPrivateKey(address.prv, password)
        assert.equal(key.prv, address.prv);
    })
    it('Should return all identities', async function(){
        let identities = await scrypta.returnIdentities()
        assert.notEqual(0, identities.count);
    })
    it('Should create RSA keys for identity', async function(){
        let address = await scrypta.createAddress(password, true)
        await scrypta.createRSAKeys(address.pub, password)
        let identity = await scrypta.returnIdentity(address.pub)
        assert.notEqual(undefined, identity.rsa);
    })
});

describe('Idanodes', async function() {
    it('Should GET first available IdaNode', function(){
        return new Promise(async response => {
            let getinfo = await scrypta.get('/wallet/getinfo')
            if(getinfo.blocks !== undefined){
                response(getinfo.blocks)
            }
        })
    })

    it('Should POST first available IdaNode', async function(){
        let Bob = await scrypta.createAddress(password, true)
        let Alice = await scrypta.createAddress(password, true)
        let trustlink = await scrypta.post('/trustlink/init', { addresses: Bob.key + ',' + Alice.key, airdrop: false})
        assert.equal(34, trustlink.data.address.length);
    })
});

describe('P2P Network', async function() {
    it('Should connect to p2p network and send a message', function(){
        this.timeout(10000)
        return new Promise(async response => {
            let address = await scrypta.createAddress(password, true)
            scrypta.connectP2P(address.walletstore, password, function(received){
                response(received)
            })
            setTimeout(function(){
                scrypta.broadcast(address.walletstore, password, 'message', 'Now are '+ new Date() +'!')
            },3500)
        })
    })
})

let ScryptaCore = require('../src/index.js')
let scrypta = new ScryptaCore
var assert = require('assert')
const password = '123456'
scrypta.debug = true
describe('Addresses', async function() {
    it('Should hash something', async function (){
        let hash = await scrypta.hash('123456')
        console.log('HASH', hash)
    })
    it('Should fund address', async function(){
        this.timeout(35000)
        let funded = await scrypta.fundAddress('SqKfYCBLjWx3NobRBTdeHN75HXn9f9wgi2po1QkwLvwHxCVHM3Qw', 'LKsWzbbmi43tHb5KPv7jv3zm43eGeYaKJK', 0.001)
        console.log(funded)
    })
    it('Should create a testnet address', async function(){
        this.timeout(35000)
        let address = await scrypta.createAddress('123456')
        console.log('ADDRESS IS', address)
        assert.strictEqual(34, address.pub.length);
    })
    it('Should create a mainnet address', async function(){
        this.timeout(35000)
        let address = await scrypta.createAddress('123456')
        console.log('ADDRESS IS', address)
        assert.strictEqual(34, address.pub.length);
    })
    it('Address can send a transaction', async function(){
        this.timeout(35000)
        let prv = 'SqKfYCBLjWx3NobRBTdeHN75HXn9f9wgi2po1QkwLvwHxCVHM3Qw'
        let pub = 'LY6BHLvjNbHCQxnpGgt6BvXhXjfX6Nk1X2'
        let to = 'LKsWzbbmi43tHb5KPv7jv3zm43eGeYaKJK'
        let amount = 0.001
        let password = 'password'
        await scrypta.importPrivateKey(prv, password)
        scrypta.debug = true
        let tx = await scrypta.send(pub, password, to, amount)
        console.log('TX RESPONSE IS', tx)
        assert.equal(64, tx.length);
    })
    it('Should return all nodes', async function(){
        let nodes = await scrypta.returnNodes()
        assert.equal(16, nodes.length);
    })
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
        this.timeout(15000)
        let address = await scrypta.createAddress(password, true)
        await scrypta.createRSAKeys(address.pub, password)
        let identity = await scrypta.returnIdentity(address.pub)
        assert.notEqual(undefined, identity.rsa);
    })
});

describe('Idanodes', async function() {
    it('Should GET first available IdaNode', function(){
        this.timeout(35000)
        return new Promise(async response => {
            let getinfo = await scrypta.get('/wallet/getinfo', 'https://idanodejs09.scryptachain.org')
            if(getinfo !== false){
                response(getinfo)
            }
        })
    })

    it('Should POST first available IdaNode', async function(){
        this.timeout(35000)
        let Bob = await scrypta.createAddress(password, true)
        let Alice = await scrypta.createAddress(password, true)
        let trustlink = await scrypta.post('/trustlink/init', { addresses: Bob.key + ',' + Alice.key, airdrop: false})
        assert.equal(34, trustlink.data.address.length);
    })
});

describe('Planum', async function() {
    it('Should return a list of unspent', async function(){
        this.timeout(30000)
        scrypta.usePlanum('6ShzCp8oXAqVSZdrkNMSj13ghobwZZRzGm')
        let unspent = await scrypta.listPlanumUnspent('LchzGX6vqmanceCzNUMTk5cmnt1p6knGgT')
        assert.equal(1, unspent.length);
    })
})

describe('P2P Network', async function() {
    it('Should connect to p2p network and send a message', function(){
        this.timeout(15000)
        return new Promise(async response => {
            let address = await scrypta.createAddress(password, true)
            scrypta.connectP2P(function(received){
                response(received)
            })
            setInterval(function(){
                scrypta.broadcast(address.walletstore, password, 'message', 'Now are '+ new Date() +'!')
            },3500)
        })
    })
})

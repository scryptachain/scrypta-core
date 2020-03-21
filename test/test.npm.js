let ScryptaCore = require('@scrypta/core')
let scrypta = new ScryptaCore
var assert = require('assert')
const password = '123456'

describe('Addresses', async function() {
    it('Address should be length 34 bytes', async function(){
        let address = await scrypta.createAddress(password, false)
        assert.equal(34, address.pub.length);
    })
    it('PubKey should be length 66 bytes', async function(){
        let address = await scrypta.createAddress(password, false)
        assert.equal(66, address.key.length);
    })
    it('PrivKey should be length 52 bytes', async function(){
        let address = await scrypta.createAddress(password, false)
        assert.equal(52, address.prv.length);
    })
    it('Wallet store shuold be decryptable and address should be the same', async function(){
        let address = await scrypta.createAddress(password, false)
        let readed = await scrypta.readKey(password, address.walletstore)
        assert.equal(readed.key, address.key);
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
        let Bob = await scrypta.createAddress(password, false)
        let Alice = await scrypta.createAddress(password, false)
        let trustlink = await scrypta.post('/trustlink/init', { addresses: Bob.key + ',' + Alice.key, airdrop: false})
        assert.equal(34, trustlink.data.address.length);
    })
});
let ScryptaCore = require('../src/index.js')
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

/*
// SHOULD CREATE ADDRESS
let password = '123456'
scrypta.createAddress(password, true).then(async res => {
    // SHOULD RETURN THE WALLETSTORE
    let walletstore = await scrypta.returnKey(res.pub)
    console.log(walletstore)

    // SHOULD GET AN IDANODE
    let getinfo = await scrypta.get('/wallet/getinfo')
    console.log(JSON.stringify(getinfo))

    // SHOULD POST AN IDANODE
    let init = await scrypta.post('/init',{address: res.pub})
    console.log(JSON.stringify(init))

    // SHOULD CONNECT TO ALL IDANODES
    scrypta.connectP2P(res.pub, password, function(received){
        console.log('Received ' + JSON.stringify(received))
    })

    // SHUOLD SEND A MESSAGE
    setInterval(function(){
        scrypta.broadcast(res.pub, password, 'message', 'Now are '+ new Date() +'!')
    },2500)
})*/
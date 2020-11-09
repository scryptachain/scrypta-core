let ScryptaCore = require('../src/index.js')
let scrypta = new ScryptaCore
var assert = require('assert')
const password = '123456'

describe('Contracts', async function() {
    it('Should create a contract request', async function(){
        this.timeout(35000)
        let address = await scrypta.createAddress('123456')
        scrypta.debug = true
        scrypta.staticnodes = true
        scrypta.mainnetIdaNodes.push('https://idanode01.beesy24.net')
        let request = await scrypta.createContractRequest(address.walletstore, '123456', { contract: "LcD7AGaY74xvVxDg3NkKjfP6QpG8Pmxpnu", function: "search", params: {name: "turinglabs"} })
        let response = await scrypta.sendContractRequest(request)
        console.log('CONTRACT RESPONSE IS', response)
        assert.notStrictEqual(false, response);
    })
    it('Should return average time from contracts', async function(){
        this.timeout(35000)
        let response = await scrypta.gettime()
        console.log(response)
        assert.notStrictEqual(false, response);
    })
});
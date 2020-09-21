let ScryptaCore = require('../src/index.js')
let scrypta = new ScryptaCore
var assert = require('assert')
const password = '123456'

describe('Contracts', async function() {
    it('Should create a contract request', async function(){
        this.timeout(35000)
        let address = await scrypta.createAddress('123456')
        let request = await scrypta.createContractRequest(address.walletstore, '123456', { contract: "LgSAtP3gPURByanZSM32kfEu9C1uyQ6Kfg", function: "index", params: {contract: "LgSAtP3gPURByanZSM32kfEu9C1uyQ6Kfg", version: "latest"} })
        console.log(request)
        let response = await scrypta.sendContractRequest(request, 'https://idanodejs01.scryptachain.org')
        console.log(response)
        assert.notStrictEqual(false, request);
    })
});
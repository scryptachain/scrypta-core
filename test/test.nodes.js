let ScryptaCore = require('../src/index.js')
let scrypta = new ScryptaCore
var assert = require('assert')

describe('Addresses', async function () {
    it('Should return all the nodes', async function () {
        this.timeout(35000)
        let nodes = await scrypta.returnNodes()
        console.log(nodes)
    })
});
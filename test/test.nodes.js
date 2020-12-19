let ScryptaCore = require('../src/index.js')
var assert = require('assert')

describe('Addresses', async function () {
    it('Should return all remote nodes', async function () {
        this.timeout(35000)
        let scrypta = new ScryptaCore
        let nodes = await scrypta.returnNodes()
        console.log(nodes)
    })
    it('Should return a defined node, same for testnet or mainnet', async function () {
        this.timeout(35000)
        let scrypta = new ScryptaCore(false, ['https://idanodejs01.scryptachain.org'])
        let nodes = await scrypta.returnNodes()
        console.log('MAINNET', nodes)
        scrypta.testnet = true
        nodes = await scrypta.returnNodes()
        console.log('TESTNET', nodes)
    })
    it('Should return defined nodes, different for testnet or mainnet', async function () {
        this.timeout(35000)
        let scrypta = new ScryptaCore(false, {mainnet: ['https://idanodejs01.scryptachain.org'], testnet: ['https://testnet.scryptachain.org']})
        let nodes = await scrypta.returnNodes()
        console.log('MAINNET', nodes)
        scrypta.testnet = true
        nodes = await scrypta.returnNodes()
        console.log('TESTNET', nodes)
    })
});
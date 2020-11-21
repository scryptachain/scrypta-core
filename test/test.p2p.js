let ScryptaCore = require('../src/index.js')
let scrypta = new ScryptaCore
// scrypta.staticnodes = true
scrypta.debug = true
scrypta.mainnetIdaNodes = ['https://idanodejs01.scryptachain.org','https://idanodejs02.scryptachain.org','https://idanodejs03.scryptachain.org','https://idanodejs04.scryptachain.org','https://idanodejs05.scryptachain.org','https://idanodejs06.scryptachain.org'] //OVVERIDE IDANODES

scrypta.connectP2P(function(received){
    console.log('Received ' + JSON.stringify(received))
})
let ScryptaCore = require('../src/index.js')
let scrypta = new ScryptaCore
// scrypta.mainnetIdaNodes = ['http://localhost:3001'] //OVVERIDE IDANODES

scrypta.connectP2P(function(received){
    console.log('Received ' + JSON.stringify(received))
})
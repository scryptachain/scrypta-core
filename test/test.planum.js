let ScryptaCore = require('../src/index.js')
let scrypta = new ScryptaCore
// scrypta.mainnetIdaNodes = ['http://localhost:3001']

async function send(amount = 0.001){
    return new Promise(async response => {
        let prv = 'Sq9GWa9vyM1HghsnVan5UJhtx2GumTaLBTHgDhCW4abjzZLmsYmr'
        let pub = 'LdRQokR1i3XDtj1V3jnCRqMPrVc7sYkeE2'
        let sidechain = '6RQ54yHx2dARWkN8Biiw3gDjb4sB5hSHSH'
        let to = 'LchzGX6vqmanceCzNUMTk5cmnt1p6knGgT'
        let password = 'password'
        scrypta.usePlanum(sidechain)
        await scrypta.importPrivateKey(prv, password)
        let tx = await scrypta.sendPlanumAsset(pub, password, to, amount)
        console.log('SXID IS ' + tx)
        response(tx)
    })
}
var i = 1
async function runtest(){
    let amount = i / 1000
    console.log('SENDING ' + amount)
    await send(amount)
    i++
    runtest()
}
runtest()
/*
setInterval(function(){
    runtest()
},2000)
*/
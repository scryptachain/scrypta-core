let ScryptaCore = require('../src/index.js')
let scrypta = new ScryptaCore
// scrypta.mainnetIdaNodes = ['http://localhost:3001']

async function send(amount = 0.001){
    return new Promise(async response => {
        let started = new Date().getTime()
        scrypta.staticnodes = true
        let prv = 'Sq9GWa9vyM1HghsnVan5UJhtx2GumTaLBTHgDhCW4abjzZLmsYmr'
        let pub = 'LdRQokR1i3XDtj1V3jnCRqMPrVc7sYkeE2'
        let sidechain = '6VheKpdJZD7dv6xCP8cEgaXFAMZ7HtgMvK'
        let to = 'LchzGX6vqmanceCzNUMTk5cmnt1p6knGgT'
        let password = 'password'
        scrypta.debug = true
        scrypta.usePlanum(sidechain)
        await scrypta.importPrivateKey(prv, password)
        let balance = await scrypta.returnPlanumBalance(pub)
        console.log('BALANCE', balance)
        let transactions = await scrypta.returnPlanumTransactions(pub)
        console.log('TRANSACTIONS', transactions)
        /**
         * SEND COINS IN THE FUTURE
         */
        // let time = new Date()
        // time.setHours(time.getHours() + 4);
        // let tx = await scrypta.sendPlanumAsset(pub, password, to, amount, '', '', time.getTime())
        if(balance.balance > 0){
            let tx = await scrypta.sendPlanumAsset(pub, password, to, amount)
            let ended = new Date().getTime()
            let elapsed = ended - started
            console.log('TRANSACTION CREATED IN ' + elapsed + 'ms')
            console.log('SXID IS ' + tx)
        }else{
            console.log('NOT ENOUGH BALANCE')
        }
        response(true)
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
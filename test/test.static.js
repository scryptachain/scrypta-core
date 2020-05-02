let ScryptaCore = require('../src/index.js')
let scrypta = new ScryptaCore
scrypta.mainnetIdaNodes = ['http://localhost:3001'] //OVVERIDE IDANODES

// SHOULD CREATE ADDRESS
let password = '123456'
scrypta.createAddress(password, true).then(async res => {
    // SHOULD RETURN THE WALLETSTORE
    console.log('CREATED NEW ADDRESS ' + res.pub)
    let walletstore = await scrypta.returnKey(res.pub)
    console.log(walletstore)

    // SHOULD GET AN IDANODE
    console.log('SHOULD GET FIRST IDANODE')
    let getinfo = await scrypta.get('/wallet/getinfo')
    console.log(JSON.stringify(getinfo))

    // SHOULD POST AN IDANODE
    let init = await scrypta.post('/init',{address: res.pub})
    console.log(JSON.stringify(init))

    // SHOULD CONNECT TO ALL IDANODES
    console.log('SHOULD CONNECT TO ALL IDANODES WITH ADDRESS ' + res.pub)
    scrypta.connectP2P(res.pub, password, function(received){
        console.log('Received ' + JSON.stringify(received))
    })

    // SHUOLD SEND A MESSAGE
    setInterval(function(){
        scrypta.broadcast(res.pub, password, 'message', 'Now are '+ new Date() +'!')
    },2500)
})
let ScryptaCore = require('../src/index.js')
let scrypta = new ScryptaCore
// scrypta.mainnetIdaNodes = ['http://localhost:3001'] -> OVERRIDE IDANODES

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
})
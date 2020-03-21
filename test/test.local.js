let ScryptaCore = require('../src/index.js')

let scrypta = new ScryptaCore
// SHOULD CREATE ADDRESS
let password = '123456'
scrypta.createAddress(password, true).then(async res => {
    // SHOULD RETURN THE WALLETSTORE
    let walletstore = await scrypta.returnKey(res.pub)
    console.log(walletstore)

    // SHOULD CONNECT TO ALL IDANODES
    scrypta.connectP2P(res.pub, password)
})
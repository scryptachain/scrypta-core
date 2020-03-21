let ScryptaCore = require('../src/index.js')

let scrypta = new ScryptaCore
// SHOULD CREATE ADDRESS
scrypta.createAddress('123456', true).then(async res => {
    // SHOULD RETURN THE WALLETSTORE
    let walletstore = await scrypta.returnKey(res.pub)
    console.log(walletstore)
})
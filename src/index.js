const _ = require('lodash')
const CoinKey = require('@scrypta/coinkey')
const crypto = require('crypto')
const CryptoJS = require('crypto-js')
const secp256k1 = require('secp256k1')
const cs = require('coinstring')
const axios = require('axios')
const Trx = require('./trx/trx')
const ScryptaDB = require('./db')
const NodeRSA = require('node-rsa');
const { sum, round, subtract } = require('mathjs')
const { captureRejectionSymbol } = require('events')

const lyraInfo = {
    mainnet: {
        private: 0xae,
        public: 0x30,
        scripthash: 0x0d
    },
    testnet: {
        private: 0xae,
        public: 0x7f,
        scripthash: 0x13
    }
}

global['io'] = { server: null, client: null, sockets: {} }
global['nodes'] = {}
global['connected'] = {}
global['cache'] = []

module.exports = class ScryptaCore {
    constructor(isBrowser = false) {
        this.RAWsAPIKey = ''
        this.PubAddress = ''
        this.mainnetIdaNodes = ['https://idanodejs01.scryptachain.org', 'https://idanodejs02.scryptachain.org', 'https://idanodejs03.scryptachain.org', 'https://idanodejs04.scryptachain.org', 'https://idanodejs05.scryptachain.org', 'https://idanodejs06.scryptachain.org']
        this.testnetIdaNodes = ['https://testnet.scryptachain.org']
        this.staticnodes = false
        this.debug = false
        this.testnet = false
        this.portP2P = 42226
        this.sidechain = ''
        this.idanode = ''
        this.isBrowser = isBrowser
        this.math = {}
        this.math.sum = sum
        this.math.round = round
        this.math.subtract = subtract

        if (isBrowser) {
            this.importBrowserSID()
        }
        this.clearCache()
    }

    //IDANODE FUNCTIONS
    returnNodes() {
        const app = this
        return new Promise(async response => {
            if (this.staticnodes === false) {
                if (this.testnet === true) {
                    response(app.testnetIdaNodes)
                } else {
                    const db = new ScryptaDB(app.isBrowser)
                    let idanodes = await db.get('nodes')
                    try {
                        let nodes_git = await axios.get('https://raw.githubusercontent.com/scryptachain/scrypta-idanode-network/master/peers')
                        let raw_nodes = nodes_git.data.split("\n")
                        let nodes = []
                        for (let x in raw_nodes) {
                            let node = raw_nodes[x].split(':')
                            let url = 'https://idanodejs' + node[0] + '.scryptachain.org'
                            await db.put('nodes', url)
                            nodes.push(url)
                        }
                        response(nodes)
                    } catch (e) {
                        if (idanodes.length > 0) {
                            response(idanodes)
                        } else {
                            // FALLBACK TO STATIC NODES IF GIT FAILS AND DB IS EMPTY
                            response(app.mainnetIdaNodes)
                        }
                    }
                }
            } else {
                response(app.mainnetIdaNodes)
            }
        })
    }

    post(endpoint, params, node = '') {
        const app = this
        return new Promise(async response => {
            if (node === '') {
                node = await app.connectNode()
            }
            let res
            try{
                res = await axios.post(node + endpoint, params, { timeout: 20000 }).catch(err => { 
                    console.log("ERROR ON IDANODE " + node + ": " + err.message) 
                    response(false)
                })
            }catch(e){
                node = await app.connectNode()
                res = await axios.post(node + endpoint, params, { timeout: 20000 }).catch(err => { 
                    console.log("ERROR ON IDANODE " + node + ": " + err.message) 
                    response(false)
                })
            }
            response(res.data)
        })
    }

    get(endpoint, node = '') {
        const app = this
        return new Promise(async response => {
            if (node === '') {
                node = await app.connectNode()
            }
            let res
            try{
                res = await axios.get(node + endpoint, { timeout: 20000 }).catch(err => { 
                    console.log("ERROR ON IDANODE " + node + ": " + err.message) 
                    response(false) 
                })
            }catch(e){
                node = await app.connectNode()
                res = await axios.get(node + endpoint, { timeout: 20000 }).catch(err => { 
                    console.log("ERROR ON IDANODE " + node + ": " + err.message) 
                    response(false) 
                })
            }
            if (res !== undefined) {
                response(res.data)
            }else{
                response(false)
            }
        })
    }

    testnet(value = true) {
        this.testnet = value
    }

    async checkNode(node) {
        return new Promise(response => {
            axios.get(node + '/wallet/getinfo', { timeout: 20000 }).catch(err => {
                response(false)
            }).then(result => {
                response(result)
            })
        })
    }

    async connectNode() {
        const app = this
        return new Promise(async response => {
            if (app.idanode === '') {
                let connected = false
                if(app.debug === true){
                    console.log('CONNECTING TO ' + app.idanode)
                }
                while (connected === false) {
                    let node = await this.returnFirstNode()
                    if (node !== false) {
                        connected = true
                        app.idanode = node
                        if(app.debug === true){
                            console.log('CONNECTED TO ' + app.idanode)
                        }
                        response(node)
                    }
                }
            } else {
                let check = await app.checkNode(app.idanode)
                if (check !== false && check.data.toindex <= 1) {
                    if(app.debug === true){
                        console.log('CONNECTED IDANODE ' + app.idanode + ' STILL VALID')
                    }
                    response(app.idanode)
                } else {
                    app.idanode = ''
                    let connected = false
                    if(app.debug === true){
                        console.log('CONNECTED IDANODE ' + app.idanode + ' NOT VALID ANYMORE, CONNECTING TO NEW IDANODE')
                    }
                    while (connected === false) {
                        let node = await this.returnFirstNode()
                        if (node !== false) {
                            connected = true
                            app.idanode = node
                            response(node)
                        }
                    }
                }
            }
        })
    }

    async returnLastChecksum(version) {
        const app = this
        return new Promise(async response => {
            const db = new ScryptaDB(app.isBrowser)
            let last = await db.get('checksums', 'version', version)
            if (last === false) {
                try {
                    let checksums_git = await axios.get('https://raw.githubusercontent.com/scryptachain/scrypta-idanodejs/master/checksum')
                    let checksums = checksums_git.data.split("\n")
                    for (let x in checksums) {
                        let checksum = checksums[x].split(':')
                        if (checksum[0] === version) {
                            await db.put('checksums', {
                                version: version,
                                checksum: checksum[1]
                            })
                            response(checksum[1])
                        }
                    }
                } catch (e) {
                    console.log(e)
                    response(false)
                }
            } else {
                response(last.checksum)
            }
        })
    }

    async returnFirstNode() {
        const app = this
        return new Promise(async response => {
            let nodes = await this.returnNodes()
            var checknodes = this.shuffle(nodes)
            let connected = false
            for (var i = 0; i < checknodes.length; i++) {
                try {
                    axios.get(checknodes[i] + '/wallet/getinfo', { timeout: 20000 }).then(async check => {
                        let checksum = await app.returnLastChecksum(check.data.version)
                        let isValid = true
                        if (checksum !== false) {
                            if (check.data.checksum !== checksum) {
                                isValid = false
                            }
                        }
                        if (check.data.blocks !== undefined && connected === false && check.data.toindex === 0 && isValid) {
                            connected = true
                            if (check.config.url !== undefined) {
                                response(check.config.url.replace('/wallet/getinfo', ''))
                            }
                        }
                    }).catch(err => {
                        response(false)
                    })
                } catch (err) {
                    // console.log(err)
                }
            }
            setTimeout(function () {
                if (connected === false) {
                    response(false)
                }
            }, 1500)
        })
    }

    //CACHE FUNCTIONS
    async clearCache(force = false) {
        const app = this
        return new Promise(async response => {
            const db = new ScryptaDB(app.isBrowser)
            if (force) {
                await db.destroy('sxidcache')
                await db.destroy('txidcache')
            }
            await db.destroy('usxocache')
            await db.destroy('utxocache')
            response(true)
        })
    }

    async returnTXIDCache() {
        const app = this
        return new Promise(async response => {
            const db = new ScryptaDB(app.isBrowser)
            let cache = await db.get('txidcache')
            response(cache)
        })
    }

    async pushTXIDtoCache(txid) {
        const app = this
        return new Promise(async response => {
            const db = new ScryptaDB(app.isBrowser)
            await db.put('txidcache', txid)
            response(true)
        })
    }

    async returnUTXOCache() {
        const app = this
        return new Promise(async response => {
            const db = new ScryptaDB(app.isBrowser)
            let cache = await db.get('utxocache')
            response(cache)
        })
    }

    async pushUTXOtoCache(utxo) {
        const app = this
        return new Promise(async response => {
            const db = new ScryptaDB(app.isBrowser)
            await db.put('utxocache', utxo)
            response(true)
        })
    }

    async returnSXIDCache() {
        const app = this
        return new Promise(async response => {
            const db = new ScryptaDB(app.isBrowser)
            let cache = await db.get('sxidcache')
            response(cache)
        })
    }

    async pushSXIDtoCache(sxid) {
        const app = this
        return new Promise(async response => {
            const db = new ScryptaDB(app.isBrowser)
            await db.put('sxidcache', sxid)
            response(true)
        })
    }

    async returnUSXOCache() {
        const app = this
        return new Promise(async response => {
            const db = new ScryptaDB(app.isBrowser)
            let cache = await db.get('usxocache')
            response(cache)
        })
    }

    async pushUSXOtoCache(usxo) {
        const app = this
        return new Promise(async response => {
            const db = new ScryptaDB(app.isBrowser)
            await db.put('usxocache', usxo)
            response(true)
        })
    }

    // UTILITIES FUNCTION
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    //CRYPT AND ENCRYPT FUNCTIONS
    async cryptData(data, password) {
        return new Promise(response => {
            let iv = crypto.randomBytes(16)
            let key = crypto.createHash('sha256').update(String(password)).digest('base64').substr(0, 32)
            let cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
            let encrypted = cipher.update(data);
            encrypted = Buffer.concat([encrypted, cipher.final()]);
            let hex = iv.toString('hex') + '*' + encrypted.toString('hex')
            response(hex)
        })
    }

    async decryptData(data, password, buffer = false) {
        return new Promise(response => {
            try {
                if(data.indexOf('*') === -1){
                    // MAINTAIN FALLBACK TO OLD ENCRYPTED WALLETS
                    var decipher = crypto.createDecipher('aes-256-cbc', password)
                    var dec = decipher.update(data, 'hex', 'utf8')
                    dec += decipher.final('utf8')
                    response(dec)
                }else{
                    let textParts = data.split('*');
                    let iv = Buffer.from(textParts.shift(), 'hex')
                    let encryptedText = Buffer.from(textParts.join('*'), 'hex')
                    let key = crypto.createHash('sha256').update(String(password)).digest('base64').substr(0, 32)
                    let decipher = crypto.createDecipheriv('aes-256-ctr', key, iv)
                    let decrypted = decipher.update(encryptedText)
                    decrypted = Buffer.concat([decrypted, decipher.final()])
                    if(buffer === false){
                        response(decrypted.toString())
                    }else{
                        response(decrypted)
                    }
                }
            } catch (e) {
                response(false)
            }
        })
    }

    // DEPRECATED
    async cryptFile(file, password) {
        return new Promise(response => {

            const reader = new FileReader();
            reader.onload = function () {
                var buf = Buffer(reader.result)
                var cipher = crypto.createCipher('aes-256-cbc', password)
                var crypted = Buffer.concat([cipher.update(buf), cipher.final()])
                response(crypted.toString('hex'))
            };

            reader.readAsArrayBuffer(file);
        })
    }

    // DEPRECATED
    async decryptFile(file, password) {
        return new Promise(response => {
            try {
                let buf = Buffer(file, 'hex')
                var decipher = crypto.createDecipher('aes-256-cbc', password)
                var decrypted = Buffer.concat([decipher.update(buf), decipher.final()])
                response(decrypted)
            } catch (e) {
                response(false)
            }
        })
    }

    //ADDRESS MANAGEMENT
    async createAddress(password, saveKey = true) {
        // LYRA WALLET
        let params = lyraInfo.mainnet
        if (this.testnet === true) {
            params = lyraInfo.testnet
        }
        var ck = new CoinKey.createRandom(params)

        var lyrapub = ck.publicAddress;
        var lyraprv = ck.privateWif;
        var lyrakey = ck.publicKey.toString('hex');

        var wallet = {
            prv: lyraprv,
            key: lyrakey
        }

        var walletstore = await this.buildWallet(password, lyrapub, wallet, saveKey)

        var response = {
            pub: lyrapub,
            key: lyrakey,
            prv: lyraprv,
            walletstore: walletstore
        }
        return response;
    }

    async buildWallet(password, pub, wallet, saveKey) {
        const app = this
        const db = new ScryptaDB(app.isBrowser)
        return new Promise(async response => {

            let wallethex = await this.cryptData(JSON.stringify(wallet), password)
            var walletstore = pub + ':' + wallethex;

            if (saveKey === true) {
                let check = await db.get('wallet', 'address', pub)
                if (!check) {
                    await db.put('wallet', {
                        address: pub,
                        wallet: walletstore
                    })
                } else {
                    await db.update('wallet', 'address', pub, {
                        address: pub,
                        wallet: walletstore
                    })
                }
            }

            response(walletstore)
        })
    }

    async initAddress(address) {
        const app = this
        const node = await app.connectNode();
        const response = await axios.post(node + '/init', { address: address, airdrop: true })
        return response;
    }

    async getPublicKey(privateWif) {
        var ck = new CoinKey.fromWif(privateWif);
        var pubkey = ck.publicKey.toString('hex');
        return pubkey;
    }

    async getAddressFromPubKey(pubKey) {
        return new Promise(response => {
            let params = lyraInfo.mainnet
            if (this.testnet === true) {
                params = lyraInfo.testnet
            }
            let pubkeybuffer = Buffer.from(pubKey, 'hex')
            var sha = crypto.createHash('sha256').update(pubkeybuffer).digest()
            let pubKeyHash = crypto.createHash('rmd160').update(sha).digest()
            var hash160Buf = Buffer.from(pubKeyHash, 'hex')
            response(cs.encode(hash160Buf, params.public))
        })
    }

    async importBrowserSID() {
        const app = this
        const db = new ScryptaDB(app.isBrowser)
        if (app.isBrowser) {
            let SID = localStorage.getItem('SID')
            if (SID !== null) {
                let SIDS = SID.split(':')
                let check = await db.get('wallet', 'address', SIDS[0])
                if (!check) {
                    await db.put('wallet', {
                        address: SIDS[0],
                        wallet: SIDS[0] + ':' + SIDS[1]
                    })
                }
            }
        }
    }


    importPrivateKey(key, password) {
        return new Promise(async response => {
            let lyrakey = await this.getPublicKey(key)
            let lyrapub = await this.getAddressFromPubKey(lyrakey)

            var wallet = {
                prv: key,
                key: lyrakey
            }
            var walletstore = await this.buildWallet(password, lyrapub, wallet, true)

            response({
                pub: lyrapub,
                key: lyrakey,
                prv: key,
                walletstore: walletstore
            })
        })
    }

    returnKey(address) {
        const app = this
        return new Promise(async response => {
            if (address.length === 34) {
                const db = new ScryptaDB(app.isBrowser)
                let doc = await db.get('wallet', 'address', address)
                if (doc !== undefined) {
                    response(doc.wallet)
                } else {
                    response(false)
                }
            } else {
                response(address)
            }
        })
    }

    async readKey(password, key) {
        let wallet = await this.returnKey(key)
        if (wallet !== false) {
            if (password !== '') {
                var SIDS = key.split(':');
                try {
                    let decrypted = await this.decryptData(SIDS[1], password)
                    return Promise.resolve(JSON.parse(decrypted));
                } catch (ex) {
                    // console.log('WRONG PASSWORD')
                    return Promise.resolve(false);
                }
            }
        } else {
            return false
        }
    }

    //TRANSACTIONS FUNCTIONS
    async listUnspent(address) {
        const app = this
        const node = await app.connectNode();
        var unspent = await app.get('/unspent/' + address)
        return unspent.unspent
    }

    async sendRawTransaction(rawtransaction) {
        const app = this
        var txid = await app.post('/sendrawtransaction',
            { rawtransaction: rawtransaction }
        ).catch(function (err) {
            console.log(err)
        })
        return txid.data
    }

    async decodeRawTransaction(rawtransaction) {
        const app = this
        const node = await app.connectNode();
        if (node !== undefined) {
            var transaction = await axios.post(
                node + '/decoderawtransaction',
                { rawtransaction: rawtransaction }
            ).catch(function (err) {
                console.log(err)
            })
            return transaction.data.transaction
        } else {
            return Promise.resolve(false)
        }
    }

    async build(key, password, send = false, to, amount, metadata = '', fees = 0.001) {
        var SID = key;
        var MAX_OPRETURN = 7500
        if (password !== '') {
            var SIDS = SID.split(':');
            try {
                let decrypted = await this.decryptData(SIDS[1], password)
                decrypted = JSON.parse(decrypted)
                var trx = Trx.transaction();
                var from = SIDS[0]
                var unspent = []
                var inputs = []
                var cache = await this.returnUTXOCache()
                if (cache !== undefined && cache.length > 0) {
                    for (var x = 0; x < cache.length; x++) {
                        if(this.debug){
                            console.log(cache[x])
                        }
                        if(cache[x].address === SIDS[0]){
                            unspent.push(cache[x])
                        }
                    }
                }
                var listunspent = await this.listUnspent(from)
                for (var x = 0; x < listunspent.length; x++) {
                    unspent.push(listunspent[x])
                }
                if(this.debug){
                    console.log('UNSPENT', unspent, unspent.length)
                }
                if (unspent.length > 0) {
                    var inputamount = 0;
                    var amountneed = amount + fees;
                    for (var i = 0; i < unspent.length; i++) {
                        if (inputamount <= amountneed) {
                            var txid = unspent[i]['txid'];
                            var index = unspent[i]['vout'];
                            var script = unspent[i]['scriptPubKey'];
                            var cache = await this.returnTXIDCache()
                            if (cache.indexOf(txid + ':' + index) === -1 && inputs.indexOf(txid + ':' + index) === -1) {
                                trx.addinput(txid, index, script);
                                inputamount += unspent[i]['amount']
                                inputs.push(txid + ':' + index)
                            }else if(this.debug){
                                console.log('INPUT ALREADY IN CACHE ' + txid + ':' + index)
                            }
                        }
                    }
                    if (inputamount >= amountneed) {
                        var change = inputamount - amountneed;
                        if (amount > 0.00001) {
                            trx.addoutput(to, amount);
                        }
                        if (change > 0.00001) {
                            trx.addoutput(from, change);
                        }
                        if (metadata !== '') {
                            if (metadata.length <= MAX_OPRETURN) {
                                //console.log('ADDING METADATA TO TX', metadata)
                                trx.addmetadata(metadata);
                            } else {
                                //console.log('METADATA TOO LONG')
                            }
                        }
                        var wif = decrypted.prv;
                        var signed = trx.sign(wif, 1);
                        if (send === false) {
                            return Promise.resolve({
                                inputs: inputs,
                                signed: signed
                            });
                        } else {
                            var txid = await this.sendRawTransaction(signed)
                            if(this.debug){
                                console.log(txid)
                            }
                            if (txid !== null && txid.length === 64) {
                                for (let i in inputs) {
                                    await this.pushTXIDtoCache(inputs[i])
                                }
                                // console.log("TX SENT: " + txid)
                                return Promise.resolve(txid)
                            }
                        }
                    } else {
                        if(this.debug){ console.log('NOT ENOUGH FUNDS') }
                        return Promise.resolve(false) //NOT ENOUGH FUNDS
                    }
                } else {
                    // console.log('NO UNSPENTS')
                    return Promise.resolve(false) //NOT ENOUGH FUNDS
                }
            } catch (error) {
                console.log(error)
                return Promise.resolve(false);
            }
        }
    }

    async send(key, password, to, amount, metadata = '') {
        let wallet = await this.returnKey(key)
        if (wallet !== false) {
            if (password !== '' && to !== '') {
                var SIDS = wallet.split(':');
                try {
                    let decrypted = await this.decryptData(SIDS[1], password)
                    if(decrypted !== false){
                        var txid = ''
                        var i = 0
                        var rawtransaction
                        while (txid !== null && txid !== undefined && txid.length !== 64) {
                            var fees = 0.001 + (i / 1000)
                            rawtransaction = await this.build(wallet, password, false, to, amount, metadata, fees)
                            if(rawtransaction === false){
                                Promise.resolve(false)
                            }
                            txid = await this.sendRawTransaction(rawtransaction.signed)
                            if(this.debug){
                                console.log(rawtransaction, txid)
                            }
                            if (txid !== null && txid !== false && txid.length === 64) {
                                for (let i in rawtransaction.inputs) {
                                    await this.pushTXIDtoCache(rawtransaction.inputs[i])
                                }
                                //Storing UTXO to cache
                                var decoded = await this.decodeRawTransaction(rawtransaction.signed)
                                if (decoded.vout[1].scriptPubKey.addresses !== undefined) {
                                    let unspent = {
                                        txid: decoded.txid,
                                        vout: 1,
                                        address: decoded.vout[1].scriptPubKey.addresses[0],
                                        scriptPubKey: decoded.vout[1].scriptPubKey.hex,
                                        amount: decoded.vout[1].value
                                    }
                                    await this.pushUTXOtoCache(unspent)
                                }
                            } else {
                                txid = null
                            }
                            i++;
                        }
                        return Promise.resolve(txid)
                    }else{
                        return Promise.resolve(false)
                    }
                } catch (e) {
                    return Promise.resolve(false)
                }
            } else {
                return false
            }
        } else {
            return false
        }
    }

    // PLANUM FUNCTIONS
    usePlanum(sidechain) {
        const app = this
        app.sidechain = sidechain
    }

    async listPlanumUnspent(address) {
        return new Promise(async response => {
            const app = this
            let unspent = []

            // PUSHING LOCAL CACHE
            var cache = await this.returnUSXOCache()
            if (cache !== undefined && cache.length > 0) {
                for (var x = 0; x < cache.length; x++) {
                    unspent.push(cache[x])
                }
            }

            if (app.sidechain !== '') {
                let unspentnode = await app.post('/sidechain/listunspent', { sidechain_address: app.sidechain, dapp_address: address })
                if (unspentnode.unspent !== undefined) {
                    for (let x in unspentnode.unspent) {
                        unspent.push(unspentnode.unspent[x])
                    }
                    response(unspent)
                } else {
                    response(false)
                }
            } else {
                response(false)
            }
        })
    }

    async sendPlanumAsset(key, password, to, amount, changeaddress = '', memo = '') {
        const app = this
        let wallet = await this.returnKey(key)
        if (wallet !== false) {
            if (password !== '' && to !== '') {
                var SIDS = wallet.split(':');
                let decrypted
                try {
                    decrypted = await this.decryptData(SIDS[1], password)
                    decrypted = JSON.parse(decrypted)
                } catch (e) {
                    return false
                }
                if(decrypted.prv !== undefined){
                    const address = SIDS[0]
                    var sxid = ''
                    let unspent = await app.listPlanumUnspent(address)
                    let check_sidechain = await app.post('/sidechain/get', { sidechain_address: app.sidechain })
                    let sidechainObj = check_sidechain.sidechain[0]
                    const decimals = sidechainObj.data.genesis.decimals
                    if (unspent.length > 0) {
                        let inputs = []
                        let outputs = {}
                        let amountinput = 0
                        amount = app.math.round(amount, decimals)
                        let usedtx = []
                        let checkto = await app.get('/validate/' + to)
                        if (checkto.data.isvalid === false) {
                            return Promise.resolve(false)
                        }

                        for (let i in unspent) {
                            if (amountinput < amount) {
                                delete unspent[i]._id
                                delete unspent[i].sidechain
                                delete unspent[i].address
                                delete unspent[i].block
                                delete unspent[i].redeemblock
                                delete unspent[i].redeemed
                                let cache = await this.returnSXIDCache()
                                if (cache.indexOf(unspent[i].sxid + ':' + unspent[i].vout) === -1) {
                                    inputs.push(unspent[i])
                                    usedtx.push(unspent[i].sxid + ':' + unspent[i].vout)
                                    let toadd = app.math.round(unspent[i].amount, decimals)
                                    amountinput = app.math.sum(amountinput, toadd)
                                    amountinput = app.math.round(amountinput, decimals)
                                }
                            }
                        }

                        let totaloutputs = 0
                        amountinput = app.math.round(amountinput, decimals)
                        amount = app.math.round(amount, decimals)
                        if (amountinput >= amount) {

                            if (to === sidechainObj.address && sidechainObj.data.burnable === false) {

                                return Promise.resolve(false)

                            } else {

                                outputs[to] = amount
                                totaloutputs = app.math.sum(totaloutputs, amount)

                                let change = app.math.subtract(amountinput, amount)
                                change = app.math.round(change, decimals)

                                if (to !== address) {
                                    if (change > 0 && changeaddress === '') {
                                        outputs[address] = change
                                        totaloutputs = app.math.sum(totaloutputs, change)
                                    } else if (change > 0 && changeaddress !== '') {
                                        // CHECK IF CHANGE ADDRESS IS VALID
                                        let checkchange = await app.get('validate/' + change)
                                        if (checkchange.data.isvalid === true) {
                                            outputs[changeaddress] = change
                                            totaloutputs = app.math.sum(totaloutputs, change)
                                        } else {
                                            // IF NOT, SEND TO MAIN ADDRESS
                                            outputs[address] = change
                                            totaloutputs = app.math.sum(totaloutputs, change)
                                        }
                                    }
                                } else {
                                    if (change > 0) {
                                        outputs[address] = app.math.sum(change, amount)
                                        outputs[address] = app.math.round(outputs[address], sidechainObj.data.genesis.decimals)
                                        totaloutputs = app.math.sum(totaloutputs, change)
                                    }
                                }

                                totaloutputs = app.math.round(totaloutputs, sidechainObj.data.genesis.decimals)

                                if (inputs.length > 0 && totaloutputs > 0) {
                                    let transaction = {}
                                    transaction["sidechain"] = app.sidechain
                                    transaction["inputs"] = inputs
                                    transaction["outputs"] = outputs
                                    transaction["memo"] = memo
                                    transaction["time"] = new Date().getTime()

                                    let signtx = await app.signMessage(decrypted.prv, JSON.stringify(transaction))

                                    let tx = {
                                        transaction: transaction,
                                        signature: signtx.signature,
                                        pubkey: decrypted.key,
                                        sxid: signtx.hash
                                    }

                                    let validatetransaction = await app.post('/sidechain/validate',
                                        {
                                            transaction: tx,
                                            address: address,
                                            sxid: signtx.hash,
                                            signature: signtx.signature,
                                            pubkey: decrypted.key
                                        }
                                    )

                                    if (validatetransaction.errors === undefined && validatetransaction.valid === true && signtx.hash !== undefined) {
                                        let sent = false
                                        let txs = []
                                        let retry = 0
                                        while (sent === false) {
                                            let written = await app.write(key, password, JSON.stringify(tx), '', '', 'chain://')
                                            if (written.txs.length >= 1 && written.txs[0] !== null) {
                                                for (let x in usedtx) {
                                                    await app.pushSXIDtoCache(usedtx[x])
                                                }
                                                let vout = 0
                                                for (let x in outputs) {
                                                    let unspent = {
                                                        sxid: tx.sxid,
                                                        vout: vout,
                                                        address: x,
                                                        amount: outputs[x],
                                                        sidechain: tx.transaction['sidechain']
                                                    }
                                                    if (unspent.address === address) {
                                                        await app.pushUSXOtoCache(unspent)
                                                    }
                                                    vout++
                                                }
                                                sent = true
                                                txs = written.txs
                                            } else {
                                                retry++
                                                await app.sleep(2000)
                                            }
                                            if (retry > 10) {
                                                sent = true
                                            }
                                        }
                                        if (txs.length >= 1) {
                                            return Promise.resolve(tx.sxid)
                                        } else {
                                            return Promise.resolve(false)
                                        }
                                    } else {
                                        return Promise.resolve(false)
                                    }

                                } else {
                                    return Promise.resolve(false)
                                }
                            }
                        } else {
                            return Promise.resolve(false)
                        }
                    } else {
                        // console.log('NO UNSPENT')
                        return false
                    }
                }else{
                    return false
                }
            } else {
                return false
            }
        } else {
            return false
        }
    }

    //PROGRESSIVE DATA MANAGEMENT
    async write(key, password, metadata, collection = '', refID = '', protocol = '', uuid = '') {
        if (password !== '' && metadata !== '') {
            let wallet = await this.returnKey(key)
            if (wallet !== false) {
                var SIDS = wallet.split(':');
                var MAX_OPRETURN = 7500
                try {
                    //console.log('WRITING TO BLOCKCHAIN')
                    let decrypted = await this.decryptData(SIDS[1], password)
                    if(decrypted !== false){
                        let address = SIDS[0]

                        if (uuid === '') {
                            var Uuid = require('uuid/v4')
                            uuid = Uuid().replace(new RegExp('-', 'g'), '.')
                        }

                        if (collection !== '') {
                            collection = '!*!' + collection
                        } else {
                            collection = '!*!'
                        }

                        if (refID !== '') {
                            refID = '!*!' + refID
                        } else {
                            refID = '!*!'
                        }

                        if (protocol !== '') {
                            protocol = '!*!' + protocol
                        } else {
                            protocol = '!*!'
                        }
                        metadata = metadata.normalize("NFD").replace(/[^\x00-\x7F]/g, "")
                        var dataToWrite = '*!*' + uuid + collection + refID + protocol + '*=>' + metadata + '*!*'
                        if (dataToWrite.length <= MAX_OPRETURN) {
                            var txid = ''
                            var i = 0
                            var totalfees = 0
                            while (txid.length !== 64) {
                                var fees = 0.001 + (i / 1000)
                                var rawtransaction = await this.build(wallet, password, false, address, 0, dataToWrite, fees)
                                if(this.debug){
                                    console.log(rawtransaction.signed)
                                }
                                if (rawtransaction.signed !== false) {
                                    txid = await this.sendRawTransaction(rawtransaction.signed)
                                    if(this.debug){
                                        console.log(txid)
                                    }
                                    if (txid !== null && txid.length === 64) {
                                        totalfees += fees
                                        for (let i in rawtransaction.inputs) {
                                            await this.pushTXIDtoCache(rawtransaction.inputs[i])
                                        }
                                        //Storing UTXO to cache
                                        var decoded = await this.decodeRawTransaction(rawtransaction.signed)
                                        if (decoded.vout[0].scriptPubKey.addresses !== undefined) {
                                            let unspent = {
                                                txid: decoded.txid,
                                                vout: 0,
                                                address: decoded.vout[0].scriptPubKey.addresses[0],
                                                scriptPubKey: decoded.vout[0].scriptPubKey.hex,
                                                amount: decoded.vout[0].value
                                            }
                                            await this.pushUTXOtoCache(unspent)
                                        }
                                    }else{
                                        txid = ''
                                    }
                                }
                                i++;
                            }

                            return Promise.resolve({
                                uuid: uuid,
                                address: wallet,
                                fees: totalfees,
                                collection: collection.replace('!*!', ''),
                                refID: refID.replace('!*!', ''),
                                protocol: protocol.replace('!*!', ''),
                                dimension: dataToWrite.length,
                                chunks: 1,
                                stored: dataToWrite,
                                txs: [txid]
                            })

                        } else {

                            var txs = []
                            var chunklength = MAX_OPRETURN - 6
                            var chunkdatalimit = chunklength - 3
                            var dataToWriteLength = dataToWrite.length
                            var nchunks = Math.ceil(dataToWriteLength / chunklength)
                            var last = nchunks - 1
                            var chunks = []

                            for (var i = 0; i < nchunks; i++) {
                                var start = i * chunklength
                                var end = start + chunklength
                                var chunk = dataToWrite.substring(start, end)

                                if (i === 0) {
                                    var startnext = (i + 1) * chunklength
                                    var endnext = startnext + chunklength
                                    var prevref = ''
                                    var nextref = dataToWrite.substring(startnext, endnext).substring(0, 3)
                                } else if (i === last) {
                                    var startprev = (i - 1) * chunklength
                                    var endprev = startprev + chunklength
                                    var nextref = ''
                                    var prevref = dataToWrite.substr(startprev, endprev).substr(chunkdatalimit, 3)
                                } else {
                                    var sni = i + 1
                                    var startnext = sni * chunklength
                                    var endnext = startnext + chunklength
                                    var nextref = dataToWrite.substring(startnext, endnext).substring(0, 3)
                                    var spi = i - 1
                                    var startprev = spi * chunklength
                                    var endprev = startprev + chunklength
                                    var prevref = dataToWrite.substr(startprev, endprev).substr(chunkdatalimit, 3)
                                }
                                chunk = prevref + chunk + nextref
                                chunks.push(chunk)
                            }

                            var totalfees = 0

                            for (var cix = 0; cix < chunks.length; cix++) {
                                var txid = ''
                                var i = 0
                                var rawtransaction
                                while (txid !== null && txid !== undefined && txid.length !== 64) {
                                    var fees = 0.001 + (i / 1000)
                                    //console.log('STORING CHUNK #' + cix, chunks[cix])
                                    rawtransaction = await this.build(wallet, password, false, address, 0, chunks[cix], fees)
                                    txid = await this.sendRawTransaction(rawtransaction.signed)
                                    //console.log(txid)
                                    if (txid !== null && txid !== false && txid.length === 64) {
                                        for (let i in rawtransaction.inputs) {
                                            await this.pushTXIDtoCache(rawtransaction.inputs[i])
                                        }
                                        totalfees += fees
                                        txs.push(txid)
                                        //Storing UTXO to cache
                                        var decoded = await this.decodeRawTransaction(rawtransaction.signed)
                                        if (decoded.vout[0].scriptPubKey.addresses !== undefined) {
                                            let unspent = {
                                                txid: decoded.txid,
                                                vout: 0,
                                                address: decoded.vout[0].scriptPubKey.addresses[0],
                                                scriptPubKey: decoded.vout[0].scriptPubKey.hex,
                                                amount: decoded.vout[0].value
                                            }
                                            await this.pushUTXOtoCache(unspent)
                                        }
                                    } else {
                                        txid = null
                                    }
                                    i++;
                                }
                            }

                            return Promise.resolve({
                                uuid: uuid,
                                address: wallet,
                                fees: totalfees,
                                collection: collection.replace('!*!', ''),
                                refID: refID.replace('!*!', ''),
                                protocol: protocol.replace('!*!', ''),
                                dimension: dataToWrite.length,
                                chunks: nchunks,
                                stored: dataToWrite,
                                txs: txs
                            })

                        }
                    }else{
                        return Promise.resolve(false);
                    }
                } catch (error) {
                    console.log(error)
                    return Promise.resolve(false);
                }
            } else {
                return false
            }
        }
    }

    async update(key, password, metadata, collection = '', refID = '', protocol = '', uuid) {
        return new Promise(response => {
            if (uuid !== undefined) {
                let written = this.write(key, password, metadata, collection, refID, protocol, uuid)
                response(written)
            } else {
                response(false)
            }
        })
    }

    async invalidate(key, password, uuid) {
        return new Promise(response => {
            if (uuid !== undefined) {
                let metadata = 'END'
                let written = this.write(key, password, metadata, '', '', '', uuid)
                response(written)
            } else {
                response(false)
            }
        })
    }

    //SIGNING FUNCTIONS
    async signMessage(key, message) {
        return new Promise(response => {
            //CREATING CK OBJECT
            let params = lyraInfo.mainnet
            if (this.testnet === true) {
                params = lyraInfo.testnet
            }
            var ck = CoinKey.fromWif(key, params);
            //CREATE HASH FROM MESSAGE
            let hash = CryptoJS.SHA256(message);
            let msg = Buffer.from(hash.toString(CryptoJS.enc.Hex), 'hex');
            //GETTING PUBKEY FROM PRIVATEKEY
            let privKey = ck.privateKey
            //SIGN MESSAGE
            const sigObj = secp256k1.sign(msg, privKey)
            const pubKey = secp256k1.publicKeyCreate(privKey)

            response({
                message: message,
                hash: hash.toString(CryptoJS.enc.Hex),
                signature: sigObj.signature.toString('hex'),
                pubkey: pubKey.toString('hex'),
                address: ck.publicAddress
            })
        })
    }

    async verifyMessage(pubkey, signature, message) {
        return new Promise(async response => {
            //CREATE HASH FROM MESSAGE
            let hash = CryptoJS.SHA256(message);
            let msg = Buffer.from(hash.toString(CryptoJS.enc.Hex), 'hex')
            //VERIFY MESSAGE
            let buf = Buffer.from(signature, 'hex')
            let pubKey = Buffer.from(pubkey, 'hex')
            let verified = secp256k1.verify(msg, buf, pubKey)
            let address = await this.getAddressFromPubKey(pubkey)
            if (verified === true) {
                response({
                    address: address,
                    pubkey: pubkey,
                    signature: signature,
                    hash: hash.toString(CryptoJS.enc.Hex),
                    message: message,
                })
            } else {
                response(false)
            }
        })
    }

    // P2P FUNCTIONALITIES

    async connectP2P(callback) {
        const app = this
        let nodes = await this.returnNodes()
        const db = new ScryptaDB(app.isBrowser)

        for (let x in nodes) {
            let node = nodes[x]
            let check = await app.checkNode(node)
            if (check !== false) {
                let ready = await app.get('/wallet/getinfo', node)
                if(ready.blocks !== undefined){
                    try{
                        console.log('Bootstrap connection to ' + node.replace('https://', 'https://p2p.'))
                        global['nodes'][node] = require('socket.io-client')(node.replace('https://', 'https://p2p.'), { reconnect: true })
                        global['nodes'][node].on('connect', function () {
                            console.log('Connected to peer: ' + global['nodes'][node].io.uri)
                            global['connected'][node] = true
                        })
                        global['nodes'][node].on('disconnect', function () {
                            // console.log('Disconnected from peer: ' + global['nodes'][node].io.uri)
                            global['connected'][node] = false
                        })

                        //PROTOCOLS
                        global['nodes'][node].on('message', async function (data) {
                            let verified = await app.verifyMessage(data.pubKey, data.signature, data.message)
                            if (verified !== false && global['cache'].indexOf(data.signature) === -1) {
                                global['cache'].push(data.signature)
                                let check = await db.get('messages', 'signature', data.signature)
                                if (!check) {
                                    await db.put('messages', {
                                        signature: data.signature,
                                        message: data.message,
                                        pubkey: data.pubKey,
                                        address: data.address
                                    }).catch(err => {
                                        // console.log(err)
                                    }).then(success => {
                                        callback(data)
                                    })
                                }
                            }
                        })
                    }catch(e){
                        console.log("CAN'T CONNECT TO " + node)
                    }
                }
            }
        }
    }

    async broadcast(key, password, protocol, message, socketID = '', nodeID = '') {
        const app = this
        key = await this.returnKey(key)
        let wallet = await this.readKey(password, key)
        if (wallet !== false) {
            let signed = await app.signMessage(wallet.prv, message)

            return new Promise(async response => {
                if (nodeID === '') {
                    for (let id in global['nodes']) {
                        global['nodes'][id].emit(protocol, signed)
                    }
                } else {
                    if (global['nodes'][nodeID]) {
                        global['nodes'][nodeID].emit(protocol, signed)
                    }
                }
                response(message)
            })
        }
    }

    // IDENTITIES FUNCTIONS
    returnIdentities() {
        const app = this
        return new Promise(response => {
            const db = new ScryptaDB(app.isBrowser)
            let wallet = db.get('wallet')
            response(wallet)
        })
    }

    returnIdentity(address) {
        const app = this
        return new Promise(response => {
            const db = new ScryptaDB(app.isBrowser)
            let wallet = db.get('wallet', 'address', address)
            if (wallet !== false) {
                response(wallet)
            } else {
                response(false)
            }
        })
    }

    createRSAKeys(address, password) {
        const app = this
        return new Promise(async response => {
            let wallet = await app.returnKey(address)
            const db = new ScryptaDB(app.isBrowser)
            let SIDS = wallet.split(':')
            let stored = await db.get('wallet', 'address', SIDS[0])
            if (stored.rsa === undefined) {
                let key = await app.readKey(password, wallet)
                if (key !== false) {
                    const key = new NodeRSA({ b: 2048 });
                    let pub = key.exportKey('pkcs8-public-pem');
                    let prv = key.exportKey('pkcs8-pem');

                    let prvhex = await this.cryptData(prv, password)
                    let checkdecryption = await this.decryptData(prvhex, password)
                    if (checkdecryption === prv) {
                        stored.rsa = {
                            pub: pub,
                            prv: prvhex
                        }
                        await db.update('wallet', 'address', stored.address, stored)
                        response(true)
                    } else {
                        response(false)
                    }
                } else {
                    response(false)
                }
            } else {
                response(wallet.rsa)
            }
        })
    }

    setDefaultIdentity(address) {
        const app = this
        return new Promise(async response => {
            const db = new ScryptaDB(app.isBrowser)
            let wallet = await db.get('wallet', 'address', address)
            if (wallet !== false && wallet !== null) {
                if (app.isBrowser) {
                    // console.log(wallet)
                    localStorage.setItem('SID', wallet.wallet)
                    response(true)
                } else {
                    await db.destroy('identity')
                    await db.put('identity', wallet)
                    response(true)
                }
            } else {
                response(false)
            }
        })
    }

    returnDefaultIdentity() {
        const app = this
        return new Promise(async response => {
            const db = new ScryptaDB(app.isBrowser)
            if (app.isBrowser) {
                if (localStorage.getItem('SID') !== null) {
                    response(localStorage.getItem('SID'))
                } else {
                    let wallet = await db.get('wallet')
                    if (wallet !== false && wallet[0] !== undefined) {
                        localStorage.setItem('SID', wallet[0].wallet)
                        response(wallet)
                    } else {
                        response(false)
                    }
                }
            } else {
                let wallet = await db.get('identity')
                if (wallet !== false && wallet[0] !== undefined) {
                    response(wallet[0])
                } else {
                    response(false)
                }
            }
        })
    }

    fetchIdentities(address) {
        return new Promise(async response => {
            const app = this
            if (wallet !== false) {
                let identities = app.post('/read', { dapp_address: address, protocol: 'I://' }).catch(err => {
                    response(err)
                })
                response(identities.data)
            } else {
                response(false)
            }
        })
    }

    shuffle(array) {
        var currentIndex = array.length, temporaryValue, randomIndex;

        while (0 !== currentIndex) {

            randomIndex = Math.floor(Math.random() * currentIndex);
            currentIndex -= 1;

            temporaryValue = array[currentIndex];
            array[currentIndex] = array[randomIndex];
            array[randomIndex] = temporaryValue;
        }

        return array;
    }
}

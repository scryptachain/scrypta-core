const _ = require('lodash')
const CoinKey = require('coinkey')
const crypto = require('crypto')
const CryptoJS = require('crypto-js')
const secp256k1 = require('secp256k1')
const cs = require('coinstring')
const axios = require('axios')
const Trx = require('./trx/trx')
var PouchDB = require('pouchdb')

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
    constructor (){
        this.RAWsAPIKey = ''
        this.PubAddress = ''
        this.testnet = false
        this.portP2P = 42226
        this.storage = new PouchDB('ScryptaCore')
        this.txidCache = new PouchDB('ScryptaTXIDCache')
        this.utxoCache = new PouchDB('ScryptaUTXOCache')
        this.messages = new PouchDB('ScryptaP2PMessages')
        this.clearCache()
    }

    //IDANODE FUNCTIONS
    returnNodes(){
        let mainnetIdaNodes = ['http://localhost:3001','https://idanodejs01.scryptachain.org', 'https://idanodejs02.scryptachain.org', 'https://idanodejs03.scryptachain.org']
        let testnetIdaNodes = ['https://testnet.scryptachain.org']
        if(this.testnet === true){
            return testnetIdaNodes
        }else{
            return mainnetIdaNodes
        }
    }

    post(endpoint, params){
        const app = this
        return new Promise(async response => {
            let node = await app.connectNode()
            let res = await axios.post(node + endpoint, params).catch(err => { response(err)})
            response(res.data)
        })
    }

    get(endpoint){
        const app = this
        return new Promise(async response => {
            let node = await app.connectNode()
            let res = await axios.get(node + endpoint).catch(err => { response(err)})
            response(res.data)
        })
    }

    testnet(value = true){
        this.testnet = value
    }
    
     async checkNode(node){
        return new Promise(response => {
            axios.get(node + '/wallet/getinfo').catch(err => {
                response(false)
            }).then(result => {
                response(result)
            })
        })
    }

    async connectNode(){
        return new Promise(async response => {
            var checknodes = this.returnNodes()
            var connected = false
            for(var i = 0; i < checknodes.length; i++){
                try{
                    axios.get(checknodes[i] + '/wallet/getinfo').then(check => {
                        if(check.data.blocks !== undefined && connected === false){
                            connected = true
                            if(check.config.url !== undefined){
                                response(check.config.url.replace('/wallet/getinfo',''))
                            }
                        }
                    })
                }catch(err){
                    console.log(err)
                }
            }
        })
    }

    //CACHE FUNCTIONS
    async clearCache(){
        return new Promise(async response => {
            await this.txidCache.destroy()
            await this.utxoCache.destroy()
            response(true)
        })
    }

    async returnTXIDCache(){
        return new Promise(async response => {
            this.txidCache.allDocs(db.allDocs({
                include_docs: true
            }).then(function (result) {
                let array = []
                for(let x in result){
                    array.push(result[x].txid)
                }
                response(array)
            }).catch(function (err) {
                response(false)
            }))
        })
    }

    async pushTXIDtoCache(txid){
        return new Promise(async response => {
            await this.txidCache.put({
                _id: txid,
                txid: txid
            })
            response(true)
        })
    }

    async returnUTXOCache(){
        return new Promise(async response => {
            this.utxoCache.allDocs(db.allDocs({
                include_docs: true
            }).then(function (result) {
                let array = []
                for(let x in result){
                    array.push(result[x].utxo)
                }
                response(array)
            }).catch(function (err) {
                response(false)
            }))
        })
    }

    async pushUTXOtoCache(utxo){
        return new Promise(async response => {
            await this.txidCache.put({
                _id: utxo,
                utxo: utxo
            })
            response(true)
        })
    }

    //CRYPT AND ENCRYPT FUNCTIONS
    async cryptData(data, password){
        return new Promise(response => {
            const cipher = crypto.createCipher('aes-256-cbc', password)
            let hex = cipher.update(JSON.stringify(data), 'utf8', 'hex')
            hex += cipher.final('hex')
            response(hex)
        })
    }

    async decryptData(data, password){
        return new Promise(response => {
            try{
                var decipher = crypto.createDecipher('aes-256-cbc', password)
                var dec = decipher.update(data,'hex','utf8')
                dec += decipher.final('utf8')
                response(JSON.parse(dec))
            }catch(e){
                response(false)
            }
        })
    }

     async cryptFile(file, password){
        return new Promise(response => {

            const reader = new FileReader();
            reader.onload = function() {
                var buf = Buffer(reader.result)
                var cipher = crypto.createCipher('aes-256-cbc', password)
                var crypted = Buffer.concat([cipher.update(buf),cipher.final()])
                response(crypted.toString('hex'))
            };

            reader.readAsArrayBuffer(file);
        })
    }

    async decryptFile(file, password){
        return new Promise(response => {
            try{
                let buf = Buffer(file)
                var decipher = crypto.createDecipher('aes-256-cbc', password)
                var decrypted = Buffer.concat([decipher.update(buf) , decipher.final()])
                response(decrypted)
            }catch(e){
                response(false)
            }
        })
    }

    //ADDRESS MANAGEMENT
    async createAddress(password, saveKey = true){
        // LYRA WALLET
        let params = lyraInfo.mainnet
        if(this.testnet === true){
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

     async buildWallet(password, pub, wallet, saveKey){
        return new Promise(async response => {

            const cipher = crypto.createCipher('aes-256-cbc', password);
            let wallethex = cipher.update(JSON.stringify(wallet), 'utf8', 'hex');
            wallethex += cipher.final('hex');

            var walletstore = pub + ':' + wallethex;
            
            if(saveKey === true){
                await this.storage.put({
                    _id: pub,
                    wallet: walletstore
                })
            }

            response(walletstore)
        })
    }

     async initAddress(address){
        const app = this
        const node = await app.connectNode();
        const response = await axios.post(node + '/init', {address: address, airdrop: true})
        return response;
    }

     async getPublicKey(privateWif){
        var ck = new CoinKey.fromWif(privateWif);
        var pubkey = ck.publicKey.toString('hex');
        return pubkey;
    }
    
    async getAddressFromPubKey(pubKey){
        return new Promise(response => {
            let params = lyraInfo.mainnet
            if(this.testnet === true){
                params = lyraInfo.testnet
            }
            let pubkeybuffer = Buffer.from(pubKey,'hex')
            var sha = crypto.createHash('sha256').update(pubkeybuffer).digest()
            let pubKeyHash = crypto.createHash('rmd160').update(sha).digest()
            var hash160Buf = Buffer.from(pubKeyHash, 'hex')
            response(cs.encode(hash160Buf, params.public)) 
        })
    }

    returnKey(address){
        if(address.length === 34){
            return new Promise(async response => {
                this.storage.get(address).then(function (doc) {
                    response(doc.wallet)
                }).catch(function (err) {
                    response(false)
                });
            })
        }else{
            return address
        }
    }

     async readKey(password, key){
        let wallet = await this.returnKey(key)
        if(wallet !== false){
            if(password !== ''){
                var SIDS = key.split(':');
                try {
                    var decipher = crypto.createDecipher('aes-256-cbc', password);
                    var dec = decipher.update(SIDS[1],'hex','utf8');
                    dec += decipher.final('utf8');
                    var decrypted = JSON.parse(dec);
                    return Promise.resolve(decrypted);
                } catch (ex) {
                    //console.log('WRONG PASSWORD')
                    return Promise.resolve(false);
                }
            }
        }else{
            return false
        }
    }

    //TRANSACTIONS FUNCTIONS
     async listUnspent(address){
        const app = this
        const node = await app.connectNode();
        var unspent = await axios.get(node + '/unspent/' + address)
        return unspent.data.unspent
    }

     async sendRawTransaction(rawtransaction){
        const app = this
        const node = await app.connectNode();
        if(node !== undefined && rawtransaction !== undefined){
            var txid = await axios.post(
                node + '/sendrawtransaction',
                { rawtransaction: rawtransaction }
            ).catch(function(err){
                console.log(err)
            })
            return txid.data.data
        } else {
            return Promise.resolve(false)
        }
    }

     async decodeRawTransaction(rawtransaction){
        const app = this
        const node = await app.connectNode();
        if(node !== undefined){
            var transaction = await axios.post(
                node + '/decoderawtransaction',
                { rawtransaction: rawtransaction }
            ).catch(function(err){
                console.log(err)
            })
            return transaction.data.transaction
        } else {
            return Promise.resolve(false)
        }
    }

     async build(key, password, send = false, to, amount, metadata = '', fees = 0.001){
        var SID = key;
        var MAX_OPRETURN = 7500
        if(password !== ''){
            var SIDS = SID.split(':');
            try {
                var decipher = crypto.createDecipher('aes-256-cbc', password);
                var dec = decipher.update(SIDS[1],'hex','utf8');
                dec += decipher.final('utf8');
                var decrypted = JSON.parse(dec);

                var trx = Trx.transaction();
                var from = SIDS[0]
                var unspent = []
                var inputs = []
                var cache = await this.returnUTXOCache()
                //console.log('CACHE', cache)
                if(cache.length > 0){
                    for(var x = 0; x < cache.length; x++){
                        unspent.push(cache[x])
                    }
                }
                var listunspent = await this.listUnspent(from)
                for(var x = 0; x < listunspent.length; x++){
                    unspent.push(listunspent[x])
                }
                //console.log('UNSPENT', unspent)
                if(unspent.length > 0){
                    var inputamount = 0;
                    var amountneed = amount + fees;
                    for (var i=0; i < unspent.length; i++){
                        if(inputamount <= amountneed){
                            var txid = unspent[i]['txid'];
                            var index = unspent[i]['vout'];
                            var script = unspent[i]['scriptPubKey'];
                            var cache = await this.returnTXIDCache()
                            if(cache.indexOf(txid + ':' + index) === -1 && inputs.indexOf(txid + ':' + index) === -1){
                                trx.addinput(txid,index,script);
                                inputamount += unspent[i]['amount']
                                inputs.push(txid + ':' + index)
                            }
                        }
                    }
                    if(inputamount >= amountneed){
                        var change = inputamount - amountneed;
                        if(amount > 0.00001){
                            trx.addoutput(to,amount);
                        }
                        if(change > 0.00001){
                            trx.addoutput(from,change);
                        }
                        if(metadata !== ''){
                            if(metadata.length <= MAX_OPRETURN){
                                //console.log('ADDING METADATA TO TX', metadata)
                                trx.addmetadata(metadata);
                            }else{
                                //console.log('METADATA TOO LONG')
                            }
                        }
                        var wif = decrypted.prv;
                        var signed = trx.sign(wif,1);
                        if(send === false){
                            return Promise.resolve({
                                inputs: inputs,
                                signed: signed
                            });
                        } else {
                            var txid = await this.sendRawTransaction(signed)
                            if(txid !== null && txid.length === 64){
                                for(let i in inputs){
                                    await this.pushTXIDtoCache(inputs[i])
                                }
                                //console.log("TX SENT: " + txid)
                                return Promise.resolve(txid)
                            }
                        }
                    }else{
                        //console.log('NOT ENOUGH FUNDS')
                        return Promise.resolve(false) //NOT ENOUGH FUNDS
                    }
                } else {
                    //console.log('NO UNSPENTS')
                    return Promise.resolve(false) //NOT ENOUGH FUNDS
                }
            } catch (error) {
                //console.log(error)
                return Promise.resolve(false);
            }
        }
    }

     async send(key, password, to, amount, metadata = ''){
        let wallet = await this.returnKey(key)
        if(wallet !== false){
            if(password !== '' && to !== ''){
                var SIDS = wallet.split(':');
                try {
                    var decipher = crypto.createDecipher('aes-256-cbc', password);
                    var dec = decipher.update(SIDS[1],'hex','utf8');
                    dec += decipher.final('utf8');

                    var txid = ''
                    var i = 0
                    var rawtransaction
                    while(txid !== null && txid !== undefined && txid.length !== 64){
                        var fees = 0.001 + (i / 1000)
                        rawtransaction = await this.build(wallet,password,false,to,amount,metadata,fees)
                        //console.log(rawtransaction)
                        txid = await this.sendRawTransaction(rawtransaction.signed)
                        //console.log(txid)
                        if(txid !== null && txid !== false && txid.length === 64){
                            for(let i in rawtransaction.inputs){
                                await this.pushTXIDtoCache(rawtransaction.inputs[i])
                            }
                            //Storing UTXO to cache
                            var decoded = await this.decodeRawTransaction(rawtransaction.signed)
                            if(decoded.vout[1].scriptPubKey.addresses !== undefined){
                                let unspent = {
                                    txid: decoded.txid,
                                    vout: 1, 
                                    address: decoded.vout[1].scriptPubKey.addresses[0],
                                    scriptPubKey: decoded.vout[1].scriptPubKey.hex,
                                    amount: decoded.vout[1].value
                                }
                                await this.pushUTXOtoCache(unspent)
                            }
                        }else{
                            txid = null
                        }
                        i++;
                    }
                    return Promise.resolve(txid)
                }catch(e){
                    return Promise.resolve(false)
                }
            }else{
                return false
            }
        }else{
            return false
        }
    }

    //PROGRESSIVE DATA MANAGEMENT
     async write(key, password, metadata, collection = '', refID = '', protocol = '', uuid = ''){
        if(password !== '' && metadata !== ''){
            let wallet = await this.returnKey(key)
            if(wallet !== false){
                var SIDS = wallet.split(':');
                var MAX_OPRETURN = 7500
                try {
                    //console.log('WRITING TO BLOCKCHAIN')
                    var decipher = crypto.createDecipher('aes-256-cbc', password);
                    var dec = decipher.update(SIDS[1],'hex','utf8');
                    dec += decipher.final('utf8');
                    
                    let address = SIDS[0]
                    
                    if(uuid === ''){
                        var Uuid = require('uuid/v4')
                        uuid = Uuid().replace(new RegExp('-', 'g'), '.')
                    }

                    if(collection !== ''){
                        collection = '!*!' + collection
                    }else{
                        collection = '!*!'
                    }

                    if(refID !== ''){
                        refID = '!*!' + refID
                    }else{
                        refID = '!*!'
                    }

                    if(protocol !== ''){
                        protocol = '!*!' + protocol
                    }else{
                        protocol = '!*!'
                    }

                    var dataToWrite = '*!*' + uuid+collection+refID+protocol+ '*=>' + metadata + '*!*'
                    if(dataToWrite.length <= MAX_OPRETURN){
                        var txid = ''
                        var i = 0
                        var totalfees = 0
                        while(txid !== null && txid !== undefined && txid.length !== 64){
                            var fees = 0.001 + (i / 1000)
                            var rawtransaction = await this.build(wallet,password,false,address,0,dataToWrite,fees)
                            // console.log(rawtransaction.signed)
                            if(rawtransaction.signed !== false){
                                txid = await this.sendRawTransaction(rawtransaction.signed)
                                if(txid !== null && txid !== false && txid.length === 64){
                                    totalfees += fees
                                    for(let i in rawtransaction.inputs){
                                        await this.pushTXIDtoCache(rawtransaction.inputs[i])
                                    }
                                    //Storing UTXO to cache
                                    var decoded = await this.decodeRawTransaction(rawtransaction.signed)
                                    if(decoded.vout[0].scriptPubKey.addresses !== undefined){
                                        let unspent = {
                                            txid: decoded.txid,
                                            vout: 0, 
                                            address: decoded.vout[0].scriptPubKey.addresses[0],
                                            scriptPubKey: decoded.vout[0].scriptPubKey.hex,
                                            amount: decoded.vout[0].value
                                        }
                                        await this.pushUTXOtoCache(unspent)
                                    }
                                }
                            }else{
                                txid = null
                            }
                            i++;
                        }
                        
                        return Promise.resolve({
                            uuid: uuid,
                            address: wallet,
                            fees: totalfees,
                            collection: collection.replace('!*!',''),
                            refID: refID.replace('!*!',''),
                            protocol: protocol.replace('!*!',''),
                            dimension: dataToWrite.length,
                            chunks: 1,
                            stored: dataToWrite,
                            txs: [txid]
                        })

                    }else{
                        
                        var txs = []
                        var chunklength = MAX_OPRETURN - 6
                        var chunkdatalimit = chunklength - 3
                        var dataToWriteLength = dataToWrite.length
                        var nchunks = Math.ceil(dataToWriteLength / chunklength)
                        var last = nchunks - 1
                        var chunks = []

                        for (var i=0; i<nchunks; i++){
                            var start = i * chunklength
                            var end = start + chunklength
                            var chunk = dataToWrite.substring(start,end)

                            if(i === 0){
                                var startnext = (i + 1) * chunklength
                                var endnext = startnext + chunklength
                                var prevref = ''
                                var nextref = dataToWrite.substring(startnext,endnext).substring(0,3)
                            } else if(i === last){
                                var startprev = (i - 1) * chunklength
                                var endprev = startprev + chunklength
                                var nextref = ''
                                var prevref = dataToWrite.substr(startprev,endprev).substr(chunkdatalimit,3)
                            } else {
                                var sni = i + 1
                                var startnext = sni * chunklength
                                var endnext = startnext + chunklength
                                var nextref = dataToWrite.substring(startnext,endnext).substring(0,3)
                                var spi = i - 1
                                var startprev = spi * chunklength
                                var endprev = startprev + chunklength
                                var prevref = dataToWrite.substr(startprev,endprev).substr(chunkdatalimit,3)
                            }
                            chunk = prevref + chunk + nextref
                            chunks.push(chunk)
                        }

                        var totalfees = 0
                        
                        for(var cix=0; cix<chunks.length; cix++){
                            var txid = ''
                            var i = 0
                            var rawtransaction
                            while(txid !== null && txid !== undefined && txid.length !== 64){
                                var fees = 0.001 + (i / 1000)
                                //console.log('STORING CHUNK #' + cix, chunks[cix])
                                rawtransaction = await this.build(eallet,password,false,wallet,0,chunks[cix],fees)
                                txid = await this.sendRawTransaction(rawtransaction.signed)
                                //console.log(txid)
                                if(txid !== null && txid !== false && txid.length === 64){
                                    for(let i in rawtransaction.inputs){
                                        await this.pushTXIDtoCache(rawtransaction.inputs[i])
                                    }
                                    totalfees += fees
                                    txs.push(txid)
                                    //Storing UTXO to cache
                                    var decoded = await this.decodeRawTransaction(rawtransaction.signed)
                                    if(decoded.vout[0].scriptPubKey.addresses !== undefined){
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
                                    txid = null
                                }
                                i++;
                            }
                        }

                        return Promise.resolve({
                            uuid: uuid,
                            address: wallet,
                            fees: totalfees,
                            collection: collection.replace('!*!',''),
                            refID: refID.replace('!*!',''),
                            protocol: protocol.replace('!*!',''),
                            dimension: dataToWrite.length,
                            chunks: nchunks,
                            stored: dataToWrite,
                            txs: txs
                        })

                    }

                } catch (error) {
                    console.log(error)
                    return Promise.resolve(false);
                }
            }else{
                return false
            }
        }
    }

     async update(key, password, metadata, collection = '', refID = '', protocol = '', uuid){
        return new Promise(response => {
            if(uuid !== undefined){
                let written = this.write(key, password, metadata, collection, refID, protocol, uuid)
                response(written)
            }else{
                response(false)
            }
        })
    }

     async invalidate(key, password, uuid){
        return new Promise(response => {
            if(uuid !== undefined){
                let metadata = 'END'
                let written = this.write(key, password, metadata, '', '', '', uuid)
                response(written)
            }else{
                response(false)
            }
        })
    }

    //SIGNING FUNCTIONS
     async signMessage(key, message){
        return new Promise(response => {
            //CREATING CK OBJECT
            let params = lyraInfo.mainnet
            if(this.testnet === true){
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
                pubKey: pubKey.toString('hex'),
                address: ck.publicAddress
            })
        })
    }

    async verifyMessage(pubkey, signature, message){
        return new Promise(async response => {
            //CREATE HASH FROM MESSAGE
            let hash = CryptoJS.SHA256(message);
            let msg = Buffer.from(hash.toString(CryptoJS.enc.Hex), 'hex')
            //VERIFY MESSAGE
            let buf = Buffer.from(signature,'hex')
            let pubKey = Buffer.from(pubkey,'hex')
            let verified = secp256k1.verify(msg, buf, pubKey)
            let address = await this.getAddressFromPubKey(pubkey)
            if(verified === true){
                response({
                    address: address,
                    pubkey: pubkey,
                    signature: signature,
                    hash: hash.toString(CryptoJS.enc.Hex),
                    message: message,
                })
            }else{
                response(false)
            }
        })
    }

    // P2P FUNCTIONALITIES

    async connectP2P(key, password, callback){
        const app = this
        let nodes = await this.returnNodes()
        key = await this.returnKey(key)
        let SIDS = key.split(':')
        let address = SIDS[0]
        let wallet = await this.readKey(password, key)
        if(wallet !== false){
            console.log('Loaded identity ' + address)
            for(let x in nodes){
                let node = nodes[x]
                console.log('Bootstrap connection to ' + node)
                global['nodes'][node] = require('socket.io-client')(node.replace('https','http') + ':' + this.portP2P, { reconnect: true })
                global['nodes'][node].on('connect', function () {
                    console.log('Connected to peer: ' + global['nodes'][node].io.uri)
                    global['connected'][node] = true
                })
                global['nodes'][node].on('disconnect', function () {
                    console.log('Disconnected from peer: ' + global['nodes'][node].io.uri)
                    global['connected'][node] = false
                })

                //PROTOCOLS
                global['nodes'][node].on('message', async function (data) {
                    let verified = await app.verifyMessage(data.pubKey, data.signature, data.message)
                    if(verified !== false && global['cache'].indexOf(data.signature) === -1){
                        global['cache'].push(data.signature)
                        app.messages.get(data.signature).then(function (doc) {
                            // MESSAGE RECEIVED YET
                        }).catch(async function (err) {
                            if(err.status === 404){
                                await app.messages.put({
                                    _id: data.signature,
                                    message: data.message,
                                    pubKey: data.pubKey,
                                    address: data.address
                                }).catch(err => {
                                    // console.log(err)
                                }).then(success => {
                                    callback(data)
                                })
                            }
                        });
                    }
                })
            }
        }
    }

    async broadcast(key, password, protocol, message, socketID = '', nodeID = ''){
        const app = this
        key = await this.returnKey(key)
        let SIDS = key.split(':')
        let wallet = await this.readKey(password, key)
        if(wallet !== false){
            let signed = await app.signMessage(wallet.prv, message)
            
            return new Promise(async response => {
                if(nodeID === ''){
                    for (let id in global['nodes']) {
                        global['nodes'][id].emit(protocol, signed)
                    }
                }else{
                    if(global['nodes'][nodeID]){
                        global['nodes'][nodeID].emit(protocol, signed)
                    }
                }
                response(message)
            })
        }
    }

}
import _ from 'lodash'
var CoinKey = require('coinkey')
var crypto = require('crypto')
var cookies = require('browser-cookies')
var axios = require('axios')
import Trx from './trx/trx.js'

const lyraInfo = {
    private: 0xae,
    public: 0x30,
    scripthash: 0x0d
};

export default class ScryptaCore {
    constructor (){
        this.RAWsAPIKey = '';
        this.PubAddress = '';
        ScryptaCore.clearCache()
    }

    static returnNodes(){
        return ['https://idanodejs01.scryptachain.org'];
    }
    static async clearCache(){
        return new Promise(async response => {
            await localStorage.removeItem('ScryptaTXIDCache')
            await localStorage.removeItem('ScryptaUTXOCache')
            response(true)
        })
    }
    static async returnTXIDCache(){
        return new Promise(async response => {
            var cache = await localStorage.getItem('ScryptaTXIDCache')
            if(cache === null){
                cache = []
            }else{
                cache = JSON.parse(cache)
            }
            response(cache)
        })
    }

    static async pushTXIDtoCache(txid){
        return new Promise(async response => {
            let cache = await this.returnTXIDCache()
            cache.push(txid)
            await localStorage.setItem('ScryptaTXIDCache',JSON.stringify(cache))
            response(true)
        })
    }

    static async returnUTXOCache(){
        return new Promise(async response => {
            var cache = await localStorage.getItem('ScryptaUTXOCache')
            if(cache === null){
                cache = []
            }else{
                cache = JSON.parse(cache)
            }
            response(cache)
        })
    }

    static async pushUTXOtoCache(utxo){
        return new Promise(async response => {
            let cache = await this.returnUTXOCache()
            cache.push(utxo)
            await localStorage.setItem('ScryptaUTXOCache',JSON.stringify(cache))
            response(true)
        })
    }
    
    static async checkNode(node){
        return new Promise(response => {
            axios.get(node + '/wallet/getinfo').catch(err => {
                response(false)
            }).then(result => {
                response(result)
            })
        })
    }

    static async connectNode(){
        return new Promise(async response => {
            var checknodes = this.returnNodes()
            var connected = false
            while(connected === false){
                var checknode = checknodes[Math.floor(Math.random()*checknodes.length)];
                const check = await this.checkNode(checknode)
                if(check !== false){
                    connected = true
                    response(checknode)
                }
            }
        })
    }

    static async cryptData(data, password){
        return new Promise(response => {
            const cipher = crypto.createCipher('aes-256-cbc', password)
            let hex = cipher.update(JSON.stringify(data), 'utf8', 'hex')
            hex += cipher.final('hex')
            response(hex)
        })
    }

    static async decryptData(data, password){
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

    static async cryptFile(file, password){
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

    static async decryptFile(file, password){
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

    static async createAddress(password, saveKey = true){
        // LYRA WALLET
        var ck = new CoinKey.createRandom(lyraInfo)
        
        // SIMMETRIC KEY
        var buf = crypto.randomBytes(16);
        var api_secret = buf.toString('hex');
        
        var lyrapub = ck.publicAddress;
        var lyraprv = ck.privateWif;
        var lyrakey = ck.publicKey.toString('hex');
        
        // STORE JUST LYRA WALLET 
        var wallet = {
            prv: lyraprv,
            api_secret: api_secret,
            key: lyrakey
        }

        const cipher = crypto.createCipher('aes-256-cbc', password);
        let wallethex = cipher.update(JSON.stringify(wallet), 'utf8', 'hex');
        wallethex += cipher.final('hex');

        var walletstore = lyrapub + ':' + wallethex;
        
        if(saveKey == true){
            if(window.location.hostname == 'localhost'){
                var cookie_secure = false;
            }else{
                var cookie_secure = true;
            }
            cookies.set('scrypta_key', walletstore, {secure: cookie_secure, domain: window.location.hostname, expires: 30, samesite: 'Strict'});
        }
        var response = {
            pub: lyrapub,
            api_secret: api_secret,
            key: lyrakey,
            prv: lyraprv,
            walletstore: walletstore
        }
        return response;
    }

    static async restoreAddress(address, pubkey, privkey, password, saveKey = true){
        
        if(address !== undefined && address.length > 0 && 
            pubkey !== undefined && pubkey.length > 0 && 
            privkey !== undefined && privkey.length > 0 && 
            password !== undefined && password.length > 0){
        
            // SIMMETRIC KEY
            var buf = crypto.randomBytes(16);
            var api_secret = buf.toString('hex');
            
            var lyrapub = address;
            var lyraprv = privkey;
            var lyrakey = pubkey;
            
            // STORE JUST LYRA WALLET 
            var wallet = {
                prv: lyraprv,
                api_secret: api_secret,
                key: lyrakey
            };

            const cipher = crypto.createCipher('aes-256-cbc', password);
            let wallethex = cipher.update(JSON.stringify(wallet), 'utf8', 'hex');
            wallethex += cipher.final('hex');

            var walletstore = lyrapub + ':' + wallethex;
            
            // SAVE ENCRYPTED VERION IN COOKIE
            if(saveKey == true){
                if(window.location.hostname == 'localhost'){
                    var cookie_secure = false;
                }else{
                    var cookie_secure = true;
                }
                cookies.set('scrypta_key', walletstore, {secure: cookie_secure, domain: window.location.hostname, expires: 30, samesite: 'Strict'});
            }

            var response = {
                pub: lyrapub,
                api_secret: api_secret,
                key: lyrakey,
                prv: lyraprv,
                walletstore: walletstore
            }
            return response;
        }else{
            return false;
        }

    }

    static async initAddress(address){
        const app = this
        const node = await app.connectNode();
        const response = await axios.post(node + '/init', {address: address, airdrop: true})
        return response;
    }

    static async getPublicKey(privateWif){
        var ck = new CoinKey.fromWif(privateWif);
        var pubkey = ck.publicKey.toString('hex');
        return pubkey;
    }

    static async saveKey(key){R
        if(window.location.hostname == 'localhost'){
            var cookie_secure = false;
        }else{
            var cookie_secure = true;
        }
        cookies.set('scrypta_key', key, {secure: cookie_secure, domain: window.location.hostname, expires: 30, samesite: 'Strict'});
        return Promise.resolve(true);
    }

    static keyExist(){
        var ScryptaCore_cookie = cookies.get('scrypta_key');
        if(ScryptaCore_cookie !== null && ScryptaCore_cookie !== ''){
            var ScryptaCore_split = ScryptaCore_cookie.split(':');
            if(ScryptaCore_split[0].length > 0){
                this.PubAddress = ScryptaCore_split[0];
                this.RAWsAPIKey = ScryptaCore_split[1];
                return ScryptaCore_split[0];
            } else {
                return false
            }
        }else{
            return false
        }
    }

    static async readKey(password = '', $key = ''){
        if($key === ''){
            var ScryptaCore_cookie = cookies.get('scrypta_key');
        }else{
            var ScryptaCore_cookie = $key;
        }
        if(password !== ''){
            var ScryptaCore_split = ScryptaCore_cookie.split(':');
            try {
                var decipher = crypto.createDecipher('aes-256-cbc', password);
                var dec = decipher.update(ScryptaCore_split[1],'hex','utf8');
                dec += decipher.final('utf8');
                var $ScryptaCore_cookie = JSON.parse(dec);
                return Promise.resolve($ScryptaCore_cookie);
            } catch (ex) {
                console.log('WRONG PASSWORD')
                return Promise.resolve(false);
            }
        }
    }

    static forgetKey(){
        if(window.location.hostname == 'localhost'){
            var cookie_secure = false;
        }else{
            var cookie_secure = true;
        }
        cookies.set('scrypta_key', "", {secure: cookie_secure, domain: window.location.hostname, expires: 0, samesite: 'Strict'});
        return true;
    }

    static async listUnspent(address){
        const app = this
        const node = await app.connectNode();
        var unspent = await axios.get(node + '/unspent/' + address)
        return unspent.data.unspent
    }

    static async sendRawTransaction(rawtransaction){
        const app = this
        const node = await app.connectNode();
        if(node !== undefined){
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

    static async decodeRawTransaction(rawtransaction){
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

    static async build(password = '', send = false, to, amount, metadata = '', fees = 0.001, key = ''){
        if(key === ''){
            var ScryptaCore_cookie = cookies.get('scrypta_key');
        }else{
            var ScryptaCore_cookie = key;
        }
        if(password !== ''){
            var ScryptaCore_split = ScryptaCore_cookie.split(':');
            try {
                var decipher = crypto.createDecipher('aes-256-cbc', password);
                var dec = decipher.update(ScryptaCore_split[1],'hex','utf8');
                dec += decipher.final('utf8');
                var $ScryptaCore_cookie = JSON.parse(dec);

                var trx = Trx.transaction();
                var from = ScryptaCore_split[0]
                var unspent = []
                var inputs = []
                var cache = await this.returnUTXOCache()
                console.log('CACHE', cache)
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
                            if(metadata.length <= 80){
                                //console.log('ADDING METADATA TO TX', metadata)
                                trx.addmetadata(metadata);
                            }else{
                                //console.log('METADATA TOO LONG')
                            }
                        }
                        var wif = $ScryptaCore_cookie.prv;
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

    static async send(password = '', to, amount, metadata = '', key = ''){
        if(key === ''){
            var ScryptaCore_cookie = cookies.get('scrypta_key');
        }else{
            var ScryptaCore_cookie = key;
        }
        if(password !== '' && to !== ''){
            var ScryptaCore_split = ScryptaCore_cookie.split(':');
            try {
                var decipher = crypto.createDecipher('aes-256-cbc', password);
                var dec = decipher.update(ScryptaCore_split[1],'hex','utf8');
                dec += decipher.final('utf8');

                var txid = ''
                var i = 0
                var rawtransaction
                while(txid !== null && txid !== undefined && txid.length !== 64){
                    var fees = 0.001 + (i / 1000)
                    rawtransaction = await this.build(password,false,to,amount,metadata,fees,ScryptaCore_cookie)
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
        }
    }

    static async write(password, metadata, collection = '', refID = '', protocol = '', key = ''){
        if(password !== '' && metadata !== ''){
            if(key === ''){
                var ScryptaCore_cookie = cookies.get('scrypta_key');
            }else{
                var ScryptaCore_cookie = key;
            }
            var ScryptaCore_split = ScryptaCore_cookie.split(':');
            try {
                //console.log('WRITING TO BLOCKCHAIN')
                var decipher = crypto.createDecipher('aes-256-cbc', password);
                var dec = decipher.update(ScryptaCore_split[1],'hex','utf8');
                dec += decipher.final('utf8');
                
                var wallet = ScryptaCore_split[0]

                var Uuid = require('uuid/v4')
                var uuid = Uuid().replace(new RegExp('-', 'g'), '.')

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
                if(dataToWrite.length <= 80){
                    var txid = ''
                    var i = 0
                    var totalfees = 0
                    while(txid !== null && txid !== undefined && txid.length !== 64){
                        var fees = 0.001 + (i / 1000)
                        var rawtransaction = await this.build(password,false,wallet,0,dataToWrite,fees,ScryptaCore_cookie)
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
                    var dataToWriteLength = dataToWrite.length
                    var nchunks = Math.ceil(dataToWriteLength / 74)
                    var last = nchunks - 1
                    var chunks = []

                    for (var i=0; i<nchunks; i++){
                        var start = i * 74
                        var end = start + 74
                        var chunk = dataToWrite.substring(start,end)

                        if(i === 0){
                            var startnext = (i + 1) * 74
                            var endnext = startnext + 74
                            var prevref = ''
                            var nextref = dataToWrite.substring(startnext,endnext).substring(0,3)
                        } else if(i === last){
                            var startprev = (i - 1) * 74
                            var endprev = startprev + 74
                            var nextref = ''
                            var prevref = dataToWrite.substr(startprev,endprev).substr(71,3)
                        } else {
                            var sni = i + 1
                            var startnext = sni * 74
                            var endnext = startnext + 74
                            var nextref = dataToWrite.substring(startnext,endnext).substring(0,3)
                            var spi = i - 1
                            var startprev = spi * 74
                            var endprev = startprev + 74
                            var prevref = dataToWrite.substr(startprev,endprev).substr(71,3)
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
                            rawtransaction = await this.build(password,false,wallet,0,chunks[cix],fees,ScryptaCore_cookie)
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
        }
    }
}
new ScryptaCore
window.ScryptaCore = ScryptaCore

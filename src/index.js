const CoinKey = require('@scrypta/coinkey')
const crypto = require('crypto')
const CryptoJS = require('crypto-js')
const secp256k1 = require('secp256k1')
const cs = require('coinstring')
const axios = require('axios')
const Trx = require('./trx/trx')
const ScryptaDB = require('./db')
const NodeRSA = require('node-rsa')
const { sum, round, subtract } = require('mathjs')
const bip39 = require('@scrypta/bip39')
const HDKey = require('hdkey')

const LYRA_DERIVATION_PATH = 'm/44\'/497\'/0\'/0';
const lyraInfo = {
    mainnet: {
        private: 0xae,
        public: 0x30,
        scripthash: 0x0d,
        bip32: {
            public: 0x0488b21e,
            private: 0x0488ade4,
        }
    },
    testnet: {
        private: 0xae,
        public: 0x7f,
        scripthash: 0x13,
        bip32: {
            public: 0x043587cf,
            private: 0x04358394,
        }
    }
}

global['io'] = { server: null, client: null, sockets: {} }
global['nodes'] = {}
global['connected'] = {}
global['cache'] = []

module.exports = class ScryptaCore {
    constructor(isBrowser = false, nodes) {
        this.RAWsAPIKey = ''
        this.PubAddress = ''
        this.staticnodes = false
        this.timeout = 30000
        this.nodes = {
            mainnet: ['https://idanodejs01.scryptachain.org', 'https://idanodejs02.scryptachain.org', 'https://idanodejs03.scryptachain.org', 'https://idanodejs04.scryptachain.org', 'https://idanodejs05.scryptachain.org', 'https://idanodejs06.scryptachain.org'],
            testnet: ['https://testnet.scryptachain.org']
        }
        if (nodes !== undefined) {
            this.staticnodes = true
            this.nodes = {
                mainnet: [],
                testnet: []
            }
            if (nodes.mainnet !== undefined) {
                this.nodes.mainnet = nodes.mainnet
            } else {
                this.nodes.mainnet = nodes
            }
            if (nodes.testnet !== undefined) {
                this.nodes.testnet = nodes.testnet
            } else {
                this.nodes.testnet = nodes
            }
        }

        this.mainnetIdaNodes = this.nodes.mainnet
        this.testnetIdaNodes = this.nodes.testnet
        this.banned = []
        this.debug = false
        this.MAX_OPRETURN = 7500
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
                        let nodes_git = await axios.get('https://raw.githubusercontent.com/scryptachain/scrypta-idanode-network/master/peersv2')
                        let raw_nodes = nodes_git.data.split("\n")
                        let nodes = []
                        const defaultIdanodeName = 'idanodejs'
                        for (let x in raw_nodes) {
                            let node = raw_nodes[x].split(':')
                            if (node[0].length > 0) {
                                let idanodeName = node[3] ? node[3] : defaultIdanodeName
                                let url = 'https://' + idanodeName + node[0] + '.scryptachain.org'
                                if (app.banned.indexOf(url) === -1) {
                                    await db.put('nodes', url)
                                    nodes.push(url)
                                }
                            }
                        }
                        if (nodes.length === 0) {
                            if (this.testnet) {
                                if (app.nodes.testnet !== undefined) {
                                    nodes = app.nodes.testnet
                                } else {
                                    nodes = app.nodes
                                }
                            } else {
                                if (app.nodes.mainnet !== undefined) {
                                    nodes = app.nodes.mainnet
                                } else {
                                    nodes = app.nodes
                                }
                            }
                        }
                        response(nodes)
                    } catch (e) {
                        if (idanodes.length > 0) {
                            response(idanodes)
                        } else {
                            // FALLBACK TO STATIC NODES IF GIT FAILS AND DB IS EMPTY
                            if (this.testnet) {
                                if (app.nodes.testnet !== undefined) {
                                    nodes = app.nodes.testnet
                                } else {
                                    nodes = app.nodes
                                }
                            } else {
                                if (app.nodes.mainnet !== undefined) {
                                    nodes = app.nodes.mainnet
                                } else {
                                    nodes = app.nodes
                                }
                            }
                            response(nodes)
                        }
                    }
                }
            } else {
                let toCheck = []
                if (this.testnet) {
                    if (app.nodes.testnet !== undefined) {
                        toCheck = app.nodes.testnet
                    } else {
                        toCheck = app.nodes
                    }
                } else {
                    if (app.nodes.mainnet !== undefined) {
                        toCheck = app.nodes.mainnet
                    } else {
                        toCheck = app.nodes
                    }
                }
                let nodes = []
                for (let k in toCheck) {
                    if (app.banned.indexOf(toCheck[k]) === -1) {
                        nodes.push(toCheck[k])
                    }
                }
                if (nodes.length === 0) {
                    if (this.testnet) {
                        if (app.nodes.testnet !== undefined) {
                            nodes = app.nodes.testnet
                        } else {
                            nodes = app.nodes
                        }
                    } else {
                        if (app.nodes.mainnet !== undefined) {
                            nodes = app.nodes.mainnet
                        } else {
                            nodes = app.nodes
                        }
                    }
                }
                response(nodes)
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
            try {
                res = await axios.post(node + endpoint, params, { timeout: app.timeout }).catch(err => {
                    console.log("ERROR ON IDANODE " + node)
                    response(false)
                })
            } catch (e) {
                node = await app.connectNode()
                res = await axios.post(node + endpoint, params, { timeout: app.timeout }).catch(err => {
                    console.log("ERROR ON IDANODE " + node)
                    response(false)
                })
            }

            if (res !== undefined && res.data !== undefined) {
                res.node = node
                response(res.data)
            } else {
                console.log("ERROR ON IDANODE WHILE POSTING" + node)
                response(false)
            }
        })
    }

    get(endpoint, node = '') {
        const app = this
        return new Promise(async response => {
            if (node === '') {
                node = await app.connectNode()
            }
            let res
            try {
                res = await axios.get(node + endpoint, { timeout: app.timeout }).catch(err => {
                    console.log("ERROR ON IDANODE " + node)
                })
                res.node = node
            } catch (e) {
                node = await app.connectNode()
                res = await axios.get(node + endpoint, { timeout: app.timeout }).catch(err => {
                    console.log("ERROR ON IDANODE " + node)
                    response(false)
                })
            }
            if (res !== undefined && res.data !== undefined) {
                res.data.node = node
                response(res.data)
            } else {
                response(false)
            }
        })
    }

    async checkNode(node) {
        const app = this
        return new Promise(response => {
            if (app.banned.indexOf(node) === -1) {
                axios.get(node + '/wallet/getinfo', { timeout: app.timeout }).catch(err => {
                    response(false)
                }).then(result => {
                    response(result)
                })
            } else {
                if (app.debug) {
                    console.log('NODE ' + node + ' BANNED')
                }
                response(false)
            }
        })
    }

    async connectNode() {
        const app = this
        return new Promise(async response => {
            if (app.idanode === '' || app.banned.indexOf(app.idanode) !== -1) {
                app.idanode = ''
                let connected = false
                if (app.debug === true) {
                    console.log('CONNECTING TO FIRST AVAILABLE IDANODE')
                }
                while (connected === false) {
                    let node = await this.returnFirstNode()
                    if (node !== false) {
                        if (this.debug === true) {
                            console.log('TRYING TO CONTACT ' + node)
                        }
                        connected = true
                        app.idanode = node
                        if (app.debug === true) {
                            console.log('CONNECTED TO ' + app.idanode)
                        }
                        response(node)
                    } else {
                        if (app.debug) {
                            console.log('NODE RESPONSE', node)
                        }
                    }
                }
            } else {
                let check = await app.checkNode(app.idanode)
                if (check !== false && check.data.toindex <= 1 && check.data.toindex >= 0 && app.banned.indexOf(app.idanode) === -1) {
                    if (app.debug === true) {
                        console.log('CONNECTED IDANODE ' + app.idanode + ' STILL VALID')
                    }
                    response(app.idanode)
                } else {
                    app.idanode = ''
                    let connected = false
                    if (app.debug === true) {
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
            let timeout = this.timeout
            for (var i = 0; i < checknodes.length; i++) {
                try {
                    if (app.banned.indexOf(checknodes[i]) === -1) {
                        if (this.debug === true) {
                            console.log('HANDSHAKING WITH ' + checknodes[i])
                            var inittime = new Date().getTime()
                        }
                        axios.get(checknodes[i] + '/wallet/getinfo', { timeout: timeout }).then(async check => {
                            if (check.config.url !== undefined) {
                                let url = check.config.url.replace('/wallet/getinfo', '')
                                let checksum = await app.returnLastChecksum(check.data.version)
                                let isValid = true
                                if (checksum !== false) {
                                    if (check.data.checksum !== checksum) {
                                        isValid = false
                                        app.banned.push(url)
                                    }
                                }
                                if (check.data.blocks !== undefined && connected === false && check.data.toindex <= 1 && check.data.toindex >= 0 && isValid) {
                                    connected = true
                                    var restime = new Date().getTime()
                                    if (this.debug) {
                                        let elapsed = restime - inittime
                                        console.log('ELAPSED ' + elapsed + 'ms TO CONNECT')
                                    }
                                    response(url)
                                } else {
                                    if (this.debug) {
                                        console.log(url + ' | (' + check.data.toindex + ' blocks) (checksum ' + isValid + ') (connected ' + connected + ')')
                                    }
                                    if (!connected && (!isValid || check.data.toindex > 1)) {
                                        app.banned.push(url)
                                        if (this.debug) {
                                            console.log('BANNING ' + url)
                                        }
                                    }
                                    response(false)
                                }
                            } else {
                                response(false)
                            }
                        }).catch(err => {
                            if (err.request._option !== undefined) {
                                let errored = err.request._options.protocol + '//' + err.request._options.hostname
                                if (this.debug) {
                                    console.log('NODE ' + errored + ' ERROED!')
                                }
                                if (!connected) {
                                    app.banned.push(errored)
                                }
                            }
                            response(false)
                        })
                    } else {
                        if (this.debug) {
                            console.log('NODE ' + checknodes[i] + ' BANNED, IGNORING!')
                        }
                    }
                } catch (err) {
                    if (this.debug) {
                        console.log(err)
                    }
                }
            }
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

    hexToBytes(b) { for (var a = [], c = 0; c < b.length; c += 2)a.push(parseInt(b.substr(c, 2), 16)); return a }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    hash(text) {
        return new Promise(response => {
            let buf = Buffer.from(text)
            var sha = crypto.createHash('sha256').update(buf).digest()
            response(sha.toString('hex'))
        })
    }

    hashtopath(hash, hardened = false) {
        let bignum = hash.match(/.{1,2}/g)
        let num = ''
        for (let k in bignum) {
            num += parseInt(bignum[k], 16).toString()
        }
        // DERIVE NUMBER FROM HASH
        let parts = num.match(/.{1,8}/g)
        let path = 'm'
        for (let k in parts) {
            path += '/'
            path += parts[k]
            if (hardened) {
                path += "'"
            }
        }
        return path
    }

    gettime() {
        return new Promise(async response => {
            setTimeout(function () {
                response(new Date().getTime())
            }, 2500)
            let sid = await this.createAddress('TEMPORARY', false)
            let averageTimeRequest = await this.createContractRequest(sid.walletstore, 'TEMPORARY',
                {
                    contract: "LLsNWqyhrH2wHph879VXTFaNLLYt43Jjq6",
                    version: "latest",
                    function: "getAverageTime",
                    params: ""
                }
            )
            let averageTime = await this.sendContractRequest(averageTimeRequest)
            response(averageTime)
        })
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
                if (data.indexOf('*') === -1) {
                    // MAINTAIN FALLBACK TO OLD ENCRYPTED WALLETS
                    var decipher = crypto.createDecipher('aes-256-cbc', password)
                    var dec = decipher.update(data, 'hex', 'utf8')
                    dec += decipher.final('utf8')
                    response(dec)
                } else {
                    let textParts = data.split('*');
                    let iv = Buffer.from(textParts.shift(), 'hex')
                    let encryptedText = Buffer.from(textParts.join('*'), 'hex')
                    let key = crypto.createHash('sha256').update(String(password)).digest('base64').substr(0, 32)
                    let decipher = crypto.createDecipheriv('aes-256-ctr', key, iv)
                    let decrypted = decipher.update(encryptedText)
                    decrypted = Buffer.concat([decrypted, decipher.final()])
                    if (buffer === false) {
                        response(decrypted.toString())
                    } else {
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

    // XSID (BIP32-39) MANAGEMENT
    async generateMnemonic(language = '') {
        return new Promise(response => {
            if (language !== '') {
                let supported = ['english', 'italian', 'spanish', 'french', 'latin']
                if (supported.indexOf(language) !== -1) {
                    bip39.setDefaultWordlist(language)
                }
            } else {
                bip39.setDefaultWordlist('english')
            }
            const mnemonic = bip39.generateMnemonic(256)
            response(mnemonic)
        })
    }

    buildxSid(password, language = '', saveKey = true, mnemonic = '', label = '') {
        const app = this
        const db = new ScryptaDB(app.isBrowser)
        return new Promise(async response => {
            if (mnemonic === '') {
                mnemonic = await this.generateMnemonic(language)
            }
            let seed = await bip39.mnemonicToSeed(mnemonic)
            var hdkey = HDKey.fromMasterSeed(Buffer.from(seed, 'hex'), this.testnet ? lyraInfo.testnet.bip32 : lyraInfo.mainnet.bip32);
            let xprv = hdkey.privateExtendedKey
            let xpub = hdkey.publicExtendedKey

            let wallethex = await this.cryptData(mnemonic.toString('hex'), password)
            let check = await this.decryptData(wallethex, password)
            if (check !== false && check === mnemonic.toString('hex')) {
                var walletstore = xpub + ':' + wallethex;
                if (saveKey === true) {
                    let check = await db.get('xsid', 'xpub', xpub)
                    if (!check) {
                        await db.put('xsid', {
                            xpub: xpub,
                            wallet: walletstore,
                            label: label
                        })
                    } else {
                        await db.update('xsid', 'xpub', xpub, {
                            xpub: xpub,
                            wallet: walletstore,
                            label: label
                        })
                    }
                }

                response({
                    mnemonic: mnemonic,
                    seed: seed.toString('hex'),
                    xprv: xprv,
                    xpub: xpub,
                    walletstore: walletstore
                })
            } else {
                response(false)
            }
        })
    }

    returnxKey(xpub) {
        const app = this
        return new Promise(async response => {
            if (xpub.length === 111) {
                const db = new ScryptaDB(app.isBrowser)
                let doc = await db.get('xsid', 'xpub', xpub)
                if (doc !== undefined) {
                    response(doc.wallet)
                } else {
                    response(false)
                }
            } else {
                response(xpub)
            }
        })
    }

    async readxKey(password, key) {
        let wallet = await this.returnxKey(key)
        if (wallet !== false) {
            if (password !== '') {
                var xSIDS = key.split(':')
                try {
                    let decrypted = await this.decryptData(xSIDS[1], password)
                    if (decrypted !== false) {
                        let split = decrypted.split(" ")
                        if (split.length === 24) {
                            let seed = await bip39.mnemonicToSeed(decrypted)
                            let xsid = await this.returnXKeysFromSeed(decrypted)
                            xsid.seed = seed
                            return Promise.resolve(xsid)
                        } else {
                            return Promise.resolve(false)
                        }
                    } else {
                        return Promise.resolve(false)
                    }
                } catch (ex) {
                    // console.log('WRONG PASSWORD')
                    return Promise.resolve(false)
                }
            }
        } else {
            return false
        }
    }

    returnXKeysFromSeed(seed) {
        return new Promise(async response => {

            try {
                var hdkey = HDKey.fromMasterSeed(Buffer.from(seed, 'hex'), this.testnet ? lyraInfo.testnet.bip32 : lyraInfo.mainnet.bip32);
            } catch (e) {
                var hdkey = HDKey.fromMasterSeed(seed, this.testnet ? lyraInfo.testnet.bip32 : lyraInfo.mainnet.bip32);
            }

            let xprv = hdkey.privateExtendedKey
            let xpub = hdkey.publicExtendedKey

            response({
                xprv: xprv,
                xpub: xpub
            })
        })
    }

    deriveKeyFromMnemonic(mnemonic, index) {
        return new Promise(async response => {
            let params = lyraInfo.mainnet
            if (this.testnet === true) {
                params = lyraInfo.testnet
            }

            let seed = await bip39.mnemonicToSeed(mnemonic)
            var hdkey = HDKey.fromMasterSeed(seed, this.testnet ? lyraInfo.testnet.bip32 : lyraInfo.mainnet.bip32);
            var childkey = hdkey.derive(index)
            let derivedxprv = childkey.privateExtendedKey
            let derivedxpub = childkey.publicExtendedKey
            var key = new CoinKey(childkey.privateKey, params)

            response({
                xpub: derivedxpub,
                xprv: derivedxprv,
                key: childkey.publicKey.toString('hex'),
                prv: key.privateWif,
                pub: key.publicAddress
            })
        })
    }

    deriveKeyFromSeed(seed, index) {
        return new Promise(async response => {
            let params = lyraInfo.mainnet
            if (this.testnet === true) {
                params = lyraInfo.testnet
            }

            var hdkey = HDKey.fromMasterSeed(Buffer.from(seed, 'hex'), this.testnet ? lyraInfo.testnet.bip32 : lyraInfo.mainnet.bip32)
            var childkey = hdkey.derive(index)
            let derivedxprv = childkey.privateExtendedKey
            let derivedxpub = childkey.publicExtendedKey
            var key = new CoinKey(childkey.privateKey, params)

            response({
                xpub: derivedxpub,
                xprv: derivedxprv,
                key: childkey.publicKey.toString('hex'),
                prv: key.privateWif,
                pub: key.publicAddress
            })
        })
    }

    deriveKeyFromXPrv(xprv, index) {
        return new Promise(async response => {
            let params = lyraInfo.mainnet
            if (this.testnet === true) {
                params = lyraInfo.testnet
            }

            var hdkey = HDKey.fromExtendedKey(xprv, this.testnet ? lyraInfo.testnet.bip32 : lyraInfo.mainnet.bip32);
            var childkey = hdkey.derive(index)
            var key = new CoinKey(childkey.privateKey, params)
            let derivedxprv = childkey.privateExtendedKey
            let derivedxpub = childkey.publicExtendedKey

            response({
                xpub: derivedxpub,
                xprv: derivedxprv,
                key: childkey.publicKey.toString('hex'),
                prv: key.privateWif,
                pub: key.publicAddress
            })
        })
    }

    deriveKeyfromXPub(xpub, index) {
        return new Promise(async response => {
            let params = lyraInfo.mainnet
            if (this.testnet === true) {
                params = lyraInfo.testnet
            }

            var hdkey = HDKey.fromExtendedKey(xpub, this.testnet ? lyraInfo.testnet.bip32 : lyraInfo.mainnet.bip32);
            var childkey = hdkey.derive(index)

            response({
                key: childkey.publicKey.toString('hex'),
                pub: await this.getAddressFromPubKey(childkey.publicKey.toString('hex'))
            })
        })
    }

    //ADDRESS MANAGEMENT
    async createAddress(password, saveKey = true, label = '') {
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

        var walletstore = await this.buildWallet(password, lyrapub, wallet, saveKey, label)

        var response = {
            pub: lyrapub,
            key: lyrakey,
            prv: lyraprv,
            walletstore: walletstore
        }
        return response;
    }

    async buildWallet(password, pub, wallet, saveKey = true, label = '') {
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
                        wallet: walletstore,
                        label: label
                    })
                } else {
                    await db.update('wallet', 'address', pub, {
                        address: pub,
                        wallet: walletstore,
                        label: label
                    })
                }
            }

            response(walletstore)
        })
    }

    async saveWallet(sid, label = '') {
        const app = this
        const db = new ScryptaDB(app.isBrowser)
        return new Promise(async response => {
            if (sid.indexOf('xpub') === -1) {
                let SIDS = sid.split(':')
                let pub = SIDS[0]
                let check = await db.get('wallet', 'address', pub)
                if (!check) {
                    await db.put('wallet', {
                        address: pub,
                        wallet: sid,
                        label: label
                    })
                } else {
                    await db.update('wallet', 'address', pub, {
                        address: pub,
                        wallet: sid,
                        label: label
                    })
                }
                response(sid)
            } else {
                let SIDS = sid.split(':')
                let pub = SIDS[0]
                let check = await db.get('xsid', 'xpub', pub)
                if (!check) {
                    await db.put('xsid', {
                        xpub: pub,
                        wallet: sid,
                        label: label
                    })
                } else {
                    await db.update('xsid', 'xpub', pub, {
                        xpub: pub,
                        wallet: sid,
                        label: label
                    })
                }
                response(sid)
            }
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
            let pubKeyHash
            try {
                pubKeyHash = crypto.createHash('rmd160').update(sha).digest()
            } catch (e) {
                pubKeyHash = crypto.createHash('ripemd160').update(sha).digest()
                // RMD NOT WORKING
            }
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
                    return true;
                }
            }
        }
    }

    importPrivateKey(key, password, save = true) {
        return new Promise(async response => {
            let lyrakey = await this.getPublicKey(key)
            let lyrapub = await this.getAddressFromPubKey(lyrakey)

            var wallet = {
                prv: key,
                key: lyrakey
            }
            var walletstore = await this.buildWallet(password, lyrapub, wallet, save)

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
                    let parsed = JSON.parse(decrypted)
                    return Promise.resolve(parsed);
                } catch (ex) {
                    // console.log('WRONG PASSWORD')
                    return Promise.resolve(false);
                }
            }
        } else {
            return false
        }
    }

    async fundAddress(privkey, to, amount) {
        return new Promise(async response => {
            let funded = false
            let success = false
            let retries = 0
            let wallet = await this.importPrivateKey(privkey, 'TEMP', false)
            let balance = await this.get('/balance/' + wallet.pub)
            if (this.debug) {
                console.log('CHECKING ADDRESS' + wallet.pub)
            }
            if (balance.balance >= amount) {
                while (funded === false) {
                    let sent = await this.send(wallet.walletstore, 'TEMP', to, amount)
                    if (sent !== false && sent !== null && sent.length === 64) {
                        funded = true
                        success = true
                    }
                    retries++
                    if (retries > 10) {
                        funded = true
                    }
                }
                if (funded === true && success === true) {
                    response(true)
                } else {
                    response(false)
                }
            } else {
                if (this.debug) {
                    console.log('BALANCE IS LOW')
                }
                response(false)
            }
        })
    }

    //TRANSACTIONS FUNCTIONS
    listUnspent(address) {
        return new Promise(async response => {
            const app = this
            const node = await app.connectNode();
            var unspent = await app.get('/unspent/' + address)
            response(unspent.unspent)
        })
    }

    sendRawTransaction(rawtransaction) {
        return new Promise(async response => {
            const app = this
            var txid = await app.post('/sendrawtransaction',
                { rawtransaction: rawtransaction }
            ).catch(async function (err) {
                txid = await app.post('/sendrawtransaction',
                    { rawtransaction: rawtransaction }
                )
            })
            response(txid.data)
        })
    }

    decodeRawTransaction(rawtransaction) {
        return new Promise(async response => {
            const app = this
            const node = await app.connectNode();
            if (node !== undefined) {
                var transaction = await axios.post(
                    node + '/decoderawtransaction',
                    { rawtransaction: rawtransaction }
                ).catch(function (err) {
                    // console.log(err)
                })
                response(transaction.data.transaction)
            } else {
                response(false)
            }
        })
    }

    async createRawTransaction(from, outputs = '', metadata = '', fees = 0.001) {
        var trx = Trx.transaction();
        var MAX_OPRETURN = this.MAX_OPRETURN
        var unspent = []
        var inputs = []
        var cache = await this.returnUTXOCache()
        if (cache !== undefined && cache.length > 0) {
            for (var x = 0; x < cache.length; x++) {
                if (this.debug) {
                    console.log(cache[x])
                }
                if (cache[x].address === SIDS[0]) {
                    unspent.push(cache[x])
                }
            }
        }
        var listunspent = await this.listUnspent(from)
        for (var x = 0; x < listunspent.length; x++) {
            unspent.push(listunspent[x])
        }
        if (this.debug) {
            console.log('UNSPENT', unspent, unspent.length)
        }
        if (unspent.length > 0) {
            var inputamount = 0;
            var amount = 0

            for (let k in outputs) {
                amount += outputs[k]
            }

            var amountneed = amount + fees;
            for (var i = 0; i < unspent.length; i++) {
                if (inputamount <= amountneed) {
                    var txid = unspent[i]['txid'];
                    var index = unspent[i]['vout'];
                    var script = unspent[i]['scriptPubKey'];
                    var cache = await this.returnTXIDCache()
                    if (cache.indexOf(txid + ':' + index) === -1 && inputs.indexOf(txid + ':' + index) === -1 && unspent[i]['address'] === from) {
                        trx.addinput(txid, index, script);
                        inputamount += unspent[i]['amount']
                        inputs.push(txid + ':' + index)
                    } else if (this.debug) {
                        console.log('INPUT ALREADY IN CACHE ' + txid + ':' + index)
                    }
                }
            }
            if (inputamount >= amountneed) {
                var change = inputamount - amountneed;
                if (Object.keys(outputs).length > 0 && outputs[from] === undefined) {
                    let keys = Object.keys(outputs)
                    for (let k in keys) {
                        if (outputs[keys[k]] > 0.00001) {
                            if (amount > 0.00001) {
                                trx.addoutput(keys[k], outputs[keys[k]]);
                            }
                        }
                    }
                    if (change > 0.00001) {
                        trx.addoutput(from, change);
                    }
                } else {
                    var realamount = inputamount - fees
                    if (realamount > 0.00001) {
                        if (this.debug === true) {
                            console.log('SENDING INPUT - FEES TO SENDER, BECAUSE SENDER AND RECEIVER ARE SAME ACCOUNT', realamount)
                        }
                        trx.addoutput(from, realamount)
                    }
                }

                if (metadata !== '') {
                    if (metadata.length <= MAX_OPRETURN) {
                        //console.log('ADDING METADATA TO TX', metadata)
                        trx.addmetadata(metadata);
                    } else {
                        //console.log('METADATA TOO LONG')
                    }
                }
                let transaction = {
                    inputs: trx.inputs,
                    outputs: trx.outputs
                }

                let hexed = Buffer.from(JSON.stringify(transaction)).toString('hex')

                return Promise.resolve({
                    serialized: trx.serialize(),
                    hexed: hexed
                })

            } else {
                if (this.debug) { console.log('NOT ENOUGH FUNDS') }
                return Promise.resolve(false) //NOT ENOUGH FUNDS
            }
        } else {
            if (this.debug) {
                console.log('NO UNSPENTS')
            }
            return Promise.resolve(false) //NOT ENOUGH FUNDS
        }
    }

    async signRawTransaction(rawtransaction, privkey) {
        return new Promise(async response => {
            if (rawtransaction.length > 0) {
                let transaction = JSON.parse(Buffer.from(rawtransaction, 'hex').toString())
                var trx = Trx.transaction();
                trx.inputs = transaction.inputs
                trx.outputs = transaction.outputs
                let signed = trx.sign(privkey)
                response(signed)
            } else {
                response(false)
            }
        })
    }

    async build(key, password, send = false, to, amount, metadata = '', fees = 0.001) {
        var SID = key;
        var MAX_OPRETURN = this.MAX_OPRETURN
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
                        if (this.debug) {
                            console.log(cache[x])
                        }
                        if (cache[x].address === SIDS[0]) {
                            unspent.push(cache[x])
                        }
                    }
                }
                var listunspent = await this.listUnspent(from)
                for (var x = 0; x < listunspent.length; x++) {
                    unspent.push(listunspent[x])
                }
                if (this.debug) {
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
                            if (cache.indexOf(txid + ':' + index) === -1 && inputs.indexOf(txid + ':' + index) === -1 && unspent[i]['address'] === from) {
                                trx.addinput(txid, index, script);
                                inputamount += unspent[i]['amount']
                                inputs.push(txid + ':' + index)
                            } else if (this.debug) {
                                console.log('INPUT ALREADY IN CACHE ' + txid + ':' + index)
                            }
                        }
                    }
                    if (inputamount >= amountneed) {
                        var change = inputamount - amountneed;
                        if (to !== from) {
                            if (amount > 0.00001) {
                                trx.addoutput(to, amount);
                            }
                            if (change > 0.00001) {
                                trx.addoutput(from, change);
                            }
                        } else {
                            var realamount = inputamount - fees
                            if (realamount > 0.00001) {
                                if (this.debug === true) {
                                    console.log('SENDING INPUT - FEES TO SENDER, BECAUSE SENDER AND RECEIVER ARE SAME ACCOUNT', realamount)
                                }
                                trx.addoutput(from, realamount)
                            }
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
                            if (this.debug) {
                                console.log('TXID IS ', txid)
                            }
                            if (txid !== undefined && txid !== null && txid.length === 64) {
                                for (let i in inputs) {
                                    await this.pushTXIDtoCache(inputs[i])
                                }
                                // console.log("TX SENT: " + txid)
                                return Promise.resolve(txid)
                            } else {
                                return Promise.resolve(false) //NOT ENOUGH FUNDS
                            }
                        }
                    } else {
                        if (this.debug) { console.log('NOT ENOUGH FUNDS') }
                        return Promise.resolve(false) //NOT ENOUGH FUNDS
                    }
                } else {
                    if (this.debug) {
                        console.log('NO UNSPENTS')
                    }
                    return Promise.resolve(false) //NOT ENOUGH FUNDS
                }
            } catch (error) {
                // console.log(error)
                return Promise.resolve(false);
            }
        }
    }

    async send(key, password, to, amount, metadata = '') {
        let wallet = await this.returnKey(key)
        amount = parseFloat(amount)
        if (wallet !== false) {
            if (password !== '' && to !== '') {
                var SIDS = wallet.split(':');
                try {
                    let decrypted = await this.decryptData(SIDS[1], password)
                    if (decrypted !== false) {
                        var txid = ''
                        var i = 0
                        var rawtransaction
                        while (txid !== null && txid !== undefined && txid.length !== 64) {
                            var fees = 0.001 + (i / 1000)
                            rawtransaction = await this.build(wallet, password, false, to, amount, metadata, fees)
                            if (this.debug) {
                                console.log('RAWTRANSACTION IS', rawtransaction)
                            }
                            if (rawtransaction === false) {
                                Promise.resolve(false)
                            }
                            txid = await this.sendRawTransaction(rawtransaction.signed)
                            if (this.debug) {
                                console.log('TXID AFTER SEND IS ', txid)
                            }
                            if (txid !== null && txid !== false && txid.length === 64) {
                                if (this.debug) {
                                    console.log('TXID IS VALID')
                                }
                                for (let i in rawtransaction.inputs) {
                                    if (this.debug) {
                                        console.log('PUSHING TXID TO CACHE')
                                    }
                                    await this.pushTXIDtoCache(rawtransaction.inputs[i])
                                }
                                //Storing UTXO to cache
                                var decoded = await this.decodeRawTransaction(rawtransaction.signed)
                                if (this.debug) {
                                    console.log('DECODED TX IS', decoded)
                                }
                                let indexunspent = 1
                                if (SIDS[0] === to) {
                                    indexunspent = 0
                                }
                                if (decoded.vout[indexunspent].scriptPubKey.addresses !== undefined) {
                                    if (this.debug) {
                                        console.log('PUSHING UNSPENT TO CACHE')
                                    }
                                    let unspent = {
                                        txid: decoded.txid,
                                        vout: indexunspent,
                                        address: decoded.vout[indexunspent].scriptPubKey.addresses[0],
                                        scriptPubKey: decoded.vout[indexunspent].scriptPubKey.hex,
                                        amount: decoded.vout[indexunspent].value
                                    }
                                    await this.pushUTXOtoCache(unspent)
                                }
                            } else {
                                txid = null
                            }
                            i++;
                        }
                        if (this.debug) {
                            console.log('RESOLVING PROMISE WITH RESULT', txid)
                        }
                        return Promise.resolve(txid)
                    } else {
                        return Promise.resolve(false)
                    }
                } catch (e) {
                    if (this.debug) {
                        console.log(e)
                    }
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
        return true;
    }

    async verifyPlanum() {
        const app = this
        return new Promise(async response => {
            let idanodeverified = false
            let check_sidechain = {}
            while (!idanodeverified) {
                check_sidechain = await app.get('/sidechain/check/' + app.sidechain + '/true')
                if (check_sidechain.verified === false) {
                    if (app.debug) {
                        console.log('NODE ' + check_sidechain.node + ' NOT SYNCED')
                    }
                    app.banned.push(check_sidechain.node)
                } else {
                    if (app.debug) {
                        console.log('SIDECHAIN HAVE ' + check_sidechain.reliability + '% OF RELIABILITY')
                    }
                    idanodeverified = true
                }
            }
            response(check_sidechain)
        })
    }

    async listPlanumUnspent(address, safe = false) {
        return new Promise(async response => {
            const app = this
            let unspent = []

            // PUSHING LOCAL CACHE
            if (safe === false) {
                var cache = await this.returnUSXOCache()
                if (cache !== undefined && cache.length > 0) {
                    for (var x = 0; x < cache.length; x++) {
                        unspent.push(cache[x])
                    }
                }
            }

            if (app.sidechain !== '') {
                let unspentnode = await app.post('/sidechain/listunspent', { sidechain_address: app.sidechain, dapp_address: address })
                if (unspentnode.unspent !== undefined) {
                    for (let x in unspentnode.unspent) {
                        if (safe === true) {
                            if (unspentnode.unspent[x].block !== undefined && unspentnode.unspent[x].block > 0) {
                                unspent.push(unspentnode.unspent[x])
                            }
                        } else {
                            unspent.push(unspentnode.unspent[x])
                        }
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

    async sendPlanumAsset(key, password, to, amount, changeaddress = '', memo = '', time = '', safe = false, inputs = []) {
        const app = this
        let wallet = await this.returnKey(key)
        amount = parseFloat(amount)
        if (wallet !== false) {
            if (password !== '' && to !== '') {
                var SIDS = wallet.split(':');
                to = to.trim()
                let decrypted
                try {
                    decrypted = await this.decryptData(SIDS[1], password)
                    decrypted = JSON.parse(decrypted)
                } catch (e) {
                    return false
                }
                if (decrypted.prv !== undefined) {
                    const address = SIDS[0]
                    let sidechainVerified = await app.verifyPlanum()
                    let unspent = await app.listPlanumUnspent(address, safe)
                    let sidechainObj = sidechainVerified.sidechain
                    const decimals = sidechainObj.decimals
                    if (unspent.length > 0) {
                        let outputs = {}
                        let amountinput = 0
                        amount = app.math.round(amount, decimals)
                        let usedtx = []
                        let checkto = await app.get('/validate/' + to)
                        if (checkto.data.isvalid === false) {
                            if (this.debug) {
                                console.log('RECEIVER IS INVALID')
                            }
                            return Promise.resolve(false)
                        }
                        let txtime
                        if (time !== '') {
                            txtime = parseInt(time)
                        } else {
                            txtime = await app.gettime()
                        }
                        if (txtime > 0) {
                            if (this.debug) {
                                console.log('SMART CONTRACT TIME IS VALID')
                            }
                        } else {
                            txtime = new Date().getTime()
                        }
                        let selectedInputs = []
                        if (inputs.length > 0) {
                            selectedInputs = inputs
                            inputs = []
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
                                if (cache.indexOf(unspent[i].sxid + ':' + unspent[i].vout) === -1 && unspent[i].time <= txtime) {
                                    let toUse = true
                                    if (selectedInputs.length > 0 && selectedInputs.indexOf(unspent[i].sxid + ':' + unspent[i].vout) === -1) {
                                        toUse = false
                                    }
                                    if (toUse) {
                                        inputs.push(unspent[i])
                                        usedtx.push(unspent[i].sxid + ':' + unspent[i].vout)
                                        let toadd = app.math.round(unspent[i].amount, decimals)
                                        amountinput = app.math.sum(amountinput, toadd)
                                        amountinput = app.math.round(amountinput, decimals)
                                    }
                                } else {
                                    if (this.debug) {
                                        console.log('CAN\'T USE PLANUM UNSPENT ' + unspent[i].sxid + ':' + unspent[i].vout)
                                        if (unspent[i].time > txtime) {
                                            console.log('INPUT IS IN THE FUTURE')
                                        }
                                    }
                                }
                            }
                        }

                        let totaloutputs = 0
                        amountinput = app.math.round(amountinput, decimals)
                        amount = app.math.round(amount, decimals)
                        if (amountinput >= amount) {

                            if (to === sidechainObj.address && sidechainObj.burnable === false) {

                                if (this.debug) {
                                    console.log('ASSETS NOT BURNABLE')
                                }
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
                                        outputs[address] = app.math.round(outputs[address], decimals)
                                        totaloutputs = app.math.sum(totaloutputs, change)
                                    }
                                }

                                totaloutputs = app.math.round(totaloutputs, decimals)

                                if (inputs.length > 0 && totaloutputs > 0) {
                                    let transaction = {}
                                    transaction["sidechain"] = app.sidechain
                                    transaction["inputs"] = inputs
                                    transaction["outputs"] = outputs
                                    transaction["memo"] = memo
                                    transaction["time"] = txtime

                                    if (this.debug) {
                                        console.log('TX TIME IS ' + transaction['time'])
                                    }
                                    let signtx = await app.signMessage(decrypted.prv, JSON.stringify(transaction))

                                    let timecheck = true
                                    for (let ji in transaction["inputs"]) {
                                        if (transaction["inputs"][ji].time > transaction["time"]) {
                                            timecheck = false
                                        }
                                    }

                                    if (timecheck) {
                                        let tx = {
                                            transaction: transaction,
                                            signature: signtx.signature,
                                            pubkey: signtx.pubkey,
                                            sxid: signtx.hash
                                        }
                                        if (this.debug) {
                                            console.log('TRANSACTION', tx)
                                        }
                                        let validatetransaction = await app.post('/sidechain/validate',
                                            {
                                                transaction: tx,
                                                address: address,
                                                sxid: signtx.hash,
                                                signature: signtx.signature,
                                                pubkey: signtx.pubkey
                                            }
                                        )
                                        if (validatetransaction.errors === undefined && validatetransaction.valid === true && signtx.hash !== undefined) {
                                            let sent = false
                                            let txs = []
                                            let retry = 0
                                            while (sent === false) {
                                                let written = await app.write(key, password, JSON.stringify(tx), '', '', 'chain://')
                                                if (written !== false && written.txs !== undefined && written.txs.length >= 1 && written.txs[0] !== null) {
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
                                            if (this.debug) {
                                                console.log('TRANSACTION VALIDATION FAILED')
                                            }
                                            return Promise.resolve(false)
                                        }
                                    } else {
                                        if (this.debug) {
                                            console.log('TIME CHECK NOT PASSED')
                                        }
                                        return Promise.resolve(false)
                                    }

                                } else {
                                    if (this.debug) {
                                        console.log('NO INPUTS OR OUTPUTS')
                                    }
                                    return Promise.resolve(false)
                                }
                            }
                        } else {
                            if (this.debug) {
                                console.log('NOT ENOUGH FUNDS')
                            }
                            return Promise.resolve(false)
                        }
                    } else {
                        if (this.debug) {
                            console.log('NO UNSPENTS')
                        }
                        return false
                    }
                } else {
                    if (this.debug) {
                        console.log('WRONG PASSWORD')
                    }
                    return false
                }
            } else {
                return false
            }
        } else {
            return false
        }
    }

    async returnPlanumBalance(address) {
        const app = this
        return new Promise(async response => {
            await app.verifyPlanum()
            let balance = await app.post("/sidechain/balance", {
                dapp_address: address,
                sidechain_address: app.sidechain,
            })
            response(balance)
        })
    }

    async returnPlanumTransactions(address) {
        const app = this
        return new Promise(async response => {
            await app.verifyPlanum()
            let transactions = await app.post("/sidechain/transactions", {
                dapp_address: address,
                sidechain_address: app.sidechain,
            })
            response(transactions)
        })
    }

    //PROGRESSIVE DATA MANAGEMENT
    async write(key, password, metadata, collection = '', refID = '', protocol = '', uuid = '', contract = '') {
        if (password !== '' && metadata !== '') {
            let wallet = await this.returnKey(key)
            if (wallet !== false) {
                var SIDS = wallet.split(':');
                var MAX_OPRETURN = this.MAX_OPRETURN
                try {
                    //console.log('WRITING TO BLOCKCHAIN')
                    let decrypted = await this.decryptData(SIDS[1], password)
                    if (decrypted !== false) {
                        let address = SIDS[0]

                        if (uuid === '') {
                            const { v4: uuidv4, validate } = require('uuid');
                            uuid = uuidv4().replace(new RegExp('-', 'g'), '.')
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

                        if (contract !== '') {
                            contract = '!*!' + contract
                        } else {
                            contract = '!*!'
                        }

                        var dataToWrite = '*!*' + uuid + collection + refID + protocol + contract + '*=>' + metadata + '*!*'
                        if (dataToWrite.length <= MAX_OPRETURN) {
                            var txid = ''
                            var i = 0
                            var totalfees = 0
                            var retries = 0
                            while (txid.length !== 64) {
                                var fees = 0.001 + (i / 1000)
                                var rawtransaction = await this.build(wallet, password, false, address, 0, dataToWrite, fees)
                                if (this.debug) {
                                    console.log(rawtransaction.signed)
                                }
                                if (rawtransaction.signed !== false) {
                                    txid = await this.sendRawTransaction(rawtransaction.signed)
                                    if (this.debug) {
                                        console.log(txid)
                                    }
                                    if (txid !== undefined && txid !== null && txid.length === 64) {
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
                                    } else {
                                        txid = ''
                                        await this.clearCache(true)
                                        await this.sleep(1000)
                                    }
                                }
                                i++;
                                retries++;
                                if (retries > 9) {
                                    txid = '0000000000000000000000000000000000000000000000000000000000000000'
                                }
                            }

                            if (txid !== '0000000000000000000000000000000000000000000000000000000000000000') {
                                return Promise.resolve({
                                    uuid: uuid,
                                    address: address,
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
                                return Promise.resolve(false)
                            }

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
                    } else {
                        if (this.debug) {
                            console.log('WRONG PASSWORD')
                        }
                        return Promise.resolve(false);
                    }
                } catch (error) {
                    if (this.debug) {
                        console.log(error)
                    }
                    return Promise.resolve(false);
                }
            } else {
                if (this.debug) {
                    console.log('CAN\'T RETURN KEY')
                }
                return false
            }
        }
    }

    async update(key, password, metadata, uuid, collection = '', refID = '', protocol = '') {
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
    async signMessage(privatekey, message) {
        return new Promise(response => {
            //CREATING CK OBJECT
            let params = lyraInfo.mainnet
            if (this.testnet === true) {
                params = lyraInfo.testnet
            }
            var ck = CoinKey.fromWif(privatekey, params);
            //CREATE HASH FROM MESSAGE
            let hash = CryptoJS.SHA256(message);
            let msg = Buffer.from(hash.toString(CryptoJS.enc.Hex), 'hex');
            //GETTING PUBKEY FROM PRIVATEKEY
            let privKey = ck.privateKey
            let privkeybuf = Buffer.from(privKey)
            //SIGN MESSAGE
            const sigObj = secp256k1.ecdsaSign(msg, privkeybuf)
            const pubKey = secp256k1.publicKeyCreate(privKey)

            response({
                message: message,
                hash: hash.toString(CryptoJS.enc.Hex),
                signature: Buffer.from(sigObj.signature).toString('hex'),
                pubkey: Buffer.from(pubKey).toString('hex'),
                address: ck.publicAddress
            })
        })
    }

    async verifyMessage(pubkey, signature, message) {
        return new Promise(async response => {
            //CREATE HASH FROM MESSAGE
            let hash = CryptoJS.SHA256(message);
            let msgbuf = Buffer.from(hash.toString(CryptoJS.enc.Hex), 'hex')
            //VERIFY MESSAGE
            let sigbuf = Buffer.from(signature, 'hex')
            let pubKey = Buffer.from(pubkey, 'hex')
            let verified = secp256k1.ecdsaVerify(sigbuf, msgbuf, pubKey)
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

    createContractRequest(key, password, request) {
        const app = this
        return new Promise(async response => {
            let wallet = await this.returnKey(key)
            if (wallet !== false) {
                if (password !== '') {
                    let identity = await app.readKey(password, key)
                    if (identity !== false) {
                        if (request.contract !== undefined && request.function !== undefined && request.params !== undefined) {
                            let hex = Buffer.from(JSON.stringify(request)).toString('hex')
                            let signed = await app.signMessage(identity.prv, hex)
                            response(signed)
                        } else {
                            response(false)
                        }
                    } else {
                        response(false)
                    }
                }
            } else {
                response(false)
            }
        })
    }

    sendContractRequest(request, node = '') {
        return new Promise(async response => {
            try {
                if (node !== '') {
                    let res = await axios.post(node + '/contracts/run', request)
                    response(res.data)
                } else {
                    if (this.debug === true) {
                        console.log('CHECKING FOR MAINTAINERS')
                    }
                    this.staticnodes = true
                    let details = JSON.parse(Buffer.from(request.message, 'hex').toString('utf-8'))
                    let sid = await this.createAddress('TEMP', false)
                    if (this.debug) {
                        console.log('DETAILS ORIGINAL REQUEST', details)
                    }
                    let indexrequest = await this.createContractRequest(
                        sid.walletstore,
                        'TEMP',
                        {
                            contract: "LgSAtP3gPURByanZSM32kfEu9C1uyQ6Kfg",
                            function: "index",
                            params: { contract: details.contract, version: 'latest' }
                        }
                    )
                    if (this.debug === true) {
                        console.log('INDEXER REQUEST', JSON.stringify(indexrequest))
                    }
                    let maintainers = false
                    let maintainersNodes = ['https://idanodejs01.scryptachain.org', 'https://idanodejs02.scryptachain.org', 'https://idanodejs03.scryptachain.org', 'https://idanodejs04.scryptachain.org', 'https://idanodejs05.scryptachain.org', 'https://idanodejs06.scryptachain.org']
                    let jj = 0
                    while (maintainers === false) {
                        try {
                            if (this.debug) {
                                console.log('ASKING FOR MAINTAINERS TO ' + maintainersNodes[jj])
                            }
                            maintainers = await this.post('/contracts/run', indexrequest, maintainersNodes[jj])
                        } catch (e) {
                            jj++
                            if (maintainersNodes[jj] === undefined) {
                                jj = 0
                            }
                            if (this.debug === true) {
                                console.log('ERROR WHILE CONTACTING ' + node)
                            }
                        }
                    }
                    if (maintainers.error === undefined) {
                        if (this.debug === true) {
                            console.log('MAINTAINERS FOUND', maintainers)
                        }
                        let res = false
                        let result = false
                        for (let k in maintainers) {
                            if (res === false) {
                                try {
                                    let noderes = await this.post('/contracts/run', request, maintainers[k].url)
                                    if (noderes !== false) {
                                        res = true
                                        result = noderes
                                    }
                                } catch (e) {
                                    if (this.debug === true) {
                                        console.log('ERROR WHILE CONTACTING ' + node)
                                    }
                                }
                            }
                        }

                        response(result)
                    } else {
                        if (this.debug === true) {
                            console.log('NO MAINTAINERS FOUND FOR CONTRACT ' + details.contract)
                        }
                        response(false)
                    }
                }
            } catch (e) {
                if (this.debug === true) {
                    console.log(e)
                }
                response(false)
            }
        })
    }

    writeContractRequest(key, password, request) {
        const app = this
        return new Promise(async response => {
            let wallet = await this.returnKey(key)
            if (wallet !== false) {
                if (password !== '') {
                    let identity = await app.readKey(password, key)
                    if (identity !== false) {
                        if (request.contract !== undefined && request.function !== undefined && request.params !== undefined) {
                            let hex = Buffer.from(JSON.stringify(request)).toString('hex')
                            let signed = await app.signMessage(identity.prv, hex)
                            let written = await this.write(key, password, JSON.stringify(signed), '', '', '', '', request.contract)
                            response(written)
                        } else {
                            response(false)
                        }
                    } else {
                        response(false)
                    }
                }
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
                if (ready.blocks !== undefined) {
                    try {
                        let p2pready = true
                        let p2pdomain = node.replace('https://', 'https://p2p.')
                        try {
                            await axios.get(p2pdomain + '/socket.io/?transport=polling')
                        } catch (e) {
                            if (this.debug) {
                                console.log(p2pdomain + ' NOT READY FOR P2P')
                            }
                            p2pready = false
                        }
                        if (p2pready) {
                            console.log('Bootstrap connection to ' + p2pdomain)
                            global['nodes'][node] = require('socket.io-client')(p2pdomain, { reconnect: true })
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
                                if (data.pubkey === undefined && data.pubKey !== undefined) {
                                    data.pubkey = data.pubKey
                                }
                                let verified = await app.verifyMessage(data.pubkey, data.signature, data.message)
                                if (verified !== false && global['cache'].indexOf(data.signature) === -1) {
                                    global['cache'].push(data.signature)
                                    let check = await db.get('p2p', 'signature', data.signature)
                                    if (!check) {
                                        await db.put('p2p', {
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
                        }
                    } catch (e) {
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

    encryptWithRSA(pubkey, text) {
        return new Promise(async response => {
            try {
                let buffer = Buffer.from(text);
                let encrypted = crypto.publicEncrypt(pubkey, buffer);
                let hex = encrypted.toString('hex')
                response(hex)
            } catch (e) {
                response('ERROR WHILE ENCRYPTING')
            }
        })
    }

    decryptWithRSA(privkey, hex) {
        return new Promise(async response => {
            var buffer = Buffer.from(hex, "hex")
            var decrypted = crypto.privateDecrypt(
                { key: privkey.toString() },
                buffer,
            )
            response(decrypted.toString("utf8"))
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

    returnDefaultxSid() {
        const app = this
        return new Promise(async response => {
            const db = new ScryptaDB(app.isBrowser)
            if (app.isBrowser) {
                if (localStorage.getItem('xSID') !== null) {
                    response(localStorage.getItem('xSID'))
                } else {
                    let wallet = await db.get('xsid')
                    if (wallet !== false && wallet[0] !== undefined) {
                        localStorage.setItem('xSID', wallet[0].wallet)
                        response(wallet[0].wallet)
                    } else {
                        response(false)
                    }
                }
            } else {
                let wallet = await db.get('xSID')
                if (wallet !== false && wallet[0] !== undefined) {
                    response(wallet[0].wallet)
                } else {
                    response(false)
                }
            }
        })
    }

    setDefaultxIdentity(xpub) {
        const app = this
        return new Promise(async response => {
            const db = new ScryptaDB(app.isBrowser)
            let wallet = await db.get('xsid', 'xpub', xpub)
            if (wallet !== false && wallet !== null) {
                if (app.isBrowser) {
                    // console.log(wallet)
                    localStorage.setItem('xSID', wallet.wallet)
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
}

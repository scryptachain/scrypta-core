import _ from 'lodash';
var CoinKey = require('coinkey');
var crypto = require('crypto');
var cookies = require('browser-cookies');
var NodeRSA = require('node-rsa');

const lyraInfo = {
    private: 0xae,
    public: 0x30,
    scripthash: 0x0d
};

class ScryptaCore {
    constructor (){
        this.RAWsAPIKey = '';
        this.PubAddress = '';
    }
    
    static returnNodes(){
        return ['idanode01.scryptachain.org','idanode02.scryptachain.org','idanode03.scryptachain.org','idanode04.scryptachain.org'];
    }

    static async createAddress(password, saveKey = true){
        // LYRA WALLET
        var ck = new CoinKey.createRandom(lyraInfo)
        
        // SIMMETRIC KEY
        var buf = crypto.randomBytes(16);
        var api_secret = buf.toString('hex');

        // ASYMMETRIC KEY
        const key = new NodeRSA({b: 512});
        var pk = key.exportKey('pkcs8-private');
        var pub = key.exportKey('pkcs8-public');
        
        var lyrapub = ck.publicAddress;
        var lyraprv = ck.privateWif;
        var lyrakey = ck.publicKey.toString('hex');

        //console.log("CREATED PUB ADDRESS: " + lyrapub);
        //console.log("CREATED PUB KEY: " + lyrakey);
        
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
            prv: lyraprv
        }
        return response;
    }

    static async getPublicKey(privateWif){
        var ck = new CoinKey.fromWif(privateWif);
        var pubkey = ck.publicKey.toString('hex');
        return pubkey;
    }

    static async saveKey(key){
        if(window.location.hostname == 'localhost'){
            var cookie_secure = false;
        }else{
            var cookie_secure = true;
        }
        cookies.set('scrypta_key', key, {secure: cookie_secure, domain: window.location.hostname, expires: 30, samesite: 'Strict'});
        return Promise.resolve(true);
    }

    static keyExsist(){
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

    static async readKey(password = ''){
        var ScryptaCore_cookie = cookies.get('scrypta_key');
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


}

window.ScryptaCore = ScryptaCore
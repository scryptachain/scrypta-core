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

class SCRYPTAKEY {
    constructor (){
        this.sAPIKey = '';
        this.RAWsAPIKey = '';
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

        console.log("CREATED PUB ADDRESS: " + lyrapub);
        
        // STORE JUST LYRA WALLET 
        var wallet = {
            pub: lyrapub,
            prv: lyraprv
        };

        const cipher = crypto.createCipher('aes-256-cbc', password);
        let wallethex = cipher.update(JSON.stringify(wallet), 'utf8', 'hex');
        wallethex += cipher.final('hex');

        walletstore = lyrapub + ':' + wallethex;

        // SAVE ENCRYPTED VERION IN COOKIE
        if(saveKey == true){
            if(window.location.hostname == 'localhost'){
                var cookie_secure = false;
            }else{
                var cookie_secure = true;
            }
            cookies.set('scrypta_key', walletstore, {secure: cookie_secure, domain: window.location.hostname, expires: 30, samesite: 'Strict'});
        }

        return Promise.resolve(true);
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
        var scryptakey_cookie = cookies.get('scrypta_key');
        if(scryptakey_cookie !== null && scryptakey_cookie !== ''){
            return true
        }else{
            return false
        }
    }

    static async readKey(password = ''){
        var scryptakey_cookie = cookies.get('scrypta_key');
        if(password !== ''){
            scryptakey_split = scryptakey_cookie.split(':');
            try {
                var decipher = crypto.createDecipher('aes-256-cbc', password);
                var dec = decipher.update(scryptakey_cookie[1],'hex','utf8');
                dec += decipher.final('utf8');
                var $scryptakey_cookie = JSON.parse(dec);
                this.sAPIKey = $scryptakey_cookie;
                this.pubaddress = scryptakey_split[0];
                this.RAWsAPIKey = scryptakey_cookie[1];
                return Promise.resolve(true);
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

window.SCRYPTAKEY = SCRYPTAKEY
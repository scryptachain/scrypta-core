module.exports = class ScryptaDB {
    constructor(isBrowser = false){
        const db = this 
        db.isBrowser = isBrowser
        db.data = {}
        db.dir = './db'
        if(!isBrowser){
            db.fs = require('fs')
        }
    }

    loadBrowserDB(){
        const db = this
        return new Promise(response => {
            const collections = ["xsid","wallet","sxidcache","usxocache","txidcache","utxocache","nodes","checksums","p2p","identity"]
            for(let x in collections){
                if (localStorage.getItem(collections[x]) !== null) {
                    db.data[collections[x]] = JSON.parse(localStorage.getItem(collections[x]))
                }else{
                    db.data[collections[x]] = []
                    localStorage.setItem(collections[x], JSON.stringify([]))
                }
            }
            response(true)
        })
    }

    loadNodeDB(){
        const db = this
        return new Promise(response => {
            db.dir = './db';
            const collections = ["wallet","sxidcache","usxocache","txidcache","utxocache","nodes","checksums","p2p","identity"]
            if (db.fs.existsSync(db.dir) === false){
                db.fs.mkdirSync(db.dir)
            }
            for(let x in collections){
                if (db.fs.existsSync(db.dir + '/' + collections[x] + '.json')) {
                    try{
                        db.data[collections[x]] = JSON.parse(db.fs.readFileSync(db.dir + '/' + collections[x] + '.json'))
                    }catch(e){
                        console.log('ERROR WHILE LOADING DB')
                    }
                }else{
                    db.data[collections[x]] = []
                    db.fs.writeFileSync(db.dir + '/' + collections[x] + '.json', '[]')
                }
            }
            response(true)
        })
    }

    put(collection, doc){
        const db = this

        return new Promise(async response => {
            if(db.isBrowser){
                await db.loadBrowserDB()
                let found = false
                for(let x in db.data[collection]){
                    if(JSON.stringify(doc) === JSON.stringify(db.data[collection][x])){
                        found = true
                    }
                }
                if(!found){
                    db.data[collection].push(doc)
                    localStorage.setItem(collection, JSON.stringify(db.data[collection]))
                }
                response(true)
            }else{
                await db.loadNodeDB()
                let found = false
                for(let x in db.data[collection]){
                    if(JSON.stringify(doc) === JSON.stringify(db.data[collection][x])){
                        found = true
                    }
                }
                if(!found){
                    if(db.data[collection] !== undefined){
                        db.data[collection].push(doc)
                        db.fs.writeFileSync(db.dir + '/' + collection + '.json', JSON.stringify(db.data[collection]))
                    }
                }
                response(true)
            }
        })    
    }

    get(collection, selector = '', id = ''){
        const db = this
        return new Promise(async response => {
            if(db.isBrowser){
                await db.loadBrowserDB()
            }else{
                await db.loadNodeDB()
            }
            if(selector !== '' && id !== ''){
                let found = false
                let doc
                for(let x in db.data[collection]){
                    if(!found){
                        if(db.data[collection][x][selector] === id){
                            found = true
                            doc = db.data[collection][x]
                        }
                    }
                }

                if(found){
                    response(doc)
                }else{
                    response(false)
                }
            }else{
                response(db.data[collection])
            }
        })
    }

    update(collection, selector, id, doc){
        const db = this
        return new Promise(async response => {
            if(db.isBrowser){
                await db.loadBrowserDB()
            }else{
                await db.loadNodeDB()
            }

            let found = false
            for(let x in db.data[collection]){
                if(!found){
                    if(db.data[collection][x][selector] === id){
                        found = true
                        db.data[collection][x] = doc
                    }
                }
            }

            if(found){
                if(db.isBrowser){
                    localStorage.setItem(collection, JSON.stringify(db.data[collection]))
                }else{
                    db.fs.writeFileSync(db.dir + '/' + collection + '.json', JSON.stringify(db.data[collection]))
                }
                response(doc)
            }else{
                response(false)
            }
        })
    }

    destroy(collection){
        const db = this
        db.data[collection] = []
        return new Promise(async response => {
            if(db.isBrowser){
                await db.loadBrowserDB()
                localStorage.setItem(collection, '[]')
            }else{
                await db.loadNodeDB()
                db.fs.writeFileSync(db.dir + '/' + collection + '.json', '[]')
            }
            response(true)
        })
    }
}
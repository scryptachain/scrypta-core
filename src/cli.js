#!/usr/bin/env node
let ScryptaCore = require('./index')
let scrypta = new ScryptaCore

const argv = require('yargs').argv
const command = argv._[0]
const arguments = []
if(argv._.length > 1){
    for(let x in argv._){
        if(x > 0){
            arguments.push(argv._[x])
        }
    }
}

// SWITCH COMMANDS
async function parseCommand(){
    switch(command){
        case "getinfo":
            let getinfo = await scrypta.get('/wallet/getinfo').catch(err=>{console.log(err)})
            console.log(JSON.stringify(getinfo))
        break;
    }
}

parseCommand()
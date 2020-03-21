#!/usr/bin/env node
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
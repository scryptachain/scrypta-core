# Scrypta-Core NPM

This is the main client side library of Scrypta Blockchain, written in NodeJS.

You can use this version by installing it directly from npm:

```npm install --save @scrypta/core```

# Use your own IdaNodes

To override the IdaNodes list you've to rewrite the array like this:

```
let ScryptaCore = require('@scrypta/core')
let scrypta = new ScryptaCore
scrypta.staticnodes = true
scrypta.mainnetIdaNodes = ['http://localhost:3001', 'https://anotheridanode.com']
```

# Scrypta-Core CLI (WIP)

If you want to use the module as a CLI you have to run:

```sudo npm link```

Then you'll be able to run commands like:
```scrypta getinfo```

This feature is a work in progress and will be released soon.

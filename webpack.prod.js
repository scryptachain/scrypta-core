const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const CleanWebpackPlugin = require('clean-webpack-plugin');

module.exports = env => {
    return {
        mode: 'production',
        entry: {
            dapi: './src/scrypta.js'
        }
    }
};
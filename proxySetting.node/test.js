const addon = require('./build/Release/proxyaddon.node');

let result = addon.setProxy('127.0.0.1:8080');
console.log(result);
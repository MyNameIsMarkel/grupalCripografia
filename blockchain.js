"use strict";
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", { value: true });
var crypto = require("crypto");
var Transaction = /** @class */ (function () {
    function Transaction(from, to, value, fee, timestamp, nonce, signature) {
        if (signature === void 0) { signature = ''; }
        this.from = from;
        this.to = to;
        this.value = value;
        this.fee = fee;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.signature = signature;
    }
    Transaction.prototype.calculateHash = function () {
        return crypto.createHash('sha256').update(this.from + this.to + this.value + this.fee + this.timestamp + this.nonce).digest('hex');
    };
    return Transaction;
}());
var Block = /** @class */ (function () {
    function Block(prevHash, transactions, timestamp, nonce) {
        if (prevHash === void 0) { prevHash = ''; }
        if (transactions === void 0) { transactions = []; }
        if (timestamp === void 0) { timestamp = Date.now(); }
        if (nonce === void 0) { nonce = 0; }
        this.prevHash = prevHash;
        this.transactions = transactions;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.hash = this.calculateHash();
    }
    Block.prototype.calculateHash = function () {
        return crypto.createHash('sha256').update(this.prevHash + JSON.stringify(this.transactions) + this.timestamp + this.nonce).digest('hex');
    };
    return Block;
}());
var Blockchain = /** @class */ (function () {
    function Blockchain() {
        this.chain = [this.createGenesisBlock()];
        this.pendingTransactions = [];
        this.accounts = {};
    }
    Blockchain.prototype.createGenesisBlock = function () {
        return new Block('0', [], Date.now());
    };
    Blockchain.prototype.getLatestBlock = function () {
        return this.chain[this.chain.length - 1];
    };
    Blockchain.prototype.createAccount = function (address, balance) {
        this.accounts[address] = balance;
    };
    Blockchain.prototype.addTransaction = function (transaction) {
        if (!transaction.from || !transaction.to) {
            throw new Error('Transaction must include from and to address.');
        }
        if (this.accounts[transaction.from] < transaction.value + transaction.fee) {
            throw new Error("Not enough balance in ".concat(transaction.from, "."));
        }
        this.pendingTransactions.push(transaction);
    };
    Blockchain.prototype.minePendingTransactions = function () {
        var block = new Block(this.getLatestBlock().hash, this.pendingTransactions, Date.now());
        this.chain.push(block);
        for (var _i = 0, _a = this.pendingTransactions; _i < _a.length; _i++) {
            var tx = _a[_i];
            this.accounts[tx.from] -= (tx.value + tx.fee);
            this.accounts[tx.to] = (this.accounts[tx.to] || 0) + tx.value;
        }
        this.pendingTransactions = [];
    };
    Blockchain.prototype.getBalanceOfAccount = function (address) {
        return this.accounts[address] || 0;
    };
    return Blockchain;
}());
// Instanciar blockchain
var myBlockchain = new Blockchain();
// Crear 100 cuentas con saldo inicial aleatorio
for (var i = 1; i <= 100; i++) {
    var address = "0x".concat(i.toString().padStart(3, '0'));
    var balance = Math.floor(Math.random() * 1000) + 1000;
    myBlockchain.createAccount(address, balance);
    console.log("Cuenta ".concat(address, " creada con saldo: ").concat(balance));
}
function randomTransaction() {
    var keys = Object.keys(myBlockchain.accounts);
    var from = keys[Math.floor(Math.random() * keys.length)];
    var to;
    do {
        to = keys[Math.floor(Math.random() * keys.length)];
    } while (to === from);
    var maxAmount = myBlockchain.accounts[from] - 1;
    var value = Math.floor(Math.random() * maxAmount);
    var fee = 1;
    var timestamp = Date.now();
    var nonce = Math.floor(Math.random() * 100000);
    return new Transaction(from, to, value, fee, timestamp, nonce);
}
// Generar 100 bloques con 1-30 transacciones aleatorias cada uno
for (var b = 1; b <= 100; b++) {
    var txCount = Math.floor(Math.random() * 30) + 1;
    for (var i = 0; i < txCount; i++) {
        try {
            var tx = randomTransaction();
            myBlockchain.addTransaction(tx);
        }
        catch (err) {
            console.log("Transacci\u00F3n inv\u00E1lida: ".concat(err.message));
        }
    }
    myBlockchain.minePendingTransactions();
    console.log("Bloque ".concat(b, " minado. Hash: ").concat(myBlockchain.getLatestBlock().hash));
}
// Ejemplo de consultas
console.log('\nCONSULTAS:');
var sampleAccount = '0x001';
console.log("Balance de ".concat(sampleAccount, ":"), myBlockchain.getBalanceOfAccount(sampleAccount));
console.log('Transacciones en bloque 1:', ((_a = myBlockchain.chain[1]) === null || _a === void 0 ? void 0 : _a.transactions) || []);
function findTransactionByHash(hash) {
    for (var _i = 0, _a = myBlockchain.chain; _i < _a.length; _i++) {
        var block = _a[_i];
        for (var _b = 0, _c = block.transactions; _b < _c.length; _b++) {
            var tx = _c[_b];
            if (tx.calculateHash() === hash) {
                return tx;
            }
        }
    }
    return null;
}
function findBlockByHash(hash) {
    return myBlockchain.chain.find(function (block) { return block.hash === hash; });
}
// Buscar una transacción por su hash (ejemplo)
var exampleTx = (_b = myBlockchain.chain[1]) === null || _b === void 0 ? void 0 : _b.transactions[0];
if (exampleTx) {
    var txHash = exampleTx.calculateHash();
    var foundTx = findTransactionByHash(txHash);
    console.log('Transacción encontrada por hash:', foundTx);
}
// Buscar bloque por hash (ejemplo)
var exampleBlockHash = (_c = myBlockchain.chain[1]) === null || _c === void 0 ? void 0 : _c.hash;
if (exampleBlockHash) {
    var foundBlock = findBlockByHash(exampleBlockHash);
    console.log('Bloque encontrado por hash:', foundBlock);
}

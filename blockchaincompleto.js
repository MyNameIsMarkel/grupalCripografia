"use strict";
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
        this.minerSignature = '';
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
    function Blockchain(aesKey) {
        this.chain = [this.createGenesisBlock()];
        this.pendingTransactions = [];
        this.accounts = {};
        // Claves del nodo minero
        var _a = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
        }), publicKey = _a.publicKey, privateKey = _a.privateKey;
        this.nodePrivateKey = privateKey;
        this.nodePublicKey = publicKey;
        this.aesKey = aesKey;
    }
    Blockchain.prototype.createGenesisBlock = function () {
        return new Block('0', [], Date.now());
    };
    Blockchain.prototype.getLatestBlock = function () {
        return this.chain[this.chain.length - 1];
    };
    Blockchain.prototype.createAccount = function (address, balance) {
        var _a = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
        }), publicKey = _a.publicKey, privateKey = _a.privateKey;
        this.accounts[address] = {
            balance: balance,
            privateKey: privateKey,
            publicKey: publicKey
        };
    };
    Blockchain.prototype.addTransaction = function (transaction) {
        if (!transaction.from || !transaction.to) {
            throw new Error('Transaction must include from and to address.');
        }
        var senderAccount = this.accounts[transaction.from];
        if (!senderAccount) {
            throw new Error("Sender account ".concat(transaction.from, " not found."));
        }
        if (senderAccount.balance < transaction.value + transaction.fee) {
            throw new Error("Not enough balance in ".concat(transaction.from, "."));
        }
        var verify = crypto.createVerify('SHA256');
        verify.update(transaction.from + transaction.to + transaction.value + transaction.fee + transaction.timestamp + transaction.nonce);
        verify.end();
        var isValidSignature = verify.verify(senderAccount.publicKey, transaction.signature, 'hex');
        if (!isValidSignature) {
            throw new Error("Firma inv\u00E1lida en transacci\u00F3n de ".concat(transaction.from));
        }
        this.pendingTransactions.push(transaction);
    };
    Blockchain.prototype.minePendingTransactions = function () {
        var block = new Block(this.getLatestBlock().hash, this.pendingTransactions, Date.now());
        var sign = crypto.createSign('SHA256');
        sign.update(block.hash);
        sign.end();
        var signature = sign.sign(this.nodePrivateKey, 'hex');
        block.minerSignature = signature;
        this.chain.push(block);
        for (var _i = 0, _a = this.pendingTransactions; _i < _a.length; _i++) {
            var tx = _a[_i];
            this.accounts[tx.from].balance -= (tx.value + tx.fee);
            if (!this.accounts[tx.to]) {
                throw new Error("Destination account ".concat(tx.to, " does not exist."));
            }
            this.accounts[tx.to].balance += tx.value;
        }
        this.pendingTransactions = [];
        return block;
    };
    Blockchain.prototype.verifyBlockSignature = function (block) {
        var verify = crypto.createVerify('SHA256');
        verify.update(block.hash);
        verify.end();
        return verify.verify(this.nodePublicKey, block.minerSignature, 'hex');
    };
    Blockchain.prototype.encryptBlock = function (block) {
        var iv = crypto.randomBytes(16);
        var cipher = crypto.createCipheriv('aes-256-cbc', this.aesKey, iv);
        var encrypted = cipher.update(JSON.stringify(block), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return iv.toString('hex') + ':' + encrypted;
    };
    Blockchain.prototype.decryptBlock = function (encryptedData) {
        var _a = encryptedData.split(':'), ivHex = _a[0], encrypted = _a[1];
        var iv = Buffer.from(ivHex, 'hex');
        var decipher = crypto.createDecipheriv('aes-256-cbc', this.aesKey, iv);
        var decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
    };
    Blockchain.prototype.receiveEncryptedBlock = function (encryptedData) {
        var block = this.decryptBlock(encryptedData);
        var isSignatureValid = this.verifyBlockSignature(block);
        if (!isSignatureValid) {
            console.log('Firma inválida al recibir bloque. Bloque rechazado.');
            return;
        }
        this.chain.push(block);
        console.log("Bloque recibido y agregado. Hash: ".concat(block.hash));
    };
    Blockchain.prototype.getBalanceOfAccount = function (address) {
        var _a, _b;
        return (_b = (_a = this.accounts[address]) === null || _a === void 0 ? void 0 : _a.balance) !== null && _b !== void 0 ? _b : 0;
    };
    return Blockchain;
}());
// Clave compartida AES de 32 bytes
var aesKey = crypto.randomBytes(32);
var nodoA = new Blockchain(aesKey);
var nodoB = new Blockchain(aesKey);
// Crear cuentas idénticas en ambos nodos
for (var i = 1; i <= 100; i++) {
    var address = "0x".concat(i.toString().padStart(3, '0'));
    var balance = Math.floor(Math.random() * 1000) + 1000;
    nodoA.createAccount(address, balance);
    nodoB.createAccount(address, balance);
}
function randomTransaction(blockchain) {
    var keys = Object.keys(blockchain.accounts);
    var from = keys[Math.floor(Math.random() * keys.length)];
    var to;
    do {
        to = keys[Math.floor(Math.random() * keys.length)];
    } while (to === from);
    var senderAccount = blockchain.accounts[from];
    var maxAmount = senderAccount.balance - 1;
    var value = Math.floor(Math.random() * maxAmount);
    var fee = 1;
    var timestamp = Date.now();
    var nonce = Math.floor(Math.random() * 100000);
    var tx = new Transaction(from, to, value, fee, timestamp, nonce);
    var sign = crypto.createSign('SHA256');
    sign.update(tx.from + tx.to + tx.value + tx.fee + tx.timestamp + tx.nonce);
    sign.end();
    var signature = sign.sign(senderAccount.privateKey, 'hex');
    tx.signature = signature;
    return tx;
}
// Simular 10 bloques en nodo A, enviar cifrados a nodo B
for (var b = 1; b <= 10; b++) {
    var txCount = Math.floor(Math.random() * 30) + 1;
    for (var i = 0; i < txCount; i++) {
        try {
            var tx = randomTransaction(nodoA);
            nodoA.addTransaction(tx);
        }
        catch (err) {
            console.log("Transacci\u00F3n inv\u00E1lida: ".concat(err.message));
        }
    }
    var minedBlock = nodoA.minePendingTransactions();
    var encryptedBlock = nodoA.encryptBlock(minedBlock);
    console.log("Nodo A min\u00F3 bloque ".concat(b, ", enviando cifrado a Nodo B..."));
    nodoB.receiveEncryptedBlock(encryptedBlock);
}
// CONSULTA en nodo B
var sampleAccount = '0x001';
console.log("\nBalance en Nodo B de ".concat(sampleAccount, ":"), nodoB.getBalanceOfAccount(sampleAccount));

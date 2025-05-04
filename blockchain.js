const crypto = require('crypto');

class Transaction {
    constructor(from, to, value, fee, timestamp, nonce, signature = '') {
        this.from = from;
        this.to = to;
        this.value = value;
        this.fee = fee;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.signature = signature;
    }

    calculateHash() {
        return crypto.createHash('sha256').update(
            this.from + this.to + this.value + this.fee + this.timestamp + this.nonce
        ).digest('hex');
    }
}

class Block {
    constructor(prevHash = '', transactions = [], timestamp = Date.now(), nonce = 0) {
        this.prevHash = prevHash;
        this.transactions = transactions;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.hash = this.calculateHash();
    }

    calculateHash() {
        return crypto.createHash('sha256').update(
            this.prevHash + JSON.stringify(this.transactions) + this.timestamp + this.nonce
        ).digest('hex');
    }
}

class Blockchain {
    constructor() {
        this.chain = [this.createGenesisBlock()];
        this.pendingTransactions = [];
        this.accounts = {};
    }

    createGenesisBlock() {
        return new Block('0', [], Date.now());
    }

    getLatestBlock() {
        return this.chain[this.chain.length - 1];
    }

    createAccount(address, balance) {
        this.accounts[address] = balance;
    }

    addTransaction(transaction) {
        if (!transaction.from || !transaction.to) {
            throw new Error('Transaction must include from and to address.');
        }
        if (this.accounts[transaction.from] < transaction.value + transaction.fee) {
            throw new Error(`Not enough balance in ${transaction.from}.`);
        }
        this.pendingTransactions.push(transaction);
    }

    minePendingTransactions() {
        const block = new Block(this.getLatestBlock().hash, this.pendingTransactions, Date.now());
        this.chain.push(block);

        for (const tx of this.pendingTransactions) {
            this.accounts[tx.from] -= (tx.value + tx.fee);
            this.accounts[tx.to] = (this.accounts[tx.to] || 0) + tx.value;
        }

        this.pendingTransactions = [];
    }

    getBalanceOfAccount(address) {
        return this.accounts[address] || 0;
    }
}

// Instanciar blockchain
const myBlockchain = new Blockchain();

// Crear 100 cuentas con saldo inicial aleatorio
for (let i = 1; i <= 100; i++) {
    const address = `0x${i.toString().padStart(3, '0')}`;
    const balance = Math.floor(Math.random() * 1000) + 1000;
    myBlockchain.createAccount(address, balance);
    console.log(`Cuenta ${address} creada con saldo: ${balance}`);
}

function randomTransaction() {
    const keys = Object.keys(myBlockchain.accounts);
    const from = keys[Math.floor(Math.random() * keys.length)];
    let to;
    do {
        to = keys[Math.floor(Math.random() * keys.length)];
    } while (to === from);

    const maxAmount = myBlockchain.accounts[from] - 1;
    const value = Math.floor(Math.random() * maxAmount);
    const fee = 1;
    const timestamp = Date.now();
    const nonce = Math.floor(Math.random() * 100000);

    return new Transaction(from, to, value, fee, timestamp, nonce);
}

// Generar 100 bloques con 1-30 transacciones aleatorias cada uno
for (let b = 1; b <= 100; b++) {
    const txCount = Math.floor(Math.random() * 30) + 1;
    for (let i = 0; i < txCount; i++) {
        try {
            const tx = randomTransaction();
            myBlockchain.addTransaction(tx);
        } catch (err) {
            console.log(`Transacción inválida: ${err.message}`);
        }
    }
    myBlockchain.minePendingTransactions();
    console.log(`Bloque ${b} minado. Hash: ${myBlockchain.getLatestBlock().hash}`);
}

// Ejemplo de consultas
console.log('\nCONSULTAS:');
const sampleAccount = '0x001';
console.log(`Balance de ${sampleAccount}:`, myBlockchain.getBalanceOfAccount(sampleAccount));

console.log('Transacciones en bloque 1:', myBlockchain.chain[1]?.transactions || []);

function findTransactionByHash(hash) {
    for (const block of myBlockchain.chain) {
        for (const tx of block.transactions) {
            if (tx.calculateHash() === hash) {
                return tx;
            }
        }
    }
    return null;
}

function findBlockByHash(hash) {
    return myBlockchain.chain.find(block => block.hash === hash);
}

// Buscar una transacción por su hash (ejemplo)
const exampleTx = myBlockchain.chain[1]?.transactions[0];
if (exampleTx) {
    const txHash = exampleTx.calculateHash();
    const foundTx = findTransactionByHash(txHash);
    console.log('Transacción encontrada por hash:', foundTx);
}

// Buscar bloque por hash (ejemplo)
const exampleBlockHash = myBlockchain.chain[1]?.hash;
if (exampleBlockHash) {
    const foundBlock = findBlockByHash(exampleBlockHash);
    console.log('Bloque encontrado por hash:', foundBlock);
}

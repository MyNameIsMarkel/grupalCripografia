import * as crypto from 'crypto';

interface Account {
    balance: number;
    privateKey: string;
    publicKey: string;
}

class Transaction {
    from: string;
    to: string;
    value: number;
    fee: number;
    timestamp: number;
    nonce: number;
    signature: string;

    constructor(from: string, to: string, value: number, fee: number, timestamp: number, nonce: number, signature: string = '') {
        this.from = from;
        this.to = to;
        this.value = value;
        this.fee = fee;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.signature = signature;
    }

    calculateHash(): string {
        return crypto.createHash('sha256').update(
            this.from + this.to + this.value + this.fee + this.timestamp + this.nonce
        ).digest('hex');
    }
}

class Block {
    prevHash: string;
    transactions: Transaction[];
    timestamp: number;
    nonce: number;
    hash: string;

    constructor(prevHash: string = '', transactions: Transaction[] = [], timestamp: number = Date.now(), nonce: number = 0) {
        this.prevHash = prevHash;
        this.transactions = transactions;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.hash = this.calculateHash();
    }

    calculateHash(): string {
        return crypto.createHash('sha256').update(
            this.prevHash + JSON.stringify(this.transactions) + this.timestamp + this.nonce
        ).digest('hex');
    }
}

class Blockchain {
    chain: Block[];
    pendingTransactions: Transaction[];
    accounts: { [key: string]: Account };

    constructor() {
        this.chain = [this.createGenesisBlock()];
        this.pendingTransactions = [];
        this.accounts = {};
    }

    createGenesisBlock(): Block {
        return new Block('0', [], Date.now());
    }

    getLatestBlock(): Block {
        return this.chain[this.chain.length - 1];
    }

    createAccount(address: string, balance: number): void {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
        });

        this.accounts[address] = {
            balance,
            privateKey,
            publicKey
        };
    }

    addTransaction(transaction: Transaction): void {
        if (!transaction.from || !transaction.to) {
            throw new Error('Transaction must include from and to address.');
        }

        const senderAccount = this.accounts[transaction.from];
        if (!senderAccount) {
            throw new Error(`Sender account ${transaction.from} not found.`);
        }

        if (senderAccount.balance < transaction.value + transaction.fee) {
            throw new Error(`Not enough balance in ${transaction.from}.`);
        }

        // Verificar la firma
        const verify = crypto.createVerify('SHA256');
        verify.update(transaction.from + transaction.to + transaction.value + transaction.fee + transaction.timestamp + transaction.nonce);
        verify.end();

        const isValidSignature = verify.verify(senderAccount.publicKey, transaction.signature, 'hex');

        if (!isValidSignature) {
            throw new Error(`Firma inválida en transacción de ${transaction.from}`);
        }

        this.pendingTransactions.push(transaction);
    }

    minePendingTransactions(): void {
        const block = new Block(this.getLatestBlock().hash, this.pendingTransactions, Date.now());
        this.chain.push(block);

        for (const tx of this.pendingTransactions) {
            this.accounts[tx.from].balance -= (tx.value + tx.fee);
            if (!this.accounts[tx.to]) {
                throw new Error(`Destination account ${tx.to} does not exist.`);
            }
            this.accounts[tx.to].balance += tx.value;
        }

        this.pendingTransactions = [];
    }

    getBalanceOfAccount(address: string): number {
        return this.accounts[address]?.balance ?? 0;
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

function randomTransaction(): Transaction {
    const keys = Object.keys(myBlockchain.accounts);
    const from = keys[Math.floor(Math.random() * keys.length)];
    let to: string;
    do {
        to = keys[Math.floor(Math.random() * keys.length)];
    } while (to === from);

    const senderAccount = myBlockchain.accounts[from];
    const maxAmount = senderAccount.balance - 1;
    const value = Math.floor(Math.random() * maxAmount);
    const fee = 1;
    const timestamp = Date.now();
    const nonce = Math.floor(Math.random() * 100000);

    const tx = new Transaction(from, to, value, fee, timestamp, nonce);

    // Firmar la transacción
    const sign = crypto.createSign('SHA256');
    sign.update(tx.from + tx.to + tx.value + tx.fee + tx.timestamp + tx.nonce);
    sign.end();
    const signature = sign.sign(senderAccount.privateKey, 'hex');
    tx.signature = signature;

    return tx;
}

// Generar 100 bloques con 1-30 transacciones aleatorias cada uno
for (let b = 1; b <= 100; b++) {
    const txCount = Math.floor(Math.random() * 30) + 1;
    for (let i = 0; i < txCount; i++) {
        try {
            const tx = randomTransaction();
            myBlockchain.addTransaction(tx);
        } catch (err) {
            console.log(`Transacción inválida: ${(err as Error).message}`);
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

function findTransactionByHash(hash: string): Transaction | null {
    for (const block of myBlockchain.chain) {
        for (const tx of block.transactions) {
            if (tx.calculateHash() === hash) {
                return tx;
            }
        }
    }
    return null;
}

function findBlockByHash(hash: string): Block | undefined {
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

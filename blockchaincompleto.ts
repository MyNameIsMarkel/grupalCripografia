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
    minerSignature: string = '';

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
    nodePrivateKey: string;
    nodePublicKey: string;
    aesKey: Buffer;
    usedNonces: Set<number>;

    constructor(aesKey: Buffer) {
        this.chain = [this.createGenesisBlock()];
        this.pendingTransactions = [];
        this.accounts = {};
        this.usedNonces = new Set();

        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
        });
        this.nodePrivateKey = privateKey;
        this.nodePublicKey = publicKey;
        this.aesKey = aesKey;
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
        this.accounts[address] = { balance, privateKey, publicKey };
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

        if (this.usedNonces.has(transaction.nonce)) {
            throw new Error(`Nonce ${transaction.nonce} has already been used.`);
        }

        const verify = crypto.createVerify('SHA256');
        verify.update(transaction.from + transaction.to + transaction.value + transaction.fee + transaction.timestamp + transaction.nonce);
        verify.end();
        const isValidSignature = verify.verify(senderAccount.publicKey, transaction.signature, 'hex');

        if (!isValidSignature) {
            throw new Error(`Invalid signature in transaction from ${transaction.from}.`);
        }

        this.pendingTransactions.push(transaction);
        this.usedNonces.add(transaction.nonce);
    }

    minePendingTransactions(): Block {
        const blockTimestamp = Date.now();
        for (const tx of this.pendingTransactions) {
            if (tx.timestamp > blockTimestamp) {
                throw new Error(`Transaction timestamp ${tx.timestamp} is after block timestamp ${blockTimestamp}.`);
            }
        }

        const block = new Block(this.getLatestBlock().hash, this.pendingTransactions, blockTimestamp);

        const sign = crypto.createSign('SHA256');
        sign.update(block.hash);
        sign.end();
        const signature = sign.sign(this.nodePrivateKey, 'hex');
        block.minerSignature = signature;

        this.chain.push(block);

        for (const tx of this.pendingTransactions) {
            this.accounts[tx.from].balance -= (tx.value + tx.fee);
            if (!this.accounts[tx.to]) {
                throw new Error(`Destination account ${tx.to} does not exist.`);
            }
            this.accounts[tx.to].balance += tx.value;
        }

        this.pendingTransactions = [];
        return block;
    }

    verifyBlockSignature(block: Block): boolean {
        const verify = crypto.createVerify('SHA256');
        verify.update(block.hash);
        verify.end();
        return verify.verify(this.nodePublicKey, block.minerSignature, 'hex');
    }

    encryptBlock(block: Block): string {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', this.aesKey, iv);
        let encrypted = cipher.update(JSON.stringify(block), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return iv.toString('hex') + ':' + encrypted;
    }

    decryptBlock(encryptedData: string): Block {
        const [ivHex, encrypted] = encryptedData.split(':');
        const iv = Buffer.from(ivHex, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', this.aesKey, iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
    }

    receiveEncryptedBlock(encryptedData: string): void {
        const block = this.decryptBlock(encryptedData);
        const isSignatureValid = this.verifyBlockSignature(block);
        if (!isSignatureValid) {
            console.log('Invalid block signature. Block rejected.');
            return;
        }
        this.chain.push(block);
        console.log(`Block received and added. Hash: ${block.hash}`);
    }

    getBalanceOfAccount(address: string): number {
        return this.accounts[address]?.balance ?? 0;
    }

    getBalanceAtBlock(address: string, blockIndex: number): number {
        if (blockIndex >= this.chain.length) {
            throw new Error(`Block index ${blockIndex} out of range.`);
        }
        let balance = this.accounts[address]?.balance ?? 0;
        for (let i = this.chain.length - 1; i > blockIndex; i--) {
            const block = this.chain[i];
            for (const tx of block.transactions) {
                if (tx.from === address) balance += tx.value + tx.fee;
                if (tx.to === address) balance -= tx.value;
            }
        }
        return balance;
    }

    findBlockByHash(hash: string): number | null {
        for (let i = 0; i < this.chain.length; i++) {
            if (this.chain[i].hash === hash) {
                return i;
            }
        }
        return null;
    }
}

// Programa principal
const aesKey = crypto.randomBytes(32);

const nodoA = new Blockchain(aesKey);
const nodoB = new Blockchain(aesKey);

nodoB.nodePublicKey = nodoA.nodePublicKey;

for (let i = 1; i <= 100; i++) {
    const address = `0x${i.toString().padStart(3, '0')}`;
    const balance = Math.floor(Math.random() * 1000) + 1000;
    nodoA.createAccount(address, balance);
    nodoB.createAccount(address, balance);
}

function randomTransaction(blockchain: Blockchain): Transaction {
    const keys = Object.keys(blockchain.accounts);
    const from = keys[Math.floor(Math.random() * keys.length)];
    let to: string;
    do {
        to = keys[Math.floor(Math.random() * keys.length)];
    } while (to === from);

    const senderAccount = blockchain.accounts[from];
    const maxAmount = senderAccount.balance - 1;
    const value = Math.floor(Math.random() * maxAmount);
    const fee = 1;
    const timestamp = Date.now();
    const nonce = Math.floor(Math.random() * 100000);

    const tx = new Transaction(from, to, value, fee, timestamp, nonce);

    const sign = crypto.createSign('SHA256');
    sign.update(tx.from + tx.to + tx.value + tx.fee + tx.timestamp + tx.nonce);
    sign.end();
    const signature = sign.sign(senderAccount.privateKey, 'hex');
    tx.signature = signature;

    return tx;
}

for (let b = 1; b <= 100; b++) {
    const txCount = Math.floor(Math.random() * 30) + 1;
    for (let i = 0; i < txCount; i++) {
        try {
            const tx = randomTransaction(nodoA);
            nodoA.addTransaction(tx);
        } catch (err) {
            console.log(`Invalid transaction: ${(err as Error).message}`);
        }
    }

    try {
        const minedBlock = nodoA.minePendingTransactions();
        const encryptedBlock = nodoA.encryptBlock(minedBlock);
        console.log(`Node A mined block ${b}, sending encrypted block to Node B...`);
        nodoB.receiveEncryptedBlock(encryptedBlock);
    } catch (err) {
        console.log(`Error mining block ${b}: ${(err as Error).message}`);
    }
}

console.log("\nFinal balances in Node B:");
for (const address in nodoB.accounts) {
    console.log(`${address}: ${nodoB.getBalanceOfAccount(address)}`);
}

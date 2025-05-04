// Importamos los módulos necesarios para criptografía y manejo de archivos
import * as crypto from 'crypto';
import * as fs from 'fs';

// Interfaz que define la estructura de una cuenta
interface Account {
    balance: number;
    privateKey: string;
    publicKey: string;
}

// Clase que representa una transacción entre cuentas
class Transaction {
    from: string;
    to: string;
    value: number;
    fee: number;
    timestamp: number;
    nonce: number;
    signature: string;

    constructor(from: string, to: string, value: number, fee: number, timestamp: number, nonce: number, signature = '') {
        this.from = from;
        this.to = to;
        this.value = value;
        this.fee = fee;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.signature = signature;
    }

    // Calcula el hash de la transacción para verificar su integridad
    calculateHash(): string {
        return crypto.createHash('sha256').update(
            this.from + this.to + this.value + this.fee + this.timestamp + this.nonce
        ).digest('hex');
    }
}

// Clase que representa un bloque en la blockchain
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

    // Calcula el hash del bloque (incluyendo las transacciones)
    calculateHash(): string {
        return crypto.createHash('sha256').update(
            this.prevHash + JSON.stringify(this.transactions) + this.timestamp + this.nonce
        ).digest('hex');
    }
}

// Clase que representa toda la cadena de bloques
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

        // Genera claves asimétricas RSA para firmar bloques
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
        });
        this.nodePrivateKey = privateKey;
        this.nodePublicKey = publicKey;
        this.aesKey = aesKey; // Clave AES para cifrado de bloques
    }

    // Crea el bloque inicial de la cadena
    createGenesisBlock(): Block {
        return new Block('0', [], Date.now());
    }

    getLatestBlock(): Block {
        return this.chain[this.chain.length - 1];
    }

    // Crea una cuenta con claves y saldo inicial
    createAccount(address: string, balance: number): void {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
        });
        this.accounts[address] = { balance, privateKey, publicKey };
    }

    // Añade una transacción a la lista de pendientes, validando firma y saldo
    addTransaction(transaction: Transaction): void {
        const sender = this.accounts[transaction.from];
        if (!sender) throw new Error(`Sender ${transaction.from} not found.`);
        if (sender.balance < transaction.value + transaction.fee)
            throw new Error(`Not enough balance in ${transaction.from}.`);
        if (this.usedNonces.has(transaction.nonce))
            throw new Error(`Nonce ${transaction.nonce} has already been used.`);

        const verify = crypto.createVerify('SHA256');
        verify.update(transaction.from + transaction.to + transaction.value + transaction.fee + transaction.timestamp + transaction.nonce);
        verify.end();

        if (!verify.verify(sender.publicKey, transaction.signature, 'hex')) {
            throw new Error(`Invalid signature from ${transaction.from}.`);
        }

        this.pendingTransactions.push(transaction);
        this.usedNonces.add(transaction.nonce);
    }

    // Mina las transacciones pendientes, creando un nuevo bloque
    minePendingTransactions(): Block {
        const block = new Block(this.getLatestBlock().hash, this.pendingTransactions, Date.now());

        const sign = crypto.createSign('SHA256');
        sign.update(block.hash);
        sign.end();
        block.minerSignature = sign.sign(this.nodePrivateKey, 'hex');

        this.chain.push(block);

        for (const tx of this.pendingTransactions) {
            this.accounts[tx.from].balance -= (tx.value + tx.fee);
            this.accounts[tx.to].balance = (this.accounts[tx.to]?.balance || 0) + tx.value;
        }

        this.pendingTransactions = [];
        return block;
    }

    // Cifra un bloque usando AES
    encryptBlock(block: Block): string {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', this.aesKey, iv);
        let encrypted = cipher.update(JSON.stringify(block), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return iv.toString('hex') + ':' + encrypted;
    }

    // Descifra un bloque cifrado
    decryptBlock(data: string): Block {
        const [ivHex, encrypted] = data.split(':');
        const iv = Buffer.from(ivHex, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', this.aesKey, iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
    }

    // Verifica la firma del bloque
    verifyBlockSignature(block: Block): boolean {
        const verify = crypto.createVerify('SHA256');
        verify.update(block.hash);
        verify.end();
        return verify.verify(this.nodePublicKey, block.minerSignature, 'hex');
    }

    // Recibe un bloque cifrado y lo agrega a la cadena si es válido
    receiveEncryptedBlock(data: string): void {
        const block = this.decryptBlock(data);
        if (!this.verifyBlockSignature(block)) {
            console.log('Invalid block signature.');
            return;
        }
        if (block.prevHash !== this.getLatestBlock().hash) {
            console.log('Invalid block linkage.');
            return;
        }
        this.chain.push(block);
        for (const tx of block.transactions) {
            if (!this.accounts[tx.to]) this.accounts[tx.to] = { balance: 0, privateKey: '', publicKey: '' };
            this.accounts[tx.to].balance += tx.value;
            this.accounts[tx.from].balance -= (tx.value + tx.fee);
        }
        console.log(`Block added. Hash: ${block.hash}`);
    }

    // Consulta el saldo de una cuenta en el estado actual
    getBalanceOfAccount(address: string): number {
        return this.accounts[address]?.balance ?? 0;
    }

    // Consulta el saldo de una cuenta en un bloque específico
    getBalanceAtBlock(address: string, blockIndex: number): number {
        let balance = 0;
        for (let i = 0; i <= blockIndex; i++) {
            const block = this.chain[i];
            for (const tx of block.transactions) {
                if (tx.to === address) balance += tx.value;
                if (tx.from === address) balance -= (tx.value + tx.fee);
            }
        }
        return balance;
    }

    // Obtiene las transacciones de un bloque específico
    getTransactionsInBlock(index: number): Transaction[] {
        return this.chain[index]?.transactions ?? [];
    }

    // Busca una transacción por su hash
    findTransactionByHash(hash: string): Transaction | null {
        for (const block of this.chain) {
            for (const tx of block.transactions) {
                if (tx.calculateHash() === hash) return tx;
            }
        }
        return null;
    }

    // Busca el índice de un bloque por su hash
    findBlockByHash(hash: string): number | null {
        return this.chain.findIndex(b => b.hash === hash);
    }

    // Guarda una snapshot cifrada de la blockchain en disco
    saveSnapshot(filePath: string): void {
        const data = JSON.stringify(this.chain);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', this.aesKey, iv);
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        fs.writeFileSync(filePath, iv.toString('hex') + ':' + encrypted, 'utf8');
    }

    // Carga una snapshot cifrada de disco
    loadSnapshot(filePath: string): void {
        const [ivHex, encrypted] = fs.readFileSync(filePath, 'utf8').split(':');
        const iv = Buffer.from(ivHex, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', this.aesKey, iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        this.chain = JSON.parse(decrypted);
    }
}

// Crea una clave simétrica con Diffie-Hellman para usar en cifrado de flujo
function createDiffieHellmanKey(): Buffer {
    const dh = crypto.createDiffieHellman(2048);
    const key = dh.generateKeys();
    const peer = crypto.createDiffieHellman(dh.getPrime(), dh.getGenerator());
    const peerKey = peer.generateKeys();
    return dh.computeSecret(peerKey);
}

// Crea una blockchain e inicializa 100 cuentas con saldo
function createBlockchainWithAccounts(): Blockchain {
    const aesKey = createDiffieHellmanKey();
    const chain = new Blockchain(aesKey);
    for (let i = 1; i <= 100; i++) {
        const addr = `0x${i.toString().padStart(3, '0')}`;
        const balance = Math.floor(Math.random() * 1000) + 1000;
        chain.createAccount(addr, balance);
    }
    return chain;
}

// Creamos 4 nodos simulando una red distribuida
const nodes = [createBlockchainWithAccounts(), createBlockchainWithAccounts(), createBlockchainWithAccounts(), createBlockchainWithAccounts()];

// Sincronizamos las claves de firma de los nodos
for (const n of nodes) {
    n.nodePublicKey = nodes[0].nodePublicKey;
}

// Genera una transacción aleatoria válida entre cuentas
function randomTransaction(bc: Blockchain): Transaction {
    const keys = Object.keys(bc.accounts);
    const from = keys[Math.floor(Math.random() * keys.length)];
    let to = from;
    while (to === from) to = keys[Math.floor(Math.random() * keys.length)];

    const sender = bc.accounts[from];
    const maxAmount = sender.balance - 1;
    const value = Math.floor(Math.random() * maxAmount);
    const fee = 1;
    const timestamp = Date.now();
    const nonce = Math.floor(Math.random() * 100000);
    const tx = new Transaction(from, to, value, fee, timestamp, nonce);

    const sign = crypto.createSign('SHA256');
    sign.update(tx.from + tx.to + tx.value + tx.fee + tx.timestamp + tx.nonce);
    sign.end();
    tx.signature = sign.sign(sender.privateKey, 'hex');
    return tx;
}

// Simulamos la minería en la red con rotación de nodos cada 2 segundos
let blockCount = 0;
const interval = setInterval(() => {
    if (blockCount >= 100) {
        clearInterval(interval);
        console.log("\n=== Final Balances (Node 1) ===");
        for (const addr in nodes[0].accounts) {
            console.log(`${addr}: ${nodes[0].getBalanceOfAccount(addr)}`);
        }
        return;
    }

    const miner = nodes[Math.floor(Math.random() * 4)];
    const txs = Math.floor(Math.random() * 10) + 1;
    for (let i = 0; i < txs; i++) {
        try {
            miner.addTransaction(randomTransaction(miner));
        } catch (e) {
            console.log(`Invalid transaction: ${(e as Error).message}`);
        }
    }

    try {
        const block = miner.minePendingTransactions();
        const encrypted = miner.encryptBlock(block);
        for (const node of nodes) {
            if (node !== miner) node.receiveEncryptedBlock(encrypted);
        }
        console.log(`Node mined block ${++blockCount}`);
    } catch (e) {
        console.log(`Error mining: ${(e as Error).message}`);
    }
}, 2000);

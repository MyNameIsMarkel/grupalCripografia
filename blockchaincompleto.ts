import * as crypto from 'crypto';

// Definición de una cuenta: saldo, clave privada, clave pública
interface Account {
    balance: number;
    privateKey: string;
    publicKey: string;
}

// Clase que representa una transacción
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

    // Calcula el hash de la transacción
    calculateHash(): string {
        return crypto.createHash('sha256').update(
            this.from + this.to + this.value + this.fee + this.timestamp + this.nonce
        ).digest('hex');
    }
}

// Clase que representa un bloque de la blockchain
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

    // Calcula el hash del bloque
    calculateHash(): string {
        return crypto.createHash('sha256').update(
            this.prevHash + JSON.stringify(this.transactions) + this.timestamp + this.nonce
        ).digest('hex');
    }
}

// Clase principal que representa la blockchain
class Blockchain {
    chain: Block[];
    pendingTransactions: Transaction[];
    accounts: { [key: string]: Account };
    nodePrivateKey: string;
    nodePublicKey: string;
    aesKey: Buffer;

    constructor(aesKey: Buffer) {
        this.chain = [this.createGenesisBlock()];
        this.pendingTransactions = [];
        this.accounts = {};

        // Generar las claves del nodo minero
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
        });
        this.nodePrivateKey = privateKey;
        this.nodePublicKey = publicKey;
        this.aesKey = aesKey;
    }

    // Crea el bloque génesis (primer bloque de la cadena)
    createGenesisBlock(): Block {
        return new Block('0', [], Date.now());
    }

    // Obtiene el último bloque de la cadena
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

    // Añade una transacción pendiente (previa validación)
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

        // Verificar la firma de la transacción
        const verify = crypto.createVerify('SHA256');
        verify.update(transaction.from + transaction.to + transaction.value + transaction.fee + transaction.timestamp + transaction.nonce);
        verify.end();
        const isValidSignature = verify.verify(senderAccount.publicKey, transaction.signature, 'hex');

        if (!isValidSignature) {
            throw new Error(`Invalid signature in transaction from ${transaction.from}.`);
        }

        this.pendingTransactions.push(transaction);
    }

    // Mina las transacciones pendientes, crea y firma un bloque
    minePendingTransactions(): Block {
        const block = new Block(this.getLatestBlock().hash, this.pendingTransactions, Date.now());

        // Firma el bloque con la clave privada del nodo
        const sign = crypto.createSign('SHA256');
        sign.update(block.hash);
        sign.end();
        const signature = sign.sign(this.nodePrivateKey, 'hex');
        block.minerSignature = signature;

        this.chain.push(block);

        // Actualiza los balances de las cuentas
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

    // Verifica la firma del bloque recibido
    verifyBlockSignature(block: Block): boolean {
        const verify = crypto.createVerify('SHA256');
        verify.update(block.hash);
        verify.end();
        return verify.verify(this.nodePublicKey, block.minerSignature, 'hex');
    }

    // Cifra un bloque para enviarlo a otro nodo
    encryptBlock(block: Block): string {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', this.aesKey, iv);
        let encrypted = cipher.update(JSON.stringify(block), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return iv.toString('hex') + ':' + encrypted;
    }

    // Descifra un bloque recibido cifrado
    decryptBlock(encryptedData: string): Block {
        const [ivHex, encrypted] = encryptedData.split(':');
        const iv = Buffer.from(ivHex, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', this.aesKey, iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
    }

    // Recibe un bloque cifrado, lo descifra, verifica la firma y lo agrega si es válido
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

    // Obtiene el balance de una cuenta
    getBalanceOfAccount(address: string): number {
        return this.accounts[address]?.balance ?? 0;
    }
}

// Programa principal

// Genera una clave AES de 32 bytes compartida entre nodos
const aesKey = crypto.randomBytes(32);

// Crear nodoA (minero) y nodoB (receptor)
const nodoA = new Blockchain(aesKey);
const nodoB = new Blockchain(aesKey);

// Compartir la clave pública del minero (nodoA) con nodoB para verificar bloques
nodoB.nodePublicKey = nodoA.nodePublicKey;

// Crear 100 cuentas en ambos nodos
for (let i = 1; i <= 100; i++) {
    const address = `0x${i.toString().padStart(3, '0')}`;
    const balance = Math.floor(Math.random() * 1000) + 1000;
    nodoA.createAccount(address, balance);
    nodoB.createAccount(address, balance);
}

// Función para generar una transacción aleatoria
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

    // Firmar la transacción
    const sign = crypto.createSign('SHA256');
    sign.update(tx.from + tx.to + tx.value + tx.fee + tx.timestamp + tx.nonce);
    sign.end();
    const signature = sign.sign(senderAccount.privateKey, 'hex');
    tx.signature = signature;

    return tx;
}

// Simular 10 bloques: nodoA mina y envía cifrado a nodoB
for (let b = 1; b <= 10; b++) {
    const txCount = Math.floor(Math.random() * 30) + 1;
    for (let i = 0; i < txCount; i++) {
        try {
            const tx = randomTransaction(nodoA);
            nodoA.addTransaction(tx);
        } catch (err) {
            console.log(`Invalid transaction: ${(err as Error).message}`);
        }
    }

    const minedBlock = nodoA.minePendingTransactions();
    const encryptedBlock = nodoA.encryptBlock(minedBlock);

    console.log(`Node A mined block ${b}, sending encrypted block to Node B...`);
    nodoB.receiveEncryptedBlock(encryptedBlock);
}

// Consultar balance de una cuenta en nodoB
const sampleAccount = '0x001';
console.log(`Balance in Node B for ${sampleAccount}:`, nodoB.getBalanceOfAccount(sampleAccount));

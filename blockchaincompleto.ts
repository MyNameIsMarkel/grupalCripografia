// Importamos el módulo de criptografía de Node.js
import * as crypto from 'crypto';

// Interfaz para representar una cuenta de usuario
interface Account {
    balance: number;      // saldo de la cuenta
    privateKey: string;   // clave privada (para firmar transacciones)
    publicKey: string;    // clave pública (para verificar firmas)
}

// Clase para representar una transacción
class Transaction {
    from: string;       // dirección del emisor
    to: string;         // dirección del receptor
    value: number;      // cantidad transferida
    fee: number;        // tarifa de la transacción
    timestamp: number;  // momento en que se creó
    nonce: number;      // número único para evitar duplicados
    signature: string;  // firma digital del emisor

    constructor(from: string, to: string, value: number, fee: number, timestamp: number, nonce: number, signature: string = '') {
        this.from = from;
        this.to = to;
        this.value = value;
        this.fee = fee;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.signature = signature;
    }

    // Calcula el hash de la transacción (para identificación y verificación)
    calculateHash(): string {
        return crypto.createHash('sha256').update(
            this.from + this.to + this.value + this.fee + this.timestamp + this.nonce
        ).digest('hex');
    }
}

// Clase que representa un bloque de la blockchain
class Block {
    prevHash: string;           // hash del bloque anterior
    transactions: Transaction[]; // lista de transacciones en este bloque
    timestamp: number;          // momento en que se minó el bloque
    nonce: number;              // número usado en prueba de trabajo (aquí no implementado)
    hash: string;               // hash del bloque actual
    minerSignature: string = ''; // firma digital del bloque por el nodo minero

    constructor(prevHash: string = '', transactions: Transaction[] = [], timestamp: number = Date.now(), nonce: number = 0) {
        this.prevHash = prevHash;
        this.transactions = transactions;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.hash = this.calculateHash(); // calcular hash al crear bloque
    }

    // Calcula el hash del bloque (incluye transacciones y prevHash)
    calculateHash(): string {
        return crypto.createHash('sha256').update(
            this.prevHash + JSON.stringify(this.transactions) + this.timestamp + this.nonce
        ).digest('hex');
    }
}

// Clase principal que representa la blockchain
class Blockchain {
    chain: Block[];                      // lista de bloques
    pendingTransactions: Transaction[];  // transacciones pendientes por minar
    accounts: { [key: string]: Account }; // mapa de cuentas
    nodePrivateKey: string;              // clave privada del nodo minero
    nodePublicKey: string;               // clave pública del nodo minero
    aesKey: Buffer;                      // clave AES para cifrado entre nodos

    constructor(aesKey: Buffer) {
        this.chain = [this.createGenesisBlock()]; // inicializa cadena con bloque génesis
        this.pendingTransactions = [];
        this.accounts = {};

        // genera las claves del nodo minero
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
        });
        this.nodePrivateKey = privateKey;
        this.nodePublicKey = publicKey;
        this.aesKey = aesKey; // clave compartida de cifrado
    }

    // Crea el bloque inicial (bloque génesis)
    createGenesisBlock(): Block {
        return new Block('0', [], Date.now());
    }

    // Devuelve el último bloque de la cadena
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

    // Añade una transacción pendiente (con verificación de firma y saldo)
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
            throw new Error(`Firma inválida en transacción de ${transaction.from}`);
        }

        this.pendingTransactions.push(transaction);
    }

    // Mina las transacciones pendientes y crea un bloque firmado
    minePendingTransactions(): Block {
        const block = new Block(this.getLatestBlock().hash, this.pendingTransactions, Date.now());

        // Firma digital del bloque por el nodo minero
        const sign = crypto.createSign('SHA256');
        sign.update(block.hash);
        sign.end();
        const signature = sign.sign(this.nodePrivateKey, 'hex');
        block.minerSignature = signature;

        this.chain.push(block);

        // Actualizar balances después de minar
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

    // Cifra un bloque usando AES para enviarlo a otro nodo
    encryptBlock(block: Block): string {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', this.aesKey, iv);
        let encrypted = cipher.update(JSON.stringify(block), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return iv.toString('hex') + ':' + encrypted; // iv y datos cifrados concatenados
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

    // Recibe un bloque cifrado, lo descifra y lo agrega si es válido
    receiveEncryptedBlock(encryptedData: string): void {
        const block = this.decryptBlock(encryptedData);
        const isSignatureValid = this.verifyBlockSignature(block);
        if (!isSignatureValid) {
            console.log('Firma inválida al recibir bloque. Bloque rechazado.');
            return;
        }
        this.chain.push(block);
        console.log(`Bloque recibido y agregado. Hash: ${block.hash}`);
    }

    // Devuelve el saldo actual de una cuenta
    getBalanceOfAccount(address: string): number {
        return this.accounts[address]?.balance ?? 0;
    }
}

// ----- INICIO DEL PROGRAMA -----

// Clave compartida de 32 bytes para cifrado AES
const aesKey = crypto.randomBytes(32);

// Creamos dos nodos con la misma clave AES
const nodoA = new Blockchain(aesKey);
const nodoB = new Blockchain(aesKey);

// Crear las mismas 100 cuentas en ambos nodos
for (let i = 1; i <= 100; i++) {
    const address = `0x${i.toString().padStart(3, '0')}`;
    const balance = Math.floor(Math.random() * 1000) + 1000;
    nodoA.createAccount(address, balance);
    nodoB.createAccount(address, balance);
}

// Generar una transacción aleatoria
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

// Simular 10 bloques: nodo A mina y envía cifrado a nodo B
for (let b = 1; b <= 10; b++) {
    const txCount = Math.floor(Math.random() * 30) + 1;
    for (let i = 0; i < txCount; i++) {
        try {
            const tx = randomTransaction(nodoA);
            nodoA.addTransaction(tx);
        } catch (err) {
            console.log(`Transacción inválida: ${(err as Error).message}`);
        }
    }

    const minedBlock = nodoA.minePendingTransactions();
    const encryptedBlock = nodoA.encryptBlock(minedBlock);

    console.log(`Nodo A minó bloque ${b}, enviando cifrado a Nodo B...`);
    nodoB.receiveEncryptedBlock(encryptedBlock);
}

// Mostrar balance de una cuenta en nodo B
const sampleAccount = '0x001';
console.log(`\nBalance en Nodo B de ${sampleAccount}:`, nodoB.getBalanceOfAccount(sampleAccount));

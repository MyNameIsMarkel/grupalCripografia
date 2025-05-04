Proyecto Blockchain - Explicación del código y funcionamiento

Este proyecto implementa una simulación de una red blockchain con las siguientes características, cumpliendo los requisitos establecidos en el documento del trabajo grupal:

1. Estructura de la Blockchain

La blockchain está compuesta por bloques enlazados mediante hashes SHA-256.

Cada bloque almacena una lista de transacciones y el hash del bloque anterior.

Cada bloque es firmado digitalmente por el nodo minero usando criptografía asimétrica (RSA).

2. Transacciones

Cada transacción incluye los campos: from, to, value, fee, timestamp, nonce y signature.

Las transacciones son firmadas digitalmente con la clave privada de la cuenta emisora.

Antes de ser añadida, la transacción es validada verificando:

Que la firma digital sea válida.

Que el saldo de la cuenta emisora sea suficiente para cubrir el monto y la comisión.

3. Cuentas

Se crean 100 cuentas, cada una con una clave pública, clave privada y saldo inicial aleatorio.

Cada cuenta gestiona su propia clave privada para firmar transacciones.

4. Nodos

Se simulan dos nodos: nodoA (minero) y nodoB (receptor).

Cada nodo tiene su propia copia de la blockchain y las cuentas iniciales.

La clave pública del nodo minero (nodoA) se comparte con nodoB para que pueda verificar la firma digital de los bloques recibidos.

5. Firma de bloques

Cada bloque es firmado por nodoA al minarlo usando su clave privada.

NodoB verifica la firma digital de cada bloque recibido usando la clave pública de nodoA.

6. Cifrado en flujo (comunicación cifrada entre nodos)

Los bloques se envían cifrados desde nodoA a nodoB utilizando el algoritmo AES-256-CBC.

Cada bloque se cifra con una clave AES compartida entre los nodos antes de transmitirse.

Al recibir un bloque, nodoB lo descifra con la misma clave AES antes de verificar su firma.

7. Procesamiento

NodoA genera entre 1 y 30 transacciones aleatorias por bloque, las valida y las mina en un nuevo bloque.

NodoA cifra el bloque y lo envía a nodoB.

NodoB descifra el bloque, verifica la firma del bloque y lo añade a su cadena si es válido.

Las transacciones inválidas (por falta de fondos) son rechazadas antes de añadirse al bloque.

8. Funciones de consulta

Se puede consultar el balance de una cuenta específica en nodoB tras procesar los bloques recibidos.

Resumen de funcionamiento:

Se minan 10 bloques en nodoA, cada uno con transacciones válidas.

Cada bloque es cifrado y enviado a nodoB.

NodoB descifra, verifica y agrega los bloques a su propia cadena si las firmas son válidas.

Al final se muestra el balance actualizado de una cuenta en nodoB.

Este proyecto cumple los siguientes requisitos del trabajo:

Firma digital de transacciones y bloques.

Comunicación cifrada entre nodos (cifrado en flujo).

Almacenamiento de blockchain estructurado con hashes y firmas.

Verificación de firmas digitales.

Actualización de balances tras minar bloques.

Función de consulta de balance.
# CUAES
#### Lucy Betts, Ilia Bolgov, Jodie Furnell, Annabel May
A recreation of the Advanced Encryption Standard, formally known as Rijndael.

## Theory

Theory behind the project and detailed description of the communication protocol is in this paper: **TO BE ADDED**

## Key ideas

The key idea of AES was to have a new encryption standard, to keep up with developing technology. Multiple entries for what could have been AES was submitted, but Rijndael was seen to be the best balance between, speed, security and size.

Rijndael, aka AES. Works by grouping sections of 16 bytes, and putting it into a string of 4x4 matricies. 
Encrypting each 4x4 matrix of 16 bytes together, makes it much more secure than previous, for example, its more secure than the famous enigma, due to enigma encrypting one piece of information at a time.
Rijndael then encrypts each 4x4 by doing a bunch of cycles of matrix calculations in galois field $GF(2^8)$, and shufles.

Galois field is

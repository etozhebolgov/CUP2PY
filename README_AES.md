# AESDemo
#### Lucy Betts, Ilia Bolgov, Jodie Furnell, Annabel May
A recreation of the Advanced Encryption Standard (AES), formally known as Rijndael.

## Key ideas

The key idea of AES was to have a new encryption standard, to keep up with developing technology. Multiple entries for what could have been AES was submitted, but Rijndael was seen to be the best balance between, speed, security and size.

Rijndael, aka AES. Works by grouping sections of 16 bytes, and putting it into a string of 4x4 matricies. 
Encrypting each 4x4 matrix of 16 bytes together, makes it much more secure than previous, for example, its more secure than the famous enigma, due to enigma encrypting one piece of information at a time.
Rijndael then encrypts each 4x4 by doing a bunch of cycles of matrix calculations in galois field $GF(2^8)$, and shufles.

Galois theory, is number theory working in a limited finite set of numbers, in this Galois feild $GF(2^8)$ (256 numbers) is what we will be using for all our matrix calculations. 
This allows the numbers loop around, so never goes outside the range, to be easily stored as bytes. 
Galois feilds is isometric and commutable, which means it can be reversed and we wont have to worry about order of numbers.

In order to do addition within $GF(2^8)$, it's repeated XORs, when adding 2 bytes together, you compare each pair of bits which represent the matching powers of 2 using XOR. Exact same for subtraction.
For multiplication within $GF(2^8)$, treat the numbers as polynomials, which is easy as its in binary, the multiplication is like normal, however when adding the different parts, you do XOR, and don't carry the numbers to the higher power. In the sernario it overflows and the result is above 256, you take the irreducible polynomial, which is always 283, aka 100011011 for $GF(2^8)$, and you divide your result by 283 using long division, using XOR instead of subtraction/edition. The remainder of the long division is your answer.

AES goes through cycles, involving matrix calculations in the Galois field, and shuffling the bytes around


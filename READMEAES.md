# CUAES
#### Lucy Betts, Ilia Bolgov, Jodie Furnell, Annabel May
A recreation of the Advanced Encryption Standard (AES), formally known as Rijndael.

## Theory

Theory behind the project and detailed description of the communication protocol is in this paper: **TO BE ADDED**

## Key ideas

The key idea of AES was to have a new encryption standard, to keep up with developing technology. Multiple entries for what could have been AES was submitted, but Rijndael was seen to be the best balance between, speed, security and size.

Rijndael, aka AES. Works by grouping sections of 16 bytes, and putting it into a string of 4x4 matricies, column-major order. 
Encrypting each 4x4 matrix of 16 bytes together, makes it much more secure than previous, for example, its more secure than the famous enigma, due to enigma encrypting one piece of information at a time.
Rijndael then encrypts each 4x4 by doing a bunch of cycles of matrix calculations in galois field $GF(2^8)$, and shufles.

Galois theory, is number theory working in a limited finite set of numbers, in this Galois feild $GF(2^8)$ (256 numbers) is what we will be using for all our matrix calculations. 
This allows the numbers loop around, so never goes outside the range, to be easily stored as bytes. 
Galois fields is isometric and commutable, which means it can be reversed and we wont have to worry about order of numbers.

In order to do addition within $GF(2^8)$, it's repeated XORs, when adding 2 bytes together, you compare each pair of bits which represent the matching powers of 2 using XOR. Exact same for subtraction.
For multiplication within $GF(2^8)$, treat the numbers as polynomials, which is easy as its in binary, the multiplication is like normal, however when adding the different parts, you do XOR, and don't carry the numbers to the higher power. In the sernario it overflows and the result is above 256, you take the irreducible polynomial, which is always 283, aka 100011011 for $GF(2^8)$, and you divide your result by 283 using long division, using XOR instead of subtraction/edition. The remainder of the long division is your answer.

AES encryption goes through cycles, involving matrix calculations in the Galois field, and shuffling the bytes around.<br />
Round 1 only has addition of the round key, and the final round has everything except mix columns. There are 10 rounds.<br />
Step 1 of the cycle, is substituting the bytes, every byte is substituted with another byte, which can be found with a look up table. Each substitution is never identical to its previous value, and is never it's inverse, so 00111101 will never become 00111101 again, or 11000010 which is it's inverse.<br />
Step 2 is shifting its rows; top row is shifted left by 0 bytes (aka, nothing), next row is shifted left by 1, with the far left going on the right, next row after that shifts 2 left, and final shifts left 3. (aka 1 right)<br />
Step 3 is mixing comlumns, this is done by multiplying the matrix of data, in Galois theory, with the matrix which has rows: (2 3 1 1),(1 2 3 1),(1 1 2 3),(3 1 1 2). This mixes columns, not only by shuffling them, but rather multiplying, and adding them.<br />
Step 4 Adding the key. Each cycle, the round key is different, in order to strenghten the encryption, The round key is derieved from the original key. The round key is added to the data matrix using XOR bitwise, aka addition within the same Galois field
Step 5, Go to to step 1 again

AES decryption is the exact opposite of the encryption<br />
Round 1 only has everything except inverse mix columns, and the final round only has subtraction of the round key. There are 10 rounds again.<br />
Step 1 Subtracting the round key. As subtraction and addition is the same within this galois feild, is the same as before, being XOR, the only thing that changes is that the round keys are in the opposite order<br />
Step 2, mixing of columns, there is an inverse matrix within this Galois feild, that can be used to undo this step, the rows being (14 11 13 9),(9 14 11 13),(13 9 14 11),(11 13 9 14), is multiplied with the encrypted matrix<br />
Step 3 shifting rows, although this time, is right instead of left, but the bytes that go off the right side still loop around to the left side<br />
Step 4 un-substituting all the bytes from the lookup table<br />
Step 5, Go to step 1 again

## Functions and their uses

**Sub_Bytes** The function that does the substituion part of AES, with inputs of the data matrix, and a boolean saying whether to encrypt or decrypt<br />
**Rotate_Rows** The function that does the shift rows part of AES, with inputs of the data matrix, and a boolean saying whether to encrypt or decrypt<br />
**Mix_Columns** The function that mixes the columns by multiplying the data matrix with the encryption/decryption matrix which mixes columns, with inputs of the data matrix, and a boolean saying whether to encrypt or decrypt<br />
**Round_Key_Value** Takes in the 4x4 Key Matrix, and computes and outputs 11 4x4 round keys<br />
**After_Round_Key_Valye** XORs 2 4x4 matrices and outputs the result matrix<br />
**HEX** Takes a 4x4 matrix in decimal and outputs it in a Hexdecimal 4x4 matrix<br />
**Rotate_Matrix** Inputs a 4x4 matrix and swaps the rows and columns around<br />
**interger_multiplication_XOR** a function that does the Galois Feild Multiplication<br />
**AES_Encrypt_unformatted** The purpose of the function is to encrypt the 4x4 list (Plainmatrix) with the AES encryption key (Key) using the algorithm for AES encryption.<br /> 
**AES_Decrypt_unformatted** The purpose of the function is to decrypt the 4x4 list (Ciphermatrix) with the AES encryption key (Key) using the algorithm for AES decryption.<br /> 
**format_string_2_4x4_matrices** The purpose of the function is to take a string and convert it into a list of 4x4 lists where each element is an intger<br />
**format_AES** The purpose of this function is to take a list of 4x4 integer lists and either encrypts or decrypts them with the 4x4 list (AES key), depending on the boolean bool_encrypt.
bool_encrypt is 0 for decryption and 1 for encryption.<br />
**format_4x4_matricies_2_string** The purpose of the function is to take a list of 4x4 list of integer characters and add those string characters together and return a string.<br />
**format_final_decrypt** The purpose of the function is to remove any '@' from the end of the input string.<br />
**input_checker** The purpose of the function is to check if the input string is empty or if there are any characters in the string not in the dictionary dictionary_letters_to_base_256. It returns a list with the input string if that is the case, otherwise it returns the input string.<br />
**format** This function converts a string into a list of 4x4 matricies, encrypts or decrypts those lists with the given AES key and then coverts the 4x4 matricies back into a string<br />
**Key_String_2_4x4_Matrix** The purpose of the function is to turn a string into a 4x4 list for an AES Key.<br />
**AES_Encrypt** The purpose of the function is to encrypt the input string with AES encryption with the given AES key.<br />
**AES_Decrypt** The purpose of the function is to decrypt the input string with AES decryption with the given AES key.<br />
**AES_Encrypt_Decrypt_file** The purpose of the function is to encrypt or decrypt the file with the name (Filename) with the given AES key string (Key).<br />



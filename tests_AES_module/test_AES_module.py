import AES_module

with open('test_AES_file.txt', 'w') as f:
    f.write('This is a test file')

def test_Rotate_Rows_Encrypt(test_matrix):
    """ [[a00, a01, a02, a03],              [[a00, a01, a02, a03],
         [a10, a11, a12, a13],     ->        [a11, a12, a13, a10],
         [a20, a21, a22, a23],               [a22, a23, a20, a21],
         [a30, a31, a32, a33]]               [a33, a30, a31, a32]]

    """
    test_matrix_RR_E = AES_module.Rotate_Rows(matrix_RR=test_matrix,bool_encrypt=1)
    test_matrix_rr_e = [
        test_matrix[0],
        [test_matrix[1][1], test_matrix[1][2], test_matrix[1][3], test_matrix[1][0]],
        [test_matrix[2][2], test_matrix[2][3], test_matrix[2][0], test_matrix[2][1]],
        [test_matrix[3][3], test_matrix[3][0], test_matrix[3][1], test_matrix[3][2]],
        ]
    assert test_matrix_RR_E == test_matrix_rr_e, "Encryption matricies aren't equal"

def test_Rotate_Rows_Decrypt(test_matrix):
    """ [[a00, a01, a02, a03],              [[a00, a01, a02, a03],
         [a10, a11, a12, a13],      ->       [a13, a10, a11, a12],
         [a20, a21, a22, a23],               [a22, a23, a20, a21],
         [a30, a31, a32, a33]]               [a31, a32, a33, a30]]

    """
    test_matrix_RR_D = AES_module.Rotate_Rows(matrix_RR=test_matrix,bool_encrypt=0)

    test_matrix_rr_d = [
        test_matrix[0],
        [test_matrix[1][3], test_matrix[1][0], test_matrix[1][1], test_matrix[1][2]],
        [test_matrix[2][2], test_matrix[2][3], test_matrix[2][0], test_matrix[2][1]],
        [test_matrix[3][1], test_matrix[3][2], test_matrix[3][3], test_matrix[3][0]],
        ]
    assert test_matrix_RR_D == test_matrix_rr_d, "Decryption matricies aren't equal"

def test_Rotate_Matrix(test_matrix):
    """ [[a00, a01, a02, a03],              [[a00, a10, a20, a30],
         [a10, a11, a12, a13],     ->        [a01, a11, a21, a31],
         [a20, a21, a22, a23],               [a02, a12, a22, a32],
         [a30, a31, a32, a33]]               [a03, a13, a23, a33]]

    """
    test_matrix_RM = AES_module.Rotate_Matrix(matrix_RM=test_matrix)
    test_matrix_rm = [
        [test_matrix[0][0], test_matrix[1][0], test_matrix[2][0], test_matrix[3][0]],
        [test_matrix[0][1], test_matrix[1][1], test_matrix[2][1], test_matrix[3][1]],
        [test_matrix[0][2], test_matrix[1][2], test_matrix[2][2], test_matrix[3][2]],
        [test_matrix[0][3], test_matrix[1][3], test_matrix[2][3], test_matrix[3][3]],
        ]
    assert test_matrix_RM == test_matrix_rm, "Rotated matricies aren't equal"

def test_HEX(test_matrix):
    """
    Write a Docstring here
    """
    Dictionary_HEX = {'0':0,'1':1,'2':2,'3':3,'4':4,'5':5,'6':6,'7':7,'8':8,'9':9,'a':10,'b':11,'c':12,'d':13,'e':14,'f':15}

    test_matrix_HEX = AES_module.HEX(matrix_HEX=test_matrix)

    test_matrix_hex = [
            [0,0,0,0],
            [0,0,0,0],
            [0,0,0,0],
            [0,0,0,0]
        ]

    for i in range(4):
        for j in range(4):
            test_matrix_i_j = test_matrix_HEX[i][j]
            test_matrix_hex[i][j]= 16*(Dictionary_HEX[test_matrix_i_j[0]])+Dictionary_HEX[test_matrix_i_j[1]]
    assert test_matrix == test_matrix_hex, "Hexed matricies aren't equal"

def testing_After_Round_Key_Value(matrix_test, matrix_test_2):
    """
    Write docstring here
    """
    test_matrix_ARKV = AES_module.After_Round_Key_Value(matrix_ARKV=matrix_test, matrix_RKV_m=matrix_test_2)

    test_matrix_arkv = [
            [0,0,0,0],
            [0,0,0,0],
            [0,0,0,0],
            [0,0,0,0]
        ]

    for i in range(4):
        for j in range(4):
            test_matrix_ARKV[i][j] = AES_module.dictionary[str(test_matrix_ARKV[i][j])][0]
            test_matrix_arkv_2 = [0,0,0,0,0,0,0,0]
            AES_module.dictionary_matrix_test_i_j_0 = AES_module.dictionary[str(matrix_test[i][j])][0]
            AES_module.dictionary_matrix_test_2_i_j_0 = AES_module.dictionary[str(matrix_test_2[i][j])][0]
            for k in range(8):
                test_matrix_arkv_2[k] = (AES_module.dictionary_matrix_test_i_j_0[k]+AES_module.dictionary_matrix_test_2_i_j_0[k])%2
            test_matrix_arkv[i][j] = test_matrix_arkv_2
    assert test_matrix_ARKV == test_matrix_arkv, "ARKV matricies aren't equal"

def test_Sub_Bytes_Big_encrypt():

    comparison_matrix_SB_E = [
    ['63', '7c', '77', '7b', 'f2', '6b', '6f', 'c5', '30', '01', '67', '2b', 'fe', 'd7', 'ab', '76'],
    ['ca', '82', 'c9', '7d', 'fa', '59', '47', 'f0', 'ad', 'd4', 'a2', 'af', '9c', 'a4', '72', 'c0'],
    ['b7', 'fd', '93', '26', '36', '3f', 'f7', 'cc', '34', 'a5', 'e5', 'f1', '71', 'd8', '31', '15'],
    ['04', 'c7', '23', 'c3', '18', '96', '05', '9a', '07', '12', '80', 'e2', 'eb', '27', 'b2', '75'],
    ['09', '83', '2c', '1a', '1b', '6e', '5a', 'a0', '52', '3b', 'd6', 'b3', '29', 'e3', '2f', '84'],
    ['53', 'd1', '00', 'ed', '20', 'fc', 'b1', '5b', '6a', 'cb', 'be', '39', '4a', '4c', '58', 'cf'],
    ['d0', 'ef', 'aa', 'fb', '43', '4d', '33', '85', '45', 'f9', '02', '7f', '50', '3c', '9f', 'a8'],
    ['51', 'a3', '40', '8f', '92', '9d', '38', 'f5', 'bc', 'b6', 'da', '21', '10', 'ff', 'f3', 'd2'],
    ['cd', '0c', '13', 'ec', '5f', '97', '44', '17', 'c4', 'a7', '7e', '3d', '64', '5d', '19', '73'],
    ['60', '81', '4f', 'dc', '22', '2a', '90', '88', '46', 'ee', 'b8', '14', 'de', '5e', '0b', 'db'],
    ['e0', '32', '3a', '0a', '49', '06', '24', '5c', 'c2', 'd3', 'ac', '62', '91', '95', 'e4', '79'],
    ['e7', 'c8', '37', '6d', '8d', 'd5', '4e', 'a9', '6c', '56', 'f4', 'ea', '65', '7a', 'ae', '08'],
    ['ba', '78', '25', '2e', '1c', 'a6', 'b4', 'c6', 'e8', 'dd', '74', '1f', '4b', 'bd', '8b', '8a'],
    ['70', '3e', 'b5', '66', '48', '03', 'f6', '0e', '61', '35', '57', 'b9', '86', 'c1', '1d', '9e'],
    ['e1', 'f8', '98', '11', '69', 'd9', '8e', '94', '9b', '1e', '87', 'e9', 'ce', '55', '28', 'df'],
    ['8c', 'a1', '89', '0d', 'bf', 'e6', '42', '68', '41', '99', '2d', '0f', 'b0', '54', 'bb', '16']
    ]

    testing_matrix_SB_E = []
    for i in range(16):
        testing_matrix_SB_E_j = []
        for j in range(4):
            testing_matrix_SB_E_k = []
            for k in range(4):
                testing_matrix_SB_E_k += [i*16+j*4 + k]
            testing_matrix_SB_E_j += [testing_matrix_SB_E_k]
        testing_matrix_SB_E_i = AES_module.HEX(matrix_HEX=AES_module.Sub_Bytes(matrix_SB=testing_matrix_SB_E_j, bool_encrypt=1))
        testing_matrix_SB_E += [testing_matrix_SB_E_i[0]+testing_matrix_SB_E_i[1]+testing_matrix_SB_E_i[2]+testing_matrix_SB_E_i[3]]
    assert comparison_matrix_SB_E == testing_matrix_SB_E, "Sub_Byte encryption matricies not equal"

def test_Sub_Bytes_Big_decrypt():

    comparison_matrix_SB_D = [
    ['52', '09', '6a', 'd5', '30', '36', 'a5', '38', 'bf', '40', 'a3', '9e', '81', 'f3', 'd7', 'fb'],
    ['7c', 'e3', '39', '82', '9b', '2f', 'ff', '87', '34', '8e', '43', '44', 'c4', 'de', 'e9', 'cb'],
    ['54', '7b', '94', '32', 'a6', 'c2', '23', '3d', 'ee', '4c', '95', '0b', '42', 'fa', 'c3', '4e'],
    ['08', '2e', 'a1', '66', '28', 'd9', '24', 'b2', '76', '5b', 'a2', '49', '6d', '8b', 'd1', '25'],
    ['72', 'f8', 'f6', '64', '86', '68', '98', '16', 'd4', 'a4', '5c', 'cc', '5d', '65', 'b6', '92'],
    ['6c', '70', '48', '50', 'fd', 'ed', 'b9', 'da', '5e', '15', '46', '57', 'a7', '8d', '9d', '84'],
    ['90', 'd8', 'ab', '00', '8c', 'bc', 'd3', '0a', 'f7', 'e4', '58', '05', 'b8', 'b3', '45', '06'],
    ['d0', '2c', '1e', '8f', 'ca', '3f', '0f', '02', 'c1', 'af', 'bd', '03', '01', '13', '8a', '6b'],
    ['3a', '91', '11', '41', '4f', '67', 'dc', 'ea', '97', 'f2', 'cf', 'ce', 'f0', 'b4', 'e6', '73'],
    ['96', 'ac', '74', '22', 'e7', 'ad', '35', '85', 'e2', 'f9', '37', 'e8', '1c', '75', 'df', '6e'],
    ['47', 'f1', '1a', '71', '1d', '29', 'c5', '89', '6f', 'b7', '62', '0e', 'aa', '18', 'be', '1b'],
    ['fc', '56', '3e', '4b', 'c6', 'd2', '79', '20', '9a', 'db', 'c0', 'fe', '78', 'cd', '5a', 'f4'],
    ['1f', 'dd', 'a8', '33', '88', '07', 'c7', '31', 'b1', '12', '10', '59', '27', '80', 'ec', '5f'],
    ['60', '51', '7f', 'a9', '19', 'b5', '4a', '0d', '2d', 'e5', '7a', '9f', '93', 'c9', '9c', 'ef'],
    ['a0', 'e0', '3b', '4d', 'ae', '2a', 'f5', 'b0', 'c8', 'eb', 'bb', '3c', '83', '53', '99', '61'],
    ['17', '2b', '04', '7e', 'ba', '77', 'd6', '26', 'e1', '69', '14', '63', '55', '21', '0c', '7d']
    ]

    testing_matrix_SB_D = []
    for i in range(16):
        testing_matrix_SB_D_j = []
        for j in range(4):
            testing_matrix_SB_D_k = []
            for k in range(4):
                testing_matrix_SB_D_k += [i*16+j*4 + k]
            testing_matrix_SB_D_j += [testing_matrix_SB_D_k]
        testing_matrix_SB_D_i = AES_module.HEX(matrix_HEX=AES_module.Sub_Bytes(matrix_SB=testing_matrix_SB_D_j, bool_encrypt=0))
        testing_matrix_SB_D += [testing_matrix_SB_D_i[0]+testing_matrix_SB_D_i[1]+testing_matrix_SB_D_i[2]+testing_matrix_SB_D_i[3]]
    assert comparison_matrix_SB_D == testing_matrix_SB_D, "Sub_Byte decryption matricies not equal"

def test_Sub_Bytes_Small_encrypt():
    Matrix_Test_Sub_Bytes_E = [
    [0x19,0xa0,0x9a,0xe9],
    [0x3d,0xf4,0xc6,0xf8],
    [0xe3,0xe2,0x8d,0x48],
    [0xbe,0x2b,0x2a,0x08],
    ]

    Matrix_Test_After_Sub_Bytes_E = AES_module.HEX(matrix_HEX=AES_module.Sub_Bytes(matrix_SB=Matrix_Test_Sub_Bytes_E, bool_encrypt=1))
    Matrix_Test_Sub_Bytes_E_Comparison = [
        ['d4','e0','b8','1e'],
        ['27','bf','b4','41'],
        ['11','98','5d','52'],
        ['ae','f1','e5','30']
    ]
    assert Matrix_Test_After_Sub_Bytes_E == Matrix_Test_Sub_Bytes_E_Comparison, "Small SB encryption matricies aren't equal"

def test_Sub_Bytes_Small_decrypt():
    Matrix_Test_Sub_Bytes_D = [
    [0x52,0x85,0xe3,0xf6],
    [0x50,0xa4,0x11,0xcf],
    [0x2f,0x5e,0xc8,0x6a],
    [0x28,0xd7,0x07,0x94],
    ]

    Matrix_Test_After_Sub_Bytes_D = AES_module.HEX(matrix_HEX=AES_module.Sub_Bytes(matrix_SB=Matrix_Test_Sub_Bytes_D, bool_encrypt=0))
    Matrix_Test_Sub_Bytes_D_Comparison = [
        ['48','67','4d','d6'],
        ['6c','1d','e3','5f'],
        ['4e','9d','b1','58'],
        ['ee','0d','38','e7']
    ]
    assert Matrix_Test_After_Sub_Bytes_D == Matrix_Test_Sub_Bytes_D_Comparison, "Small SB decryption matricies aren't equal"

def test_AES_Encrypt_small():
    user_input_plain_string = "ÒNdwëŇò7ÊÊŞ'ýĚnţ"
    test_Key = 'ÍØģæĘL÷ŻŽ5ģës\nŢę'
    user_input_cipher_string = '_ű4ŵŪùs!ù%ĹĩþbżÒ'
    assert AES_module.AES_Encrypt(Plaintext=user_input_plain_string, Key=test_Key) == user_input_cipher_string, "AES_Encrypt_small not encrypted to the expected value"

def test_AES_Decrypt_small():
    user_input_plain_string = "ÒNdwëŇò7ÊÊŞ'ýĚnţ"
    test_Key = 'ÍØģæĘL÷ŻŽ5ģës\nŢę'
    user_input_cipher_string = '_ű4ŵŪùs!ù%ĹĩþbżÒ'

    assert AES_module.AES_Decrypt(Ciphertext=user_input_cipher_string, Key=test_Key) == user_input_plain_string, "AES_Decrypt_small not decrypted to the expected value"


def test_AES_Encrypt_unformatted_small():
    K = [
        [0x2b,0x28,0xab,0x09],
        [0x7e,0xae,0xf7,0xcf],
        [0x15,0xd2,0x15,0x4f],
        [0x16,0xa6,0x88,0x3c]
        ]

    comparison_matrix = [
    [0x39,0x02,0xdc,0x19],
    [0x25,0xdc,0x11,0x6a],
    [0x84,0x09,0x85,0x0b],
    [0x1d,0xfb,0x97,0x32],
    ]

    testing_matrix = [
    [0x32,0x88,0x31,0xe0],
    [0x43,0x5a,0x31,0x37],
    [0xf6,0x30,0x98,0x07],
    [0xa8,0x8d,0xa2,0x34],
    ]

    assert (AES_module.AES_Encrypt_unformatted(Plainmatrix=testing_matrix, Key = K)) == (comparison_matrix), "AES_Encrypt_unformatted_small not ancrypted to the expected value"

def test_AES_Decrypt_unformatted_small():
    K = [
        [0x2b,0x28,0xab,0x09],
        [0x7e,0xae,0xf7,0xcf],
        [0x15,0xd2,0x15,0x4f],
        [0x16,0xa6,0x88,0x3c]
        ]

    comparison_matrix = [
    [0x32,0x88,0x31,0xe0],
    [0x43,0x5a,0x31,0x37],
    [0xf6,0x30,0x98,0x07],
    [0xa8,0x8d,0xa2,0x34],
    ]

    testing_matrix = [
    [0x39,0x02,0xdc,0x19],
    [0x25,0xdc,0x11,0x6a],
    [0x84,0x09,0x85,0x0b],
    [0x1d,0xfb,0x97,0x32],
    ]

    assert (AES_module.AES_Decrypt_unformatted(Ciphermatrix=testing_matrix, Key = K)) == (comparison_matrix), "AES_Decrypt_unformatted_small not decrypted to the expected value"


def test_AES_Encrypt_Decrypt_file_Encrypt(test_string_key):
    AES_module.AES_Encrypt_Decrypt_file(Filename='test_AES_file.txt', Key=test_string_key, bool_encrypt=1)

def test_AES_Encrypt_Decrypt_file_Decrypt(test_string_key):
    AES_module.AES_Encrypt_Decrypt_file(Filename='test_AES_file.txt', Key=test_string_key, bool_encrypt=0)


def test_format_String_2_4x4_Matrix_type_and_Key(user_input):
        length_user_input_minus_sixteen = len(user_input)-16
        if length_user_input_minus_sixteen < 0:
            for i in range(-length_user_input_minus_sixteen):
                user_input += '@'
        comparison_format_string_2_4x4_matrix_user_input = [[
            [AES_module.dictionary_letters_to_base_256[user_input[0]], AES_module.dictionary_letters_to_base_256[user_input[4]], AES_module.dictionary_letters_to_base_256[user_input[8]], AES_module.dictionary_letters_to_base_256[user_input[12]]],
            [AES_module.dictionary_letters_to_base_256[user_input[1]], AES_module.dictionary_letters_to_base_256[user_input[5]], AES_module.dictionary_letters_to_base_256[user_input[9]], AES_module.dictionary_letters_to_base_256[user_input[13]]],
            [AES_module.dictionary_letters_to_base_256[user_input[2]], AES_module.dictionary_letters_to_base_256[user_input[6]], AES_module.dictionary_letters_to_base_256[user_input[10]], AES_module.dictionary_letters_to_base_256[user_input[14]]],
            [AES_module.dictionary_letters_to_base_256[user_input[3]], AES_module.dictionary_letters_to_base_256[user_input[7]], AES_module.dictionary_letters_to_base_256[user_input[11]], AES_module.dictionary_letters_to_base_256[user_input[15]]],
        ]]
        assert comparison_format_string_2_4x4_matrix_user_input == AES_module.format_string_2_4x4_matrices(string_F_S_2_4x4_M=user_input[:16]), "format_String_2_4x4_Matrix did not return the expected matrix"

def test_Key_String_2_4x4_Matrix_type_and_Key(user_input):
    Key_String_2_4x4_Matrix_user_input = AES_module.Key_String_2_4x4_Matrix(string_K_S_2_4x4_M=user_input)
    if (not type(user_input) == str) or (len(user_input)<16):
        assert type(Key_String_2_4x4_Matrix_user_input) == str, "Key_String_2_4x4_Matrix did not return a string"
    else:
        assert type(Key_String_2_4x4_Matrix_user_input) == list, "Key_String_2_4x4_Matrix did not return a 4x4 list"
        assert AES_module.format_string_2_4x4_matrices(string_F_S_2_4x4_M=user_input[:16])[0] == Key_String_2_4x4_Matrix_user_input, "test_Key_String_2_4x4_Matrix did not return the expected matrix"


testing_matrix = [
    [0x32,0x88,0x31,0xe0],
    [0x43,0x5a,0x31,0x37],
    [0xf6,0x30,0x98,0x07],
    [0xa8,0x8d,0xa2,0x34],
]

testing_matrix_2 = [
    [0x2b,0x28,0xab,0x09],
    [0x7e,0xae,0xf7,0xcf],
    [0x15,0xd2,0x15,0x4f],
    [0x16,0xa6,0x88,0x3c]
]

test_key_string = 'Hello World this is a test'



test_Rotate_Rows_Encrypt(test_matrix=testing_matrix)
test_Rotate_Rows_Decrypt(test_matrix=testing_matrix)
test_Rotate_Matrix(test_matrix=testing_matrix)
test_HEX(test_matrix=testing_matrix)
testing_After_Round_Key_Value(matrix_test=testing_matrix, matrix_test_2=testing_matrix_2)
test_Sub_Bytes_Big_encrypt()
test_Sub_Bytes_Big_decrypt()
test_Sub_Bytes_Small_encrypt()
test_Sub_Bytes_Small_decrypt()
test_AES_Encrypt_small()
test_AES_Decrypt_small()
test_AES_Encrypt_unformatted_small()
test_AES_Decrypt_unformatted_small()
test_AES_Encrypt_Decrypt_file_Encrypt(test_string_key=test_key_string)
test_AES_Encrypt_Decrypt_file_Decrypt(test_string_key=test_key_string)
test_format_String_2_4x4_Matrix_type_and_Key(user_input=test_key_string)
test_Key_String_2_4x4_Matrix_type_and_Key(user_input=test_key_string)

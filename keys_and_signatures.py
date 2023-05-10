import rsa
from base64 import b64encode, b64decode
import hashlib
import AESDemo #  also part of the project

def generateKeys(publicName, privateName):
    """
    Generates and saves RSA key pair.
    """
    (publicKey, privateKey) = rsa.newkeys(1024)
    with open(publicName, "wb") as p:
        p.write(publicKey.save_pkcs1("PEM"))
    with open(privateName, "wb") as p:
        p.write(privateKey.save_pkcs1("PEM"))


# =====================================================================================================================


def loadPublicKey(localName):
    """
    Loads RSA PublicKey.
    """
    with open(localName + "_publicKey.pem", "rb") as p:
        publicKey = rsa.PublicKey.load_pkcs1(p.read())
    return publicKey


def loadPrivateKey(localName):
    """
    Loads RSA PrivateKey.
    """
    with open(localName + "_privateKey.pem", "rb") as p:
        privateKey = rsa.PrivateKey.load_pkcs1(p.read())
    return privateKey


# =====================================================================================================================


def encrypt(message, key):
    """
    Encrypts a message using PublicKey.
    """
    return rsa.encrypt(message.encode("ascii"), key)


def decrypt(ciphertext, key):
    """
    Encrypts a ciphertext using PrivateKey.
    """
    try:
        return rsa.decrypt(ciphertext, key).decode("ascii")
    except Exception as e:
        print(f"Couldn't decrypt the ciphertext: {e}")
        return False


# =====================================================================================================================


def digitalSignature(record, privateKey):
    """
    Creates and returns digital signature.
    """
    message = str(record).encode()
    return rsa.sign(message, privateKey, "SHA-256")


def checkDigitalSignature(message, publicKey, signature):
    """
    Checks digital signature.
    """
    try:
        return rsa.verify(message.encode(), signature, publicKey) == "SHA-256"
    except Exception as e:
        print(f"Error while trying to validate digital signature: {e}")
        return False


# =====================================================================================================================


def publicKeyToString(publicKey):
    """
    Converts object of class rsa.PublicKey into .PEM string representation.
    :param publicKey:
    :return:
    """
    return publicKey.save_pkcs1("PEM").decode()


def stringToPublicKey(string_publicKey):
    """
    Converts .PEM string with public key into object of a class rsa.PublicKey.
    :param string_publicKey:
    :return:
    """
    return rsa.PublicKey.load_pkcs1(string_publicKey.encode())


def signatureToB64(signature):
    """
    Encodes digital signature to Base64.
    :param signature:
    :return:
    """
    return b64encode(signature)


def b64ToSignature(b64Signature):
    """
    Decodes digital signature from Base64.
    :param b64Signature:
    :return:
    """
    return b64decode(b64Signature)


def publicKeyHash(string_publicKey):
    """
    Returns SHA-256 HEX of string of a public key.
    :param string_publicKey:
    :return:
    """
    return hashlib.sha256(string_publicKey.encode()).hexdigest()


def encryptPrivateKey(localName, password):
    """
    Encrypts local file with private key with user's password.
    :param localName:
    :param password: At least 16 symbols.
    :return:
    """
    AESDemo.AES_Encrypt_Decrypt_file(localName + '_privateKey.pem', password, True)


def decryptPrivateKey(localName, password):
    """
    Decrypts local file with privateK key with user's password.
    :param localName:
    :param password: At least 16 symbols.
    :return:
    """
    AESDemo.AES_Encrypt_Decrypt_file(localName + '_privateKey.pem', password, False)


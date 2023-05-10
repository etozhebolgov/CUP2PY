import sqlite3
from keys_and_signatures import *


def newAddressBook(databaseName, addressBookName):
    """
    Creates a new address book.
    :param databaseName:
    :param addressBookName:
    :return:
    """
    try:
        connection = sqlite3.connect(databaseName)
        cursor = connection.cursor()
        cursor.execute(
            f"CREATE TABLE {addressBookName} (publicKeyHash BLOB, publicKey BLOB, ip TEXT, updateDate DATETIME, digitalSignature BLOB)"
        )
        connection.close()
    except sqlite3.OperationalError:
        print("This address book already exists.")


def getRecordByPublicKey(databaseName, addressBook, publicKey):
    """
    Gets record from SQL table and returns as list (with publicKey as publicKey
    :param addressBook:
    :param publicKey:
    :return:
    """
    return getRecordByPublicKeyHash(databaseName, addressBook, publicKeyHash(publicKeyToString(publicKey)))


def getRecordByPublicKeyHash(databaseName, addressBook, publicKeyHashValue):
    """
    Gets record from SQL table and returns as list (with publicKey as publicKey
    :param addressBook:
    :param publicKey:
    :return:
    """
    connection = sqlite3.connect(databaseName)
    cursor = connection.cursor()
    cursor.execute(
        f"SELECT * FROM {addressBook} \n WHERE publicKeyHash='{publicKeyHashValue}'"
    )
    connection.commit()
    recordData = cursor.fetchall()

    if recordData:
        return recordData[0]
    else:
        return False


def getAllRecordIps(
    databaseName, addressBook, excludedHashesList
):  # under construction
    """
    Gets a list of ip addresses from chosen address books excluding chosen hashes.
    :param databaseName:
    :param addressBook:
    :param excludedHashesList:
    :return:
    """
    excludedHashesList.append(
        ""
    )  # because sqlite is weird - crashes when < 2 elements.
    excludedHashesList.append("")

    connection = sqlite3.connect(databaseName)
    cursor = connection.cursor()
    cursor.execute(
        f"SELECT ip FROM {addressBook} \n WHERE publicKeyHash NOT IN {tuple(excludedHashesList)}"
    )
    connection.commit()
    recordData = cursor.fetchall()
    ipList = [i[0] for i in recordData]

    return ipList


def updateTableRecord(databaseName, addressBook, userRecordTuple):
    """
    Updates record in address book.
    :param databaseName:
    :param addressBook:
    :param userRecordTuple:
    :return:
    """
    connection = sqlite3.connect(databaseName)
    cursor = connection.cursor()

    orderedTuple = (
        userRecordTuple[2],
        userRecordTuple[3],
        userRecordTuple[4],
        userRecordTuple[1],
    )

    cursor.execute(
        f"UPDATE {addressBook} SET ip = ?, updateDate = ?, digitalSignature = ?"
        f" WHERE publicKey = ?",
        orderedTuple,
    )
    connection.commit()


def writeTableRecord(databaseName, addressBook, userRecordTuple):
    """
    Adds record to address book.
    :param databaseName:
    :param addressBook:
    :param userRecordTuple:
    :return:
    """
    connection = sqlite3.connect(databaseName)
    cursor = connection.cursor()
    cursor.execute(
        f"INSERT INTO {addressBook} (publicKeyHash, publicKey, ip, updateDate, digitalSignature)\n VALUES (?,?,?,?,?)",
        userRecordTuple,
    )
    connection.commit()

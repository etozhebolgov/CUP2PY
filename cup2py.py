"""
########################################
CUP2PY

Proof of concept for decentralised protocol for peer-to-peer (P2P) communication.

v.1.0.0
12 May 2023
########################################
Ilia Bolgov, Lucy Betts, Jodie Furnell, Annabel May
special thanks to Alex

Dr Vincent Anthony Knight
########################################
"""

import os
import datetime

from keys_and_signatures import *
from request_types import *
from request_types import UpdateRequest, SearchRequest
from sql import *


# =====================================================================================================================


class Session:
    """
    Class of communication session. Main functionality of the project is contained inside this class.
    """

    def __init__(
        self,
        databaseName=None,
        chosenAddressBook=None,
        chosenUserRecord=None,
        chosenUserRecordPrivateKeyFile=None,
    ):
        """
        Defines session object.
        :param databaseName: filename (with path) of the SQLite database, used to store Address Books.
        :param chosenAddressBook: filename (with path) of the chosen Address Book.
        :param chosenUserRecord: object of datatype UserRecord. This is the User Record which is used for communication.
        :param chosenUserRecordPrivateKeyFile: filename (with path) of the .PEM file with chosenUser's private key. In this version of library is not used directly.
        """
        self.databaseName = databaseName
        self.chosenAddressBook = chosenAddressBook
        self.chosenUserRecord = chosenUserRecord
        self.chosenUserRecordPrivateKeyFile = chosenUserRecordPrivateKeyFile

    def setDatabaseName(self, databaseName):
        """
        Sets chosen database as default database for the session.
        :param databaseName: name or path of database file.
        """
        self.databaseName = databaseName

    def setAddressBook(self, addressBook):
        """
        Set chosen address book (table in database) as default for the session.
        :param addressBook: name of the table in database.
        """
        self.chosenAddressBook = addressBook

    def checkIfAddressBookAndDatabase(self):
        return self.databaseName and self.chosenAddressBook

    def setUser(self, userRecord):
        """
        Set chosen user record (object of datatype UserRecord) as default for the session
        :param userRecord: chosen user record.
        """
        if checkIfUserRecord(userRecord):
            self.chosenUserRecord = userRecord
        else:
            print(f'Wrong type of object for {self}.chosenUserRecord')

    def createAddressBookInDatabase(self):
        """
        Creates Address Book (SQL table) in chosen database from attributes set for the session.
        :return:
        """
        if not self.checkIfAddressBookAndDatabase():
            print("DatabaseName or chosenAddressBook are not defined for this session")
            return

        if self.chosenAddressBook and self.databaseName:
            try:
                newAddressBook(
                    databaseName=self.databaseName,
                    addressBookName=self.chosenAddressBook,
                )
            except Exception as e:
                print(
                    f"Couldn't create new addressBook {self.chosenAddressBook} in database {self.databaseName}: {e}"
                )
        else:
            print(
                "Please specify the name for address book and database as attributes of this session."
            )

    def getUser(self, publicKey):
        """
        Searches and returns user by public key from chosenAddressBook table in SQLite database chosenDatabaseName.
        :param publicKey: User's public key, object of class rsa.PublicKey
        :return: object of class userRecord if the record is found, or False, if the record is not found or incorrectly stored.
        """
        return self.getUserByHash(publicKeyHash(publicKeyToString(publicKey)))

    def getUserByHash(self, publicKeyHashValue):
        """
        Searches and returns user by public key hash from chosenAddressBook table in SQLite database chosenDatabaseName.
        :param publicKeyHashValue: public key hash string
        :return: object of class userRecord if the record is found, or False, if the record is not found or incorrectly stored.
        """
        if not self.checkIfAddressBookAndDatabase():
            print("DatabaseName or chosenAddressBook are not defined for this session")
            return

        try:
            recordData = getRecordByPublicKeyHash(
                self.databaseName, self.chosenAddressBook, publicKeyHashValue
            )
            if recordData:
                if recordData[0] == publicKeyHash(recordData[1]):
                    userRecord = dataToUserRecord(
                        recordData[1], recordData[2], recordData[3], recordData[4]
                    )
                    return userRecord
                else:
                    print(
                        "Security error: the hash doesn't equal to the hash of the given public key."
                    )
                    return False
            else:
                return False
        except Exception as e:
            print(f"Error while trying to get userRecord from the table: {e}")

    def updateAddressBookRecord(self, userRecord):
        """
        Verifies and adds userRecord to chosenAddressBook if it was not there, if it was - updates if the latest.
        :param userRecord:
        :return:
        """
        if not self.checkIfAddressBookAndDatabase():
            print("DatabaseName or chosenAddressBook are not defined for this session")
            return

        if checkDigitalSignature(
            userRecord.message(), userRecord.publicKey, userRecord.digitalSignature
        ):
            userRecordInAB = self.getUser(userRecord.publicKey)
            if userRecordInAB:
                if userRecordInAB.updateDate < userRecord.updateDate:
                    updateTableRecord(
                        self.databaseName, self.chosenAddressBook, userRecord.tuple()
                    )
                    return userRecord
                else:
                    return False
            else:
                writeTableRecord(
                    self.databaseName, self.chosenAddressBook, userRecord.tuple()
                )
                return userRecord
        else:
            return False

    def requestHandler(self, message):
        """
        Identifies and processes search and update requests.
        :param message: string
        :returns for SEARCH: returns [(UPDATE, [ipOfSender]), (SEARCH, ipList)], if required User Record is found, otherwise returns (SEARCH, ipList).
        :returns for UPDATE: returns (UPDATE, ipList).
        :returns in other cases returns None.
        """
        if not self.checkIfAddressBookAndDatabase() or not self.chosenUserRecord:
            print("DatabaseName, chosenAddressBook or chosenUserRecord are not defined for this session")
            return

        receivedRequest = getRequest(message)

        if type(receivedRequest) == SearchRequest:
            # SEARCH;<SearchedPublicKeyHash>;<SenderStringPublicKey>;<SenderIP>;<SenderUpdateDate>;<SenderStringDigitalSignature>;<RecursionDepth>;[<ListOfChechkedHashes>]
            receivedSearchRequest = receivedRequest

            if receivedSearchRequest.searchDepth > 0:
                receivedSearchRequest.depthStep(
                    publicKeyHash(publicKeyToString(self.chosenUserRecord.publicKey)))

                searchedUser = self.getUserByHash(
                    receivedSearchRequest.searchedPublicKeyHash
                )
                if searchedUser:
                    return [self.updateToSend(
                        newUpdateRequest(searchedUser, 0),
                        [receivedSearchRequest.senderUserRecord.ip]), self.searchToSend(receivedSearchRequest)]
                else:
                    return self.searchToSend(receivedSearchRequest)

        elif type(receivedRequest) == UpdateRequest:
            # UPDATE;<SenderStringPublicKey>;<SenderIP>;<SenderUpdateDate>;<SenderStringDigitalSignature>;<RecursionDepth>;[<ListOfChechkedHashes>]
            receivedUpdateRequest = receivedRequest

            if self.updateAddressBookRecord(receivedUpdateRequest.userRecord):
                if receivedUpdateRequest.updateDepth > 0:
                    receivedUpdateRequest.depthStep(
                        publicKeyHash(publicKeyToString(self.chosenUserRecord.publicKey))
                    )
                    return self.updateToSend(receivedUpdateRequest)

        else:
            print('Incorrect request')
            return

    def updateToSend(self, updateRequest, ipList=None):
        """
        Returns string request and list of ip addresses this request will be send to.
        :param updateRequest: object of class UpdateRequest.
        :param ipList: List of IP addresses to return. If None, returns all suitable IPs in chosenAddressBook.
        :return: (updateRequestToSend, ipList)
        """
        if not self.checkIfAddressBookAndDatabase() and not ipList:
            print("DatabaseName or chosenAddressBook are not defined for this session")
            return
        try:
            updateRequestToSend = updateRequest.requestString()
            if not ipList:
                ipList = getAllRecordIps(
                    self.databaseName,
                    self.chosenAddressBook,
                    updateRequest.checkedPublicKeyHashes,
                )

            return updateRequestToSend, ipList
        except Exception as e:
            print(f"Couldn't convert UPDATE request into string representation: {e}")

    def searchToSend(self, searchRequest, ipList=None):
        """
        Returns string request and list of ip addresses this request will be send to.
        :param searchRequest:o bject of class SearchRequest.
        :param ipList: List of ips to return. If None, returns all suitable ips in chosenAddressBook.
        :return: (searchRequestToSend, ipList)
        """
        if not self.checkIfAddressBookAndDatabase() and not ipList:
            print("DatabaseName or chosenAddressBook are not defined for this session")
            return
        try:
            searchRequestToSend = searchRequest.requestString()
            if not ipList:
                ipList = getAllRecordIps(
                    self.databaseName,
                    self.chosenAddressBook,
                    searchRequest.checkedPublicKeyHashes,
                )

            return searchRequestToSend, ipList
        except Exception as e:
            print(f"Couldn't convert SEARCH request into string representation: {e}")

# =====================================================================================================================


class UserRecord:
    def __init__(self, publicKey, ip, updateDate, digitalSignature=None):
        """
        Class for records of IP updates in UserRecord datatype.
        :param publicKey: RSA Public Key - plays a role of id. (class rsa.PublicKey)
        :param ip: IP address which user wants to use for communication.
        :param updateDate: Date and time of creation of a record: needed for security and for other users to know which one to use.
        :param digitalSignature: Digital signature: needed to verify that the UserRecord was actually created by this user.
        """
        self.publicKey = publicKey
        self.ip = ip
        self.updateDate = updateDate
        self.digitalSignature = digitalSignature

    def message(self):
        """
        Used to create digital signature from User Record.
        :return:
        """
        return str((self.publicKey, self.ip, self.updateDate))

    def tuple(self):
        """
        Used for database storage purposes.
        :return:
        """
        return (
            publicKeyHash(publicKeyToString(self.publicKey)),
            publicKeyToString(self.publicKey),
            self.ip,
            str(self.updateDate),
            signatureToB64(self.digitalSignature),
        )

    def __repr__(self):
        return f"{publicKeyHash(publicKeyToString(self.publicKey))}\n{self.ip}\n{self.updateDate}\n{signatureToB64(self.digitalSignature)}"  # FIX SIGNATURE AND PUBLIC KEY


# =====================================================================================================================


def generateUserKeyPair(
    localName, path=os.getcwd()
):  # local name is only seen by the user himself. Returns publicKey, stores private and public
    """
    Function which creates a new User Record and saves the user files, as well as returns the created User Record.
    :param localName: Local name for the user - used for creation of public and private key files.
    :param path: Where locally they want the public and private key files to be stored. By default: cwd.
    :return: The pair of public key and private key.
    """
    publicName = f"{path}//{localName}_publicKey.pem"
    privateName = f"{path}//{localName}_privateKey.pem"

    if not (os.path.exists(publicName) or os.path.exists(privateName)):
        generateKeys(publicName, privateName)
        generatedPublicKey, generatedPrivateKey = (
            loadPublicKey(localName),
            loadPrivateKey(localName),
        )
        return generatedPrivateKey, generatedPublicKey
    else:
        print(f"The user files with local name '{localName}' already exists.")


def userRecordFromKeyPair(privateKey, publicKey, ip):
    """
    Function which creates and returns a new Update Record
    :param publicKey: RSA Public Key - also used as id.
    :param privateKey: RSA Private Key.
    :param ip: IP address user wants other people to use to connect with him. By default - his current IP.
    :return: Created new User Record.
    """
    updateDate = datetime.datetime.now()

    userRecord = UserRecord(publicKey=publicKey, ip=ip, updateDate=updateDate)

    message = userRecord.message()
    digitalSignatureOfRecord = digitalSignature(message, privateKey)

    userRecord.digitalSignature = digitalSignatureOfRecord

    return userRecord


def generateUser(localName, ip, path=os.getcwd()):
    """
    Generates and returns brand new user record.
    :param localName: name for files with locally stored keys.
    :param ip: IP address for the record.
    :param path: path to store the files. By default - current directory.
    :return:
    """
    userPrivateKey, userPublicKey = generateUserKeyPair(localName, path)
    return userRecordFromKeyPair(userPrivateKey, userPublicKey, ip)


# =====================================================================================================================


def dataToUserRecord(stringPublicKey, ip, stringUpdateDate, b64EncodedSignature):
    """
    Converts string from request to object of datatype UserRecord.
    :param stringPublicKey:
    :param ip:
    :param stringUpdateDate:
    :param b64EncodedSignature:
    :return:
    """
    user = UserRecord(
        stringToPublicKey(stringPublicKey),
        ip,
        datetime.datetime.strptime(stringUpdateDate, "%Y-%m-%d %H:%M:%S.%f"),
        b64ToSignature(b64EncodedSignature),
    )
    return user


def compileUpdateRequest(requestElements):
    """
    Creates object of class UpdateRequest from the list with parameters.
    :param requestElements: list with parameters:
    ["UPDATE", <stringPublicKey>, <ip>, <updateDate>, <stringDigitalSignature>, <recursionDepth>, [<checkedPublicKeyHashes>]]
    :return: object of class UpdateRequest
    """
    if requestElements[6][1:-1]:
        checkedList = requestElements[6][1:-1].split(",")

    else:
        checkedList = []
    requestUserRecord = dataToUserRecord(
        requestElements[1], requestElements[2], requestElements[3], requestElements[4]
    )
    compiledUpdateRequest = UpdateRequest(
        requestUserRecord, int(requestElements[5]), checkedList
    )
    return compiledUpdateRequest


def compileSearchRequest(requestElements):
    """
    Creates object of class SearchRequest from the list with parameters.
    :param requestElements: list with parameters
    ["SEARCH", <searchedStringPublicKeyHash>, <senderStringPublicKey>, <senderIp>, <senderUpdateDate>, <stringDigitalSignature>, <recursionDepth>, [<checkedPublicKeyHashes>]]
    :return: object of class SearchRequest
    """
    if requestElements[7][1:-1]:
        checkedList = requestElements[7][1:-1].split(",")
    else:
        checkedList = []

    requestUserRecord = dataToUserRecord(
        requestElements[2], requestElements[3], requestElements[4], requestElements[5]
    )
    compiledSearchRequest = SearchRequest(
        requestElements[1], requestUserRecord, int(requestElements[6]), checkedList
    )

    return compiledSearchRequest

def getRequest(message):
    """
    Takes string version of UPDATE or SEARCh request, returns an object of a suitable class.
    :param message:
    :return:
    """
    try:
        receivedRequest = message.split(";")
        requestType = receivedRequest[0]
        if requestType == "SEARCH":
            return compileSearchRequest(receivedRequest)

        elif requestType == "UPDATE":
            return compileUpdateRequest(receivedRequest)

    except Exception as e:
        print(f"Couldn't get request from received string: {e}")

# =====================================================================================================================

def checkIfUserRecord(variable):
    """
    Checks if a variable is of a class UserRecord.
    :param variable:
    :return:
    """
    return type(variable) == UserRecord
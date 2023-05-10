import unittest
import cup2py
import datetime
import random
import string

# IMPORTANT: check that the cwd doesn't have any files in it, except for the 'test_cup2py.py' script.

def randomPassword():
    """
    Generates random strings for testing of AES functions.
    :return:
    """
    length = random.randint(17, 25)
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for _ in range(length))
    return result_str

class TestCup2py(unittest.TestCase):
    def test_generateUserKeyPair(self):
        """
        Generation of User Record - automatically, checks digital signature and attributes.
        :return:
        """
        ip = '8.8.8.8'

        user = cup2py.generateUser('test1', ip)

        ip_check = (user.ip == ip)
        updateDate_check = (user.updateDate < datetime.datetime.now())
        signature_verification = cup2py.checkDigitalSignature(user.message(), user.publicKey, user.digitalSignature)

        self.assertTrue(ip_check and updateDate_check and signature_verification)

    def test_loadKeyPair(self):
        """
        Generation of User Record - keypair generated separately, checks digital signature and attributes.
        :return:
        """
        ip = '8.8.8.8'

        cup2py.generateUserKeyPair('test2')
        priv, pub = cup2py.loadPrivateKey('test2'), cup2py.loadPublicKey('test2')
        user = cup2py.userRecordFromKeyPair(priv, pub, ip)

        publicKey_check = (user.publicKey == pub)
        ip_check = (user.ip == ip)
        updateDate_check = (user.updateDate < datetime.datetime.now())
        signature_verification = cup2py.checkDigitalSignature(user.message(), user.publicKey, user.digitalSignature)

        self.assertTrue(publicKey_check and ip_check and updateDate_check and signature_verification)

    def test_sessionAttribute_chosenUserRecord_correctDatatype(self):
        """
        Generates user, creates a session, sets user as chosenUserRecord.
        :return:
        """
        ip = '8.8.8.8'
        user = cup2py.generateUser('test3', ip)

        s = cup2py.Session()
        s.setDatabaseName('testing.db')
        s.setAddressBook('test3')
        s.createAddressBookInDatabase()
        s.setUser(user)

        self.assertEqual(s.chosenUserRecord, user)

    def test_sessionAttribute_chosenUserRecord_wrongDatatype(self):
        """
        Creates session, tries to set chosenUserRecord as objects of wrong datatypes.
        :return:
        """
        s = cup2py.Session()
        s.setDatabaseName('testing.db')
        s.setAddressBook('test4')
        s.createAddressBookInDatabase()

        s.setUser(123)
        s.setUser('test')

        self.assertEqual(s.chosenUserRecord, None)

    def test_createAddressBookTwice_storeAndGetRecord(self):
        """
        Creates Address Book, adds user record, tries to create this Address Book again,
        gets the record from the Address Book, checks if they are the same.

        Tests if the record can be stored and returned from Address Book.
        Tests that Address Books can't be overwritten.
        Also tests getUserByPublicKeyHash() as it is called by getUser() using the same universal function publicKeyHash().
        :return:
        """
        s = cup2py.Session()
        s.setDatabaseName('testing.db')
        s.setAddressBook('test5')
        s.createAddressBookInDatabase()

        user = cup2py.generateUser('test5', '8.8.8.8')

        user_publicKey = user.publicKey
        user_ip = user.ip
        user_updateDate = user.updateDate
        user_signature = user.digitalSignature

        s.updateAddressBookRecord(user)
        s.createAddressBookInDatabase()

        user_from_address_book = s.getUser(user_publicKey)

        new_user_publicKey = user_from_address_book.publicKey
        new_user_ip = user_from_address_book.ip
        new_user_updateDate = user_from_address_book.updateDate
        new_user_signature = user_from_address_book.digitalSignature

        self.assertEqual(user_publicKey, new_user_publicKey)
        self.assertEqual(user_ip, new_user_ip)
        self.assertEqual(user_updateDate, new_user_updateDate)
        self.assertEqual(user_signature, new_user_signature)

    def test_tryReturnNonExistingRecord(self):
        """
        Tries to get a record which is not in the Address Book.
        :return:
        """
        s = cup2py.Session()
        s.setDatabaseName('testing.db')
        s.setAddressBook('test6')
        s.createAddressBookInDatabase()

        user = cup2py.generateUser('test6', '8.8.8.8')

        non_existing_user = s.getUser(user.publicKey)

        self.assertFalse(non_existing_user)

    def test_generateExistingKeypair(self):
        """
        Generate keypair, stores it, tries to generate the same file, checks if the
        fist generated pair is the same as one stored.
        :return:
        """
        priv, pub = cup2py.generateUserKeyPair('test7')
        cup2py.generateUserKeyPair('test7')
        loaded_priv, loaded_pub = cup2py.loadPrivateKey('test7'), cup2py.loadPublicKey('test7')

        self.assertEqual(priv, loaded_priv)
        self.assertEqual(pub, loaded_pub)

    def test_updateRequestToStringAndBack(self):
        """
        Creates UPDATE request object, turns it into string representation and back into request object.
        :return:
        """
        s = cup2py.Session()
        s.setDatabaseName('testing.db')
        s.setAddressBook('test8')
        s.createAddressBookInDatabase()

        someUser = cup2py.generateUser('test8', '6.6.6.6')

        requestFromUser = cup2py.newUpdateRequest(someUser, updateDepth=4)
        stringFromRequest, ipList = s.updateToSend(requestFromUser, ['1.2.3.4'])
        reuquestFromString = cup2py.getRequest(stringFromRequest)

        userFromRequest = reuquestFromString.userRecord

        user_publicKey = someUser.publicKey
        user_ip = someUser.ip
        user_updateDate = someUser.updateDate
        user_signature = someUser.digitalSignature

        new_user_publicKey = userFromRequest.publicKey
        new_user_ip = userFromRequest.ip
        new_user_updateDate = userFromRequest.updateDate
        new_user_signature = userFromRequest.digitalSignature

        self.assertEqual(user_publicKey, new_user_publicKey)
        self.assertEqual(user_ip, new_user_ip)
        self.assertEqual(user_updateDate, new_user_updateDate)
        self.assertEqual(user_signature, new_user_signature)

        signature_verification = cup2py.checkDigitalSignature(userFromRequest.message(), userFromRequest.publicKey, userFromRequest.digitalSignature)
        self.assertTrue(signature_verification)

    def test_searchRequestToStringAndBack(self):
        """
        Creates SEARCH request object, turns it into string representation and back into request object.
        :return:
        """
        s = cup2py.Session()
        s.setDatabaseName('testing.db')
        s.setAddressBook('test9')
        s.createAddressBookInDatabase()

        someUser = cup2py.generateUser('test9', '6.6.6.6')

        requestFromUser = cup2py.newSearchRequest('a0b6cf0eca84da0ceef68c4c6600658c71a1d2f3653a25b0723cf838ccd4eb6c', someUser, searchDepth=4)
        stringFromRequest, ipList = s.searchToSend(requestFromUser, ['1.2.3.4'])
        reuquestFromString = cup2py.getRequest(stringFromRequest)

        userFromRequest = reuquestFromString.senderUserRecord

        user_publicKey = someUser.publicKey
        user_ip = someUser.ip
        user_updateDate = someUser.updateDate
        user_signature = someUser.digitalSignature

        new_user_publicKey = userFromRequest.publicKey
        new_user_ip = userFromRequest.ip
        new_user_updateDate = userFromRequest.updateDate
        new_user_signature = userFromRequest.digitalSignature

        self.assertEqual(user_publicKey, new_user_publicKey)
        self.assertEqual(user_ip, new_user_ip)
        self.assertEqual(user_updateDate, new_user_updateDate)
        self.assertEqual(user_signature, new_user_signature)

        signature_verification = cup2py.checkDigitalSignature(userFromRequest.message(), userFromRequest.publicKey, userFromRequest.digitalSignature)
        self.assertTrue(signature_verification)

    def test_processUpdateRequestWithRecursionDepthLimit(self):
        """
        Creates UPDATE request with updateDepth == 0, tries to process it.
        :return:
        """
        s = cup2py.Session()
        s.setDatabaseName('testing.db')
        s.setAddressBook('test10')
        s.createAddressBookInDatabase()
        localUser = cup2py.generateUser('test10_local', '1.2.3.4')
        s.setUser(localUser)

        someUser = cup2py.generateUser('test10', '6.6.6.6')

        requestFromUser = cup2py.newUpdateRequest(someUser, updateDepth=0)
        stringFromRequest, ipList = s.updateToSend(requestFromUser, ['10.12.15.14', '1.2.3.4'])

        handledRequest = s.requestHandler(stringFromRequest)

        self.assertEqual(handledRequest, None)

    def test_correctUpdate(self):
        """
        Handles UPDATE request with older record in the Address Book - should change it and return it.
        Also tests UpdateRecord().depthStep()
        :return:
        """
        s = cup2py.Session()
        s.setDatabaseName('testing.db')
        s.setAddressBook('test11')
        s.createAddressBookInDatabase()
        localUser = cup2py.generateUser('test11_local', '1.2.1.2')
        s.setUser(localUser)

        cup2py.generateUserKeyPair('test11')
        priv, pub = cup2py.loadPrivateKey('test11'), cup2py.loadPublicKey('test11')
        user_0 = cup2py.userRecordFromKeyPair(priv, pub, '1.1.1.1')

        s.updateAddressBookRecord(user_0)

        newIp = '2.2.2.2'
        user_1 = cup2py.userRecordFromKeyPair(priv, pub, newIp)
        requestFromUser = cup2py.newUpdateRequest(user_1, updateDepth=3)
        stringFromRequest, ipList = s.updateToSend(requestFromUser, ['10.12.15.14', '1.2.3.4'])
        handledRequest, ipList = s.requestHandler(stringFromRequest)
        request = cup2py.getRequest(handledRequest)

        self.assertEqual(request.updateDepth, 2)
        self.assertTrue(cup2py.publicKeyHash(cup2py.publicKeyToString(localUser.publicKey)) in request.checkedPublicKeyHashes)
        userFromAddressBook = s.getUser(request.userRecord.publicKey)

        self.assertEqual(userFromAddressBook.publicKey, user_0.publicKey, user_1.publicKey)
        self.assertEqual(userFromAddressBook.ip, newIp)
        self.assertNotEqual(userFromAddressBook.ip, '1.1.1.1')

    def test_oldUpdate(self):
        """
        Checks if outdated UPDATE request is going to be ignored.
        :return:
        """
        s = cup2py.Session()
        s.setDatabaseName('testing.db')
        s.setAddressBook('test12')
        s.createAddressBookInDatabase()
        s.setUser(cup2py.generateUser('test12_local', '1.2.1.2'))

        cup2py.generateUserKeyPair('test12')
        priv, pub = cup2py.loadPrivateKey('test12'), cup2py.loadPublicKey('test12')

        user_0 = cup2py.userRecordFromKeyPair(priv, pub, '1.1.1.1')
        user_1 = cup2py.userRecordFromKeyPair(priv, pub, '2.2.2.2')

        s.updateAddressBookRecord(user_1)

        requestFromUser = cup2py.newUpdateRequest(user_0, updateDepth=3)
        stringFromRequest, ipList = s.updateToSend(requestFromUser, ['10.12.15.14', '1.2.3.4'])
        requestResult = s.requestHandler(stringFromRequest)

        userFromAddressBook = s.getUser(user_0.publicKey)

        self.assertEqual(userFromAddressBook.ip, '2.2.2.2')
        self.assertEqual(requestResult, None)

    def test_searchFromString(self):
        """
        Handling string SEARCH request; the record is not found in the Adddress Book
        :return:
        """
        s = cup2py.Session()
        s.setDatabaseName('testing.db')
        s.setAddressBook('test13')
        s.createAddressBookInDatabase()
        s.setUser(cup2py.generateUser('test13_local', '1.2.1.2'))

        stringPublicKey = "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAKgrzOf9CyaDXONfTqiOcT1dYrz5KKkoSCB0QWZUjQ0WfMb3muvwtCU/\ndNuqp7wvRITT0B3Sh5Nllq2rYVK3tKiF9PHEFs3HcyyCb1b3EXoAUCVbdzorllDz\nYEH8xp26pvDI5G0A1oWl0BgOEbmpemT4t9GeRp8t2qH6GRXvhjcXAgMBAAE=\n-----END RSA PUBLIC KEY-----\n"
        resultingRequestString, ipList = s.requestHandler(f'SEARCH;'
                                         f'7c53d01b56c06c5b605293afcbe6daaa5f7d6d9d748f291c47e0b6acc6b53c34;'
                                         f'{stringPublicKey};'
                                         f'1.2.3.4;'
                                         f'2023-04-27 22:25:19.167142;'
                                         f'j7psde5DeokYLVPlaNWWahZH+AHt6/453GKZQgjzv9+kK2JWC5qMI23uugyhO/O9L/0Cdx/UOcKWZtCI1OnCcYK9Zm0TVrejJo8z6mbEnLmYUPepPUEr8SdJ6RkAUNySBuM/YzLw/cdUiB7m31sYvRvWWN5oSR+vhYU7HIBecT4=;'
                                         f'1;'
                                         f'[46270c88bd690bf60f9827e9ad45f9209b8de259fc4c4f467a539b0839ff5cf3,'
                                         f'5d823d8f4275c07177c4c86f99a6e54675174f05350f36b3969425456708a5aa,'
                                         f'c6c3274051c92e00fd4387e7a38767b9829188b3e0c85705747c83765178bea5]')

        resultingRequest = cup2py.getRequest(resultingRequestString)

        req_searchedHash = resultingRequest.searchedPublicKeyHash
        req_searchDepth = resultingRequest.searchDepth
        req_userRecord = resultingRequest.senderUserRecord
        req_checkedPublicKeyHashes = resultingRequest.checkedPublicKeyHashes

        local_hash = cup2py.publicKeyHash(cup2py.publicKeyToString(s.chosenUserRecord.publicKey))

        self.assertEqual(cup2py.publicKeyToString(req_userRecord.publicKey), stringPublicKey)
        self.assertEqual(req_searchedHash, '7c53d01b56c06c5b605293afcbe6daaa5f7d6d9d748f291c47e0b6acc6b53c34')
        self.assertEqual(req_searchDepth, 0)
        self.assertEqual(req_checkedPublicKeyHashes, ['46270c88bd690bf60f9827e9ad45f9209b8de259fc4c4f467a539b0839ff5cf3','5d823d8f4275c07177c4c86f99a6e54675174f05350f36b3969425456708a5aa', 'c6c3274051c92e00fd4387e7a38767b9829188b3e0c85705747c83765178bea5', local_hash])

    def test_updateFromString(self):
        """
        Handling string UPDATE request;
        :return:
        """
        s = cup2py.Session()
        s.setDatabaseName('testing.db')
        s.setAddressBook('test14')
        s.createAddressBookInDatabase()
        s.setUser(cup2py.generateUser('test14_local', '1.2.1.2'))

        stringPublicKey = "-----BEGIN RSA PUBLIC KEY-----\n" \
                               "MIGJAoGBAJjFY391xRrNVAeJbkbp4rozwQpUuv3hrGGfOjh+TWtUlD43Ss9wCNHF\n" \
                               "z71EJrDcgOwr5AZJq6UjeNMFnxmKQvHBtoXQhH74AiQ54MQr6oAambcwqsQpMLCC\n" \
                               "SzQwy0qmiuxR8ZK7CQkKu8WG3xyEaDco4aycXUavW86u6uV/mCzvAgMBAAE=\n" \
                               "-----END RSA PUBLIC KEY-----\n"

        requestOutput = s.requestHandler(f"UPDATE;"
                                         f"{stringPublicKey};"
                                         f"31.205.18.217;2023-04-27 22:25:19.167142;"
                                         f"j7psde5DeokYLVPlaNWWahZH+AHt6/453GKZQgjzv9+kK2JWC5qMI23uugyhO/O9L/0Cdx/UOcKWZtCI1OnCcYK9Zm0TVrejJo8z6mbEnLmYUPepPUEr8SdJ6RkAUNySBuM/YzLw/cdUiB7m31sYvRvWWN5oSR+vhYU7HIBecT4=;"
                                         f"2;"
                                         f"[]")
        if type(requestOutput) == tuple:
            resultingRequestString, ipList = requestOutput

            resultingRequest = cup2py.getRequest(resultingRequestString)

            req_userRecord = resultingRequest.userRecord
            req_updateDepth = resultingRequest.updateDepth
            req_checkedPublicKeyHashes = resultingRequest.checkedPublicKeyHashes

            local_hash = cup2py.publicKeyHash(cup2py.publicKeyToString(s.chosenUserRecord.publicKey))

            self.assertEqual(cup2py.publicKeyToString(req_userRecord.publicKey), stringPublicKey)
            self.assertEqual(req_checkedPublicKeyHashes, [local_hash])
            self.assertEqual(req_updateDepth, 1)

            userInAddressBook = s.getUser(cup2py.stringToPublicKey(stringPublicKey))
            print(userInAddressBook)
            self.assertTrue(userInAddressBook)
        else:
            self.assertTrue(False)


    def test_searchRequestFoundUserRecord(self):
        """
        Creates User Record, adds to Address Book; Creates and handles SEARCH request. Should return list with [UPDATE, SEARCH]
        :return:
        """
        s = cup2py.Session()
        s.setDatabaseName('testing.db')
        s.setAddressBook('test15')
        s.createAddressBookInDatabase()
        localUser = cup2py.generateUser('test15_local', '1.2.1.2')
        s.setUser(localUser)

        cup2py.generateUserKeyPair('test15')
        priv, pub = cup2py.loadPrivateKey('test15'), cup2py.loadPublicKey('test15')
        user_0 = cup2py.userRecordFromKeyPair(priv, pub, '1.1.1.1')

        s.updateAddressBookRecord(user_0)

        searchedHash = cup2py.publicKeyHash(cup2py.publicKeyToString(user_0.publicKey))
        requestFromUser = cup2py.newSearchRequest(searchedHash, localUser, searchDepth=4)
        requestString = requestFromUser.requestString()
        handlingResult = s.requestHandler(requestString)

        self.assertEqual(type(handlingResult), list)

        update, ipList1 = handlingResult[0]
        search, ipList2 = handlingResult[1]

        updateRequest = cup2py.getRequest(update)
        searchRequest = cup2py.getRequest(search)

        self.assertEqual(updateRequest.userRecord.publicKey, user_0.publicKey)
        self.assertEqual(searchRequest.senderUserRecord.publicKey, localUser.publicKey)

    def test_searchRequestDepthLimit(self):
        """
        Tries to handle SEARCH request with searchDepth == 0.
        :return:
        """
        s = cup2py.Session()
        s.setDatabaseName('testing.db')
        s.setAddressBook('test16')
        s.createAddressBookInDatabase()
        localUser = cup2py.generateUser('test16_local', '1.2.1.2')
        s.setUser(localUser)

        cup2py.generateUserKeyPair('test16')
        priv, pub = cup2py.loadPrivateKey('test16'), cup2py.loadPublicKey('test16')
        user_0 = cup2py.userRecordFromKeyPair(priv, pub, '1.1.1.1')

        s.updateAddressBookRecord(user_0)

        searchedHash = cup2py.publicKeyHash(cup2py.publicKeyToString(user_0.publicKey))
        requestFromUser = cup2py.newSearchRequest(searchedHash, localUser, searchDepth=0)
        requestString = requestFromUser.requestString()
        handlingResult = s.requestHandler(requestString)

        self.assertEqual(handlingResult, None)

    def test_searchRequestNotFoundUserRecord(self):
        """
        Handles SEARCH request, searched User Record is not in Address Book. Returns updated SEARCH request.
        :return:
        """
        s = cup2py.Session()
        s.setDatabaseName('testing.db')
        s.setAddressBook('test17')
        s.createAddressBookInDatabase()
        localUser = cup2py.generateUser('test17_local', '1.2.1.2')
        s.setUser(localUser)

        cup2py.generateUserKeyPair('test17')
        priv, pub = cup2py.loadPrivateKey('test17'), cup2py.loadPublicKey('test17')
        user_0 = cup2py.userRecordFromKeyPair(priv, pub, '1.1.1.1')

        searchedHash = cup2py.publicKeyHash(cup2py.publicKeyToString(user_0.publicKey))
        requestFromUser = cup2py.newSearchRequest(searchedHash, localUser, searchDepth=4)
        requestString = requestFromUser.requestString()
        handlingResult, ipList = s.requestHandler(requestString)
        handledRequest = cup2py.getRequest(handlingResult)
        self.assertEqual(type(handledRequest), cup2py.SearchRequest)
        self.assertEqual(handledRequest.searchDepth, 3)
        self.assertTrue(cup2py.publicKeyHash(cup2py.publicKeyToString(localUser.publicKey)) in handledRequest.checkedPublicKeyHashes)

    def test_encryptAndDecryptPrivateKey(self):
        """
        Test if AESDemo encryption and decryption of private keys works correctly with random passwords.
        :return:
        """
        password = randomPassword()
        localName = 'test18'
        cup2py.generateUserKeyPair(localName)
        priv = cup2py.loadPrivateKey(localName)

        cup2py.encryptPrivateKey(localName, password)
        cup2py.decryptPrivateKey(localName, password)

        privAfter = cup2py.loadPrivateKey(localName)

        self.assertEqual(priv, privAfter)

    def test_wrongRequestString(self):
        """
        Tests reqeustHandler(), getRequest() for wrong inputs.
        :return:
        """
        s = cup2py.Session()
        s.setDatabaseName('testing.db')
        s.setAddressBook('test19')
        s.createAddressBookInDatabase()
        localUser = cup2py.generateUser('test19_local', '1.2.1.2')
        s.setUser(localUser)

        string_1 = 'if this project is not going to get 100%, I might lose my faith in humanity. And Lagos is a beautiful city.'
        string_2 = 12345
        string_3 = 0.1
        output_1 = s.requestHandler(string_1)
        output_2 = s.requestHandler(string_2)
        output_3 = s.requestHandler(string_3)

        self.assertEqual(output_1, None)
        self.assertEqual(output_2, None)
        self.assertEqual(output_3, None)

    def test_wrongSignature(self):
        """
        Tries to verify incorrect Digital Signature.
        :return:
        """
        isVerified = cup2py.checkDigitalSignature('123', '234', '345')
        self.assertFalse(isVerified)

if __name__ == '__main__':
    unittest.main()
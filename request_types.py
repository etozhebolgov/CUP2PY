class UpdateRequest:
    def __init__(self, userRecord, updateDepth, checkedPublicKeyHashes=[]):
        """
        Class for data type UpdateRequest: request to introduce a new user or update existing one.
        (User sends it to all users on his AB, they check the digital signature,
            and if it is verified they 1) add it to their AB, 2) pass it further. Until updateDepth == 0)

        :param userRecord: a record of data type userRecord
        :param updateDepth: The recursion depth for the update.
        :param checkedPublicKeyHashes: The list of public key hashes of users who already had this request sent to.
        """
        self.userRecord = userRecord

        self.updateDepth = updateDepth
        self.checkedPublicKeyHashes = checkedPublicKeyHashes

    def depthStep(self, localStringPublicKeyHash):
        """
        Updates recursion depth, adds local public key hash to the list of checked public key hashes.
        :param localStringPublicKeyHash:
        :return:
        """
        self.updateDepth -= 1
        self.checkedPublicKeyHashes.append(localStringPublicKeyHash)

    def requestString(self):
        """
        Creates formatted string from request to send.
        :return:
        """
        # UPDATE;STRING_PUBLIC_KEY;IP;UPDATE_DATE;STRING_DIGITAL_SIGNATURE;DEPTH;[PKU1, PKU2, PKU3, ...] <- Hashes
        userRecordValues = self.userRecord.tuple()

        listString = str(self.checkedPublicKeyHashes).replace("'", "").replace(" ", "")

        return f"UPDATE;{userRecordValues[1]};{userRecordValues[2]};{userRecordValues[3]};{userRecordValues[4].decode()};{self.updateDepth};{listString}"


def newUpdateRequest(userRecord, updateDepth=3, checkedPublicKeys=[]):
    """
    Function which takes object of type userRecord and the value for recursion depth and returns object of type updateRequest.
    :param userRecord: Object of type userRecord.
    :param updateDepth: Value for recursion depth.
    :return: Object of type updateRequest.
    """
    updateRequest = UpdateRequest(userRecord, updateDepth, checkedPublicKeys)
    return updateRequest


# =====================================================================================================================


class SearchRequest:
    def __init__(
        self,
        searchedPublicKeyHash,
        senderUserRecord,
        searchDepth,
        checkedPublicKeyHashes=[],
    ):
        """
        Class for data type SearchRequest: request to find a users latest IpuserRecord by his Public Key.
        (to then add it to the AB and use the ip it contains)

        :param searchedPublicKeyHash: The public key which we are trying to find.
        :param senderPublicKey: The public key of a user which requested the search.
        :param searchDepth: The recursion depth for the search.
        :param checkedPublicKeys: The list of public keys of users who already had this request sent to.
        """
        self.searchedPublicKeyHash = searchedPublicKeyHash

        self.senderUserRecord = senderUserRecord

        self.searchDepth = searchDepth
        self.checkedPublicKeyHashes = checkedPublicKeyHashes

    def depthStep(self, localStringPublicKey):
        """
        Updates recursion depth, adds local public key hash to the list of checked public key hashes.
        :param localStringPublicKey:
        :return:
        """
        self.searchDepth -= 1
        self.checkedPublicKeyHashes.append(localStringPublicKey)

    def requestString(self):
        """
        Creates formatted string from request to send.
        :return:
        """
        # SEARCH;STRING_PUBLIC_KEY_HASH(SEARCHED);SENDER_STRING_PUBLIC_KEY,IP;UPDATE_DATE;STRING_DIGITAL_SIGNATURE;DEPTH;[...]
        userRecordValues = self.senderUserRecord.tuple()

        listString = str(self.checkedPublicKeyHashes).replace("'", "").replace(" ", "")

        return f"SEARCH;{self.searchedPublicKeyHash};{userRecordValues[1]};{userRecordValues[2]};{userRecordValues[3]};{userRecordValues[4].decode()};{self.searchDepth};{listString}"


def newSearchRequest(
    searchedPublicKeyHash, senderUserRecord, searchDepth=3, checkedPublicKeyHashes=[]
):
    """
    Function which creates new objects of datatype SearchRecord.
    :param searchedPublicKeyHash:
    :param senderUserRecord:
    :param searchDepth:
    :param checkedPublicKeyHashes:
    :return:
    """
    searchRequest = SearchRequest(
        searchedPublicKeyHash, senderUserRecord, searchDepth, checkedPublicKeyHashes
    )
    return searchRequest

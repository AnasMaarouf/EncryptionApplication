# EncryptionApplication
Encryption and decryption application which encrypts files within the given folder (including files in the subfolders of the given folder).

# "Fisher-Yates shuffle" algorithm
The shuffle algorithm run several times during ONE SINGLE encryption or decryption process. This is a lot to compute with specifically large encryptionkey, as the Big-O notation is O(DataSize * KeySize), where "DataSize" is the number of bytes from the data, and "KeySize" is the number of bytes in the encryption key. It is run (the number of bytes in the encryptionkey) of times, using each byte of the encryptionkey as the seed for the random number generation, to be used as the index of the data which will be swapped.
The reason to shuffle the data the number of bytes in the encryptionkey, with the combination of using each byte of the key as the seed for the random number generation, is to make it more dependent on the encryptionkey, than to sum each byte of the key and using that with the fisher-yates shuffle algorithm once.

# XOR-encryption and addition/Subtraction-encryption
These are used as an additional measure to

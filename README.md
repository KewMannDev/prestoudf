# Trino UDF | Gradle | Docker

The framework can be used to write, build and test User Defined Functions for Trino locally. This project uses gradle file to build the jar. Find the steps below to build and test the UDF written here.
- Clone the repo ```  git clone https://github.com/KewMannDev/trino-encryption-at-rest  ```
- build the repo with Gradle: `gradle clean build`

Once the build is complete, execute the below commands (from the folder where the make file exists)
- ```  cd docker-trino-cluster  ```
- ```  make all  ```
- ```  cd kudu-trino-docker/docker-trino-cluster  ```  
- ```  make run-with-logs ``` If you want to see the logs which will show that your UDF is loaded  

#### Plugin Installation.
1. Stop Trino service.
2. Create a folder called `udfs` in Trino's plugin directory.
3. Put `trino-encryption-at-rest-1.0.jar` into the `udfs` directory.
4. Start Trino service.

#### Trino UDF tested succesfully
![Successful Testing of UDF](https://media.giphy.com/media/If0etk7IQZL9aExA2q/giphy.gif)

#### Supported Data Types for Encryption and Decryption.
Encryption is done with AES CBC. Please note that `decrypt_aes()` function return results as `VARCHAR`.
- TIMESTAMP (<b>***Note:</b> decrypted result will be in EPOCH format)
  <br/> e.g. 
  <br/>`SELECT encrypt_aes(TIMESTAMP '2020-06-10 15:55:23', 'aesEncryptionKey', 'encryptionIntVec');`
  <br/>`SELECT decrypt_aes('5bmR8Hbvvtux0YXWCfshmvULTEQSQJEHVqTL5mDcZAc=', 'aesEncryptionKey','encryptionIntVec');`
- DATE (<b>***Note:</b> decrypted result will be in EPOCH format.) 
  <br/>(i.e. Number of days from current date to 1st Jan 1970)
  <br/> e.g.
  <br/>`SELECT encrypt_aes(DATE'2021-01-07', 'aesEncryptionKey','encryptionIntVec');`
  <br/>`SELECT decrypt_aes('o4TD0ocZxXVb9GNXbgGdRw==', 'aesEncryptionKey','encryptionIntVec');`
- INTEGER
  <br/> e.g.
  <br/> `SELECT encrypt_aes(INTEGER'2', 'aesEncryptionKey','encryptionIntVec');`
  <br/> `SELECT decrypt_aes('fcIq+td9rGOdwQBfFxQ+hQ==','aesEncryptionKey','encryptionIntVec');`
- BIGINT
  <br/> e.g.
  <br/> `SELECT encrypt_aes(BIGINT'2', 'aesEncryptionKey','encryptionIntVec');`
  <br/> `SELECT decrypt_aes('fcIq+td9rGOdwQBfFxQ+hQ==', 'aesEncryptionKey','encryptionIntVec');`
- SMALLINT
  <br/> e.g.
  <br/> `SELECT encrypt_aes(SMALLINT'2', 'aesEncryptionKey','encryptionIntVec');`
  <br/> `SELECT decrypt_aes('fcIq+td9rGOdwQBfFxQ+hQ==', 'aesEncryptionKey','encryptionIntVec');`
- BOOLEAN
  <br/> e.g.
  <br/> `SELECT encrypt_aes(BOOLEAN'false', 'aesEncryptionKey','encryptionIntVec');`
  <br/> `SELECT decrypt_aes('Q4IMMUqyg1593AyrBi/9Ng==','aesEncryptionKey','encryptionIntVec');`
- CHAR
  <br/> e.g.
  <br/> `SELECT encrypt_aes(CHAR'a', 'aesEncryptionKey','encryptionIntVec');`
  <br/> `SELECT decrypt_aes('slwc7guak65+GvHr4xte3g==', 'aesEncryptionKey','encryptionIntVec');`
- JSON
  <br/> e.g.
  <br/> `SELECT encrypt_aes(JSON'{"test":"test"}', 'aesEncryptionKey','encryptionIntVec');`
  <br/> `SELECT decrypt_aes('EYwChBJWPl0z/SEx7SHOVg==', 'aesEncryptionKey','encryptionIntVec');`
- VARBINARY
  <br/> e.g.
  <br/> `SELECT encrypt_aes(X'65683F', 'aesEncryptionKey','encryptionIntVec');`
  <br/> `SELECT decrypt_aes('+NbU9fmJIkyc82MoYje6ag==', 'aesEncryptionKey','encryptionIntVec');`
- VARCHAR
  <br/> e.g.
  <br/> `SELECT encrypt_aes('hello', 'aesEncryptionKey','encryptionIntVec');`
  <br/> `SELECT decrypt_aes('rcEnllV7eBFiRdDF1WPlWg==', 'aesEncryptionKey','encryptionIntVec');`
- DOUBLE
  <br/> e.g.
  <br/> `SELECT encrypt_aes(DOUBLE'2.2', 'aesEncryptionKey','encryptionIntVec');`
  <br/> `SELECT decrypt_aes('nE2X2dbrCP1+UsSVxwW1XA==', 'aesEncryptionKey','encryptionIntVec');`
- IPADDRESS
  <br/> e.g.
  <br/> `SELECT encrypt_aes(IPADDRESS'255.255.255.255', 'aesEncryptionKey','encryptionIntVec');`
  <br/> `SELECT decrypt_aes_ip('oJQGwsOud1zAT0IVbNVlrZSDe37eIEokK2MT/7C5W+g=', 'aesEncryptionKey','encryptionIntVec');`
- UUID
  <br/> e.g.
  <br/> `SELECT encrypt_aes(UUID '12151fd2-7586-11e9-8f9e-2a86e4085a59', 'aesEncryptionKey','encryptionIntVec');`
  <br/> `SELECT decrypt_aes_uuid('z055LZcjp/tYoagILaYYVmk1GmqVOC3FXhGII/wC3G0=', 'aesEncryptionKey','encryptionIntVec');`
- HyperLogLog
  <br/> e.g.
  <br/> `SELECT encrypt_aes(cast(X'65683F' AS HyperLogLog),'aesEncryptionKey','encryptionIntVec');`
  <br/> `SELECT decrypt_aes('dHOVkKfJIRWVtakUgw+H6w==','aesEncryptionKey','encryptionIntVec');`

#### Binary Decryption
Data can be decrypted to VARBINARY by using `decrypt_aes_binary()` function.
<br/> e.g.
<br/> `SELECT decrypt_aes_binary('dHOVkKfJIRWVtakUgw+H6w==', 'aesEncryptionKey','encryptionIntVec');`

#### Non Supported Data Types
The following are the data types which will need to be cast to `VARCHAR` before encrypting:
- REAL
- DECIMAL
- TIME

<br/>e.g.
<br/> `SELECT encrypt_aes(CAST(REAL '2.2' AS VARCHAR), 'aesEncryptionKey','encryptionIntVec');`
<br/> `SELECT decrypt_aes('1VNUqYxcuI3V9mR57TQH6Q==', 'aesEncryptionKey','encryptionIntVec');`

The following are the data types which will need to be cast to `VARBINARY` before encrypting:
- P4HyperLogLog
- QDigest
- TDigest

### Credits

 - [jampp](https://github.com/jampp)/**[presto-udfs](https://github.com/jampp/presto-udfs)**

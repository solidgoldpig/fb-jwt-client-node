/* eslint-disable prefer-promise-reject-errors */

const test = require('tape')

const aes256 = require('./fb-jwt-aes256')

/* test values */
const userToken = 'testUserToken'
const data = '{"foo":"bar"}'
const expectedEncryptedData = 'RRqDeJRQlZULKx1NYql/imRmDsy9AZshKozgLuY='
const expectedEncryptedDataWithIV = 'lGqo0ndPhzip43NWVjCRbcVPzdGsNzDwkzJy7Ck='

// Decrypting user data
test('When decrypting data and failing to pass a key', async t => {
  try {
    aes256.decrypt(undefined, data)
    t.notOk(true, 'it should throw an error')
  } catch (e) {
    t.equal(e.name, 'FBJWTAES256Error', 'it should return an error object of the correct type')
    t.equal(e.code, 'ENODECRYPTKEY', 'it should return correct error code')
    t.equal(e.message, 'Key must be a non-empty string', 'it should return the correct error message')
  }

  t.end()
})

test('When decrypting data and failing to pass a value to decrypt', async t => {
  try {
    aes256.decrypt(userToken, undefined)
    t.notOk(true, 'it should throw an error')
  } catch (e) {
    t.equal(e.name, 'FBJWTAES256Error', 'it should return an error object of the correct type')
    t.equal(e.code, 'ENODECRYPTVALUE', 'it should return correct error code')
    t.equal(e.message, 'Encrypted value must be a non-empty string', 'it should return the correct error message')
  }

  t.end()
})

test('When decrypting data', async t => {
  const decryptedData = aes256.decrypt(userToken, expectedEncryptedData)
  t.deepEqual(data, decryptedData, 'it should return the correct data from valid encrypted input')

  t.end()
})

// Encrypting data
test('When encrypting data and failing to pass a key', async t => {
  try {
    aes256.encrypt(undefined, data)
    t.notOk(true, 'it should throw an error')
  } catch (e) {
    t.equal(e.name, 'FBJWTAES256Error', 'it should return an error object of the correct type')
    t.equal(e.code, 'ENOENCRYPTKEY', 'it should return correct error code')
    t.equal(e.message, 'Key must be a non-empty string', 'it should return the correct error message')
  }

  t.end()
})

test('When encrypting data and failing to pass a value to encrypt', async t => {
  try {
    aes256.encrypt(userToken, undefined)
    t.notOk(true, 'it should throw an error')
  } catch (e) {
    t.equal(e.name, 'FBJWTAES256Error', 'it should return an error object of the correct type')
    t.equal(e.code, 'ENOENCRYPTVALUE', 'it should return correct error code')
    t.equal(e.message, 'Plaintext value must be a non-empty string', 'it should return the correct error message')
  }

  t.end()
})

test('When encrypting data', async t => {
  const encryptedData = aes256.encrypt(userToken, data)
  const decryptedData = aes256.decrypt(userToken, encryptedData)
  t.equal(data, decryptedData, 'it should encrypt the data correctly')
  // NB. have to decrypt the encryptedData to check
  // since the Initialization Vector guarantees the output will be different each time

  const encryptedDataAgain = aes256.encrypt(userToken, data)
  t.notEqual(encryptedDataAgain, encryptedData, 'it should not return the same value for the same input')

  t.end()
})

test('When encrypting data with a provided IV seed', async t => {
  const encryptedData = aes256.encrypt(userToken, data, 'ivSeed')
  t.equal(encryptedData, expectedEncryptedDataWithIV, 'it should encrypt the data correctly')

  const encryptedDataAgain = aes256.encrypt(userToken, data, 'ivSeed')
  t.equal(encryptedDataAgain, encryptedData, 'it should return the same value for the same input')

  t.end()
})

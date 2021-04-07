const crypto = require('crypto')
const CIPHER_ALGORITHM = 'aes-256-ctr'

const {FBError} = require('@solidgoldpig/fb-utils-node')
class FBJWTAES256Error extends FBError {}

/**
   * Encrypt a clear-text message using AES-256 plus an Initialization Vector.
   *
   * @param {string} key
   * A passphrase of any length to used to generate a symmetric session key.
   *
   * @param {string} plaintext
   * The clear-text message to be encrypted.
   *
   * @param {string} [ivSeed]
   * Seed to use as Initialization Vector.
   *
   * @return {string}
   * A custom-encrypted version of the input.
   *
   * @public
   * @method
   */
const encrypt = (key, plaintext, ivSeed) => {
  if (typeof key !== 'string' || !key) {
    throw new FBJWTAES256Error('Key must be a non-empty string', {
      error: {
        code: 'ENOENCRYPTKEY'
      }
    })
  }
  if (typeof plaintext !== 'string' || !plaintext) {
    throw new FBJWTAES256Error('Plaintext value must be a non-empty string', {
      error: {
        code: 'ENOENCRYPTVALUE'
      }
    })
  }

  const sha256 = crypto.createHash('sha256')
  sha256.update(key)

  // Initialization Vector
  const iv = ivSeed ? crypto.createHash('md5').update(ivSeed).digest() : crypto.randomBytes(16)

  const cipher = crypto.createCipheriv(CIPHER_ALGORITHM, sha256.digest(), iv)
  const ciphertext = cipher.update(Buffer.from(plaintext))
  const encrypted = Buffer.concat([iv, ciphertext, cipher.final()]).toString('base64')

  return encrypted
}

/**
   * Decrypt an encrypted message back to clear-text using AES-256 plus an Initialization Vector.
   *
   * @param {string} key
   * A passphrase of any length to used to generate a symmetric session key.
   *
   * @param {string} encrypted
   * The encrypted message to be decrypted.
   *
   * @return {string}
   * The original plain-text message.
   *
   * @public
   * @method
   */
const decrypt = (key, encrypted) => {
  if (typeof key !== 'string' || !key) {
    throw new FBJWTAES256Error('Key must be a non-empty string', {
      error: {
        code: 'ENODECRYPTKEY'
      }
    })
  }
  if (typeof encrypted !== 'string' || !encrypted) {
    throw new FBJWTAES256Error('Encrypted value must be a non-empty string', {
      error: {
        code: 'ENODECRYPTVALUE'
      }
    })
  }

  const sha256 = crypto.createHash('sha256')
  sha256.update(key)

  const input = Buffer.from(encrypted, 'base64')

  if (input.length < 17) {
    throw new TypeError('Provided "encrypted" must decrypt to a non-empty string')
  }

  // Initialization Vector
  const iv = input.slice(0, 16)
  const decipher = crypto.createDecipheriv(CIPHER_ALGORITHM, sha256.digest(), iv)

  const ciphertext = input.slice(16)
  const plaintext = decipher.update(ciphertext) + decipher.final()

  return plaintext
}

module.exports = {
  encrypt,
  decrypt
}

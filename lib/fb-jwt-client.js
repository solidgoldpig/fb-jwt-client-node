const got = require('got')
const merge = require('got/source/merge')
const jwt = require('jsonwebtoken')
const pathToRegexp = require('path-to-regexp')
const crypto = require('crypto')

const aes256 = require('./fb-jwt-aes256')

const {FBError} = require('@solidgoldpig/fb-utils-node')
class FBJWTClientError extends FBError {}

// algo to encrypt user data with
const algorithm = 'HS256'

const getResponseLabels = (response) => {
  const responseLabels = {
    status_code: response.statusCode
  }
  if (response.statusMessage) {
    responseLabels.status_message = response.statusMessage
  }
  if (response.name) {
    responseLabels.error_name = response.name
  }
  return responseLabels
}

const getErrorStatusCode = (message) => {
  let statusCode = 500
  if (message === 'ENOTFOUND') {
    // no dns resolution
    statusCode = 502
  } else if (message === 'ECONNREFUSED') {
    // connection rejected
    statusCode = 503
  }
  return statusCode
}

/**
 * Creates client using JSON Web Tokens
 * @class
 */
class FBJWTClient {
  /**
   * Initialise client
   *
   * @param {string} serviceSecret
   * Service secret
   *
   * @param {string} serviceToken
   * Service token
   *
   * @param {string} serviceSlug
   * Service slug
   *
   * @param {string} microserviceUrl
   * URL of microservice to communicate with
   *
   * @param {error} [errorClass]
   * Error class (defaults to FBJWTClientError)
   *
   * @return {object}
   **/
  constructor (serviceSecret, serviceToken, serviceSlug, microserviceUrl, errorClass) {
    if (errorClass) {
      this.ErrorClass = errorClass
    }
    if (!serviceSecret) {
      this.throwRequestError('ENOSERVICESECRET', 'No service secret passed to client')
    }
    if (!serviceToken) {
      this.throwRequestError('ENOSERVICETOKEN', 'No service token passed to client')
    }
    if (!serviceSlug) {
      this.throwRequestError('ENOSERVICESLUG', 'No service slug passed to client')
    }
    if (!microserviceUrl) {
      this.throwRequestError('ENOMICROSERVICEURL', 'No microservice url passed to client')
    }

    this.serviceSecret = serviceSecret
    this.serviceToken = serviceToken
    this.serviceUrl = microserviceUrl
    this.serviceSlug = serviceSlug

    // provide default Prometheus startTimer behaviour so as not to have to wrap all instrumentation calls in conditionals
    const defaultMetrics = {
      startTimer: () => {
        return () => {}
      }
    }
    this.apiMetrics = Object.assign({}, defaultMetrics)
    this.requestMetrics = Object.assign({}, defaultMetrics)
  }

  /**
   * Add metrics recorders for requests
   *
   * @param {object} apiMetrics
   * Prometheus histogram instance
   *
   * @param {object} requestMetrics
   * Prometheus histogram instance
   *
   * @return {undefined}
   *
   **/
  setMetricsInstrumentation (apiMetrics, requestMetrics) {
    this.apiMetrics = apiMetrics
    this.requestMetrics = requestMetrics
  }

  /**
   * Generate access token
   *
   * @param {string} [data]
   * Request data
   *
   * @return {string}
   * Access token
   *
   **/
  generateAccessToken (data) {
    // NB. jsonwebtoken helpfully sets ‘iat’ option by default
    const checksum = crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex')
    const payload = {checksum}
    const accessToken = jwt.sign(payload, this.serviceToken, {algorithm})
    return accessToken
  }

  /**
   * Encrypt data with AES 256
   *
   * @param {string} token
   * Token
   *
   * @param {any} data
   * Request data
   *
   * @param {string} [ivSeed]
   * Initialization Vector
   *
   * @return {string}
   * Encrypted data
   *
   **/
  encrypt (token, data, ivSeed) {
    const dataString = JSON.stringify(data)
    const encryptedData = aes256.encrypt(token, dataString, ivSeed)
    return encryptedData
  }

  /**
   * Decrypt data
   *
   * @param {string} token
   * Token
   *
   * @param {string} encryptedData
   * Encrypted data
   *
   * @return {string}
   * Decrypted data
   *
   **/
  decrypt (token, encryptedData) {
    let data
    try {
      data = aes256.decrypt(token, encryptedData)
      data = JSON.parse(data)
    } catch (e) {
      this.throwRequestError(500, 'EINVALIDPAYLOAD')
    }
    return data
  }

  /**
   * Encrypt user ID and token using service secret
   *
   * Guaranteed to return the same value
   *
   * @param {string} userId
   * User ID
   *
   * @param {string} userToken
   * User token
   *
   * @return {string}
   *
   **/
  encryptUserIdAndToken (userId, userToken) {
    const serviceSecret = this.serviceSecret
    const ivSeed = userId + userToken
    return this.encrypt(serviceSecret, {userId, userToken}, ivSeed)
  }

  /**
   * Decrypt user ID and token using service secret
   *
   * @param {string} encryptedData
   * Encrypted user ID and token
   *
   * @return {object}
   *
   **/
  decryptUserIdAndToken (encryptedData) {
    const serviceSecret = this.serviceSecret
    return this.decrypt(serviceSecret, encryptedData)
  }

  /**
   * Create user-specific endpoint
   *
   * @param {string} urlPattern
   * Uncompiled pathToRegexp url pattern
   *
   * @param {object} context
   * Object of values to substitute
   *
   * @return {string}
   * Endpoint URL
   *
   **/
  createEndpointUrl (urlPattern, context = {}) {
    const toPath = pathToRegexp.compile(urlPattern)
    const endpointUrl = this.serviceUrl + toPath(context)
    return endpointUrl
  }

  /**
   * Create request options
   *
   * @param {string} urlPattern
   * Uncompiled pathToRegexp url pattern
   *
   * @param {string} context
   * User ID
   *
   * @param {object} [data]
   * Payload
   *
   * @param {boolean} [searchParams]
   * Send payload as query string
   *
   * @return {object}
   * Request options
   *
   **/
  createRequestOptions (urlPattern, context, data = {}, searchParams) {
    const accessToken = this.generateAccessToken(data)
    const url = this.createEndpointUrl(urlPattern, context)
    const hasData = Object.keys(data).length
    const json = hasData && !searchParams ? data : true
    const requestOptions = {
      url,
      headers: {
        'x-access-token': accessToken
      }
    }
    if (hasData && !searchParams) {
      requestOptions.body = json
    }
    if (searchParams && hasData) {
      requestOptions.searchParams = {
        payload: Buffer.from(JSON.stringify(data)).toString('Base64')
      }
    }
    requestOptions.json = true
    return requestOptions
  }

  logError (type, error, labels, logger) {
    const errorResponse = error.error || error.body
    const errorResponseObj = typeof errorResponse === 'object' ? JSON.stringify(errorResponse) : ''

    if (error.gotOptions) {
      error.client_headers = error.gotOptions.headers
    }
    const logObject = Object.assign({}, labels, {error})

    logger.error(logObject, `JWT ${type} request error: ${this.constructor.name}: ${labels.method.toUpperCase()} ${labels.base_url}${labels.url} - ${error.name} - ${error.code ? error.code : ''} - ${error.statusCode ? error.statusCode : ''} - ${error.statusMessage ? error.statusMessage : ''} - ${errorResponseObj}`)
  }

  /**
   * Handle client requests
   *
   * @param {string} method
   * Method for request
   *
   * @param {object} args
   * Args for request
   *
   * @param {string} args.urlPattern
   * Url pattern for request
   *
   * @param {object} args.context
   * Context for url pattern substitution
   *
   * @param {object} [args.payload]
   * Payload to send as query param to endpoint
   *
   * @param {object} [args.sendOptions]
   * Additional options to pass to got method
   *
   * @param {object} [logger]
   * Bunyan logger instance
   *
   * @return {object}
   * Returns JSON object or handles exception
   *
   **/
  async send (method, args, logger) {
    const {
      url,
      context = {},
      payload,
      sendOptions
    } = args
    const client = this
    const client_name = this.constructor.name // eslint-disable-line camelcase
    const base_url = this.serviceUrl // eslint-disable-line camelcase
    const options = this.createRequestOptions(url, context, payload, method === 'get')

    const labels = {
      client_name,
      base_url,
      url,
      method
    }

    const logError = (type, e) => {
      const errorType = `jwt_${type.toLowerCase()}_request_error`
      const logLabels = Object.assign({}, labels, {
        name: errorType
      })
      client.logError(type, e, logLabels, logger)
    }

    let requestMetricsEnd
    let retryCounter = 1

    const gotOptions = merge.options(got.defaults.options, {
      hooks: {
        beforeRequest: [
          (options, error, retryCount) => {
            requestMetricsEnd = this.requestMetrics.startTimer(labels)
          }
        ],
        beforeRetry: [
          (options, error, retryCount) => {
            error.retryCount = retryCount
            retryCounter = retryCount
            logError('client', error)
            if (requestMetricsEnd) {
              requestMetricsEnd(getResponseLabels(error))
            }
            requestMetricsEnd = this.requestMetrics.startTimer(labels)
          }
        ],
        beforeError: [
          (error) => {
            error.retryCount = retryCounter
            requestMetricsEnd(getResponseLabels(error))
            return error
          }
        ],
        afterResponse: [
          (response, retryWithMergedOptions) => {
            if (response.statusCode >= 400) {
              const {statusCode, statusMessage, body, retryCount} = response
              const error = {
                statusCode,
                statusMessage,
                body,
                retryCount
              }
              logError('client', error)
            }
            requestMetricsEnd(getResponseLabels(response))
            response.body = response.body || '{}'
            return response
          }
        ]
      }
    }, sendOptions, options)

    const apiMetricsEnd = this.apiMetrics.startTimer(labels)

    try {
      const response = await got[method](gotOptions)
      apiMetricsEnd(getResponseLabels(response))
      return response.body
    } catch (error) {
      // Horrible kludge to handle services returning ' ' as body
      const response = error.response
      if (response && response.statusCode < 300) {
        if (response.body && !response.body.trim()) {
          requestMetricsEnd(getResponseLabels(response))
          return {}
        }
      }
      apiMetricsEnd(getResponseLabels(error))
      if (logger) {
        logError('API', error)
      }
      client.handleRequestError(error)
    }
  }

  /**
   * Handle client get requests
   *
   * @param {object} args
   * Args for request
   *
   * @param {string} args.url
   * Url pattern for request
   *
   * @param {object} args.context
   * Context for url pattern substitution
   *
   * @param {object} [args.payload]
   * Payload to send as query param to endpoint
   *
   * @param {object} [args.sendOptions]
   * Additional options to pass to got method
   *
   * @param {object} [logger]
   * Bunyan logger instance
   *
   * @return {promise<object>}
   * Returns promise resolving to JSON object or handles exception
   *
   **/
  async sendGet (args, logger) {
    return this.send('get', args, logger)
  }

  /**
   * Handle client post requests
   *
   * @param {object} args
   * Args for request
   *
   * @param {string} args.url
   * Url pattern for request
   *
   * @param {object} args.context
   * Context for url pattern substitution
   *
   * @param {object} args.payload
   * Payload to post to endpoint
   *
   * @param {object} [args.sendOptions]
   * Additional options to pass to got method
   *
   * @param {object} [logger]
   * Bunyan logger instance
   *
   * @return {promise<object>}
   * Returns promise resolving to JSON object or handles exception
   *
   **/
  async sendPost (args, logger) {
    return this.send('post', args, logger)
  }

  /**
   * Handle client response errors
   *
   * @param {object} err
   * Error returned by Request
   *
   * @return {undefined}
   * Returns nothing as it should throw an error
   *
   **/
  handleRequestError (err) {
    // rethrow error if already client error
    if (err.name === this.ErrorClass.name) {
      throw err
    }
    if (err.body) {
      if (typeof err.body === 'object') {
        err.error = err.body
      }
    }
    const {statusCode} = err
    if (statusCode) {
      if (statusCode === 404) {
        // Data does not exist - ie. expired
        this.throwRequestError(404)
      } else {
        let message
        if (err.error) {
          message = err.error.name || err.error.code || 'EUNSPECIFIED'
        }
        this.throwRequestError(statusCode, message)
      }
    } else if (err.error) {
      // Handle errors which have an error object
      const errorObj = err.error
      const message = errorObj.name || errorObj.code || 'EUNSPECIFIED'
      const statusCode = getErrorStatusCode(message)
      this.throwRequestError(statusCode, message)
    } else {
      // Handle errors which have no error object
      const message = err.code || 'ENOERROR'
      const statusCode = getErrorStatusCode(message)
      this.throwRequestError(statusCode, message)
    }
  }

  /**
   * Convenience function for throwing errors
   *
   * @param {number|string} code
   * Error code
   *
   * @param {string} [message]
   * Error message (defaults to code)
   *
   * @return {undefined}
   * Returns nothing as it should throw an error
   *
   **/
  throwRequestError (code, message) {
    message = message || code
    throw new this.ErrorClass({
      error: {
        code,
        message
      }
    })
  }
}

// default client error class
FBJWTClient.prototype.ErrorClass = FBJWTClientError

module.exports = FBJWTClient

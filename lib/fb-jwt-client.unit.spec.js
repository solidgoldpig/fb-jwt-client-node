const test = require('tape')
const {stub, useFakeTimers} = require('sinon')
const nock = require('nock')

const jwt = require('jsonwebtoken')

const got = require('got')

const FBJWTClient = require('./fb-jwt-client')

/* test values */
const userId = 'testUserId'
const userToken = 'testUserToken'
const serviceSlug = 'testServiceSlug'
const serviceSecret = 'testServiceSecret'
const serviceToken = 'testServiceToken'
const microserviceUrl = 'https://microservice'
const createEndpointUrl = `${microserviceUrl}/service/${serviceSlug}/user/${userId}`
const data = {foo: 'bar'}
const encryptedData = 'RRqDeJRQlZULKx1NYql/imRmDsy9AZshKozgLuY='
const userIdTokenData = {userId, userToken}
const encryptedUserIdTokenData = 'Ejo7ypk1TFQNAbbkUFW8NeQhcZt1Wxf1IJNLhDjbtpoUdfluylSqWDCRXuulEqMiCdiQzhjIeLHANj9mMK0sMl6jTA=='
const expectedEncryptedData = 'pOXXs5YW9mUW1weBLNawiMRFdk6Hh92YBfGqmg8ych8PqnZ5l8JbcqHXHKjmcrKYJqZXn53sFr/eCq7Mbh5j9rj87w=='

// Ensure that client is properly instantiated

/**
 * Convenience function for testing client instantiation
 *
 * @param {object} t
 *  Object containing tape methods
 *
 * @param {array} params
 *  Arguments to pass to client constructor
 *
 * @param {string} expectedCode
 *  Error code expected to be returned by client
 *
 * @param {string} expectedMessage
 *  Error message expected to be returned by client
 *
 * @return {undefined}
 *
 **/
const testInstantiation = (t, params, expectedCode, expectedMessage) => {
  let failedClient
  try {
    t.throws(failedClient = new FBJWTClient(...params))
  } catch (e) {
    t.equal(e.name, 'FBJWTClientError', 'it should return an error of the correct type')
    t.equal(e.code, expectedCode, 'it should return the correct error code')
    t.equal(e.message, expectedMessage, 'it should return the correct error message')
  }
  t.equal(failedClient, undefined, 'it should not return an instantiated client')
  t.end()
}

test('When instantiating client without a service secret', t => {
  testInstantiation(t, [], 'ENOSERVICESECRET', 'No service secret passed to client')
})

test('When instantiating client without a service token', t => {
  testInstantiation(t, [serviceSecret], 'ENOSERVICETOKEN', 'No service token passed to client')
})

test('When instantiating client without a service slug', t => {
  testInstantiation(t, [serviceSecret, serviceToken], 'ENOSERVICESLUG', 'No service slug passed to client')
})

test('When instantiating client without a service url', t => {
  testInstantiation(t, [serviceSecret, serviceToken, serviceSlug], 'ENOMICROSERVICEURL', 'No microservice url passed to client')
})

test('When instantiating client with a custom error', t => {
  class MyError extends FBJWTClient.prototype.ErrorClass { }
  try {
    t.throws(new FBJWTClient(null, serviceToken, serviceSlug, microserviceUrl, MyError))
  } catch (e) {
    t.equal(e.name, 'MyError', 'it should use the error class passed')
  }
  t.end()
})

// Set up a client to test the methods
const jwtClient = new FBJWTClient(serviceSecret, serviceToken, serviceSlug, microserviceUrl)

// Injecting metrics instrumentation
test('When injecting metrics instrumentation', t => {
  const apiMetrics = {}
  const requestMetrics = {}

  const metricsClient = new FBJWTClient(serviceSecret, serviceToken, serviceSlug, microserviceUrl)
  metricsClient.setMetricsInstrumentation(apiMetrics, requestMetrics)

  t.equal(metricsClient.apiMetrics, apiMetrics, 'it should update the apiMetrics method')
  t.equal(metricsClient.requestMetrics, requestMetrics, 'it should update the apiMetrics method')

  t.end()
})

// Endpoint URLs
test('When asking for endpoint urls', t => {
  const getUrl =
    jwtClient.createEndpointUrl('/service/:serviceSlug/user/:userId', {serviceSlug, userId})
  t.equal(getUrl, createEndpointUrl, 'it should return the correct value for the get endpoint')

  t.end()
})

// JWT
test('When generating json web token', async t => {
  const clock = useFakeTimers({
    now: 1483228800000
  })
  const accessToken = jwtClient.generateAccessToken({data: 'testData'})
  const decodedAccessToken = jwt.verify(accessToken, serviceToken)
  t.equal(decodedAccessToken.checksum, 'b5118e71a8ed3abbc8c40d4058b0dd54b9410ffd56ef888f602ed10026c46a3a', 'it should output a token containing the checksum for the data')
  t.equal(decodedAccessToken.iat, 1483228800, 'it should output a token containing the iat property')

  clock.restore()
  t.end()
})

test('Wnen creating request options', t => {
  const generateAccessTokenStub = stub(jwtClient, 'generateAccessToken')
  generateAccessTokenStub.callsFake(() => 'testAccessToken')
  const requestOptions = jwtClient.createRequestOptions('/foo', {}, {foo: 'bar'})
  t.deepEqual(requestOptions, {
    url: 'https://microservice/foo',
    headers: {'x-access-token': 'testAccessToken'},
    body: {foo: 'bar'},
    json: true
  }, 'it should set the correct url, headers and json object')

  const requestGetOptions = jwtClient.createRequestOptions('/foo', {}, {foo: 'bar'}, true)
  t.deepEqual(requestGetOptions, {
    url: 'https://microservice/foo',
    headers: {'x-access-token': 'testAccessToken'},
    searchParams: {payload: 'eyJmb28iOiJiYXIifQ=='},
    json: true
  }, 'and when a querystring is specified, it should set json option to true and the searchParams option to the payload’s value')
  generateAccessTokenStub.restore()
  t.end()
})

// Decrypting user data
test('When decrypting data', async t => {
  const decryptedData = jwtClient.decrypt(userToken, encryptedData)
  t.deepEqual(data, decryptedData, 'it should return the correct data from valid encrypted input')

  t.end()
})

test('When decrypting invalid data', async t => {
  try {
    t.throws(jwtClient.decrypt(userToken, 'invalid'))
  } catch (e) {
    t.equal(e.name, 'FBJWTClientError', 'it should return an error object of the correct type')
    t.equal(e.code, 500, 'it should return correct error code')
    t.equal(e.message, 'EINVALIDPAYLOAD', 'it should return the correct error message')
  }

  t.end()
})

// Encrypting data
test('When encrypting data', async t => {
  const encryptedData = jwtClient.encrypt(userToken, data)
  const decryptedData = jwtClient.decrypt(userToken, encryptedData)
  t.deepEqual(data, decryptedData, 'it should encrypt the data correctly')
  // NB. have to decrypt the encryptedData to check
  // since the Initialization Vector guarantees the output will be different each time

  const encryptedDataAgain = jwtClient.encrypt(userToken, data)
  t.notEqual(encryptedDataAgain, encryptedData, 'it should not return the same value for the same input')

  t.end()
})

test('When encrypting data with a provided IV seed', async t => {
  const encryptedData = jwtClient.encrypt(userToken, data, 'ivSeed')
  const decryptedData = jwtClient.decrypt(userToken, encryptedData)
  t.deepEqual(data, decryptedData, 'it should encrypt the data correctly')

  const encryptedDataAgain = jwtClient.encrypt(userToken, data, 'ivSeed')
  t.equal(encryptedDataAgain, encryptedData, 'it should return the same value for the same input')

  t.end()
})

// Encrypting user ID and token
test('When encrypting the user ID and token', async t => {
  const encryptedData = jwtClient.encryptUserIdAndToken(userId, userToken)
  t.equal(encryptedData, expectedEncryptedData, 'it should encrypt the data correctly')

  const encryptedDataAgain = jwtClient.encryptUserIdAndToken(userId, userToken)
  t.equal(encryptedDataAgain, encryptedData, 'it should return the same value for the same input')

  t.end()
})

// Decrypting user ID and token
test('When decrypting the user’s ID and token', async t => {
  const decryptedData = jwtClient.decryptUserIdAndToken(encryptedUserIdTokenData)
  t.deepEqual(userIdTokenData, decryptedData, 'it should return the correct data from valid encrypted input')

  t.end()
})

test('When decrypting invalid user ID and token', async t => {
  try {
    t.throws(jwtClient.decryptUserIdAndToken(userToken, 'invalid'))
  } catch (e) {
    t.equal(e.name, 'FBJWTClientError', 'it should return an error object of the correct type')
    t.equal(e.code, 500, 'it should return correct error code')
    t.equal(e.message, 'EINVALIDPAYLOAD', 'it should return the correct error message')
  }

  t.end()
})

// Sending gets
test('When sending gets', async t => {
  const stubAccessToken = stub(jwtClient, 'generateAccessToken')
  stubAccessToken.callsFake(() => 'testAccessToken')
  const gotStub = stub(got, 'get')
  gotStub.callsFake(options => {
    return Promise.resolve({
      body: data
    })
  })

  const fetchedData = await jwtClient.sendGet({
    url: '/user/:userId',
    context: {userId}
  })

  const callArgs = gotStub.getCall(0).args[0]

  t.equal(callArgs.url, `${microserviceUrl}/user/testUserId`, 'it should call the correct url')
  t.equal(callArgs.headers['x-access-token'], 'testAccessToken', 'it should add the correct x-access-token header')
  t.deepEqual(fetchedData, data, 'it should return the unencrypted data')
  stubAccessToken.restore()

  await jwtClient.sendGet({
    url: '/user/:userId',
    context: {userId},
    payload: {foo: 'bar'}
  })

  const callArgsB = gotStub.getCall(0).args[0]
  // NB. querystring checking handled in createRequestOptions tests
  // since searchParams options get stashed on request agent's internal self object
  t.equal(callArgsB.url, `${microserviceUrl}/user/testUserId`, 'it should call the correct url')
  t.equal(callArgsB.headers['x-access-token'], 'testAccessToken', 'it should add the correct x-access-token header')

  stubAccessToken.restore()
  gotStub.restore()
  t.end()
})

// Sending posts
test('When sending posts', async t => {
  const gotStub = stub(got, 'post')
  gotStub.callsFake(options => {
    return Promise.resolve({
      body: {foo: 'bar'}
    })
  })

  const generateAccessTokenStub = stub(jwtClient, 'generateAccessToken')
  generateAccessTokenStub.callsFake(() => 'accessToken')

  const responseBody = await jwtClient.sendPost({
    url: '/user/:userId',
    context: {userId},
    payload: data
  })

  const callArgs = gotStub.getCall(0).args[0]
  t.equal(callArgs.url, `${microserviceUrl}/user/testUserId`, 'it should call the correct url')
  t.deepEqual(callArgs.body, data, 'it should post the correct data')
  t.deepEqual(callArgs.headers['x-access-token'], 'accessToken', 'it should add the x-access-token header')

  t.deepEqual(responseBody, {foo: 'bar'}, 'it should return the response’s body parsed as JSON')

  gotStub.restore()
  generateAccessTokenStub.restore()
  t.end()
})

test('When calling an endpoint successfully', async t => {
  const nockedClient = new FBJWTClient(serviceSecret, serviceToken, serviceSlug, 'http://testdomain')

  nock('http://testdomain')
    .get('/route')
    .reply(200, {success: true})

  const apiMetricsEndStub = stub()
  const apiMetricsStartTimerStub = stub(nockedClient.apiMetrics, 'startTimer')
  apiMetricsStartTimerStub.callsFake(() => apiMetricsEndStub)

  const requestMetricsEndStub = stub()
  const requestMetricsStartTimerStub = stub(nockedClient.requestMetrics, 'startTimer')
  requestMetricsStartTimerStub.callsFake(() => requestMetricsEndStub)

  await nockedClient.send('get', {
    url: '/route'
  })

  t.deepEqual(apiMetricsStartTimerStub.getCall(0).args[0], {
    client_name: 'FBJWTClient',
    base_url: 'http://testdomain',
    url: '/route',
    method: 'get'
  }, 'it should start the instrumentation timer with the correct args')
  t.deepEqual(apiMetricsEndStub.getCall(0).args[0], {status_code: 200}, 'it should stop the instrumentation timer with the correct args')

  t.deepEqual(requestMetricsStartTimerStub.getCall(0).args[0], {
    client_name: 'FBJWTClient',
    base_url: 'http://testdomain',
    url: '/route',
    method: 'get'
  }, 'it should start the instrumentation timer with the correct args')
  t.deepEqual(requestMetricsEndStub.getCall(0).args[0], {status_code: 200}, 'it should stop the instrumentation timer with the correct args')

  apiMetricsStartTimerStub.restore()
  requestMetricsStartTimerStub.restore()

  t.end()
})

test('When calling an endpoint unsuccessfully', async t => {
  const nockedClient = new FBJWTClient(serviceSecret, serviceToken, serviceSlug, 'http://testdomain')

  nock('http://testdomain')
    .get('/notfound')
    .reply(404, {code: 404, name: 'ENOTFOUND'})

  const apiMetricsEndStub = stub()
  const apiMetricsStartTimerStub = stub(nockedClient.apiMetrics, 'startTimer')
  apiMetricsStartTimerStub.callsFake(() => apiMetricsEndStub)

  const requestMetricsEndStub = stub()
  const requestMetricsStartTimerStub = stub(nockedClient.requestMetrics, 'startTimer')
  requestMetricsStartTimerStub.callsFake(() => requestMetricsEndStub)

  try {
    t.throws(await nockedClient.send('get', {
      url: '/notfound'
    }, {error: () => {}}))
  } catch (e) {
  //
  }

  t.deepEqual(apiMetricsStartTimerStub.getCall(0).args[0], {
    client_name: 'FBJWTClient',
    base_url: 'http://testdomain',
    url: '/notfound',
    method: 'get'
  }, 'it should start the instrumentation timer with the correct args')
  t.deepEqual(apiMetricsEndStub.getCall(0).args[0], {status_code: 404, status_message: 'Not Found', error_name: 'HTTPError'}, 'it should stop the instrumentation timer with the correct args')

  t.deepEqual(requestMetricsStartTimerStub.getCall(0).args[0], {
    client_name: 'FBJWTClient',
    base_url: 'http://testdomain',
    url: '/notfound',
    method: 'get'
  }, 'it should start the instrumentation timer with the correct args')
  t.deepEqual(requestMetricsEndStub.getCall(0).args[0], {status_code: 404}, 'it should stop the instrumentation timer with the correct args')

  apiMetricsStartTimerStub.restore()
  requestMetricsStartTimerStub.restore()

  t.end()
})

test('When retrying an endpoint', async t => {
  const retryClient = new FBJWTClient(serviceSecret, serviceToken, serviceSlug, 'http://testdomain')

  const apiMetricsEndStub = stub()
  const apiMetricsStartTimerStub = stub(retryClient.apiMetrics, 'startTimer')
  apiMetricsStartTimerStub.callsFake(() => apiMetricsEndStub)

  const requestMetricsEndStub = stub()
  const requestMetricsStartTimerStub = stub(retryClient.requestMetrics, 'startTimer')
  requestMetricsStartTimerStub.callsFake(() => requestMetricsEndStub)

  let retryCounter = 0
  const retries = () => {
    if (retryCounter) {
      return 0
    }
    retryCounter++
    return 1
  }
  try {
    t.throws(await retryClient.send('get', {
      url: '/missing',
      sendOptions: {
        retry: {retries}
      }
    }, {error: () => {}}))
  } catch (e) {
    //
  }

  t.deepEqual(apiMetricsStartTimerStub.getCall(0).args[0], {
    client_name: 'FBJWTClient',
    base_url: 'http://testdomain',
    url: '/missing',
    method: 'get'
  }, 'it should start the instrumentation timer with the correct args')
  t.deepEqual(apiMetricsEndStub.getCall(0).args[0], {status_code: undefined, error_name: 'RequestError'}, 'it should stop the instrumentation timer with the correct args')
  t.equal(apiMetricsStartTimerStub.callCount, 1, 'it should start the api instrumentation once')
  t.equal(apiMetricsEndStub.callCount, 1, 'it should end the api instrumentation once')

  t.deepEqual(requestMetricsStartTimerStub.getCall(1).args[0], {
    client_name: 'FBJWTClient',
    base_url: 'http://testdomain',
    url: '/missing',
    method: 'get'
  }, 'it should start the instrumentation timer with the correct args')
  t.deepEqual(requestMetricsEndStub.getCall(0).args[0], {status_code: undefined, error_name: 'RequestError'}, 'it should stop the instrumentation timer with the correct args')

  t.equal(requestMetricsStartTimerStub.callCount, 2, 'it should start the request instrumentation for each individual request')
  t.equal(requestMetricsEndStub.callCount, 2, 'it should start the request instrumentation for each individual request')

  apiMetricsStartTimerStub.restore()
  requestMetricsStartTimerStub.restore()

  t.end()
})

const getNockedResponse = (url, response, code = 201) => {
  const serviceUrl = 'http://testdomain'
  const nockedClient = new FBJWTClient(serviceSecret, serviceToken, serviceSlug, serviceUrl)

  nock(serviceUrl)
    .get(url)
    .reply(code, response)

  return nockedClient.send('get', {url})
}

test('When calling an endpoint that returns json as it body', async t => {
  const response = await getNockedResponse('/json-body', {success: true})
  t.deepEqual(response, {success: true}, 'it should return the body')
  t.end()
})

test('When calling an endpoint that returns empty json as it body', async t => {
  const response = await getNockedResponse('/empty-json-body', {})
  t.deepEqual(response, {}, 'it should return the body')
  t.end()
})

test('When calling an endpoint that returns an empty string as it body', async t => {
  const response = await getNockedResponse('/empty-string-body', '')
  t.deepEqual(response, {}, 'it should return an empty json object')
  t.end()
})

test('When calling an endpoint that returns an empty string as it body', async t => {
  const response = await getNockedResponse('/undefined-body')
  t.deepEqual(response, {}, 'it should return an empty json object')
  t.end()
})

test('When calling an endpoint that returns spaces as it body', async t => {
  const response = await getNockedResponse('/spaces-body', ' ')
  t.deepEqual(response, {}, 'it should return an empty json object')
  t.end()
})

test('When calling an endpoint that returns spaces as it body', async t => {
  try {
    t.throws(await getNockedResponse('/non-empty-body', ' hello'))
  } catch (e) {
    t.deepEqual(e.name, 'FBJWTClientError', 'it should return an empty json object')
  }

  t.end()
})

/**
 * Convenience function for testing client error handling
 *
 * Stubs request[stubMethod], creates error object response and tests
 * - error name
 * - error code
 * - error message
 * - data is undefined
 *
 * @param {function} clientMethod
 *  Function providing call to client method to execute with args pre-populated
 *
 * @param {string} stubMethod
 *  Request method to stub
 *
 * @param {object} t
 *  Object containing tape methods
 *
 * @param {number|string} requestErrorCode
 *  Error code or status code returned by request
 *
 * @param {number} [applicationErrorCode]
 *  Error code expoected to be thrown by client (defaults to requestErrorCode)
 *
 * @param {number} [expectedRequestErrorCode]
 *  Error code expoected to be thrown if no code is returned by client (defaults to requestErrorCode)
 *
 * @return {undefined}
 *
 **/
const testError = async (clientMethod, stubMethod, t, requestErrorCode, applicationErrorCode, expectedRequestErrorCode) => {
  applicationErrorCode = applicationErrorCode || requestErrorCode

  const error = {}

  if (typeof requestErrorCode === 'string') {
    error.body = {
      name: requestErrorCode
    }
  } else {
    error.statusCode = requestErrorCode
  }

  expectedRequestErrorCode = expectedRequestErrorCode || requestErrorCode

  const gotStub = stub(got, stubMethod)
  gotStub.callsFake(options => {
    return Promise.reject(error)
  })

  try {
    t.throws(await clientMethod())
  } catch (e) {
    t.equal(e.name, 'FBJWTClientError', 'it should return an error object of the correct type')
    t.equal(e.code, applicationErrorCode, `it should return correct error code (${applicationErrorCode})`)
    t.equal(e.message, expectedRequestErrorCode, `it should return the correct error message (${expectedRequestErrorCode})`)
  }

  gotStub.restore()
  t.end()
}

// Convenience function for testing client's sendGet method - calls generic testError function
// Params same as for testError, minus the clientMethod and stubMethod ones
const testGetError = async (t, requestErrorCode, applicationErrorCode, expectedRequestErrorCode) => {
  const clientMethod = async () => {
    return jwtClient.sendGet({
      url: '/url'
    })
  }
  testError(clientMethod, 'get', t, requestErrorCode, applicationErrorCode, expectedRequestErrorCode)
}

// Convenience function for testing client's sendPost method - calls generic testError function
// Params same as for testError, minus the clientMethod and stubMethod one
const testPostError = async (t, requestErrorCode, applicationErrorCode, expectedRequestErrorCode) => {
  const clientMethod = async () => {
    return jwtClient.sendPost({
      url: '/url',
      payload: data
    })
  }
  testError(clientMethod, 'post', t, requestErrorCode, applicationErrorCode, expectedRequestErrorCode)
}

// Test all the errors for jwtClient.sendGet

test('When requesting a resource that does not exist', async t => {
  testGetError(t, 404)
})

test('When making an unauthorized get request', async t => {
  testGetError(t, 401)
})

test('When making an invalid get request', async t => {
  testGetError(t, 403)
})

test('When get endpoint cannot be reached', async t => {
  testGetError(t, 'ECONNREFUSED', 503)
})

test('When dns resolution for get endpoint fails', async t => {
  testGetError(t, 'ENOTFOUND', 502)
})

test('When making a get request and an unspecified error code is returned', async t => {
  testGetError(t, 'e.madeup', 500)
})

test('When making a get request and an error object without error code is returned', async t => {
  testGetError(t, '', 500, 'EUNSPECIFIED')
})

test('When making a get request and an error occurs but no error code is present', async t => {
  testGetError(t, undefined, 500, 'ENOERROR')
})

// // Test all the errors for jwtClient.sendPost

test('When making an unauthorized post request', async t => {
  testPostError(t, 401)
})

test('When making an invalid post request', async t => {
  testPostError(t, 403)
})

test('When post endpoint cannot be reached', async t => {
  testPostError(t, 'ECONNREFUSED', 503)
})

test('When dns resolution for post endpoint fails', async t => {
  testPostError(t, 'ENOTFOUND', 502)
})

test('When making a post request and an unspecified error code is returned', async t => {
  testPostError(t, 'e.madeup', 500)
})

test('When making a post request and an error object without error code is returned', async t => {
  testPostError(t, '', 500, 'EUNSPECIFIED')
})

test('When making a post request and an error occurs but no error code is present', async t => {
  testPostError(t, undefined, 500, 'ENOERROR')
})

test('When making a request and both a status code and an error object containing a name are present', async t => {
  const gotStub = stub(got, 'get')
  gotStub.callsFake(options => {
    const error = new Error()
    error.statusCode = 400
    error.statusMessage = 'boom'
    error.error = {
      name: 'e.error.name',
      code: 400
    }
    return Promise.reject(error)
  })

  try {
    t.throws(await jwtClient.sendGet({url: '/url'}))
  } catch (e) {
    t.equals(e.name, 'FBJWTClientError', 'it should use the name specified in the error object as the message')
    t.equals(e.code, 400, 'it should use the name specified in the error object as the message')
    t.equals(e.message, 'e.error.name', 'it should use the name specified in the error object as the message')
  }

  gotStub.restore()
  t.end()
})

test('When making a request and both a status code and an error object with a code but no name are present', async t => {
  const gotStub = stub(got, 'get')
  gotStub.callsFake(options => {
    const error = new Error()
    error.statusCode = 400
    error.error = {
      code: 409
    }
    return Promise.reject(error)
  })

  try {
    t.throws(await jwtClient.sendGet({url: '/url'}))
  } catch (e) {
    t.equals(e.message, 409, 'it should use the code specified in the error object as the message')
  }

  gotStub.restore()
  t.end()
})

test('When making a request and both a status code and an error object with no name and no code are present', async t => {
  const gotStub = stub(got, 'get')
  gotStub.callsFake(options => {
    const error = new Error()
    error.statusCode = 400
    error.error = {
      foo: 409
    }
    return Promise.reject(error)
  })

  try {
    t.throws(await jwtClient.sendGet({url: '/url'}))
  } catch (e) {
    t.equals(e.message, 'EUNSPECIFIED', 'it should use ‘EUNSPECIFIED‘ as the message')
  }

  gotStub.restore()
  t.end()
})

// Rethrow errors

test('When client handles an error that it created', async t => {
  const thrown = new jwtClient.ErrorClass('Boom', {error: {code: 'EBOOM'}})
  try {
    t.throws(jwtClient.handleRequestError(thrown))
  } catch (e) {
    t.equal(e, thrown, 'it should rethrow the error as is')
  }

  t.end()
})

// Logging errors

test('When a get request results in an error and a logger instance has been provided', async t => {
  const gotStub = stub(got, 'get')
  const error = new Error()
  error.code = 'EBANG'
  error.statusCode = 400
  error.statusMessage = 'boom'
  error.body = {
    name: 'e.error.name',
    message: 'bang!',
    code: 400
  }
  gotStub.callsFake(options => {
    return Promise.reject(error)
  })

  const logErrorStub = stub()
  const logger = {
    error: logErrorStub
  }

  try {
    t.throws(await jwtClient.sendGet({url: '/url'}, logger))
  } catch (e) {
    const callArgs = logErrorStub.getCall(0).args
    t.equals(logErrorStub.calledOnce, true, 'it should use the provided logger instance to log the error')
    t.deepEquals(callArgs[0], {
      name: 'jwt_api_request_error',
      client_name: 'FBJWTClient',
      url: '/url',
      base_url: 'https://microservice',
      method: 'get',
      error
    }, 'it should set the error returned as the err property of the object passed to the logger')
    t.deepEquals(callArgs[1], 'JWT API request error: FBJWTClient: GET https://microservice/url - Error - EBANG - 400 - boom - {"name":"e.error.name","message":"bang!","code":400}', 'it should generate a message explaining the error')
  }

  gotStub.restore()
  logErrorStub.resetHistory()
  t.end()
})

test('When a post request results in an error and a logger instance has been provided', async t => {
  const gotStub = stub(got, 'post')
  const error = new Error()
  error.gotOptions = {
    headers: {
      'x-something': 'x-something-value'
    }
  }
  gotStub.callsFake(options => {
    return Promise.reject(error)
  })

  const logErrorStub = stub()
  const logger = {
    error: logErrorStub
  }

  try {
    t.throws(await jwtClient.sendPost({url: '/url'}, logger))
  } catch (e) {
    const callArgs = logErrorStub.getCall(0).args
    t.equals(logErrorStub.calledOnce, true, 'it should use the provided logger instance to log the error')
    t.deepEquals(callArgs[0], {
      name: 'jwt_api_request_error',
      client_name: 'FBJWTClient',
      url: '/url',
      base_url: 'https://microservice',
      method: 'post',
      error
    }, 'it should set the error returned as the err property of the object passed to the logger')
    t.deepEquals(callArgs[1], 'JWT API request error: FBJWTClient: POST https://microservice/url - Error -  -  -  - ', 'it should generate a message explaining the error')
  }

  gotStub.restore()
  t.end()
})

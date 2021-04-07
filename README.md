# Form Builder JSON Web Token client (Node)

Base client for making requests to Form Builder platform endpoints that require JSON Web Tokens for authenctication

## Requirements

Node

## Installation

`npm install @solidgoldpig/fb-jwt-client-node`

## Usage

### Loading and initialising basic client

``` javascript
// load client class
const FBJWTClient = require('@solidgoldpig/fb-jwt-client-node')

// initialise client
const jwtClient = new FBJWTClient(serviceSecret, serviceToken, serviceSlug, microserviceUrl, [errorClass])
```

#### `serviceSecret`

Constructor will throw an error if no service secret is passed

#### `serviceToken`

Constructor will throw an error if no service token is passed

#### `serviceSlug`

Constructor will throw an error if no service slug is passed

#### `microserviceUrl`

Constructor will throw an error if no service url is passed

#### `errorClass`

By default, uses FBJWTClientError

### Extending

``` javascript
// extend base class
class FBMyClient extends FBJWTClient {
  constructor (serviceSecret, serviceToken, serviceSlug, microserviceUrl, myVar) {
    super(serviceSecret, serviceToken, serviceSlug, microserviceUrl)
    // do something with additional constructor argument
    this.myVar = myVar
  }
}

const myClient = new FBMyClient('service_secret', 'service_token', 'myservice', 'http://myservice', 'my var')
```

``` javascript
// extend base class with custom error
class FBAnotherClient extends FBJWTClient {
  constructor (serviceSecret, serviceToken, serviceSlug, microserviceUrl) {
    // create custom error class
    class FBAnotherClientError extends FBJWTClient.prototype.ErrorClass {}
    super(serviceSecret, serviceToken, serviceSlug, microserviceUrl, FBAnotherClientError)
  }
}
```

### Methods

- generateAccessToken

  Generate JWT access token

- createEndpointUrl

  Return user-specific endpoint

- sendGet

  Handle client get requests

- sendPost

  Handle client post requests

- encrypt

  Encrypt data with AES 256

- decrypt

  Decrypt data
  
- encryptUserIdAndToken

  Encrypt user ID and token using service secret

- decryptUserIdAndToken

  Decrypt user ID and token using service secret

- handleRequestError

  Handle client response errors

- createRequestOptions

  Create request options

- throwRequestError

  Convenience function for throwing errors

## Further details

See documentation in code for further details and `fb-user-datastore-client-node` and `fb-submitter-client-node` for examples.
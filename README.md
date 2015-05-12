# Reddit OAuth2 Provider

[![Build Status](https://img.shields.io/travis/rtheunissen/oauth2-reddit.svg?style=flat-square&branch=master)](https://travis-ci.org/rtheunissen/oauth2-reddit)
[![Scrutinizer](https://img.shields.io/scrutinizer/g/rtheunissen/oauth2-reddit.svg?style=flat-square)]()
[![Scrutinizer Coverage](https://img.shields.io/scrutinizer/coverage/g/rtheunissen/oauth2-reddit.svg?style=flat-square)]()
[![Latest Version](https://img.shields.io/packagist/v/rtheunissen/oauth2-reddit.svg?style=flat-square)](https://packagist.org/packages/rtheunissen/oauth2-reddit)
[![License](https://img.shields.io/packagist/l/rtheunissen/oauth2-reddit.svg?style=flat-square)](https://packagist.org/packages/rtheunissen/oauth2-reddit)
[![Join the chat at https://gitter.im/rtheunissen/oauth2-reddit](https://img.shields.io/badge/gitter-join%20chat%20%E2%86%92-brightgreen.svg?style=flat-square)](https://gitter.im/rtheunissen/oauth2-reddit)

This package provides Reddit integration for [thephpleague/oauth2-client](https://github.com/thephpleague/oauth2-client).

## Installation

```sh
composer require rtheunissen/oauth2-reddit
```

## Usage

```php
use Rudolf\OAuth2\Client\Provider\Reddit;

$reddit = new Reddit([
    'clientId'      => 'yourClientId',
    'clientSecret'  => 'yourClientSecret',
    'redirectUri'   => 'yourRedirectUri',
    'userAgent'     => 'platform:appid:version, (by /u/username)',
    'scopes'        => ['identity', 'read', ...],
]);
```

#### Requesting an access token 

There are four different ways to request an access token, and you should
be able to determine which to use based on the nature of your application.

Have a read through the [Reddit OAuth2 Wiki](https://github.com/reddit/reddit/wiki/OAuth2) to find out more.

##### For web apps, using 'code' and 'state'

```php
$url = $reddit->getAuthorizationUrl([
    'duration' => $duration,  // "permanent" or "temporary" by default
]);
```

You'll receive both `code` and `state` when redirected from Reddit.

```php
$accessToken = $reddit->getAccessToken('authorization_code', [
    'code'  => $code,
    'state' => $state
]);
```

##### For scripts intended for personal use, using 'username' and 'password'

```php
$accessToken = $reddit->getAccessToken('password', [
    'username' => $username,
    'password' => $password,
]);
```

##### For installed applications

> You should generate and save unique ID on your client. The ID should be unique **per-device** or **per-user** of your app. A randomized or pseudo-randomized value is acceptable for generating the ID; however, you should retain and re-use the same device_id when renewing your access token.

```php
$accessToken = $reddit->getAccessToken('installed_client', [
    'device_id' => $deviceId,  // 20-30 character ASCII string
]);
```

##### For confidential clients (web apps / scripts)

```php
$accessToken = $reddit->getAccessToken('client_credentials');
```

#### Refreshing an access token

The only way to get a refresh token is by using the state and code redirect flow,
with the duration set as "permanent". The resulting access token will have a valid
`refreshToken` property, which you can use to refresh the token.

Note that the refreshed token won't have a `refreshToken` field. You should use the 
same refresh token every time you refresh the current token, and simply update its
`accessToken` and `expires` properties.

```php
$refreshToken = $reddit->getAccessToken('refresh_token', [
    'refresh_token' => $accessToken->refreshToken
]);

$accessToken->accessToken = $refreshToken->accessToken;
$accessToken->expires = $refreshToken->expires;

// Remember to re-store the refreshed access token at this point
```

#### Using the access token

Reddit requires a few authorization headers when making authenticated API requests.
These can be accessed using `$reddit->getHeaders($token)`.

Note: The pending v1.0.0 release of [thephpleague/oauth2-client](https://github.com/thephpleague/oauth2-client/1.0)
will make this easier by providing an authenticated request object which you can adjust for each request.

Until then, you are advised to use either a dedicated HTTP client or the client used by the provider:

```php
$client = $reddit->getHttpClient(); // Guzzle 3
```

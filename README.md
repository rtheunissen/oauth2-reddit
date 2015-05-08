# Reddit OAuth2 Provider

[![Build Status](https://img.shields.io/travis/rtheunissen/oauth2-reddit.svg)](https://travis-ci.org/rtheunissen/oauth2-reddit)
[![Latest Version](https://img.shields.io/packagist/v/rtheunissen/oauth2-reddit.svg)](https://packagist.org/packages/rtheunissen/oauth2-reddit)
[![License](https://img.shields.io/packagist/l/rtheunissen/oauth2-reddit.svg)](https://packagist.org/packages/rtheunissen/oauth2-reddit)

[![Join the chat at https://gitter.im/rtheunissen/oauth2-reddit](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/rtheunissen/oauth2-reddit?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

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

```php
$url = $reddit->getAuthorizationUrl([
    'duration' => 'permanent', // in order to receive a refresh token
]);
```


After being redirected back, you'll have both code and state parameters.

```php
$accessToken = $reddit->getAccessToken('authorization_code', [
    'code'  => $code,
    'state' => $state
]);
```

#### Requesting an access token without redirecting

You can request access to a 'script' app by using a username and password.
In this case you don't need to use `getAuthorizationUrl`.

```php
$accessToken = $reddit->getAccessToken('password', [
    'username' => $username,
    'password' => $password,
]);

```


#### Using the access token

Reddit requires a few authorization headers to allow authenticated requests using an access token. 
These can be accessed using `$reddit->getHeaders($token)`.

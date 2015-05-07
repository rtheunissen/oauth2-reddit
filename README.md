# Reddit OAuth2 client provider

[![Build Status](https://img.shields.io/travis/rtheunissen/oauth2-reddit.svg)](https://travis-ci.org/rtheunissen/oauth2-reddit)
[![Latest Version](https://img.shields.io/packagist/v/rtheunissen/oauth2-reddit.svg)](https://packagist.org/packages/rtheunissen/oauth2-reddit)
[![License](https://img.shields.io/packagist/l/rtheunissen/oauth2-reddit.svg)](https://packagist.org/packages/rtheunissen/oauth2-reddit)

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
    'scopes'        => ['identity', 'read'],
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

In order to make authenticated requests using an access token, Reddit requires that a few authorization headers be sent along with the request data. These can be accessed using `$reddit->getHeaders($token)`.

Use https://oauth.reddit.com as the base of the URL, and note that this is just an example and should be adapted to suit whatever HTTP library you are using.

```php
$client->post($url, $data, $reddit->getHeaders($token));
```


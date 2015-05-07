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
$provider = new Rudolf\OAuth2\Client\Provider\Reddit([
    'clientId' => '',
    'clientSecret' => '',
    'redirectUri' => '',
    'userAgent' => '',
]);
```

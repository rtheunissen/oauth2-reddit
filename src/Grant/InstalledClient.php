<?php

namespace Concat\OAuth2\Client\Grant;

use League\OAuth2\Client\Grant\GrantInterface;
use League\OAuth2\Client\Token\AccessToken;

/**
 * @see https://github.com/reddit/reddit/wiki/OAuth2
 */
class InstalledClient implements GrantInterface
{
    public function __toString()
    {
        return 'https://oauth.reddit.com/grants/installed_client';
    }

    public function prepRequestParams($defaultParams, $params)
    {
        if ( ! isset($params["device_id"]) || empty($params["device_id"])) {
            throw new \BadMethodCallException("Missing device_id");
        }

        // device_id has to be a 20-30 character ASCII string
        if ( ! preg_match("/^[[:ascii:]]{20,30}$/", $params["device_id"])) {
          throw new \InvalidArgumentException("Invalid device_id");
        }

        return array_merge($defaultParams, $params);
    }

    public function handleResponse($response = [])
    {
        return new AccessToken($response);
    }
}

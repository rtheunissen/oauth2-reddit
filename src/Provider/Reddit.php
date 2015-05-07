<?php

namespace Rudolf\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;

class Reddit extends AbstractProvider
{

    /**
     * User agent string required by Reddit
     * @see https://github.com/reddit/reddit/wiki/API
     */
    public $userAgent = "";

    /**
     * {@inheritDoc}
     */
    public $authorizationHeader = "bearer";

    /**
     * {@inheritDoc}
     */
    public function urlAuthorize()
    {
        return "https://ssl.reddit.com/api/v1/authorize";
    }

    /**
     * {@inheritDoc}
     */
    public function urlAccessToken()
    {
        return "https://ssl.reddit.com/api/v1/access_token";
    }

    /**
     * {@inheritDoc}
     */
    public function urlUserDetails(AccessToken $token)
    {
        return "https://oauth.reddit.com/api/v1/me.json";
    }

    /**
     * {@inheritDoc}
     */
    public function userDetails($response, AccessToken $token)
    {
        return $response;
    }

    /**
     * Returns the user agent, which is required to be set.
     *
     * @return string
     */
    protected function getUserAgent()
    {
        return $this->userAgent ?: $_SERVER['HTTP_USER_AGENT'];
    }

    /**
     * {@inheritDoc}
     */
    public function getHeaders($token = null)
    {
        $headers = [
            "User-Agent" => $this->getUserAgent(),
        ];

        // We have to use HTTP Basic Auth when requesting an access token
        if ( ! $token) {
            $auth = base64_encode("{$this->clientId}:{$this->clientSecret}");
            $headers["Authorization"] = 'Basic $auth';
        }

        // The basic auth token will be overided by the parent auth headers
        return array_merge(parent::getHeaders($token), $headers);
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthorizationUrl($options = array())
    {
        $url = parent::getAuthorizationUrl();

        // This is required as an option to be given a refresh token
        if (isset($options['duration'])) {
            $url .= "&duration={$options['duration']}";
        }

        return $url;
    }
}

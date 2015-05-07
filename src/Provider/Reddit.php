<?php

namespace Rudolf\OAuth2\Client\Reddit\Provider;

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
        return array_merge(parent::getHeaders($token), [
            "User-Agent" => $this->getUserAgent(),
        ]);
    }
}

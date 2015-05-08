<?php

namespace Rudolf\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;

use InvalidArgumentException;

class Reddit extends AbstractProvider
{

    /**
     * User agent string required by Reddit
     * Format <platform>:<app ID>:<version string> (by /u/<reddit username>)
     *
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
        return "https://oauth.reddit.com/api/v1/me";
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
     * @throws Rudolf\OAuth2\Client\Exception\ProviderException
     */
    protected function getUserAgent()
    {
        if ($this->userAgent) {
            return $this->userAgent;
        }

        // Use the server user agent as a fallback if no explicit one was set.
        return $_SERVER["HTTP_USER_AGENT"];
    }


    /**
     * Validates that the user agent follows the Reddit API guide.
     * Pattern: <platform>:<app ID>:<version string> (by /u/<reddit username>)
     *
     * @throws Rudolf\OAuth2\Client\Exception\ProviderException
     */
    protected function validateUserAgent()
    {
        if ( ! preg_match("~^.+:.+:.+ \(by /u/.+\)$~", $this->getUserAgent())) {
            throw new InvalidArgumentException("User agent is not valid");
        }
    }

    /**
     * {@inheritDoc}
     */
    public function getHeaders($token = null)
    {
        $this->validateUserAgent();

        $headers = [
            "User-Agent" => $this->getUserAgent(),
        ];

        // We have to use HTTP Basic Auth when requesting an access token
        if ( ! $token) {
            $auth = base64_encode("{$this->clientId}:{$this->clientSecret}");
            $headers["Authorization"] = "Basic $auth";
        }

        return array_merge(parent::getHeaders($token), $headers);
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthorizationUrl($options = [])
    {
        $url = parent::getAuthorizationUrl();

        // This is required as an option to be given a refresh token
        if (isset($options['duration'])) {
            $url .= "&duration={$options['duration']}";
        }

        return $url;
    }
}

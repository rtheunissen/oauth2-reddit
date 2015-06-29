<?php

namespace Concat\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;
use Concat\OAuth2\Client\Grant\InstalledClient;
use InvalidArgumentException;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;

class Reddit extends AbstractProvider
{

    use BearerAuthorizationTrait;

    /**
     * User agent string required by reddit
     * Format <platform>:<app ID>:<version string> (by /u/<reddit username>)
     *
     * @see https://github.com/reddit/reddit/wiki/API
     */
    protected $userAgent = "";

    /**
     * {@inheritDoc}
     */
    public function getBaseAuthorizationUrl()
    {
        return "https://ssl.reddit.com/api/v1/authorize";
    }

    /**
     * {@inheritDoc}
     */
    public function getBaseAccessTokenUrl()
    {
        return "https://ssl.reddit.com/api/v1/access_token";
    }

    /**
     * {@inheritDoc}
     */
    public function getUserDetailsUrl(AccessToken $token)
    {
        return "https://oauth.reddit.com/api/v1/me";
    }

    /**
     * {@inheritDoc}
     */
    public function getDefaultScopes()
    {
        return [
            'identity',
        ];
    }

    /**
     * {@inheritDoc}
     */
    public function prepareUserDetails(array $response, AccessToken $token)
    {
        return $response;
    }

    protected function checkResponse(ResponseInterface $response, $data)
    {

    }

    /**
     * Returns the user agent, which is required to be set.
     *
     * @return string
     * @throws Concat\OAuth2\Client\Exception\ProviderException
     */
    public function getUserAgent()
    {
        if ($this->userAgent) {
            return $this->userAgent;
        }

        // Use the server user agent as a fallback if no explicit one was set.
        return $_SERVER["HTTP_USER_AGENT"];
    }


    protected function getDefaultHeaders(AccessToken $token = null)
    {
        if ($token) {
            // Using the token, so user agent is required.

            if ( ! ($ua = $this->getUserAgent())) {
                throw new InvalidArgumentException("User agent is required");
            }

            return [
                "User-Agent" => $ua,
            ];
        }

        // Requesting a token, so HTTP Basic auth is required.
        $encoded = base64_encode("{$this->clientId}:{$this->clientSecret}");

        return [
            'Authorization' => "Basic $encoded",
        ];
    }


    /**
     * {@inheritDoc}
     *
     * @see https://github.com/reddit/reddit/wiki/OAuth2
     */
    public function getAccessToken($grant = "authorization_code", $params = [])
    {
        // Allow Reddit-specific 'installed_client' to be specified as a string,
        // keeping consistent with the other grant types.
        if ($grant === "installed_client") {
            $grant = new InstalledClient();
        }

        return parent::getAccessToken($grant, $params);
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthorizationUrl($options = [])
    {
        $url = parent::getAuthorizationUrl($options);

        // This is required as an option to be given a refresh token
        if (isset($options["duration"])) {
            $url .= "&duration={$options['duration']}";
        }

        return $url;
    }
}

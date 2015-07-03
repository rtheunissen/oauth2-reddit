<?php

namespace Concat\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;
use Concat\OAuth2\Client\Grant\InstalledClient;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use InvalidArgumentException;

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
        return "https://www.reddit.com/api/v1/authorize";
    }

    /**
     * {@inheritDoc}
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return "https://www.reddit.com/api/v1/access_token";
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
    public function createUser(array $response, AccessToken $token)
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
        return @$_SERVER["HTTP_USER_AGENT"];
    }

    protected function getAccessTokenOptions(array $params)
    {
        $options = parent::getAccessTokenOptions($params);

        // Requesting a token, so HTTP Basic auth is required.
        $encoded = base64_encode("{$this->clientId}:{$this->clientSecret}");

        $options['headers'] = [
            'Authorization' => "Basic $encoded",
            'Content-Type'  => 'application/x-www-form-urlencoded',
        ];

        return $options;
    }

    /**
     * Builds the access token URL's query string.
     *
     * @param array $params Query parameters
     * @return string Query string
     */
    protected function getAccessTokenQuery(array $params)
    {
        return urldecode(http_build_query($params));
    }

    protected function getDefaultHeaders($token = null)
    {
        if (! ($ua = $this->getUserAgent())) {
            throw new InvalidArgumentException("User agent is required");
        }

        return [
            "User-Agent" => $ua,
        ];
    }


    /**
     * {@inheritDoc}
     *
     * @see https://github.com/reddit/reddit/wiki/OAuth2
     */
    public function getAccessToken($grant, array $options = [])
    {
        // Allow Reddit-specific 'installed_client' to be specified as a string,
        // to keep consistent with the other grant types.
        if ($grant === "installed_client") {
            $grant = new InstalledClient();
        }

        return parent::getAccessToken($grant, $options);
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthorizationUrl(array $options = [])
    {
        $url = parent::getAuthorizationUrl($options);

        // This is required as an option to be given a refresh token
        if (isset($options["duration"])) {
            $url .= "&duration={$options['duration']}";
        }

        return $url;
    }
}

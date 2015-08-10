<?php

namespace Rudolf\OAuth2\Client\Grant;

use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Token\AccessToken;
use InvalidArgumentException;

/**
 * @see https://github.com/reddit/reddit/wiki/OAuth2
 */
class InstalledClient extends AbstractGrant
{
    public function getName()
    {
        return 'https://oauth.reddit.com/grants/installed_client';
    }

    protected function getRequiredRequestParameters()
    {
        return [
            'device_id',
        ];
    }

    /**
     * Prepares an access token request's parameters by checking that all
     * required parameters are set, then merging with any given defaults.
     *
     * @param array $defaults
     * @param array $options
     *
     * @return array
     */
    public function prepareRequestParameters(array $defaults, array $options)
    {
        $parameters = parent::prepareRequestParameters($defaults, $options);

        // device_id has to be a 20-30 character ASCII string
        if (! preg_match("/^[[:ascii:]]{20,30}$/", $options["device_id"])) {
            throw new InvalidArgumentException("Invalid device_id");
        }

        return $parameters;
    }
}

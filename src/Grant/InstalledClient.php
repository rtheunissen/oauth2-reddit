<?php

namespace Rudolf\OAuth2\Client\Grant;

use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Token\AccessToken;

/**
 * @see https://github.com/reddit/reddit/wiki/OAuth2
 */
class InstalledClient extends AbstractGrant
{
	public function __toString()
	{
		return 'https://oauth.reddit.com/grants/installed_client';
	}

	/**
     * Get a list of all required request parameters.
     *
     * @return array
     */
    protected function getRequiredRequestParams()
    {
    	return ['device_id'];
    }

	public function prepRequestParams(array $defaultParams, array $params)
    {
    	$params = parent::prepRequestParams($defaultParams, $params);

        // device_id has to be a 20-30 character ASCII string
        if ( ! preg_match("/^[[:ascii:]]{20,30}$/", $params["device_id"])) {
        	throw new \InvalidArgumentException("Invalid device_id");
        }

        return $params;
    }

    public function handleResponse(array $response = [])
    {
        return new AccessToken($response);
    }
}
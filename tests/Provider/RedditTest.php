<?php

namespace Rudolf\OAuth2\Client\Tests\Provider;

use Rudolf\OAuth2\Client\Provider\Reddit;
use League\OAuth2\Client\Token\AccessToken;

class RedditTest extends \PHPUnit_Framework_TestCase
{

    private function getBaseCredentials()
    {
        return [
            'userAgent' => 'phpunit:oauth2:test (by /u/oauth2)',
            'scopes'    => ['identity', 'read'],
        ];
    }

    private function getCredentialsFromEnv($type)
    {
        $credentials = [];
        foreach ($_ENV as $key => $value) {
            $prefix = "reddit_$type";

            if (strpos($key, $prefix) === 0) {
                $credentials[substr($key, strlen($prefix))] = $value;
            }
        }
        return $credentials;
    }

    /**
     * Please note that these credentials are for test purposes only
     * and don't belong to a proper application. Therefore it's okay
     * to specify them here out in the open, where it would obviously
     * be a very bad idea otherwise.
     */
    private function getCredentials($type = 'web')
    {
        $env = __DIR__ . "/env.json";

        if (is_file($env)) {
            $credentials = json_decode(file_get_contents($env), true);
        } else if (@$_ENV['TRAVIS']) {
            // get credentials from env
            $credentials = $this->getCredentialsFromEnv($type);
        } else {
            $this->markTestSkipped();
        }

        return array_merge($this->getBaseCredentials(), $credentials[$type]);
    }

    private function createProvider($credentials)
    {
        return new Reddit($credentials);
    }

    private function assertValidAccessToken(AccessToken $token)
    {
        $this->assertObjectHasAttribute('accessToken', $token);
        $this->assertObjectHasAttribute('expires', $token);

        $this->assertRegExp("~\d{10,}~", "$token->expires");
        $this->assertTrue( ! empty($token->accessToken));
    }

    private function _testGetAuthorizationUrl($options = [])
    {
        $credentials = $this->getCredentials();
        $provider = $this->createProvider($credentials);

        $url = $provider->getAuthorizationUrl($options);
        extract(parse_url($url));

        $this->assertEquals('https', $scheme);
        $this->assertEquals('ssl.reddit.com', $host);
        $this->assertEquals('/api/v1/authorize', $path);

        parse_str($query);

        $this->assertEquals($client_id,         $credentials['clientId']);
        $this->assertEquals($redirect_uri,      $credentials['redirectUri']);
        $this->assertEquals($response_type,     'code');
        $this->assertEquals($approval_prompt,   'auto');
        $this->assertEquals($scope,             'identity,read');

        if (isset($options['duration'])) {
            $this->assertEquals($duration, $options['duration']);
        } else {
            $this->assertFalse(isset($duration));
        }

        $this->assertRegExp('~[a-zA-Z0-9]{32}~', $state);
    }

    public function testGetAuthorizationUrl()
    {
        $this->_testGetAuthorizationUrl(['duration' => 'permanent']);
        $this->_testGetAuthorizationUrl(['duration' => 'temporary']);
        $this->_testGetAuthorizationUrl();
    }

    public function testGetHeaders()
    {
        $credentials = $this->getCredentials();
        $auth = base64_encode(
            "{$credentials['clientId']}:{$credentials['clientSecret']}");

        $expected = [
            "User-Agent"    => $credentials['userAgent'],
            "Authorization" => "Basic $auth"
        ];

        $provider = $this->createProvider($credentials);
        $this->assertEquals($expected, $provider->getHeaders());
    }

    public function testUserDetails()
    {
        $credentials = $this->getCredentials('password');
        $provider = $this->createProvider($credentials);
        $token = $provider->getAccessToken('password', [
            'username' => $credentials['username'],
            'password' => $credentials['password']
        ]);
        $userData = $provider->getUserDetails($token);
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testGetHeadersInvalidUserAgent()
    {
        $credentials = $this->getCredentials();
        $credentials['userAgent'] = 'invalid';

        $invalidProvider = $this->createProvider($credentials);
        $invalidProvider->getHeaders();
    }

    public function testGetUserAgentFromServer()
    {
        $credentials = $this->getCredentials();
        $userAgent = $credentials['userAgent'];
        $_SERVER['HTTP_USER_AGENT'] = $userAgent;

        $credentials['userAgent'] = '';

        $provider = $this->createProvider($credentials);

        $this->assertFalse(!! $provider->userAgent);
        $provider->getHeaders();
    }

    public function testGetHeadersWithToken()
    {
        $accessToken = md5(time());
        $token = new AccessToken([
            'access_token' => $accessToken,
            'expires'      => time() + 3600
        ]);

        $credentials = $this->getCredentials();
        $expected = [
            "User-Agent"    => $credentials['userAgent'],
            "Authorization" => "bearer $accessToken"
        ];

        $provider = $this->createProvider($credentials);
        $this->assertEquals($expected, $provider->getHeaders($token));
    }

    public function testGetAccessTokenUsingClientCredentials()
    {
        $credentials = $this->getCredentials('client_credentials');
        $provider = $this->createProvider($credentials);
        $token = $provider->getAccessToken('client_credentials');
        $this->assertValidAccessToken($token);
    }

    public function testGetAccessTokenUsingUsernameAndPassword()
    {
        $credentials = $this->getCredentials('password');
        $provider = $this->createProvider($credentials);
        $token = $provider->getAccessToken('password', [
            'username' => $credentials['username'],
            'password' => $credentials['password']
        ]);

        $this->assertValidAccessToken($token);
    }

    public function testGetAccessTokenUsingImplicitFlow()
    {
        $credentials = $this->getCredentials('installed_client');
        $provider = $this->createProvider($credentials);
        $token = $provider->getAccessToken('installed_client', [
            'device_id' => uniqid('', true),
        ]);

        $this->assertValidAccessToken($token);
    }

    private function _testDeviceId($options = [])
    {
        $credentials = $this->getCredentials('installed_client');
        $provider = $this->createProvider($credentials);
        $token = $provider->getAccessToken('installed_client', $options);
    }

    /**
     * @expectedException BadMethodCallException
     */
    public function testGetAccessTokenUsingImplicitFlowWithoutDeviceId()
    {
        $this->_testDeviceId();
    }

    /**
     * @expectedException BadMethodCallException
     */
    public function testGetAccessTokenUsingImplicitFlowWithBlankDeviceId()
    {
        $this->_testDeviceId([
            "device_id" => "" // equivalent to not provided
        ]);
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testGetAccessTokenUsingImplicitFlowWithShortDeviceId()
    {
        $this->_testDeviceId([
            "device_id" => "abc" // too short
        ]);
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testGetAccessTokenUsingImplicitFlowWithInvalidDeviceId()
    {
        $this->_testDeviceId([
            "device_id" => str_repeat("☕", 24), // has to be ASCII
        ]);
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testGetAccessTokenUsingImplicitFlowWithLongDeviceId()
    {
        $this->_testDeviceId([
            "device_id" => md5(""), // too long
        ]);
    }
}

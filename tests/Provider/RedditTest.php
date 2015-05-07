<?php

namespace Rudolf\OAuth2\Client\Tests\Provider;

use Rudolf\OAuth2\Client\Provider\Reddit;
use Rudolf\OAuth2\Client\Exception\ProviderException;

use League\OAuth2\Client\Token\AccessToken;

class RedditTest extends \PHPUnit_Framework_TestCase
{

    private function getDefaultOptions()
    {
        return [
            'clientId'      => '1234',
            'clientSecret'  => 'topsykretz',
            'redirectUri'   => 'http://example.com',
            'userAgent'     => 'platform:app_id:version (by /u/username)',
            'scopes'        => ['identity', 'read'],
        ];
    }

    private function createProvider($options = [])
    {
        return new Reddit(array_merge($this->getDefaultOptions(), $options));
    }

    public function setUp()
    {
        $this->provider = $this->createProvider();
    }

    private function _testGetAuthorizationUrl($options = [])
    {
        $url = $this->provider->getAuthorizationUrl($options);

        extract(parse_url($url));

        $this->assertEquals('https', $scheme);
        $this->assertEquals('ssl.reddit.com', $host);
        $this->assertEquals('/api/v1/authorize', $path);

        parse_str($query);
        $expected = $this->getDefaultOptions();

        $this->assertEquals($client_id,         $expected['clientId']);
        $this->assertEquals($redirect_uri,      $expected['redirectUri']);
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
        $expected = [
            "User-Agent"    => "platform:app_id:version (by /u/username)",
            "Authorization" => "Basic MTIzNDp0b3BzeWtyZXR6"
        ];
        $this->assertEquals($expected, $this->provider->getHeaders());
    }

    public function testGetHeadersInvalidUserAgent()
    {
        $invalidProvider = $this->createProvider([
            "userAgent" => "invalidUserAgent!!",
        ]);

        $this->setExpectedException(ProviderException::class);
        $invalidProvider->getHeaders();
    }

    public function testGetHeadersWithToken()
    {
        $accessToken = md5(time());

        $token = new AccessToken([
            'access_token' => $accessToken,
            'expires'      => time() + 10
        ]);

        $expected = [
            "User-Agent"    => "platform:app_id:version (by /u/username)",
            "Authorization" => "bearer $accessToken"
        ];

        $this->assertEquals($expected, $this->provider->getHeaders($token));
    }
}

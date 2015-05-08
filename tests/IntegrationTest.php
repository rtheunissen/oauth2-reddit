<?php

namespace Rudolf\OAuth2\Client\Tests\Provider;

use Rudolf\OAuth2\Client\Provider\Reddit;
use League\OAuth2\Client\Token\AccessToken;

class IntegrationTest extends \PHPUnit_Framework_TestCase
{


    private function getCredentials($type)
    {
        return [
            'client_credentials' => [
                'clientId'      => '_E1mlXLDmcCcNA',
                'clientSecret'  => '1YqWC1U93XWOJBoRdLB0PtjOZ_U',
                // 'redirectUri'   => 'https://github.com/rtheunissen/oauth2-reddit',
                'userAgent'     => 'phpunit:php-oauth2-web:na (by /u/rtheunissen)',
                'scopes'        => ['identity'],
            ],
        ][$type];
    }

    private function createProvider($type)
    {
        return new Reddit($this->getCredentials($type));
    }

    protected function setUp()
    {
        // if( ! isset($_ENV['INTEGRATION'])) {
            // $this->markTestSkipped('Skipping integration test');
        // }
    }


    public function testReceiveStateAndCode()
    {
        $provider = $this->createProvider('client_credentials');

        $token = $provider->getAccessToken('client_credentials');

        /*

      public $accessToken =>
      string(28) "-cI-vtCDC1WNBWaHlgr0XYtW0OaU"
      public $expires =>
      int(1431071867)
      public $refreshToken =>
      NULL
      public $uid =>
      NULL


        */

        var_dump($token);
    }

    // private function _testGetAuthorizationUrl($options = [])
    // {
    //     $url = $this->provider->getAuthorizationUrl($options);
    //     extract(parse_url($url));

    //     $this->assertEquals('https', $scheme);
    //     $this->assertEquals('ssl.reddit.com', $host);
    //     $this->assertEquals('/api/v1/authorize', $path);

    //     parse_str($query);
    //     $expected = $this->getDefaultOptions();

    //     $this->assertEquals($client_id,         $expected['clientId']);
    //     $this->assertEquals($redirect_uri,      $expected['redirectUri']);
    //     $this->assertEquals($response_type,     'code');
    //     $this->assertEquals($approval_prompt,   'auto');
    //     $this->assertEquals($scope,             'identity,read');

    //     if (isset($options['duration'])) {
    //         $this->assertEquals($duration, $options['duration']);
    //     } else {
    //         $this->assertFalse(isset($duration));
    //     }

    //     $this->assertRegExp('~[a-zA-Z0-9]{32}~', $state);
    // }

    // public function testGetAuthorizationUrl()
    // {
    //     $this->_testGetAuthorizationUrl(['duration' => 'permanent']);
    //     $this->_testGetAuthorizationUrl(['duration' => 'temporary']);
    //     $this->_testGetAuthorizationUrl();
    // }

    // public function testGetHeaders()
    // {
    //     extract($this->getDefaultOptions());
    //     $auth = base64_encode("{$clientId}:{$clientSecret}");

    //     $expected = [
    //         "User-Agent"    => "platform:app_id:version (by /u/username)",
    //         "Authorization" => "Basic $auth"
    //     ];
    //     $this->assertEquals($expected, $this->provider->getHeaders());
    // }

    // public function testUrlAccessToken()
    // {
    //     $url = $this->provider->urlAccessToken();
    //     extract(parse_url($url));

    //     $this->assertEquals('https', $scheme);
    //     $this->assertEquals('ssl.reddit.com', $host);
    //     $this->assertEquals('/api/v1/access_token', $path);
    // }

    // public function testUrlUserDetails()
    // {
    //     $token = $this->createFakeAccessToken();
    //     $url = $this->provider->urlUserDetails($token);
    //     extract(parse_url($url));

    //     $this->assertEquals('https', $scheme);
    //     $this->assertEquals('oauth.reddit.com', $host);
    //     $this->assertEquals('/api/v1/me', $path);
    // }

    // public function testUserDetails()
    // {
    //     $token = $this->createFakeAccessToken();
    //     $request = [
    //         'test' => true,
    //         'data' => [1, 2, 3],
    //     ];

    //     $userData = $this->provider->userDetails($request, $token);
    //     $this->assertEquals($request, $userData);
    // }

    // private function createFakeAccessToken($data = [])
    // {
    //     if ( ! $data) {
    //         $data = [
    //             'access_token' => md5(time()),
    //             'expires'      => time() + 3600
    //         ];
    //     }
    //     return new AccessToken($data);
    // }

    // /**
    //  * @expectedException InvalidArgumentException
    //  */
    // public function testGetHeadersInvalidUserAgent()
    // {
    //     $invalidProvider = $this->createProvider([
    //         "userAgent" => "invalidUserAgent!!",
    //     ]);

    //     $invalidProvider->getHeaders();
    // }

    // public function testGetUserAgentFromServer()
    // {
    //     $_SERVER['HTTP_USER_AGENT'] = $this->getDefaultOptions()['userAgent'];

    //     $provider = $this->createProvider([
    //         'userAgent' => ''
    //     ]);

    //     $this->assertFalse(!! $provider->userAgent);
    //     $provider->getHeaders();
    // }

    // public function testGetHeadersWithToken()
    // {
    //     $accessToken = md5(time());

    //     $token = $this->createFakeAccessToken([
    //         'access_token' => $accessToken,
    //         'expires'      => time() + 3600
    //     ]);

    //     $expected = [
    //         "User-Agent"    => "platform:app_id:version (by /u/username)",
    //         "Authorization" => "bearer $accessToken"
    //     ];

    //     $this->assertEquals($expected, $this->provider->getHeaders($token));
    // }
}

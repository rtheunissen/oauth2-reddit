<?php

namespace Rudolf\OAuth2\Client\Provider;


class RedditUser implements ResourceOwnerInterface 
{
    /**
     * @var array
     */
    protected $data;

    /**
     * @param  array $response
     */
    public function __construct(array $response)
    {
        $this->data = $response;
        dd($this->data);
    }
}
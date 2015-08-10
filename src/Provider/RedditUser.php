<?php

namespace Rudolf\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

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

    /**
	 * {@inheritdoc}
     */
    public function getId() 
    {

    }
    
    /**
	 * {@inheritdoc}
     */
    public function toArray()
    {
    	
    }
}
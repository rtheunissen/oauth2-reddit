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
    }

    /**
	 * {@inheritdoc}
     */
    public function getId() 
    {
    	return $this->data['id'];
    }

    /**
     * Get name
     *
     * @return string
     */
    public function getName()
    {
    	return $this->data['name'];
    }
    
    /**
     * Get created at date
     *
     * @return string
     */
    public function getCreatedAt()
    {
    	return $this->data['created'];
    }

    /**
     * Get Link Karma
     *
     * @return string
     */
    public function getLinkKarma()
    {
    	return $this->data['link_karma'];
    }

    /**
     * Get Comment Karma
     *
     * @return string
     */
    public function getCommentKarma()
    {
    	return $this->data['comment_karma'];
    }

    /**
	 * {@inheritdoc}
     */
    public function toArray()
    {
    	return $this->data;
    }
}
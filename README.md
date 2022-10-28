# mwstake/mediawiki-component-oauth-client

Library for user authentication over OAuth2 protocol.

## Installation

```bash
composer require mwstake/mediawiki-component-oauth-client
```

## Usage

### Connection params
```php

$GLOBALS['wgOAuthClientConfig'] = [
	'base_uri' => '',
			'client_id' => '##CLIENT_ID##',
			'client_secret' => '##CLIENT_SECRET##',
			// if needed adapt endpoints, if not, omit to use the defaults
			'endpoints' => [
				'authorize' => '/oauth2/authorize',
				'token' => '/oauth2/token',
				'user' => '/oauth2/user',
			],
			// if needed adapt scopes, if not, omit to use the defaults
			'default_scopes' => [],
			'redirect_uri' => ##REDIRECT_URI##,
];

```

### Login page

Your implementation needs to provide a login page that will be used as the redirect target for the OAuth2 authorization code flow.

Specify the name of the SpecialPage in `$GLOBALS['wgOAuthLoginPage'] = 'MyPage`;`

### Resource owner

If you want to have a custom resource owner, implement a class that implements `League\OAuth2\Client\Provider\ResourceOwnerInterface`
and set it in `$GLOBALS['wgOAuthClientResourceOwner'] = MyResourceOwner::class;`.

Otherwise, the default `League\OAuth2\Client\Provider\GenericResourceOwner` will be used.



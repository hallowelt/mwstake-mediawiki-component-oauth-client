<?php

if ( !defined( 'MEDIAWIKI' ) && !defined( 'MW_PHPUNIT_TEST' ) ) {
	return;
}

if ( defined( 'MWSTAKE_MEDIAWIKI_COMPONENT_OAUTH_CLIENT_VERSION' ) ) {
	return;
}

define( 'MWSTAKE_MEDIAWIKI_COMPONENT_OAUTH_CLIENT_VERSION', '2.0.0' );

MWStake\MediaWiki\ComponentLoader\Bootstrapper::getInstance()
	->register( 'oauth-client', function () {
		$GLOBALS['wgServiceWiringFiles'][] = __DIR__ . '/ServiceWiring.php';

		$GLOBALS['wgOAuthClientConfig'] = $GLOBALS['wgOAuthClientConfig'] ?? [];
		$GLOBALS['wgOAuthClientConfig'] += [
			'base_uri' => '',
			'client_id' => null,
			'client_secret' => null,
			'endpoints' => [
				'authorize' => '/oauth2/authorize',
				'token' => '/oauth2/token',
				'user' => '/oauth2/user',
			],
			'default_scopes' => [],
			'redirect_uri' => null
		];

		$GLOBALS['wgOAuthLoginPage'] = null;
		// Object factory spec, ctor will be called with user data array
		$GLOBALS['wgOAuthClientResourceOwner'] = [
			'class' => \League\OAuth2\Client\Provider\GenericResourceOwner::class
		];
	} );




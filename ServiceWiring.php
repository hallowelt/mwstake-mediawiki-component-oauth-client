<?php

use MediaWiki\Logger\LoggerFactory;
use MediaWiki\MediaWikiServices;

return [
	'OAuth2Connection' => static function ( MediaWikiServices $services ) {
		$logger = LoggerFactory::getInstance( 'oauth-client-connection' );
		$provider = new \MWStake\MediaWiki\Component\OAuthClient\Provider(
			$services->getMainConfig(), $logger
		);

		return new \MWStake\MediaWiki\Component\OAuthClient\Connection(
			$provider,
			RequestContext::getMain()->getRequest()->getSession(),
			$logger
		);
	}
];

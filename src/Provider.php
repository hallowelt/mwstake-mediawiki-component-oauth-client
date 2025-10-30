<?php

namespace MWStake\MediaWiki\Component\OAuthClient;

use Config;
use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use MediaWiki\MediaWikiServices;
use MediaWiki\Session\Session;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Math\BigInteger;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;

class Provider extends AbstractProvider {
	use BearerAuthorizationTrait;

	/** @var Config */
	private $config;
	/** @var LoggerInterface */
	private $logger;
	/** @var array */
	private $resourceOwnerSpec;
	/** @var string */
	private $loginPage;
	/** @var Session */
	private $session;

	/**
	 * @param Config $config
	 * @param LoggerInterface $logger
	 */
	public function __construct( Config $config, LoggerInterface $logger ) {
		$this->config = $config;
		$this->logger = $logger;
		$this->resourceOwnerSpec = $config->get( 'OAuthClientResourceOwner' );
		$this->loginPage = $config->get( 'OAuthLoginPage' );
		$options = $config->get( 'OAuthClientConfig' );

		$parentConfig = [
			'clientId' => $options['client_id'],
			'clientSecret' => $options['client_secret'],
			'redirectUri' => $options['redirect_uri'],
		];
		parent::__construct( $parentConfig );
	}

	/**
	 * @param Session $session
	 */
	public function setSession( Session $session ) {
		$this->session = $session;
	}

	/**
	 * @return string
	 * @throws Exception
	 */
	public function getBaseAuthorizationUrl() {
		return $this->compileUrl( 'authorize' );
	}

	/**
	 * @param array $params
	 * @return string
	 * @throws Exception
	 */
	public function getBaseAccessTokenUrl( array $params ) {
		return $this->compileUrl( 'token' );
	}

	/**
	 * @param AccessToken $token
	 * @return string
	 * @throws Exception
	 */
	public function getResourceOwnerDetailsUrl( AccessToken $token ) {
		return $this->compileUrl( 'user' );
	}

	public function redirectToLogin() {
		if ( !$this->session || !$this->loginPage ) {
			throw new Exception( "Cannot redirect to login" );
		}
		$page = MediaWikiServices::getInstance()->getSpecialPageFactory()->getPage( $this->loginPage );
		if ( !$page ) {
			throw new Exception( "Cannot redirect to login" );
		}
		$url = $page->getPageTitle()->getFullURL( [ 'returnto' => $this->session->getRequest()->getVal( 'title' ) ] );
		header( 'Location: ' . $url );
	}

	/**
	 * @return string[]
	 */
	protected function getDefaultScopes() {
		return $this->getConfigItem( 'default_scopes' );
	}

	/**
	 * @param ResponseInterface $response
	 * @param array|string $data
	 * @throws Exception
	 */
	protected function checkResponse( ResponseInterface $response, $data ) {
		if ( isset( $data['id_token'] ) ) {
			$this->verifyJWT( $data['id_token'] );
		}
		if ( $response->getStatusCode() !== 200 ) {
			$this->logger->error( 'Response verification failed: {code} {reason}', [
				'code' => $response->getStatusCode(),
				'reason' => $response->getReasonPhrase(),
			] );
			throw new Exception( "Invalid response from authentication provider" );
		}
	}

	/**
	 * @param string $token
	 * @throws \SodiumException
	 */
	private function verifyJWT( $token ) {
		JWT::$leeway = 10;
		// Checks validity period, signature
		$d = JWT::decode( $token, $this->getJWTKeys() );

		if ( $d->iss !== $this->getBaseUrl() ) {
			$this->logger->error( 'Verify JWT: iss not valid: iss={iss} expected={base}', [
				'iss' => $d->iss,
				'base' => $this->getBaseUrl(),
			] );
			throw new Exception( 'Verify JWT: iss not valid' );
		}

		$clientId = $this->config->get( 'OAuthClientConfig' )['clientId'] ?? null;
		if ( $d->aud !== $clientId ) {
			$this->logger->error( 'Verify JWT: iss not valid: aud={aud} expected={client}', [
				'aud' => $d->aud,
				'client' => $clientId,
			] );
			throw new Exception( 'Verify JWT: aud not valid' );
		}

		if ( !property_exists( $d, 'sub' ) ) {
			$this->logger->error( 'Verify JWT: sub claim is missing' );
			throw new Exception( 'Verify JWT: sub claim missing' );
		}

		$nonce = $d->nonce ?? null;
		if ( $nonce ) {
			if ( !$this->session ) {
				throw new Exception( 'Session must be set before obtaining AccessToken' );
			}
			$storedNonce = $this->session->get( 'oauth2nonce' );
			if ( !hash_equals( $nonce, $storedNonce ) ) {
				throw new Exception( 'Verify JWT: nonce does not match' );
			}
		}
	}

	/**
	 * @inheritDoc
	 */
	protected function createAccessToken( array $response, AbstractGrant $grant ) {
		if ( isset( $response['expires_at'] ) ) {
			$response['expires'] = $response['expires_at'];
		}
		return parent::createAccessToken( $response, $grant );
	}

	/**
	 * @return array
	 * @throws \SodiumException
	 */
	private function getJWTKeys() {
		$keyResponse = $this->getResponse(
			$this->getRequest( 'GET', $this->compileUrl( 'jwks' ) )
		);
		if ( $keyResponse->getStatusCode() !== 200 ) {
			$this->logger->error( 'Failed to retrive JWKS: {code} {reason}', [
				'code' => $keyResponse->getStatusCode(),
				'reason' => $keyResponse->getReasonPhrase(),
			] );
			throw new Exception( "Could not retrieve JWT public key" );
		}
		$keys = json_decode( $keyResponse->getBody(), 1 );
		$res = [];
		foreach ( $keys['keys'] as $keyData ) {
			if ( $keyData['kty'] !== 'RSA' ) {
				// Dont know how to handle other types
				continue;
			}
			$modulus = sodium_base642bin( $keyData['n'], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING );
			$exponent = sodium_base642bin( $keyData['e'], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING );
			$key = PublicKeyLoader::loadPublicKey( [
				'e' => new BigInteger( $exponent, 256 ),
				'n' => new BigInteger( $modulus, 256 ),
			] );

			$res[$keyData['kid']] = new Key( $key->toString( 'pkcs8' ), $keyData['alg'] );
		}
		return $res;
	}

	/**
	 * @param array $response
	 * @param AccessToken $token
	 * @return ResourceOwnerInterface
	 */
	protected function createResourceOwner( array $response, AccessToken $token ) {
		$spec = $this->resourceOwnerSpec ?? [];
		$spec['args'] = array_merge( ( $spec['args'] ?? [] ), [ $response, 'resourceOwnerId' ] );
		return MediaWikiServices::getInstance()->getObjectFactory()->createObject( $spec );
	}

	/**
	 * @return string
	 * @throws Exception
	 */
	public function getBaseUrl() {
		$url = $this->getConfigItem( 'base_uri' );
		if ( !$url ) {
			$this->logger->error( 'Config variable base_uri must be set' );
			throw new Exception( 'Config variable base_uri must be set' );
		}

		return rtrim( $url, '/' );
	}

	/**
	 * @param string $type
	 * @return string
	 * @throws Exception
	 */
	public function compileUrl( $type ) {
		$endpoints = $this->getConfigItem( 'endpoints' );
		return $this->getBaseUrl() . ( $endpoints[$type] ?? '' );
	}

	/**
	 * @param string $key
	 * @param mixed $default
	 * @return mixed
	 */
	private function getConfigItem( $key, $default = null ) {
		$config = $this->config->get( 'OAuthClientConfig' );
		return $config[$key] ?? $default;
	}
}

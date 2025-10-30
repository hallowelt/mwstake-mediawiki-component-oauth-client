<?php

namespace MWStake\MediaWiki\Component\OAuthClient;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use MediaWiki\Session\Session;
use Psr\Http\Message\RequestInterface;
use Psr\Log\LoggerInterface;

class Connection {
	/** @var Provider */
	private $provider;
	/** @var Session */
	private $session;
	/** @var LoggerInterface */
	private $logger;
	/** @var AccessToken|null */
	private $accessToken = null;
	/** @var array|null */
	private $integrationData = null;

	/**
	 * @param Provider $provider
	 * @param Session $session
	 * @param LoggerInterface $logger
	 */
	public function __construct( Provider $provider, Session $session, LoggerInterface $logger ) {
		$this->provider = $provider;
		$this->provider->setSession( $session );
		$this->session = $session;
		$this->logger = $logger;
	}

	/**
	 * @param string $returnTo
	 * @return string
	 * @throws \SodiumException
	 */
	public function getAuthorizationUrl( $returnTo = '' ) {
		$this->session->persist();
		$this->session->set( 'returnto', $returnTo );

		$codeVerifier = bin2hex( random_bytes( 32 ) );
		$codeChallenge = sodium_bin2base64(
			hash( 'sha256', $codeVerifier, true ),
			SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING
		);
		$this->session->set( 'oauth2codeverifier', $codeVerifier );
		$nonce = $this->getNonce();
		$this->session->set( 'oauth2nonce', $nonce );

		$url = $this->provider->getAuthorizationUrl( [
			'code_challenge' => $codeChallenge,
			'code_challenge_method' => 'S256',
			'nonce' => $nonce
		] );

		$this->session->set( 'oauth2state', $this->provider->getState() );
		$this->session->save();

		return $url;
	}

	/**
	 * @param \WebRequest $request
	 * @return AccessToken|AccessTokenInterface|null
	 * @throws IdentityProviderException
	 */
	public function obtainAccessToken( \WebRequest $request ) {
		$storedState = $this->session->get( 'oauth2state' );
		$providedState = $request->getVal( 'state' );

		if ( !hash_equals( $storedState, $providedState ) ) {
			$this->logger->error( "State mismatch: provided={provided} expected={exp}", [
				'provided' => $providedState,
				'exp' => $storedState,
			] );
			throw new \UnexpectedValueException(
				'Provided state param in the callback does not match original state'
			);
		}

		$this->accessToken = $this->provider->getAccessToken( 'authorization_code', [
			'code' => $request->getVal( 'code' ),
			'code_verifier' => $this->session->get(
				'oauth2codeverifier'
			)
		] );

		if ( !$this->storeAccessToken( $this->accessToken ) ) {
			$this->logger->warning( 'Failed to store access token' );
		}
		return $this->accessToken;
	}

	/**
	 * @return ResourceOwnerInterface
	 * @throws \Exception
	 */
	public function getResourceOwner(): ResourceOwnerInterface {
		if ( !$this->accessToken ) {
			$this->logger->error(
				"Attempted to retrieve resource owner before obtaining the access token"
			);
			throw new \Exception( 'Access token not yet obtained' );
		}

		$ro = $this->provider->getResourceOwner( $this->accessToken );
		if ( !( $ro instanceof ResourceOwnerInterface ) ) {
			$this->logger->error(
				"Failed to retrieve or cast resource owner"
			);
			throw new \Exception( 'Could not retrieve resource owner' );
		}
		return $ro;
	}

	/**
	 * @param string $method
	 * @param string $url
	 * @param array $options
	 * @return RequestInterface
	 */
	public function getAuthenticatedRequest( $method, $url, $options = [] ) {
		$token = $this->getAccessToken();
		if ( !$token ) {
			return null;
		}
		$url = $this->provider->getBaseUrl() . '/' . $url;
		return $this->provider->getAuthenticatedRequest(
			$method, $url, $this->getAccessToken()->getToken(), $options
		);
	}

	/**
	 * Currently unused, needed for the future
	 *
	 * @return AccessTokenInterface|null
	 * @throws IdentityProviderException
	 */
	private function getAccessToken(): ?AccessTokenInterface {
		if ( !$this->accessToken && !$this->trySetStoredAccessToken() ) {
			return null;
		}
		if ( $this->accessToken->getExpires() && $this->accessToken->hasExpired() ) {
			$this->refreshAccessToken();
		}

		return $this->accessToken;
	}

	private function trySetStoredAccessToken() {
		$token = $this->retrieveStoredAccessToken();
		if ( !( $token instanceof AccessTokenInterface ) ) {
			return false;
		}

		$this->accessToken = $token;
		return true;
	}

	/**
	 * @throws IdentityProviderException
	 */
	private function refreshAccessToken() {
		try {
			$this->accessToken = $this->provider->getAccessToken( 'refresh_token', [
				'refresh_token' => $this->accessToken->getRefreshToken(),
			] );
			if ( !$this->storeAccessToken( $this->accessToken ) ) {
				$this->logger->warning( 'Failed to store access token' );
				throw new \Exception();
			}
		} catch ( \Exception $e ) {
			$this->provider->redirectToLogin();
		}
	}

	/**
	 * @return string
	 * @throws \SodiumException
	 */
	private function getNonce() {
		return sodium_bin2base64(
			hash( 'sha256', $this->session->getId(), true ),
			SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING
		);
	}

	/**
	 * @return Provider
	 */
	public function getProvider() {
		return $this->provider;
	}

	/**
	 * @param AccessTokenInterface $accessToken
	 * @return bool
	 */
	protected function storeAccessToken( AccessTokenInterface $accessToken ): bool {
		$this->session->set( 'oauth2AccessToken', $accessToken->jsonSerialize() );
		return true;
	}

	/**
	 * @return AccessTokenInterface|null
	 */
	protected function retrieveStoredAccessToken(): ?AccessTokenInterface {
		$tkn = $this->session->get( 'oauth2AccessToken', null );
		if ( !$tkn ) {
			return null;
		}

		return new AccessToken( $token );
	}
}

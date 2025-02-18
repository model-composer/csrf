<?php namespace Model\CSRF;

use Model\Session\Session;
use Model\Session\SessionInterface;

class CSRF
{
	public static function checkPayload(string $context, ?array $payload = null, string $key = 'cp_token'): void
	{
		if ($payload === null)
			$payload = \Model\Core\Model::getInput();

		if (empty($payload[$key]) or !self::check($context, $payload[$key]))
			throw new \Exception('Bad token', 401);
	}

	public static function render(string $context, string $key = 'cp_token'): void
	{
		echo '<input type="hidden" name="' . $key . '" value="' . self::getToken($context) . '" />';
	}

	public static function check(string $context, string $token): bool
	{
		return ($token === self::getToken($context));
	}

	public static function getToken(string $context): string
	{
		return sha1($context . '-' . self::getMainToken());
	}

	private static function getMainToken(?SessionInterface $session = null): string
	{
		$session ??= new Session();
		if (!$session->has('csrf-main-token'))
			$session->set('csrf-main-token', bin2hex(random_bytes(24)));

		return $session->get('csrf-main-token');
	}
}

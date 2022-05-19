<?php namespace Model\CSRF;

class CSRF
{
	public static function checkPayload(string $context, ?array $payload = null, string $key = 'cp_token'): void
	{
		if ($payload === null)
			$payload = $_POST;

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

	private static function getMainToken(): string
	{
		if (!isset($_SESSION['csrf-main-token']))
			$_SESSION['csrf-main-token'] = bin2hex(random_bytes(24));
		return $_SESSION['csrf-main-token'];
	}
}

<?php namespace Model\CSRF;

class CSRF
{
	public static function checkPost(string $context, string $key = 'c_id'): void
	{
		if (empty($_POST[$key]) or !self::check($context, $_POST[$key]))
			throw new \Exception('Bad token', 401);
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

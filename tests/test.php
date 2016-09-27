<?php

require_once __DIR__.'/../vendor/autoload.php'; // Autoload files using Composer autoload

$cwsDebug = new Cws\CwsDebug();
$cwsDebug->setDebugVerbose();
$cwsDebug->setEchoMode();

$cwsCrypto = new Cws\CwsCrypto($cwsDebug);

/*
 * Create and check password hash
 */

// password
$password = '1337StrongPassword';

// mode
$cwsCrypto->setPbkdf2Mode();
//$cwsCrypto->setBcryptMode(); // default

$hash = $cwsCrypto->hashPassword($password);
$check = $cwsCrypto->checkPassword($password, $hash);

/*
 * Encrypt/Decrypt datas
 */

// data
$data = 'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor ';
$data .= 'incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ';
$data .= 'ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit ';
$data .= 'in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat ';
$data .= 'non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.';

// encryption key
$cwsCrypto->setEncryptionKey('En;4QfZ2kh>8_47rz;H@WKwj6.xXRdF0cDL+)[.v:W1Xi}N|Jo{Hx^u?');

$encryptedData = $cwsCrypto->encrypt($data);
$cwsCrypto->decrypt($encryptedData);

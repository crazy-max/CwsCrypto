<?php

// Download CwsDump at https://github.com/crazy-max/CwsDump
require_once '../CwsDump/class.cws.dump.php';
$cwsDump = new CwsDump();

// Download CwsDebug at https://github.com/crazy-max/CwsDebug
require_once '../CwsDebug/class.cws.debug.php';
$cwsDebug = new CwsDebug($cwsDump);
$cwsDebug->setDebugVerbose();
$cwsDebug->setEchoMode();

require_once 'class.cws.crypto.php';
$cwsCrypto = new CwsCrypto($cwsDebug);

/**
 * Create and check password hash
 */

// password
$password = '1337StrongPassword';

// mode
$cwsCrypto->setPbkdf2Mode();
//$cwsCrypto->setBcryptMode(); // default

$hash = $cwsCrypto->hashPassword($password);
$check = $cwsCrypto->checkPassword($password, $hash);

/**
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

$encryptedDatas = $cwsCrypto->encrypt($data);
$cwsCrypto->decrypt($encryptedDatas);

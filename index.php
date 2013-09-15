<?php

require 'class.cws.crypto.php';

$cwsCrypto = new CwsCrypto();
$cwsCrypto->setDebugVerbose(CWSCRYPTO_VERBOSE_DEBUG);  // default CWSCRYPTO_VERBOSE_QUIET

/**
 * Create and check password hash
 */

$password = '1337StrongPassword';

// You can use the second parameter or set the default mode.
//$cwsCrypto->setDefaultMode(CWSCRYPTO_MODE_BCRYPT);

// BCRYPT hash mode
$hash = $cwsCrypto->hashPassword($password, CWSCRYPTO_MODE_BCRYPT);
//$hash = $cwsCrypto->hashPassword($password); // To use if default mode setted
$check = $cwsCrypto->checkPassword($password, $hash, CWSCRYPTO_MODE_BCRYPT);
//$check = $cwsCrypto->checkPassword($password, $hash); // To use if default mode setted

// PBKDF2 hash mode
$hash = $cwsCrypto->hashPassword($password, CWSCRYPTO_MODE_PBKDF2);
$check = $cwsCrypto->checkPassword($password, $hash, CWSCRYPTO_MODE_PBKDF2);

/**
 * Encrypt/Decrypt datas
 */

// Datas
$datas = 'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor ';
$datas .= 'incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ';
$datas .= 'ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit ';
$datas .= 'in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat ';
$datas .= 'non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. ';

// Random encryption key of 56 chars
// You can use the second parameter or set the default key.
$datasEncryptionKey = 'En;4QfZ2kh>8_47rz;H@WKwj6.xXRdF0cDL+)[.v:W1Xi}N|Jo{Hx^u?';
//$cwsCrypto->setDefaultKey('En;4QfZ2kh>8_47rz;H@WKwj6.xXRdF0cDL+)[.v:W1Xi}N|Jo{Hx^u?');

// Encrypt
$encryptedDatas = $cwsCrypto->encrypt($datas, $datasEncryptionKey);
//$encryptedDatas = $cwsCrypto->encrypt($datas); // To use if default key setted

// Decrypt
$cwsCrypto->decrypt($encryptedDatas, $datasEncryptionKey);
//$cwsCrypto->decrypt($datas); // To use if default key setted

?>
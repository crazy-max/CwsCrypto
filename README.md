# CwsCrypto

CwsCrypto is a PHP class for password hashing with two different encryption methods.

### The PBKDF2 key derivation function

Defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
This implementation of PBKDF2 was originally created by https://defuse.ca/php-pbkdf2.htm
With improvements by http://www.variations-of-shadow.com

### The OpenBSD-style Blowfish-based bcrypt

 This hashing method is known in PHP as CRYPT_BLOWFISH.
 More infos : http://www.php.net/security/crypt_blowfish.php
 This implementation of BCRYPT was originally created by http://www.openwall.com/phpass/
 
### Generate random bytes
 
 A random() function is available to generate secure random bytes with 5 methods :
* [mcrypt_create_iv](http://php.net/manual/en/function.mcrypt-create-iv.php)
* [openssl_random_pseudo_bytes](http://php.net/manual/en/function.openssl-random-pseudo-bytes.php)
* [GetRandom](http://msdn.microsoft.com/en-us/library/aa388176(VS.85).aspx) function from CAPICOM Microsoft class
* [/dev/urandom](http://en.wikipedia.org/wiki//dev/random) on Unix systems
* Mix of [microtime](http://php.net/manual/en/function.microtime.php) and [getmypid](http://php.net/manual/en/function.getmypid.php) functions

### Encrypt/Decrypt datas

There is also a method to encrypt/decrypt data using a symectric encryption string with the blowfish algorithm and an encryption key in CFB mode but please be advised that you should not use this method for truly sensitive data. 

## Requirements and installation

* PHP version >= 5.3.x
* Copy the ``class.cws.crypto.php`` file in a folder on your server.
* You can use the ``index.php`` file sample to help you.

## Gettings started

```php
<?php

require 'class.cws.crypto.php';

$cwsCrypto = new CwsCrypto();
$cwsCrypto->setDebugVerbose(CWSCRYPTO_VERBOSE_DEBUG);  // default CWSCRYPTO_VERBOSE_QUIET

/**
 * Create and check password hash
 */

$password = '1337StrongPassword';

// BCRYPT hash mode
$hash = $cwsCrypto->hashPassword($password, CWSCRYPTO_MODE_BCRYPT);
$check = $cwsCrypto->checkPassword($password, $hash, CWSCRYPTO_MODE_BCRYPT);

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
$datasEncryptionKey = 'En;4QfZ2kh>8_47rz;H@WKwj6.xXRdF0cDL+)[.v:W1Xi}N|Jo{Hx^u?';

// Encrypt
$encryptedDatas = $cwsCrypto->encrypt($datas, $datasEncryptionKey);

// Decrypt
$cwsCrypto->decrypt($encryptedDatas, $datasEncryptionKey);

?>
```

## Example

An example is available in ``index.php`` file :

![](http://static.crazyws.fr/resources/blog/2013/08/cwscrypto-pbkdf2-bcrypt.png)

## Methods

**hashPassword** - Create a password hash.<br />
**checkPassword** - Check a hash with the password given.<br />
**encrypt** - Generate a symectric encryption string with the blowfish algorithm and an encryption key in CFB mode.<br />
**decrypt** - Return the decrypted string generated from the encrypt method.<br />
**random** - Generate secure random bytes with 5 methods : mcrypt_create_iv, openssl_random_pseudo_bytes, GetRandom() from CAPICOM Microsoft class, /dev/urandom on Unix systems or microtime() and getmypid() functions.<br />

**getVersion** - Get the CwsCrypto version.<br />
**getDebugVerbose** - Get the current debug verbose mode.<br />
**setDebugVerbose** - Control the debug output.<br />
**getErrorMsg** - Get the last error message.<br />

## License

LGPL. See ``LICENSE`` for more details.

## More infos

http://www.crazyws.fr/dev/classes-php/cwscrypto-creer-et-verifier-un-hash-avec-algorithme-bcrypt-ou-pbkdf2-ZFFIT.html

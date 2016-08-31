[![Latest Stable Version](https://img.shields.io/packagist/v/crazy-max/cws-crypto.svg?style=flat-square)](https://packagist.org/packages/crazy-max/cws-crypto)
[![Minimum PHP Version](https://img.shields.io/badge/php-%3E%3D%205.3.0-8892BF.svg?style=flat-square)](https://php.net/)
[![Build Status](https://img.shields.io/travis/crazy-max/CwsCrypto/master.svg?style=flat-square)](https://travis-ci.org/crazy-max/CwsCrypto)
[![Scrutinizer Code Quality](https://img.shields.io/scrutinizer/g/crazy-max/CwsCrypto.svg?style=flat-square)](https://scrutinizer-ci.com/g/crazy-max/CwsCrypto)
[![Gemnasium](https://img.shields.io/gemnasium/crazy-max/CwsCrypto.svg?style=flat-square)](https://gemnasium.com/github.com/crazy-max/CwsCrypto)

# CwsCrypto

PHP class for password hashing with two different encryption methods.

## Overview

### The PBKDF2 key derivation function

Defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt<br />
This implementation of PBKDF2 was originally created by https://defuse.ca/php-pbkdf2.htm<br />
With improvements by http://www.variations-of-shadow.com

### The OpenBSD-style Blowfish-based bcrypt

This hashing method is known in PHP as CRYPT_BLOWFISH.<br />
More infos : http://www.php.net/security/crypt_blowfish.php<br />
This implementation of BCRYPT was originally created by http://www.openwall.com/phpass/

### Generate random bytes
 
 A random() function is available to generate secure random bytes with 5 methods :
* [mcrypt_create_iv](http://php.net/manual/en/function.mcrypt-create-iv.php)
* [openssl_random_pseudo_bytes](http://php.net/manual/en/function.openssl-random-pseudo-bytes.php)
* [GetRandom](http://msdn.microsoft.com/en-us/library/aa388176%28VS.85%29.aspx) function from CAPICOM Microsoft class
* [/dev/urandom](http://en.wikipedia.org/wiki//dev/random) on Unix systems
* Mix of [microtime](http://php.net/manual/en/function.microtime.php) and [getmypid](http://php.net/manual/en/function.getmypid.php) functions

### Encrypt/Decrypt datas

There is also a method to encrypt/decrypt data using a symectric encryption string with the blowfish algorithm and an encryption key in CFB mode but please be advised that you should not use this method for truly sensitive data. 

## Requirements

* PHP >= 5.3.0
* CwsDebug >= 1.9

## Installation with Composer

```bash
composer require crazy-max/cws-crypto
```

And download the code:

```bash
composer install # or update
```

## Getting started

See `tests/test.php` file sample to help you.

## Example

![](https://raw.github.com/crazy-max/CwsCrypto/master/example.png)

## Methods

**hashPassword** - Create a password hash.<br />
**checkPassword** - Check a hash with the password given.<br />
**encrypt** - Generate a symectric encryption string with the blowfish algorithm and an encryption key in CFB mode.<br />
**decrypt** - Return the decrypted string generated from the encrypt method.<br />
**random** - Generate secure random bytes with 5 methods : mcrypt_create_iv, openssl_random_pseudo_bytes, GetRandom() from CAPICOM Microsoft class, /dev/urandom on Unix systems or mt_rand() and getmypid() functions.<br />

**setPbkdf2Mode** - Set the pbkdf2 mode for hashing/check password.<br />
**setBcryptMode** - Set the bcrypt mode for hashing/check password. (default)<br />
**setEncryptionKey** - Set the encryption key for encrypt/decrypt method (max length 56).<br />
**getError** - Get the last error.<br />

## License

LGPL. See ``LICENSE`` for more details.

## More infos

http://www.crazyws.fr/dev/classes-php/cwscrypto-creer-et-verifier-un-hash-avec-algorithme-bcrypt-ou-pbkdf2-ZFFIT.html

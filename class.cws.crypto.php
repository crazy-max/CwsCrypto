<?php

/**
 * CwsCrypto
 *
 * CwsCrypto is a PHP class for password hashing with two different encryption methods :
 * - The PBKDF2 key derivation function (length 191).
 * - The OpenBSD-style Blowfish-based bcrypt (length 60).
 * A random() function is available to generate secure random bytes.
 * There is also a method to encrypt/decrypt data using a symectric encryption string with
 * the blowfish algorithm and an encryption key in CFB mode but please be advised that you
 * should not use this method for truly sensitive data.
 *
 * CwsCrypto is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your option)
 * or (at your option) any later version.
 *
 * CwsCrypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 * 
 * Related post: http://goo.gl/GtwtCz
 * 
 * @package CwsCrypto
 * @author Cr@zy
 * @copyright 2013, Cr@zy
 * @license GNU LESSER GENERAL PUBLIC LICENSE
 * @version 1.2
 * @link https://github.com/crazy-max/CwsCrypto
 *
 */

define('CWSCRYPTO_VERBOSE_QUIET',          0); // means no output at all.
define('CWSCRYPTO_VERBOSE_SIMPLE',         1); // means only output simple report.
define('CWSCRYPTO_VERBOSE_REPORT',         2); // means output a detail report.
define('CWSCRYPTO_VERBOSE_DEBUG',          3); // means output detail report as well as debug info.

define('CWSCRYPTO_MODE_PBKDF2',            0);
define('CWSCRYPTO_MODE_BCRYPT',            1);

define('CWSCRYPTO_PBKDF2_LENGTH',          191);
define('CWSCRYPTO_PBKDF2_ALGORITHM',       'sha256');
define('CWSCRYPTO_PBKDF2_MIN_ITE',         1024);
define('CWSCRYPTO_PBKDF2_MAX_ITE',         2048);
define('CWSCRYPTO_PBKDF2_RANDOM_BYTES',    24);
define('CWSCRYPTO_PBKDF2_HASH_BYTES',      24);
define('CWSCRYPTO_PBKDF2_SEPARATOR',       ':');
define('CWSCRYPTO_PBKDF2_SECTIONS',        4);
define('CWSCRYPTO_PBKDF2_ALGORITHM_INDEX', 0);
define('CWSCRYPTO_PBKDF2_ITE_INDEX',       1);
define('CWSCRYPTO_PBKDF2_SALT_INDEX',      2);
define('CWSCRYPTO_PBKDF2_HASH_INDEX',      3);

define('CWSCRYPTO_BCRYPT_LENGTH',          60);
define('CWSCRYPTO_BCRYPT_MIN_ITE',         4);
define('CWSCRYPTO_BCRYPT_MAX_ITE',         10);
define('CWSCRYPTO_BCRYPT_RANDOM_BYTES',    16);

define('CWSCRYPTO_ENC_SEPARATOR',          '|');
define('CWSCRYPTO_ENC_SECTIONS',           3);
define('CWSCRYPTO_ENC_STARTINDEX_INDEX',   0);
define('CWSCRYPTO_ENC_DATALENGTH_INDEX',   1);
define('CWSCRYPTO_ENC_DATA_INDEX',         2);

class CwsCrypto
{
    /**
     * CwsCrypto version.
     * @var string
     */
    private $version = "1.2";
    
    /**
     * Default mode for hashing/check password
     * CWSCRYPTO_MODE_BCRYPT or CWSCRYPTO_MODE_PBKDF2.
     * @var int
     */
    private $defaultMode;
    
    /**
     * Default key for encrypt/decrypt method
     * @var string
     */
    private $defaultKey;
    
    /**
     * Control the debug output.
     * default CWSCRYPTO_VERBOSE_QUIET
     * @var int
     */
    private $debugVerbose = CWSCRYPTO_VERBOSE_QUIET;
    
    /**
     * The last error message.
     * @var string
     */
    private $errorMsg;
    
    /**
     * Defines new line ending.
     * @var string
     */
    private $_newline = "<br />\n";
    
    public function __construct() {}

    /**
     * Output additional msg for debug.
     * @param string $msg : if not given, output the last error msg.
     * @param int $verbose_level : the output level of this message.
     * @param bool $newline : insert new line or not.
     * @param bool $code : is code or not.
     */
    private function output($msg=null, $verbose_level=CWSCRYPTO_VERBOSE_SIMPLE, $newline=true, $code=false)
    {
        if ($this->debugVerbose >= $verbose_level) {
            if (empty($msg)) {
                echo '<span style="color:#CC0000">ERROR: ' . $this->errorMsg . '</span>';
            } else {
                if ($code) {
                    echo '<textarea style="width:100%;height:150px;">';
                    print_r($msg);
                    echo '</textarea>';
                } else {
                    echo $msg;
                }
            }
            if ($newline) {
                echo $this->_newline;
            }
        }
    }
    
    /**
     * Create a password hash
     * @param string $password : The password
     * @param int $hashMode : The password hash mode (CWSCRYPTO_MODE_BCRYPT or CWSCRYPTO_MODE_PBKDF2)
     * @return string|NULL
     */
    public function hashPassword($password, $hashMode=null)
    {
        if (empty($hashMode) && !empty($this->defaultMode)) {
            $hashMode = $this->defaultMode;
        }
        
        if ($hashMode == CWSCRYPTO_MODE_BCRYPT) {
            return $this->hashModeBcrypt($password);
        } elseif ($hashMode == CWSCRYPTO_MODE_PBKDF2) {
            return $this->hashModePbkdf2($password);
        }
        
        $this->errorMsg = "Encrypt mode unknown...";
        $this->output();
        return null;
    }

    /**
     * Create a password hash using BCRYPT mode (CRYPT_BLOWFISH hash type).
     * @param string $password
     * @return string|NULL
     */
    private function hashModeBcrypt($password)
    {
        $this->output('<h2>Create password hash using BCRYPT</h2>', CWSCRYPTO_VERBOSE_SIMPLE, false);
        $this->output('<strong>Password :</strong> ' . $password, CWSCRYPTO_VERBOSE_SIMPLE);

        $ite = rand(CWSCRYPTO_BCRYPT_MIN_ITE, CWSCRYPTO_BCRYPT_MAX_ITE);
        $this->output('<strong>Iterations :</strong> ' . $ite, CWSCRYPTO_VERBOSE_SIMPLE);

        $salt = $this->getBlowfishSalt($ite);
        $this->output('<strong>Salt :</strong> ' . $salt, CWSCRYPTO_VERBOSE_SIMPLE);

        $hash = crypt($password, $salt);
        $this->output('<strong>Hash :</strong> ' . $hash, CWSCRYPTO_VERBOSE_SIMPLE);
        $this->output('<strong>Length :</strong> ' . strlen($hash), CWSCRYPTO_VERBOSE_SIMPLE);

        if (CRYPT_BLOWFISH == 1 && strlen($hash) == CWSCRYPTO_BCRYPT_LENGTH) {
            return $hash;
        }

        $this->errorMsg = "Cannot generate the BCRYPT password hash...";
        $this->output();
        return null;
    }

    /**
     * Create a password hash using PBKDF2 mode.
     * @param string $password
     * @return string|NULL
     */
    private function hashModePbkdf2($password)
    {
        $this->output('<h2>Create password hash using PBKDF2</h2>', CWSCRYPTO_VERBOSE_SIMPLE, false);
        $this->output('<strong>Password :</strong> ' . $password, CWSCRYPTO_VERBOSE_SIMPLE);

        $salt = $this->random(CWSCRYPTO_PBKDF2_RANDOM_BYTES);
        $this->output('<strong>Salt :</strong> ' . $salt, CWSCRYPTO_VERBOSE_SIMPLE);

        $algorithm = $this->encode(CWSCRYPTO_PBKDF2_ALGORITHM);
        $this->output('<strong>Algorithm :</strong> ' . CWSCRYPTO_PBKDF2_ALGORITHM, CWSCRYPTO_VERBOSE_SIMPLE);

        $ite = rand(CWSCRYPTO_PBKDF2_MIN_ITE, CWSCRYPTO_PBKDF2_MAX_ITE);
        $this->output('<strong>Iterations :</strong> ' . $ite, CWSCRYPTO_VERBOSE_SIMPLE);
        $ite = $this->encode(rand(CWSCRYPTO_PBKDF2_MIN_ITE, CWSCRYPTO_PBKDF2_MAX_ITE));
        
        $params = $algorithm . CWSCRYPTO_PBKDF2_SEPARATOR;
        $params .= $ite . CWSCRYPTO_PBKDF2_SEPARATOR;
        $params .= $salt . CWSCRYPTO_PBKDF2_SEPARATOR;
        
        $hash = $this->getPbkdf2($algorithm, $password, $salt, $ite, CWSCRYPTO_PBKDF2_HASH_BYTES, true);
        $this->output('<strong>Hash :</strong> ' . $hash, CWSCRYPTO_VERBOSE_SIMPLE);
        $this->output('<strong>Length :</strong> ' . strlen($hash), CWSCRYPTO_VERBOSE_SIMPLE);

        $finalHash = $params . base64_encode($hash);
        $this->output('<strong>Encoded hash</strong>', CWSCRYPTO_VERBOSE_SIMPLE);
        $this->output($finalHash, CWSCRYPTO_VERBOSE_SIMPLE, false, true);
        $this->output('<strong>Length :</strong> ' . strlen($finalHash), CWSCRYPTO_VERBOSE_SIMPLE);

        if (strlen($finalHash) == CWSCRYPTO_PBKDF2_LENGTH) {
            return $finalHash;
        }

        $this->errorMsg = "Cannot generate the PBKDF2 password hash...";
        $this->output();
        return null;
    }
    
    /**
     * Check a hash with the password given.
     * @param string $password : The password
     * @param string $hash : The stored password hash
     * @param int $hashMode : The password hash mode (CWSCRYPTO_MODE_BCRYPT or CWSCRYPTO_MODE_PBKDF2)
     * @return boolean
     */
    public function checkPassword($password, $hash, $hashMode=null)
    {
        if (empty($hashMode) && !empty($this->defaultMode)) {
            $hashMode = $this->defaultMode;
        }
        
        if ($hashMode == CWSCRYPTO_MODE_BCRYPT) {
            return $this->checkModeBcrypt($password, $hash);
        } elseif ($hashMode == CWSCRYPTO_MODE_PBKDF2) {
            return $this->checkModePbkdf2($password, $hash);
        }
        
        $this->errorMsg = "Encrypt mode unknown...";
        $this->output();
        return false;
    }

    /**
     * Check a hash with the password given using BCRYPT mode.
     * @param string $password
     * @param string $hash
     * @return boolean
     */
    private function checkModeBcrypt($password, $hash)
    {
        $this->output('<h2>Check password hash in BCRYPT mode</h2>', CWSCRYPTO_VERBOSE_SIMPLE, false);
        $this->output('<strong>Password :</strong> ' . $password, CWSCRYPTO_VERBOSE_SIMPLE);
        $this->output('<strong>Hash :</strong> ' . $hash, CWSCRYPTO_VERBOSE_SIMPLE);

        $checkHash = crypt($password, $hash);
        $this->output('<strong>Check hash :</strong> ' . $checkHash, CWSCRYPTO_VERBOSE_SIMPLE);

        $result = $this->slowEquals($hash, $checkHash);
        $this->output('<strong>Valid? :</strong> ' . ($result ? 'YES!' : 'NO...'), CWSCRYPTO_VERBOSE_SIMPLE);

        return $result;
    }

    /**
     * Check a hash with the password given using PBKDF2 mode.
     * @param string $password
     * @param string $hash
     * @return boolean
     */
    private function checkModePbkdf2($password, $hash)
    {
        $this->output('<h2>Check password hash in PBKDF2 mode</h2>', CWSCRYPTO_VERBOSE_SIMPLE, false);
        $this->output('<strong>Password :</strong> ' . $password, CWSCRYPTO_VERBOSE_SIMPLE);
        $this->output('<strong>Hash</strong>', CWSCRYPTO_VERBOSE_SIMPLE);
        $this->output($hash, CWSCRYPTO_VERBOSE_SIMPLE, false, true);

        $params = explode(CWSCRYPTO_PBKDF2_SEPARATOR, $hash);
        if (count($params) < CWSCRYPTO_PBKDF2_SECTIONS) {
            return false;
        }
        
        $algorithm = $params[CWSCRYPTO_PBKDF2_ALGORITHM_INDEX];
        $salt = $params[CWSCRYPTO_PBKDF2_SALT_INDEX];
        $ite = $params[CWSCRYPTO_PBKDF2_ITE_INDEX];
        $hash = base64_decode($params[CWSCRYPTO_PBKDF2_HASH_INDEX]);
        $this->output('<strong>Decoded hash :</strong> ' . $hash, CWSCRYPTO_VERBOSE_SIMPLE);
                
        $checkHash = $this->getPbkdf2($algorithm, $password, $salt, $ite, strlen($hash), true);
        $this->output('<strong>Check hash :</strong> ' . $checkHash, CWSCRYPTO_VERBOSE_SIMPLE);

        $result = $this->slowEquals($hash, $checkHash);
        $this->output('<strong>Valid? :</strong> ' . ($result ? 'YES!' : 'NO...'), CWSCRYPTO_VERBOSE_SIMPLE);

        return $result;
    }
    
    /**
     * Generate a symectric encryption string with the blowfish algorithm and
     * an encryption key in CFB mode.
     * Please be advised that you should not use this method for truly sensitive data.
     * @param string $data : The data to encrypt
     * @param string $key : The encryption key (max length 56)
     * @return string|NULL : The encrypted string
     */
    public function encrypt($data, $key=null)
    {
        $this->output('<h2>Encrypt data</h2>', CWSCRYPTO_VERBOSE_SIMPLE, false);
        
        if (empty($key) && !empty($this->defaultKey)) {
            $key = $this->defaultKey;
        }
        
        if (empty($data) || empty($key)) {
            $this->errorMsg = "Data or encryption key empty...";
            $this->output();
            return null;
        }

        $this->output('<strong>Encryption key :</strong> ' . $key, CWSCRYPTO_VERBOSE_SIMPLE);
        $this->output('<strong>Data</strong>', CWSCRYPTO_VERBOSE_SIMPLE);
        $this->output($data, CWSCRYPTO_VERBOSE_SIMPLE, false, true);

        $td = mcrypt_module_open(MCRYPT_BLOWFISH, '', MCRYPT_MODE_CFB, '');
        
        $ivsize = mcrypt_enc_get_iv_size($td);
        $iv = mcrypt_create_iv($ivsize, MCRYPT_DEV_URANDOM);
        $key = $this->validateKey($key, mcrypt_enc_get_key_size($td));
        
        mcrypt_generic_init($td, $key, $iv);
        
        $encryptedData = mcrypt_generic($td, $this->encode($data));
        mcrypt_generic_deinit($td);

        $result = $iv . $encryptedData;
        $this->output('<strong>Encrypted data</strong>', CWSCRYPTO_VERBOSE_SIMPLE);
        $this->output($result, CWSCRYPTO_VERBOSE_SIMPLE, false, true);
        
        return $result;
    }
    
    /**
     * Return the decrypted string generated from the encrypt method.
     * @param string $data : The encrypted string
     * @param string $key : The encryption key (max length 56)
     * @return null|string : The decrypted string
     */
    public function decrypt($data, $key=null)
    {
        $this->output('<h2>Decrypt data</h2>', CWSCRYPTO_VERBOSE_SIMPLE, false);
        
        if (empty($key) && !empty($this->defaultKey)) {
            $key = $this->defaultKey;
        }
        
        if (empty($data) || empty($key)) {
            $this->errorMsg = "Data or encryption key empty...";
            $this->output();
            return null;
        }

        $this->output('<strong>Encryption key :</strong> ' . $key, CWSCRYPTO_VERBOSE_SIMPLE);
        $this->output('<strong>Encrypted data</strong>', CWSCRYPTO_VERBOSE_SIMPLE);
        $this->output($data, CWSCRYPTO_VERBOSE_SIMPLE, false, true);

        $result = null;
        $td = mcrypt_module_open(MCRYPT_BLOWFISH, '', MCRYPT_MODE_CFB, '');
        
        $ivsize = mcrypt_enc_get_iv_size($td);
        $iv = substr($data, 0, $ivsize);
        $key = $this->validateKey($key, mcrypt_enc_get_key_size($td));
        
        if ($iv) {
            $data = substr($data, $ivsize);
            mcrypt_generic_init($td, $key, $iv);
            $decryptData = mdecrypt_generic($td, $data);
            $result = $this->decode($decryptData);
        }

        $this->output('<strong>Data</strong>', CWSCRYPTO_VERBOSE_SIMPLE);
        $this->output($result, CWSCRYPTO_VERBOSE_SIMPLE, false, true);
        
        return $result;
    }
    
    /**
     * Generate secure random bytes with 5 methods : mcrypt_create_iv,
     * openssl_random_pseudo_bytes, GetRandom() from CAPICOM Microsoft class,
     * /dev/urandom on Unix systems or mt_rand() and getmypid() functions.
     * @param int $length : The length of random bytes
     * @param boolean $base64 : Encodes random bytes with MIME base64
     * @return string|NULL : The random bytes
     */
    public static function random($length=32, $base64=true)
    {
        // Try with mcrypt_create_iv function
        if (function_exists('mcrypt_create_iv') && self::isPHPVersionHigher('5.3.7')) {
            $bytes = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
            if ($bytes !== false && strlen($bytes) === $length) {
                return $base64 ? base64_encode($bytes) : $bytes;
            }
        }
    
        // Try with openssl_random_pseudo_bytes function
        if (function_exists('openssl_random_pseudo_bytes') && self::isPHPVersionHigher('5.3.4')) {
            $bytes = openssl_random_pseudo_bytes($length, $usable);
            if ($usable === true) {
                return $base64 ? base64_encode($bytes) : $bytes;
            }
        }
    
        // Try with CAPICOM Microsoft class
        if (self::isOnWindows() && class_exists('\\COM', false)) {
            try {
                $capi = new COM('CAPICOM.Utilities.1');
                $bytes = $capi->GetRandom($length, 0);
                if ($bytes !== false && strlen($bytes) === $length) {
                    return $base64 ? base64_encode($bytes) : $bytes;
                }
            } catch (Exception $ex) {
            }
        }
    
        // Try with /dev/urandom
        if (!self::isOnWindows() && file_exists('/dev/urandom') && is_readable('/dev/urandom')) {
            $fp = @fopen('/dev/urandom', 'rb');
            if ($fp !== false) {
                $bytes = @fread($fp, $length);
                @fclose($fp);
                if ($bytes !== false && strlen($bytes) === $length) {
                    return $base64 ? base64_encode($bytes) : $bytes;
                }
            }
        }

        // Otherwise use mt_rand() and getmypid() functions
        if (strlen($bytes) < $length) {
            $bytes = '';
            $state = mt_rand();
            if (function_exists('getmypid')) {
                $state .= getmypid();
            }
            for ($i = 0; $i < $length; $i += 16) {
                $state = md5(mt_rand() . $state);
                $bytes .= pack('H*', md5($state));
            }
            return substr($bytes, 0, $length);
        }

        $this->errorMsg = "Unable to generate sufficiently strong random bytes due to a lack of sources with sufficient entropy...";
        $this->output();
        return null;
    }

    /**
     * Generate a Blowfish salt.
     * Blowfish hashing with a salt as follows: "$2a$" (PHP < 5.3.7), "$2x$" or "$2y$",
     * a two digit cost parameter, "$", and 22 characters from the alphabet "./0-9A-Za-z".
     * More infos : http://www.php.net/security/crypt_blowfish.php
     * This implementation of BCRYPT was originally created by http://www.openwall.com/phpass/
     * @param int $ite : The two digit cost parameter must be in range 04-31
     * @return string : The Blowfish salt
     */
    private function getBlowfishSalt($ite)
    {
        $input = $this->random(CWSCRYPTO_BCRYPT_RANDOM_BYTES, false);
        $itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

        $output = '$2a$';
        $output .= chr(ord('0') + $ite / 10);
        $output .= chr(ord('0') + $ite % 10);
        $output .= '$';

        $i = 0;
        do {
            $c1 = ord($input[$i++]);
            $output .= $itoa64[$c1 >> 2];
            $c1 = ($c1 & 0x03) << 4;
            if ($i >= 16) {
                $output .= $itoa64[$c1];
                break;
            }

            $c2 = ord($input[$i++]);
            $c1 |= $c2 >> 4;
            $output .= $itoa64[$c1];
            $c1 = ($c2 & 0x0f) << 2;

            $c2 = ord($input[$i++]);
            $c1 |= $c2 >> 6;
            $output .= $itoa64[$c1];
            $output .= $itoa64[$c2 & 0x3f];
        } while (1);

        return $output;
    }
    
    /**
     * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
     * This implementation of PBKDF2 was originally created by https://defuse.ca/php-pbkdf2.htm
     * With improvements by http://www.variations-of-shadow.com
     * @param string $algorithm : The hash algorithm to use. Recommended: SHA256
     * @param string $password : The password.
     * @param string $salt : A salt that is unique to the password.
     * @param string $ite : Iteration count encoded.
     * @param int $key_length : The length of the derived key in bytes.
     * @param boolean $raw_output : If true, the key is returned in raw binary format. Hex encoded otherwise.
     * @return string|NULL : A $key_length-byte key derived from the password and salt.
     */
    private static function getPbkdf2($algorithm, $password, $salt, $ite, $key_length, $raw_output=false)
    {
        $algorithm = strtolower(self::decode($algorithm));
        if (!in_array($algorithm, hash_algos(), true)) {
            $this->errorMsg = "Invalid hash algorithm for PBKDF2...";
            $this->output();
            return null;
        }
        
        $ite = self::decode($ite);
        if (!is_numeric($ite) || $ite <= 0 || $key_length <= 0) {
            $this->errorMsg = "Invalid parameters for PBKDF2...";
            $this->output();
            return null;
        }
        
        $hash_length = strlen(hash($algorithm, "", true));
        $block_count = ceil($key_length / $hash_length);
        
        $output = "";
        for ($i = 1; $i <= $block_count; $i++) {
            $last = $salt . pack("N", $i);
            $last = $xorsum = hash_hmac($algorithm, $last, $password, true);
            for ($j = 1; $j < $ite; $j++) {
                $xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
            }
            $output .= $xorsum;
        }
    
        if ($raw_output) {
            return substr($output, 0, $key_length);
        } else {
            return bin2hex(substr($output, 0, $key_length));
        }
    }
    
    /**
     * Validate a key relative to maximum supported keysize of the opened mode.
     * @param string $key : The key to validate
     * @param int $size : The size of the key (check with mcrypt_enc_get_key_size)
     * @return string $key : The validated key
     */
    private static function validateKey($key, $size)
    {
        $length = strlen($key);
        
        if ($length < $size) {
            $key = str_pad($key, $size, $key);
        } elseif ($length > $size) {
            $key = substr($key, 0, $size);
        }
        
        return $key;
    }
    
    /**
     * Encode data inside a random string.
     * @param string $data : the data to encode
     * @return string : the encoded data
     */
    private static function encode($data)
    {
        $rdm = self::random();
        $data = base64_encode($data);
        $startIndex = rand(1, strlen($rdm));
        $params = base64_encode($startIndex) . CWSCRYPTO_ENC_SEPARATOR;
        $params .= base64_encode(strlen($data)) . CWSCRYPTO_ENC_SEPARATOR;
        return $params . substr_replace($rdm, $data, $startIndex, 0);
    }
    
    /**
     * Decode and extract data from encoded one.
     * @param string $encData : the encoded data
     * @return string : The decoded data
     */
    private static function decode($encData)
    {
        $params = explode(CWSCRYPTO_ENC_SEPARATOR, $encData);
        if (count($params) < CWSCRYPTO_ENC_SECTIONS) {
            return false;
        }
    
        $startIndex = intval(base64_decode($params[CWSCRYPTO_ENC_STARTINDEX_INDEX]));
        $dataLength = intval(base64_decode($params[CWSCRYPTO_ENC_DATALENGTH_INDEX]));
    
        if (empty($startIndex) || empty($dataLength)) {
            return false;
        }
    
        $data = $params[CWSCRYPTO_ENC_DATA_INDEX];
        return base64_decode(substr($data, $startIndex, $dataLength));
    }
    
    /**
     * Compares two strings $a and $b in length-constant time.
     * @param string $a
     * @param string $b
     * @return boolean
     */
    private static function slowEquals($a, $b)
    {
        $diff = strlen($a) ^ strlen($b);
        for ($i = 0; $i < strlen($a) && $i < strlen($b); $i++) {
            $diff |= ord($a[$i]) ^ ord($b[$i]);
        }
        return $diff === 0;
    }
    
    /**
     * Check if PHP currently runs on Windows OS.
     * @return boolean
     */
    private static function isOnWindows()
    {
        return strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    }
    
    /**
     * Check if the current PHP version is greater than that passed as a parameter.
     * @param string $version : The PHP version to compare
     * @return boolean
     */
    private static function isPHPVersionHigher($version)
    {
        return version_compare(PHP_VERSION, $version) >= 0;
    }
    
    /**
     * Getters and setters
     */
    
    /**
     * Get the version.
     * @return the $version
     */
    public function getVersion ()
    {
        return $this->version;
    }

    /**
     * Set the default mode for hashing/check password.
     * @param number $defaultMode
     */
    public function setDefaultMode ($defaultMode)
    {
        $this->defaultMode = $defaultMode;
    }

    /**
     * Set the default key for encrypt/decrypt method.
     * @param string $defaultKey
     */
    public function setDefaultKey ($defaultKey)
    {
        $this->defaultKey = $defaultKey;
    }

    /**
     * Get the debug verbose.
     * @return the $debugVerbose
     */
    public function getDebugVerbose ()
    {
        return $this->debugVerbose;
    }
    
    /**
     * Set the debug verbose.
     * @param number $debugVerbose
     */
    public function setDebugVerbose ($debugVerbose)
    {
        $this->debugVerbose = $debugVerbose;
    }
    
    /**
     * Get the error msg.
     * @return the $errorMsg
     */
    public function getErrorMsg ()
    {
        return $this->errorMsg;
    }
}

?>
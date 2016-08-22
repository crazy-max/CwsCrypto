<?php

/**
 * CwsCrypto
 *
 * @package CwsCrypto
 * @author Cr@zy
 * @copyright 2013-2016, Cr@zy
 * @license GNU LESSER GENERAL PUBLIC LICENSE
 * @link https://github.com/crazy-max/CwsCrypto
 */

namespace Cws;

class CwsCrypto
{
    const CAPICOM_CLASS = 'COM';
    
    const MODE_PBKDF2 = 0;
    const MODE_BCRYPT = 1;
    
    const PBKDF2_LENGTH = 191;
    const PBKDF2_ALGORITHM = 'sha256';
    const PBKDF2_MIN_ITE = 1024;
    const PBKDF2_MAX_ITE = 2048;
    const PBKDF2_RANDOM_BYTES = 24;
    const PBKDF2_HASH_BYTES = 24;
    const PBKDF2_SEPARATOR = ':';
    const PBKDF2_SECTIONS = 4;
    const PBKDF2_ALGORITHM_INDEX = 0;
    const PBKDF2_ITE_INDEX = 1;
    const PBKDF2_SALT_INDEX = 2;
    const PBKDF2_HASH_INDEX = 3;
    
    const BCRYPT_LENGTH = 60;
    const BCRYPT_MIN_ITE = 4;
    const BCRYPT_MAX_ITE = 10;
    const BCRYPT_RANDOM_BYTES = 16;
    
    const ENC_SEPARATOR = '|';
    const ENC_SECTIONS = 3;
    const ENC_STARTINDEX_INDEX = 0;
    const ENC_DATALENGTH_INDEX = 1;
    const ENC_DATA_INDEX = 2;
    
    /**
     * Mode for hashing/check password
     * default MODE_BCRYPT
     * @var int
     */
    private $mode;
    
    /**
     * Encryption key for encrypt/decrypt method
     * @var string
     */
    private $encryptionKey;
    
    /**
     * The last error.
     * @var string
     */
    private $error;
    
    /**
     * The cws debug instance.
     * @var CwsDebug
     */
    private $cwsDebug;
    
    public function __construct(CwsDebug $cwsDebug)
    {
        $this->cwsDebug = $cwsDebug;
        $this->mode = self::MODE_BCRYPT;
    }
    
    /**
     * Create a password hash
     * @param string $password : The password
     * @return string|NULL
     */
    public function hashPassword($password)
    {
        if ($this->mode == self::MODE_BCRYPT) {
            return $this->hashModeBcrypt($password);
        } elseif ($this->mode == self::MODE_PBKDF2) {
            return $this->hashModePbkdf2($password);
        }
        
        $this->error = 'You have to set the mode...';
        $this->cwsDebug->error($this->error);
        return null;
    }
    
    /**
     * Create a password hash using BCRYPT mode (CRYPT_BLOWFISH hash type).
     * @param string $password
     * @return string|NULL
     */
    private function hashModeBcrypt($password)
    {
        $this->cwsDebug->titleH2('Create password hash using BCRYPT');
        $this->cwsDebug->labelValue('Password', $password);
        
        $ite = rand(self::BCRYPT_MIN_ITE, self::BCRYPT_MAX_ITE);
        $this->cwsDebug->labelValue('Iterations', $ite);
        
        $salt = $this->getBlowfishSalt($ite);
        $this->cwsDebug->labelValue('Salt', $salt);
        
        $hash = crypt($password, $salt);
        $this->cwsDebug->labelValue('Hash', $hash);
        $this->cwsDebug->labelValue('Length', strlen($hash));
        
        if (CRYPT_BLOWFISH == 1 && strlen($hash) == self::BCRYPT_LENGTH) {
            return $hash;
        }
        
        $this->error = 'Cannot generate the BCRYPT password hash...';
        $this->cwsDebug->error($this->error);
        return null;
    }
    
    /**
     * Create a password hash using PBKDF2 mode.
     * @param string $password
     * @return string|NULL
     */
    private function hashModePbkdf2($password)
    {
        $this->cwsDebug->titleH2('Create password hash using PBKDF2');
        $this->cwsDebug->labelValue('Password', $password);
        
        $salt = $this->random(self::PBKDF2_RANDOM_BYTES);
        $this->cwsDebug->labelValue('Salt', $salt);
        
        $algorithm = $this->encode(self::PBKDF2_ALGORITHM);
        $this->cwsDebug->labelValue('Algorithm', self::PBKDF2_ALGORITHM);
        
        $ite = rand(self::PBKDF2_MIN_ITE, self::PBKDF2_MAX_ITE);
        $this->cwsDebug->labelValue('Iterations', $ite);
        $ite = $this->encode(rand(self::PBKDF2_MIN_ITE, self::PBKDF2_MAX_ITE));
        
        $params = $algorithm . self::PBKDF2_SEPARATOR;
        $params .= $ite . self::PBKDF2_SEPARATOR;
        $params .= $salt . self::PBKDF2_SEPARATOR;
        
        $hash = $this->getPbkdf2($algorithm, $password, $salt, $ite, self::PBKDF2_HASH_BYTES, true);
        $this->cwsDebug->labelValue('Hash', $hash);
        $this->cwsDebug->labelValue('Length', strlen($hash));
        
        $finalHash = $params . base64_encode($hash);
        $this->cwsDebug->dump('Encoded hash (length : ' . strlen($finalHash) . ')', $finalHash);
        
        if (strlen($finalHash) == self::PBKDF2_LENGTH) {
            return $finalHash;
        }
        
        $this->error = 'Cannot generate the PBKDF2 password hash...';
        $this->cwsDebug->error($this->error);
        return null;
    }
    
    /**
     * Check a hash with the password given.
     * @param string $password : The password
     * @param string $hash : The stored password hash
     * @return boolean
     */
    public function checkPassword($password, $hash)
    {
        if ($this->mode == self::MODE_BCRYPT) {
            return $this->checkModeBcrypt($password, $hash);
        } elseif ($this->mode == self::MODE_PBKDF2) {
            return $this->checkModePbkdf2($password, $hash);
        }
        
        $this->error = 'You have to set the mode...';
        $this->cwsDebug->error($this->error);
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
        $this->cwsDebug->titleH2('Check password hash in BCRYPT mode');
        $this->cwsDebug->labelValue('Password', $password);
        $this->cwsDebug->labelValue('Hash', $hash);
        
        $checkHash = crypt($password, $hash);
        $this->cwsDebug->labelValue('Check hash', $checkHash);
        
        $result = $this->slowEquals($hash, $checkHash);
        $this->cwsDebug->labelValue('Valid?', ($result ? 'YES!' : 'NO...'));
       
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
        $this->cwsDebug->titleH2('Check password hash in PBKDF2 mode');
        $this->cwsDebug->labelValue('Password', $password);
        $this->cwsDebug->dump('Hash', $hash);
        
        $params = explode(self::PBKDF2_SEPARATOR, $hash);
        if (count($params) < self::PBKDF2_SECTIONS) {
            return false;
        }
        
        $algorithm = $params[self::PBKDF2_ALGORITHM_INDEX];
        $salt = $params[self::PBKDF2_SALT_INDEX];
        $ite = $params[self::PBKDF2_ITE_INDEX];
        $hash = base64_decode($params[self::PBKDF2_HASH_INDEX]);
        $this->cwsDebug->labelValue('Decoded hash', $hash);
                
        $checkHash = $this->getPbkdf2($algorithm, $password, $salt, $ite, strlen($hash), true);
        $this->cwsDebug->labelValue('Check hash', $checkHash);
        
        $result = $this->slowEquals($hash, $checkHash);
        $this->cwsDebug->labelValue('Valid?', ($result ? 'YES!' : 'NO...'));
        
        return $result;
    }
    
    /**
     * Generate a symectric encryption string with the blowfish algorithm and
     * an encryption key in CFB mode.
     * Please be advised that you should not use this method for truly sensitive data.
     * @param string $data : The data to encrypt
     * @return string|NULL : The encrypted string
     */
    public function encrypt($data)
    {
        $this->cwsDebug->titleH2('Encrypt data');
        
        if (empty($this->encryptionKey)) {
            $this->error = 'You have to set the encryption key...';
            $this->cwsDebug->error($this->error);
            return null;
        }
        
        if (empty($data)) {
            $this->error = 'Data empty...';
            $this->cwsDebug->error($this->error);
            return null;
        }
        
        $this->cwsDebug->labelValue('Encryption key', $this->encryptionKey);
        $this->cwsDebug->dump('Data', $data);
        
        $td = mcrypt_module_open(MCRYPT_BLOWFISH, '', MCRYPT_MODE_CFB, '');
        
        $ivsize = mcrypt_enc_get_iv_size($td);
        $iv = mcrypt_create_iv($ivsize, MCRYPT_DEV_URANDOM);
        $key = $this->validateKey($this->encryptionKey, mcrypt_enc_get_key_size($td));
        
        mcrypt_generic_init($td, $key, $iv);
        
        $encryptedData = mcrypt_generic($td, $this->encode($data));
        mcrypt_generic_deinit($td);
        
        $result = $iv . $encryptedData;
        $this->cwsDebug->dump('Encrypted data', $result);
        
        return $result;
    }
    
    /**
     * Return the decrypted string generated from the encrypt method.
     * @param string $data : The encrypted string
     * @return null|string : The decrypted string
     */
    public function decrypt($data)
    {
        $this->cwsDebug->titleH2('Decrypt data');
        
        if (empty($this->encryptionKey)) {
            $this->error = 'You have to set the encryption key...';
            $this->cwsDebug->error($this->error);
            return null;
        }
        
        if (empty($data)) {
            $this->error = 'Data empty...';
            $this->cwsDebug->error($this->error);
            return null;
        }
        
        $this->cwsDebug->labelValue('Encryption key', $this->encryptionKey);
        $this->cwsDebug->dump('Encrypted data', strval($data));
        
        $result = null;
        $td = mcrypt_module_open(MCRYPT_BLOWFISH, '', MCRYPT_MODE_CFB, '');
        
        $ivsize = mcrypt_enc_get_iv_size($td);
        $iv = substr($data, 0, $ivsize);
        $key = $this->validateKey($this->encryptionKey, mcrypt_enc_get_key_size($td));
        
        if ($iv) {
            $data = substr($data, $ivsize);
            mcrypt_generic_init($td, $key, $iv);
            $decryptData = mdecrypt_generic($td, $data);
            $result = $this->decode($decryptData);
        }
        
        $this->cwsDebug->dump('Data', $result);
        
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
    public function random($length = 32, $base64 = true)
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
        if (self::isWindows() && class_exists('\\COM', false)) {
            try {
                $capicomClass = self::CAPICOM_CLASS;
                $capi = new $capicomClass('CAPICOM.Utilities.1');
                $bytes = $capi->GetRandom($length, 0);
                if ($bytes !== false && strlen($bytes) === $length) {
                    return $base64 ? base64_encode($bytes) : $bytes;
                }
            } catch (Exception $ex) {
            }
        }
        
        // Try with /dev/urandom
        if (!self::isWindows() && file_exists('/dev/urandom') && is_readable('/dev/urandom')) {
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
        
        $this->error = 'Unable to generate sufficiently strong random bytes due to a lack of sources with sufficient entropy...';
        $this->cwsDebug->error($this->error);
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
        $input = $this->random(self::BCRYPT_RANDOM_BYTES, false);
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
    private function getPbkdf2($algorithm, $password, $salt, $ite, $key_length, $raw_output = false)
    {
        $algorithm = strtolower(self::decode($algorithm));
        if (!in_array($algorithm, hash_algos(), true)) {
            $this->error = 'Invalid hash algorithm for PBKDF2...';
            $this->cwsDebug->error($this->error);
            return null;
        }
        
        $ite = self::decode($ite);
        if (!is_numeric($ite) || $ite <= 0 || $key_length <= 0) {
            $this->error = 'Invalid parameters for PBKDF2...';
            $this->cwsDebug->error($this->error);
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
     * Encode data inside a random string.
     * @param string $data : the data to encode
     * @return string : the encoded data
     */
    private function encode($data)
    {
        $rdm = $this->random();
        $data = base64_encode($data);
        $startIndex = rand(1, strlen($rdm));
        $params = base64_encode($startIndex) . self::ENC_SEPARATOR;
        $params .= base64_encode(strlen($data)) . self::ENC_SEPARATOR;
        return $params . substr_replace($rdm, $data, $startIndex, 0);
    }
    
    /**
     * Decode and extract data from encoded one.
     * @param string $encData : the encoded data
     * @return string : The decoded data
     */
    private function decode($encData)
    {
        $params = explode(self::ENC_SEPARATOR, $encData);
        if (count($params) < self::ENC_SECTIONS) {
            return false;
        }
        
        $startIndex = intval(base64_decode($params[self::ENC_STARTINDEX_INDEX]));
        $dataLength = intval(base64_decode($params[self::ENC_DATALENGTH_INDEX]));
        
        if (empty($startIndex) || empty($dataLength)) {
            return false;
        }
        
        $data = $params[self::ENC_DATA_INDEX];
        return base64_decode(substr($data, $startIndex, $dataLength));
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
    private static function isWindows()
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
     * Set the pbkdf2 mode for hashing/check password.
     */
    public function setPbkdf2Mode()
    {
        $this->setMode(self::MODE_PBKDF2);
    }
    
    /**
     * Set the bcrypt mode for hashing/check password.
     */
    public function setBcryptMode()
    {
        $this->setMode(self::MODE_BCRYPT);
    }
    
    /**
     * Set the mode for hashing/check password.
     * @param int $mode
     */
    private function setMode($mode)
    {
        $this->mode = $mode;
    }
    
    /**
     * Set the encryption key for encrypt/decrypt method (max length 56).
     * @param string $encryptionKey
     */
    public function setEncryptionKey($encryptionKey)
    {
        $this->encryptionKey = $encryptionKey;
    }
    
    /**
     * The last error.
     * @return string $error
     */
    public function getError() {
        return $this->error;
    }
}

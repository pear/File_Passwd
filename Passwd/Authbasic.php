<?php
// +----------------------------------------------------------------------+
// | PHP Version 4                                                        |
// +----------------------------------------------------------------------+
// | Copyright (c) 1997-2003 The PHP Group                                |
// +----------------------------------------------------------------------+
// | This source file is subject to version 2.0 of the PHP license,       |
// | that is bundled with this package in the file LICENSE, and is        |
// | available at through the world-wide-web at                           |
// | http://www.php.net/license/2_02.txt.                                 |
// | If you did not receive a copy of the PHP license and are unable to   |
// | obtain it through the world-wide-web, please send a note to          |
// | license@php.net so we can mail you a copy immediately.               |
// +----------------------------------------------------------------------+
// | Author: Michael Wallner <mike@php.net>                               |
// +----------------------------------------------------------------------+
//
// $Id$

/**
* Manipulate AuthUserFiles as used for HTTP Basic Authentication.
*
* @author   Michael Wallner <mike@php.net>
* @package  File_Passwd
*/

/**
* Requires File::Passwd::Common
*/
require_once('File/Passwd/Common.php');

/**
* Allowed 64 characters for MD5 encryption
*/
$GLOBALS['_FILE_PASSWD_AUTHBASIC_64'] = 
    './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

/**
* Manipulate AuthUserFiles as used for HTTP Basic Authentication.
*
* <kbd><u>
*   Usage Example:
* </u></kbd>
* <code>
*   $htp = &File_Passwd::factory('AuthBasic');
*   $htp->setMode('sha');
*   $htp->setFile('/www/mike/auth/.htpasswd');
*   $htp->load();
*   $htp->addUser('mike', 'secret');
*   $htp->save();
* </code>
* 
* <kbd><u>
*   Output of listUser()
* </u></kbd>
* <pre>
*      array
*       + user => crypted_passwd
*       + user => crypted_passwd
* </pre>
* 
* @author   Michael Wallner <mike@php.net>
* @package  File_Passwd
* @version  $Revision$
* @access   public
*/
class File_Passwd_Authbasic extends File_Passwd_Common {

    /** 
    * Path to AuthUserFile
    *
    * @var string
    * @access private
    */
    var $_file = '.htpasswd';

    /** 
    * Actual encryption mode
    *
    * @var string
    * @access private
    */
    var $_mode = 'sha';

    /** 
    * Supported encryption modes
    *
    * @var array
    * @access private
    */
    var $_modes = array('md5' => 'm', 'des' => 'd', 'sha' => 's');

    /** 
    * Constructor
    * 
    * @access public
    * @param  string $file   path to AuthUserFile
    */
    function File_Passwd_Authbasic($file = '.htpasswd') {
        $this->__construct($file);
    }

    /**
    * Constructor (ZE2)
    * 
    * Rewritten because DES encryption is not 
    * supportet by the Win32 htpasswd binary.
    * 
    * @access protected
    * @param  string $file   path to AuthUserFile
    */
    function __construct($file = '.htpasswd') {
        if (strtoupper(substr(PHP_OS, 0, 3)) == 'WIN') {
            unset($this->_modes['des']);
        }
        $this->setFile($file);
    }

    /**
    * Fast authentication of a certain user
    * 
    * Returns a PEAR_Error if:
    *   o file doesn't exist
    *   o file couldn't be opened in read mode
    *   o file couldn't be locked exclusively
    *   o file couldn't be unlocked (only if auth fails)
    *   o file couldn't be closed (only if auth fails)
    *
    * @static   call this method statically for a reasonable fast authentication
    * 
    * @throws   PEAR_Error
    * @access   public
    * @return   mixed   true if authenticated, false if not or PEAR_Error
    * @param    string  $file   path to passwd file
    * @param    string  $user   user to authenticate
    * @param    string  $pass   plaintext password
    * @param    string  $mode   des, sha or md5
    */
    function staticAuth($file, $user, $pass, $mode){
        $line = File_Passwd_Common::_auth($file, $user);
        if (!$line || PEAR::isError($line)) {
            return $line;
        }
        list(,$real) = explode(':', $line);
        return ($real === File_Passwd_Authbasic::_genPass($pass, $real, $mode));
    }
    
    /** 
    * Apply changes and rewrite AuthUserFile
    *
    * Returns a PEAR_Error if:
    *   o directory in which the file should reside couldn't be created
    *   o file couldn't be opened in write mode
    *   o file couldn't be locked exclusively
    *   o file couldn't be unlocked
    *   o file couldn't be closed
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true on success or PEAR_Error
    */
    function save() {
        $content = '';
        foreach ($this->_users as $user => $pass) {
            $content .= $user . ':' . $pass . "\n";
        }
        return $this->_save($content);
    }

    /** 
    * Add an user
    *
    * The username must start with an alphabetical character and must NOT
    * contain any other characters than alphanumerics, the underline and dash.
    * 
    * Returns a PEAR_Error if:
    *   o user already exists
    *   o user contains illegal characters
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true on success or PEAR_Error
    * @param string $user
    * @param string $pass
    */
    function addUser($user, $pass) {
        if ($this->userExists($user)) {
            return PEAR::raiseError(
                sprintf(FILE_PASSWD_E_EXISTS_ALREADY_STR, 'User ', $user),
                FILE_PASSWD_E_EXISTS_ALREADY
            );
        }
        if (!preg_match($this->_pcre, $user)) {
            return PEAR::raiseError(
                sprintf(FILE_PASSWD_E_INVALID_CHARS_STR, 'User ', $user),
                FILE_PASSWD_E_INVALID_CHARS
            );
        }
        $this->_users[$user] = $this->_genPass($pass);
        return true;
    }

    /** 
    * Change the password of a certain user
    *
    * This method in fact adds the user with the new password after deleting it.
    * 
    * Returns a PEAR_Error if user doesn't exist.
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true on success or a PEAR_Error
    * @param string $user   the user whose password should be changed
    * @param string $pass   the new plaintext password
    */
    function changePasswd($user, $pass) {
        if (!$this->userExists($user)) {
            return PEAR::raiseError(
                sprintf(FILE_PASSWD_E_EXISTS_NOT_STR, 'User ', $user),
                FILE_PASSWD_E_EXISTS_NOT
            );
        }
        $this->_users[$user] = $this->_genPass($pass);
        return true;
    }

    /** 
    * Verify password
    *
    * ATTN: Not available with MD5 ecncryption!
    * 
    * If you use MD5 encryption you cannot verify your passwords.
    * This depends on Apache's htpasswd binary, which uses a
    * unusual format for MD5 passwords.
    * 
    * Returns a PEAR_Error if:
    *   o user doesn't exist
    *   o you try to verify MD5 passwords
    *   o an invalid encryption mode was supplied
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true if passwords equal, false if they don't, or PEAR_Error
    * @param string $user   the user whose password should be verified
    * @param string $pass   the plaintext password to verify
    */
    function verifyPasswd($user, $pass) {
        if (!$this->userExists($user)) {
            return PEAR::raiseError(
                sprintf(FILE_PASSWD_E_EXISTS_NOT_STR, 'User ', $user),
                FILE_PASSWD_E_EXISTS_NOT
            );
        }
        $real = $this->_users[$user];
        return ($real === $this->_genPass($pass, $real));
    }

    /** 
    * Get actual encryption mode
    *
    * @access public
    * @return string
    */
    function getMode() {
        return $this->_mode;
    }

    /** 
    * Get supported encryption modes
    *
    * <pre>
    *   array
    *    + md5
    *    + sha
    *    + des
    * </pre>
    * 
    * ATTN: DES encryption not available on Win32!
    * 
    * If you are on a Win32 plattform, the binary distribution of
    * Apache's htpasswd executable doesn't support DES encryption.
    * 
    * @access public
    * @return array
    */
    function listModes() {
        return array_keys($this->_modes);
    }

    /** 
    * Set the encryption mode
    *
    * You can choose one of md5, sha or des.
    * 
    * ATTN: DES encryption not available on Win32!
    * 
    * If you are on a Win32 plattform, the binary distribution of
    * Apache's htpasswd executable doesn't support DES encryption.
    * 
    * Returns a PEAR_Error if a specific encryption mode is not supported.
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true on succes or PEAR_Error
    * @param string $mode
    */
    function setMode($mode) {
        $mode = strToLower($mode);
        if (!isset($this->_modes[$mode])) {
            return PEAR::raiseError(
                sprintf(FILE_PASSWD_E_INVALID_ENC_MODE_STR, $this->_mode),
                FILE_PASSWD_E_INVALID_ENC_MODE
            );
        }
        $this->_mode = $mode;
        return true;
    }

    /**
    * Generate password with htpasswd executable
    * 
    * @access   private
    * @return   string  the crypted password
    * @param    string  $pass   the plaintext password
    * @param    string  $salt   the salt to use
    * @param    string  $mode   encyption mode, usually determined from
    *                           <var>$this->_mode</var>
    */
    function _genPass($pass, $salt = null, $mode = null){
        $salt = is_null($salt) ? File_Passwd_Authbasic::_genSalt() : $salt;
        $mode = is_null($mode) ? strToLower($this->_mode) : strToLower($mode);
        switch($mode){
            case 'des': 
                return crypt($pass, substr($salt, 0,2));
                break;
            case 'sha':
                return '{SHA}' . base64_encode(
                    File_Passwd_Authbasic::_hexbin(sha1($pass))
                );
                break;
            case 'md5':
                return File_Passwd_Authbasic::_md5crypt($pass, $salt);
                break;
        }
        return PEAR::raiseError(
            sprintf(FILE_PASSWD_E_INVALID_ENC_MODE_STR, $mode),
            FILE_PASSWD_E_INVALID_ENC_MODE                
        );
    }
    
    /** 
    * Parse the AuthUserFile
    * 
    * Returns a PEAR_Error if AuthUserFile has invalid format.
    *
    * @throws PEAR_Error
    * @access public
    * @return mixed true on success or PEAR_error
    */
    function parse() {
        $this->_users = array();
        foreach ($this->_contents as $line) {
            $user = explode(':', $line);
            if (count($user) != 2) {
                return PEAR::raiseError(
                    FILE_PASSWD_E_INVALID_FORMAT_STR,
                    FILE_PASSWD_E_INVALID_FORMAT
                );
            }
            $this->_users[$user[0]] = trim($user[1]);
        }
        $this->_contents = array();
        return true;
    }
    
    /**
    * Encrypt string (with given salt) in APR-md5 style
    * 
    * @static
    * @access   private
    * @return   string  encrypted passwd
    * @param    string  $string     the sting to encrypt
    * @param    string  $salt       the salt to use for encryption
    */
    function _md5crypt($string, $salt = null){
        if (is_null($salt)) {
            $salt = File_Passwd_Authbasic::_genSalt();
        } elseif (preg_match('/^\$apr1\$/', $salt)) {
            $salt = preg_replace('/^\$apr1\$(.{8}).*/', '\\1', $salt);
        } else {
            $salt = substr($salt, 0,8);
        }
        
        $length     = strlen($string);
        $context    = $string . '$apr1$' . $salt;
        $binary     = File_Passwd_Authbasic::_hexbin(
            md5($string . $salt . $string)
        );
        
        for ($i = $length; $i > 0; $i -= 16) {
            $context .= substr($binary, 0, ($i > 16 ? 16 : $i));
        }
        for ( $i = $length; $i > 0; $i >>= 1) {
            $context .= ($i & 1) ? chr(0) : $string[0];
        }
        
        $binary = File_Passwd_Authbasic::_hexbin(md5($context));
        
        for($i = 0; $i < 1000; $i++) {
            $new = ($i & 1) ? $string : substr($binary, 0,16);
            if ($i % 3) {
                $new .= $salt;
            }
            if ($i % 7) {
                $new .= $string;
            }
            $new .= ($i & 1) ? substr($binary, 0,16) : $string;
            $binary = File_Passwd_Authbasic::_hexbin(md5($new));
        }
        
        $p = array();
        for ($i = 0; $i < 5; $i++) {
            $k = $i + 6;
            $j = $i + 12;
            if ($j == 16) {
                $j = 5;
            }
            $p[] = File_Passwd_Authbasic::_md5to64(
                (ord($binary[$i]) << 16) |
                (ord($binary[$k]) << 8) |
                (ord($binary[$j])),
                5
            );
        }
        
        return 
            '$apr1$' . $salt . '$' . implode($p) . 
            File_Passwd_Authbasic::_md5to64(ord($binary[11]), 3);
    }
    
    /**
    * Generate salt
    *
    * @access   private
    * @return   string
    */
    function _genSalt(){
        $rs = '';
        for($i = 0; $i < 8; $i++) {
            $rs .= $GLOBALS['_FILE_PASSWD_AUTHBASIC_64'][rand(0,63)];
        }
        return $rs;
    }

    /**
    * Convert hexadecimal string to binary data
    *
    * @static
    * @access   private
    * @return   mixed
    * @param    string  $hex
    */
    function _hexbin($hex){
        $rs = '';
        $ln = strlen($hex);
        for($i = 0; $i < $ln; $i += 2) {
            $rs .= chr(array_shift(sscanf(substr($hex, $i, 2), '%x')));
        }
        return $rs;
    }
    
    /**
    * Convert to allowed 64 characters for encryption
    *
    * @static
    * @access   private
    * @return   string
    * @param    string  $value
    * @param    int     $count
    */
    function _md5to64($value, $count){
        $result = '';
        $count  = abs($count);
        while(--$count) {
            $result .= $GLOBALS['_FILE_PASSWD_AUTHBASIC_64'][$value & 0x3f];
            $value >>= 6;
        }
        return $result;
    }
}
?>
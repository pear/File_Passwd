<?php
//
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
// | Author: Michael Wallner <mike@iworks.at>                             |
// +----------------------------------------------------------------------+
//
// $Id$
//

require_once('File/Passwd/Common.php');

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
*   $htp->setExePath('/usr/bin/htpasswd');
*   $htp->load();
*   $htp->addUser('mike', 'secret');
*   $htp->save();
* </code>
* 
* <b>NOTE:</b>
* You usually need not set the full path to the
* htpasswd binary unless it's not in your $PATH.
* For use in safe_mode see "Limitations".
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
* 
* <kbd><u>
*   Limitations:
* </u></kbd>
* 
* If you have "safe_mode" enabled you only
* can use DES encryption for your passwords.
* <b>NOTE:</b>
* If you're additionally on Win32 you even cannot use this class.
* <i>
* This behavior derives from the unusual implementiation
* of the Apache's htpasswd encryption.
* </i>
* 
* @author   Michael Wallner <mike@iworks.at>
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
    var $_mode = 'des';

    /** 
    * Path to htpasswd executable
    *
    * @var string
    * @access private
    */
    var $_path_to_htp = 'htpasswd';

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
            if (ini_get('safe_mode')) {
                die('Sorry, you\'re on Win32 and safe_mode is enabled.')
            }
        }
        if (ini_get('safe_mode')) {
            unset($this->_modes['sha']);
            unset($this->_modes['md5']);
        }
        $this->setFile($file);
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
            return PEAR::raiseError('user already exists');
        }
        if (!preg_match('/^[a-z]+[a-z0-9\-_]*$/i', $user)) {
            return PEAR::raiseError("User '$user' contains illegal characters.");
        }
        $this->_users[$user] = $this->_genPass($pass);
        return true;
    }

    /** 
    * Change the password of a certain user
    *
    * This method in fact adds the user with the new password after deleting it.
    * 
    * Returns a PEAR_Error if:
    *   o user doesn't exists
    *   o user contains illegal characters
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true on success or a PEAR_Error
    * @param string $user   the user whose password should be changed
    * @param string $pass   the new plaintext password
    */
    function changePasswd($user, $pass) {
        if (PEAR::isError($error = $this->delUser($user))) {
            return $error;
        }
        return $this->addUser($user, $pass);
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
            return PEAR::raiseError('user \'' . $user . '\' does not exist');
        }
        switch ($this->_mode) {
            case 'sha' :
                return ($this->_genPass($pass) === $this->_users[$user]);
                break;
            case 'des' :
                $real = crypt($pass, substr($this->_users[$user], 0, 2));
                return ($real == $this->_users[$user]);
                break;
            case 'md5':
                return PEAR::raiseError('md5 passwords cannot be verified');
                break;
            default :
                return PEAR::raiseError('invalid mode: \''.$this->_mode.'\'');
        }
    }

    /** 
    * Get path to htpasswd executable if supplied earlier
    *
    * @access public
    * @return string
    */
    function getExePath() {
        return $this->_path_to_htp;
    }

    /** 
    * Set path to htpasswd executable
    *
    * NOTE: You usually don't need to set the complete path to 
    *       the htpasswd binary unless it is NOT in your PATH!
    * 
    * Returns a PEAR_Error if supplied path doesn't map to a file or
    * is not equal to 'htpasswd'. That's just if you want to reset this
    * property to the default value.
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true on succes or a PEAR_Error
    * @param string $path_to_htp
    */
    function setExePath($path_to_htp) {
        if (!is_file($path_to_htp) && ($path_to_htp != 'htpasswd')) {
            return PEAR::raiseError('Invalid path to htpasswd excecutable.');
        }
        $this->_path_to_htp = $path_to_htp;
        return true;
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
            return PEAR::raiseError('mode \''.$mode.'\' not supported');
        }
        $this->_mode = $mode;
        return true;
    }

    /**
    * Generate password with htpasswd executable
    * 
    * @access private
    * @return string    the crypted password
    * @param string     the plaintext password
    */
    function _genPass($pass){
        /**
        * If safe_mode is enabled this is the only chance
        * to get a htpasswd style password.
        */
        if (strToLower($this->_mode) == 'des') {
            return crypt($pass, substr(md5(rand()), 0,2));
        }
        /**
        * Else execute htpasswd on the shell.
        */
        $htpw = $this->_path_to_htp.' -nb'.$this->_modes[$this->_mode];
        return preg_replace(
            '/.*myDefaultUserForHtPasswd:(\S*).*/s', 
            '\\1',
            trim(`$htpw myDefaultUserForHtPasswd "{addSlashes($pass)}"`)
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
                return PEAR::raiseError('AuthUserFile has invalid format.');
            }
            $this->_users[$user[0]] = trim($user[1]);
        }
        $this->_contents = array();
        return true;
    }
}
?>
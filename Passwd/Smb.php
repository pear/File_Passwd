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
* Manipulate SMB server passwd files.
*
* @author   Michael Bretterklieber <michael@bretterklieber.com>
* @author   Michael Wallner <mike@php.net>
* @package  File_Passwd
*/

/**
* Requires File::Passwd::Common
*/
require_once('File/Passwd/Common.php');

/**
* Requires Crypt::CHAP
*/
require_once('Crypt/CHAP.php');

/**
* Manipulate SMB server passwd files.
*
* <kbd><u>
*   Usage Example 1 (modifying existing file):
* </u></kbd>
*
* <code>
* $f = &File_Passwd::factory('SMB');
* $f->setFile('./smbpasswd');
* $f->load();
* $f->addUser('sepp3', 'MyPw', array('userid' => 12));
* $f->changePasswd('sepp', 'MyPw');
* $f->delUser('karli');
* foreach($f->listUser() as $user => $data) {
*   echo $user . ':' . implode(':', $data) ."\n";
* }
* $f->save();
* </code>
* 
* <kbd><u>
*   Usage Example 2 (creating a new file):
* </u></kbd>
*
* <code>
* $f = &File_Passwd::factory('SMB');
* $f->setFile('./smbpasswd');
* $f->addUser('sepp1', 'MyPw', array('userid'=> 12));
* $f->addUser('sepp3', 'MyPw', array('userid' => 1000));
* $f->save();
* </code>
* 
* <kbd><u>
*   Usage Example 3 (authentication):
* </u></kbd>
*
* <code>
* $f = &File_Passwd::factory('SMB');
* $f->setFile('./smbpasswd');
* $f->load();
* if (true === $f->verifyPasswd('sepp', 'MyPw')) {
*     echo "User valid";
* } else {
*     echo "User invalid or disabled";
* }
* </code>
* 
* @author   Michael Bretterklieber <michael@bretterklieber.com>
* @author   Michael Wallner <mike@php.net>
* @package  File_Passwd
* @version  $Revision$
* @access   public
*/
class File_Passwd_Smb extends File_Passwd_Common
{
    /**
    * Object which generates the NT-Hash and LAN-Manager-Hash passwds
    * 
    * @access protected
    * @var object
    */
    var $msc;

    /**
    * Constructor
    *
    * @access public
    * @param  string $file  SMB passwd file
    */
    function File_Passwd_Smb($file = 'smbpasswd')
    {
        $this->__construct($file);
    }
    
    /**
    * Constructor (ZE2)
    * 
    * Rewritten because we want to init our crypt engine.
    *
    * @access public
    * @param  string $file  SMB passwd file
    */
    function __construct($file = 'smbpasswd')
    {
        $this->setFile($file);
        $this->msc = &new Crypt_MSCHAPv1;
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
    *   o invalid encryption method <var>$nt_or_lm</var> was provided
    *
    * @static   call this method statically for a reasonable fast authentication
    * @access   public
    * @return   mixed   true if authenticated, false if not or PEAR_Error
    * @param    string  $file       path to passwd file
    * @param    string  $user       user to authenticate
    * @param    string  $pass       plaintext password
    * @param    string  $nt_or_lm   encryption mode to use (NT or LM hash)
    */
    function staticAuth($file, $user, $pass, $nt_or_lm)
    {
        $line = File_Passwd_Common::_auth($file, $user);
        if (!$line || PEAR::isError($line)) {
            return $line;
        }
        @list(,$nt,$lm) = explode(':', $line);
        $chap           = &new Crypt_MSCHAPv1;
        switch(strToLower($nt_or_lm)){
        	case 'nt': 
                $real       = $nt; 
                $crypted    = $chap->ntPasswordHash($pass); 
                break;
        	case 'lm': 
                $real       = $lm;
                $crypted    = $chap->lmPasswordHash($pass); 
                break;
        	default:
                return PEAR::raiseError(
                    sprintf(FILE_PASSWD_E_INVALID_ENC_MODE_STR, $nt_or_lm),
                    FILE_PASSWD_E_INVALID_ENC_MODE
                );
        }
        return ($crypted === $real);
    }
    
    /**
    * Parse smbpasswd file
    *
    * Returns a PEAR_Error if passwd file has invalid format.
    * 
    * @access public
    * @return mixed   true on success or PEAR_Error
    */    
    function parse()
    {
        foreach ($this->_contents as $line){
            $info = explode(':', $line);
            if (count($info) < 4) {
                return PEAR::raiseError(
                    FILE_PASSWD_E_INVALID_FORMAT_STR,
                    FILE_PASSWD_E_INVALID_FORMAT
                );
            }
            $user = array_shift($info);
            if (!empty($user)) {
                array_walk($info, 'trim');
                $this->_users[$user] = @array(
                    'userid'    => $info[0],
                    'lmhash'    => $info[1],
                    'nthash'    => $info[2],
                    'flags'     => $info[3],
                    'lct'       => $info[4],
                    'comment'   => $info[5]
                );
            }
        }
        $this->_contents = array();
        return true; 
    }
    
    /**
    * Add a user
    *
    * Returns a PEAR_Error if:
    *   o user already exists
    *   o user contains illegal characters
    *
    * @throws PEAR_Error
    * @return mixed true on success or PEAR_Error
    * @access public
    * @param  string    $user       the user to add
    * @param  string    $pass       the new plaintext password
    * @param  array     $params     additional properties of user
    *                                + userid
    *                                + flags
    *                                + lct
    *                                + comment
    * @param  boolean   $isMachine  whether to add an machine account
    */
    function addUser($user, $pass, $params, $isMachine = false)
    {
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
        if ($isMachine) {
            $flags = '[W           ]';
            $user .= '$';
        } else {
            $flags = '[U           ]';
        }
        $this->_users[$user] = array(
            'userid'    => @$params['userid'],
            'flags'     => $flags,
            'lct'       => @$params['lct'],
            'comment'   => @$params['comment']
        );
        return $this->changePasswd($user, $pass);
    }

    /**
    * Modify a certain user
    * 
    * <b>You should not modify the password with this method 
    * unless it is already encrypted as nthash and lmhash!</b>
    *
    * Returns a PEAR_Error if:
    *   o user doesn't exist
    *   o an invalid property was supplied
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true on success or PEAR_Error
    * @param  string    $user   the user to modify
    * @param  array     $params an associative array of properties to change
    */
    function modUser($user, $params)
    {
        if (!$this->userExists($user)) {
            return PEAR::raiseError(
                sprintf(FILE_PASSWD_E_EXISTS_NOT_STR, 'User ', $user),
                FILE_PASSWD_E_EXISTS_NOT
            );
        }
        if (!preg_match($this->_pcre, $user)) {
            return PEAR::raiseError(
                sprintf(FILE_PASSWD_E_INVALID_CHARS_STR, 'User ', $user),
                FILE_PASSWD_E_INVALID_CHARS
            );
        }
        foreach ($params as $key => $value){
            $key = strToLower($key);
            if (!isset($this->_users[$user][$key])) {
                return PEAR::raiseError(
                    sprintf(FILE_PASSWD_E_INVALID_PROPERTY_STR, $key),
                    FILE_PASSWD_E_INVALID_PROPERTY
                );
            }
            $this->_users[$user][$key] = $value;
        }
        return true;
    }

    /**
    * Change the passwd of a certain user
    *
    * Returns a PEAR_Error if <var>$user</var> doesn't exist.
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true on success or PEAR_Error
    * @param  string    $user   the user whose passwd should be changed
    * @param  string    $pass   the new plaintext passwd
    */
    function changePasswd($user, $pass)
    {
        if (!$this->userExists($user)) {
            return PEAR::raiseError(
                sprintf(FILE_PASSWD_E_EXISTS_NOT_STR, 'User ', $user),
                FILE_PASSWD_E_EXISTS_NOT
            );
        }
        $nthash = strToUpper($this->msc->ntPasswordHash($pass));
        $lmhash = strToUpper($this->msc->lmPasswordHash($pass));
        $this->_users[$user]['nthash'] = $nthash;
        $this->_users[$user]['lmhash'] = $lmhash;
        return true;
    }
    
    /**
    * Verifies a user's password
    * 
    * Prefer NT-Hash instead of weak LAN-Manager-Hash
    *
    * Returns a PEAR_Error if:
    *   o user doesn't exist
    *   o user is disabled
    *
    * @return mixed true if passwds equal, false if they don't or PEAR_Error
    * @access public		
    * @param string $user       username
    * @param string $nthash     NT-Hash in hex
    * @param string $lmhash     LAN-Manager-Hash in hex
    */
    function verifyEncryptedPasswd($user, $nthash, $lmhash = '')
    {
        if (!$this->userExist($user)) {
            return PEAR::raiseError(
                sprintf(FILE_PASSWD_E_EXISTS_NOT_STR, 'User ', $user),
                FILE_PASSWD_E_EXISTS_NOT
            );
        }
        if (strstr($this->_users[$user]['flags'], 'D')) {
            return PEAR::raiseError("User '$user' is disabled.", 0);
        }
        if (!empty($nthash)) {
            return $this->_users[$user]['nthash'] === strToUpper($nthash);
        }
        if (!empty($lmhash)) {
            return $this->_users[$user]['lm'] === strToUpper($lmhash);
        }
        return false;
    }

    /**
    * Verifies an account with the given plaintext password
    *
    * Returns a PEAR_Error if:
    *   o user doesn't exist
    *   o user is disabled
    *
    * @throws PEAR_Error
    * @return mixed     true if passwds equal, false if they don't or PEAR_Error
    * @access public		
    * @param  string    $user username
    * @param  string    $pass the plaintext password
    */
    function verifyPasswd($user, $pass)
    {
        $nthash = bin2hex($this->msc->ntPasswordHash($pass));
        $lmhash = bin2hex($this->msc->lmPasswordHash($pass));
        return $this->verifyEncryptedPasswd($user, $nthash, $lmhash);
    }

    /**
    * Apply changes and rewrite CVS passwd file
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
    function save()
    {
        $content = '';
        foreach ($this->_users as $user => $userdata) {
            $content .= $user . ':' . implode(':', $userdata) . "\n";
        }
        return $this->_save($content);
    }    
}
?>

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
// | Author: Rasmus Lerdorf <rasmus@php.net>                              |
// +----------------------------------------------------------------------+
//
// $Id$

/**
* Manipulate many kinds of passwd files.
* 
* @author       Rasmus Lerdorf <rasmus@php.net>
* @package      File_Passwd
* @category     FileSystem
*/

/**
* Requires PEAR.
*/
require_once('PEAR.php');

/**
* Undefined error.
*/
define('FILE_PASSWD_E_UNDEFINED',                   0);
/**
* Invalid file format.
*/
define('FILE_PASSWD_E_INVALID_FORMAT',              1);
define('FILE_PASSWD_E_INVALID_FORMAT_STR',          'Passwd file has invalid format.');
/**
* Invalid extra property.
*/
define('FILE_PASSWD_E_INVALID_PROPERTY',            2);
define('FILE_PASSWD_E_INVALID_PROPERTY_STR',        'Invalid property \'%s\'.');
/**
* Invalid characters.
*/
define('FILE_PASSWD_E_INVALID_CHARS',               3);
define('FILE_PASSWD_E_INVALID_CHARS_STR',           '%s\'%s\' contains illegal characters.');
/**
* Invalid encryption mode.
*/
define('FILE_PASSWD_E_INVALID_ENC_MODE',            4);
define('FILE_PASSWD_E_INVALID_ENC_MODE_STR',        'Encryption mode \'%s\' not supported.');
/**
* Exists already.
*/
define('FILE_PASSWD_E_EXISTS_ALREADY',              5);
define('FILE_PASSWD_E_EXISTS_ALREADY_STR',          '%s\'%s\' already exists.');
/**
* Exists not.
*/
define('FILE_PASSWD_E_EXISTS_NOT',                  6);
define('FILE_PASSWD_E_EXISTS_NOT_STR',              '%s\'%s\' doesn\'t exist.');
/**
* User not in group.
*/
define('FILE_PASSWD_E_USER_NOT_IN_GROUP',           7);
define('FILE_PASSWD_E_USER_NOT_IN_GROUP_STR',       'User \'%s\' doesn\'t exist in group \'%s\'.');
/**
* User not in realm.
*/
define('FILE_PASSWD_E_USER_NOT_IN_REALM',           8);
define('FILE_PASSWD_E_USER_NOT_IN_REALM_STR',       'User \'%s\' doesn\'t exist in realm \'%s\'.');
/**
* Parameter must be of type array.
*/
define('FILE_PASSWD_E_PARAM_MUST_BE_ARRAY',         9);
define('FILE_PASSWD_E_PARAM_MUST_BE_ARRAY_STR',     'Parameter %s must be of type array.');
/**
* Method not implemented.
*/
define('FILE_PASSWD_E_METHOD_NOT_IMPLEMENTED',      10);
define('FILE_PASSWD_E_METHOD_NOT_IMPLEMENTED_STR',  'Method \'%s()\' not implemented.');
/**
* Directory couldn't be created.
*/
define('FILE_PASSWD_E_DIR_NOT_CREATED',             11);
define('FILE_PASSWD_E_DIR_NOT_CREATED_STR',         'Couldn\'t create directory \'%s\'.');
/**
* File couldn't be opened.
*/
define('FILE_PASSWD_E_FILE_NOT_OPENED',             12);
define('FILE_PASSWD_E_FILE_NOT_OPENED_STR',         'Couldn\'t open file \'%s\'.');
/**
* File coudn't be locked.
*/
define('FILE_PASSWD_E_FILE_NOT_LOCKED',             13);
define('FILE_PASSWD_E_FILE_NOT_LOCKED_STR',         'Couldn\'t lock file \'%s\'.');
/**
* File couldn't be unlocked.
*/
define('FILE_PASSWD_E_FILE_NOT_UNLOCKED',           14);
define('FILE_PASSWD_E_FILE_NOT_UNLOCKED_STR',       'Couldn\'t unlock file.');
/**
* File couldn't be closed.
*/
define('FILE_PASSWD_E_FILE_NOT_CLOSED',             15);
define('FILE_PASSWD_E_FILE_NOT_CLOSED_STR',         'Couldn\'t close file.');

/**
* Class to manage passwd-style files
*
* @author       Rasmus Lerdorf <rasmus@php.net>
* @package      File_Passwd
* @category     FileSystem
* @version      $Revision$
* @deprecated   <b>Please use the provided factory instead!</b>
* 
* <code>
*  $passwd = &File_Passwd::factory('Unix');
* </code>
*/
class File_Passwd {

    /**
    * Passwd file
    * @var string
    */
    var $filename;

    /**
    * Hash list of users
    * @var array
    */
    var $users;
    
    /**
    * hash list of csv-users
    * @var array
    */
    var $cvs;
    
    /**
    * filehandle for lockfile
    * @var int
    */
    var $fplock;
    
    /**
    * locking state
    * @var boolean
    */
    var $locked;
    
    /**
    * name of the lockfile
    * @var string    
    */ 
    var $lockfile = './passwd.lock';

    /**
    * Constructor
    * 
    * Requires the name of the passwd file. This functions opens the file and 
    * read it. Changes to this file will written first in the lock file, 
    * so it is still possible to access the passwd file by another programs. 
    * The lock parameter controls the locking oft the lockfile, not of the 
    * passwd file! (Swapping $lock and $lockfile would break BC).
    * Don't forget to call close() to save changes!
    * 
    * @param $file		name of the passwd file
    * @param $lock		if 'true' $lockfile will be locked
    * @param $lockfile	name of the temp file, where changes are saved
    *
    * @access public
    * @see close() 
    */

    function File_Passwd($file, $lock = 0, $lockfile = "") {
        $this->filename = $file;
        if( !empty( $lockfile) ) {
            $this->lockfile = $lockfile ;
        }

        if($lock) {
            $this->fplock = fopen($this->lockfile, 'w');
            flock($this->fplock, LOCK_EX);
            $this->locked = true;
        }
    
        $fp = fopen($file,'r') ;
        if( !$fp) {
            return PEAR::raiseError( "Couldn't open '$file'!", 1) ;
        }
        while(!feof($fp)) {
            $line = fgets($fp, 128);
            if (!strlen($line)) {
                continue;
            }
            @list($user, $pass, $cvsuser) = explode(':', $line);
            if(strlen($user)) {
                $this->users[$user] = trim($pass);
                $this->cvs[$user] = trim($cvsuser);	
            }
        }
        fclose($fp);
    } // end func File_Passwd()

    /**
    * Adds a user
    *
    * @param $user new user id
    * @param $pass password for new user
    * @param $cvs  cvs user id (needed for pserver passwd files)
    *
    * @return mixed returns PEAR_Error, if the user already exists
    * @access public
    */
    function addUser($user, $pass, $cvsuser = "") {
        if(!isset($this->users[$user]) && $this->locked) {
            $this->users[$user] = crypt($pass);
            $this->cvs[$user] = $cvsuser;
            return true;
        } else {
            return PEAR::raiseError(
                "Couldn't add user '$user', because the user already exists!", 
                2
            );
        }
    } // end func addUser()

    /**
    * Modifies a user
    *
    * @param $user user id
    * @param $pass new password for user
    * @param $cvs  cvs user id (needed for pserver passwd files)
    *
    * @return mixed returns PEAR_Error, if the user doesn't exists
    * @access public
    */

    function modUser($user, $pass, $cvsuser="") {
        if(isset($this->users[$user]) && $this->locked) {
            $this->users[$user] = crypt($pass);
            $this->cvs[$user] = $cvsuser;
            return true;
        } else {
            return PEAR::raiseError(
                "Couldn't modify user '$user', because the user doesn't exists!",
                3
            );
        }
    } // end func modUser()

    /**
    * Deletes a user
    *
    * @param $user user id
    *
    * @return mixed returns PEAR_Error, if the user doesn't exists
    * @access public	
    */
    
    function delUser($user) {
        if(isset($this->users[$user]) && $this->locked) {
            unset($this->users[$user]);
            unset($this->cvs[$user]);
        } else {
            return PEAR::raiseError(
                "Couldn't delete user '$user', because the user doesn't exists!",
                3
            ); 
        }
    } // end func delUser()

    /**
    * Verifies a user's password
    *
    * @param $user user id
    * @param $pass password for user
    *
    * @return boolean true if password is ok
    * @access public		
    */
    function verifyPassword($user, $pass) {
        if(isset($this->users[$user])) {
            return (
                $this->users[$user] == crypt(
                    $pass, 
                    substr($this->users[$user], 0, CRYPT_SALT_LENGTH)
                )
            );
        }
        return false;
    } // end func verifyPassword()

    /**
    * Return all users from passwd file
    *
    * @access public
    * @return array
    */
    function listUsers() {
        return $this->users;
    } // end func listUsers()

    /**
    * Writes changes to passwd file and unlocks it
    *
    * @access public
    */
    function close() {
        if($this->locked) {
            foreach($this->users as $user => $pass) {
                if($this->cvs[$user]) {
                    fputs($this->fplock, "$user:$pass:" . $this->cvs[$user] . "\n");
                } else {
                    fputs($this->fplock, "$user:$pass\n");
                }
            }
            rename($this->lockfile, $this->filename);
            flock($this->fplock, LOCK_UN);
            $this->locked = false;
            fclose($this->fplock);
        }
    } // end func close()


    /**
    * Lock the lockfile
    *
    * @access public
    */
    function lock() {
        $this->fplock = fopen($this->lockfile, 'w');
        flock($this->fplock, LOCK_EX);
        $this->locked = true;
    }

    /**
    * Unlock the lockfile
    *
    * @access public
    */
    function unlock() {
        flock($this->fplock, LOCK_UN);
        $this->locked = false;
        fclose($this->fplock);
    }

    /**
    * Determine if lockfile is locked
    *
    * @return boolean
    * @access public
    */
    function isLocked() {
        return($this->locked);
    }

    /**
    * Get the CVS username 
    *
    * @param  string username
    * @return string
    * @access public
    */
    function getCvsUser($user) {
       return($this->cvs[$user]);
    }

    /**
    * Get API version
    *
    * @author   Michael Wallner <mike@php.net>
    * 
    * @static
    * @access   public
    * @return   string          API version
    */
    function apiVersion(){
    	return '@API_VERSION@';
    }
    
    /**
    * Factory for new extensions
    * 
    * o Unix        for standard Unix passwd files
    * o CVS         for CVS pserver passwd files
    * o SMB         for SMB server passwd files
    * o Authbasic   for AuthUserFiles
    * o Authdigest  for AuthDigestFiles
    * 
    * Returns a PEAR_Error if the desired class/file couldn't be loaded.
    * 
    * @author   Michael Wallner <mike@php.net>
    * 
    * @static   use &File_Passwd::factory() for instantiating you passwd object
    * 
    * @throws   PEAR_Error
    * @access   public
    * @return   object    File_Passwd_$class - desired Passwd object
    * @param    string    $class the desired subclass of File_Passwd
    */
    function &factory($class){
        $class = ucFirst(strToLower($class));
        if (!@include_once("File/Passwd/$class.php")) {
            return PEAR::raiseError("Couldn't load file Passwd/$class.php", 0);
        }
        $class = 'File_Passwd_'.$class;
        if (!class_exists($class)) {
            return PEAR::raiseError("Couldn't load class $class.", 0);
        }
        $instance = &new $class();
        return $instance;
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
    *   o invalid <var>$type</var> was provided
    *   o invalid <var>$opt</var> was provided
    * 
    * Depending on <var>$type</var>, <var>$opt</var> should be:
    *   o Smb:          encryption method (NT or LM)
    *   o Unix:         encryption method (des or md5)
    *   o Authdigest:   the realm the user is in
    *   o Authbasic:    n/a (empty) (*)
    *   o Cvs:          n/a (empty)
    * 
    *   (*) The File_Passwd_Authbasic facility can verify
    *       only DES enrypted passwords when called statically.
    *
    * @author   Michael Wallner <mike@php.net>
    * 
    * @static   call this method statically for a reasonable fast authentication
    * 
    * @throws   PEAR_Error
    * @access   public
    * @return   return      mixed   true if authenticated, 
    *                               false if not or PEAR_error
    * @param    string      $type   Unix, Cvs, Smb, Authbasic or Authdigest
    * @param    string      $file   path to passwd file
    * @param    string      $user   the user to authenticate
    * @param    string      $pass   the plaintext password
    * @param    string      $opt    o Smb:          NT or LM
    *                               o Unix:         des or md5
    *                               o Authdigest    realm the user is in
    */
    function staticAuth($type, $file, $user, $pass, $opt = ''){
        $type = ucFirst(strToLower($type));
        if (!@include_once("File/Passwd/$type.php")) {
            return PEAR::raiseError("Coudn't load file Passwd/$type.php", 0);
        }
        switch($type){
        	case 'Unix': 
        		return File_Passwd_Unix::staticAuth($file, $user, $pass, $opt);
        		break;
        	case 'Cvs': 
        		return File_Passwd_Cvs::staticAuth($file, $user, $pass);
        		break;
            case 'Smb':
                return File_Passwd_Smb::StaticAuth($file, $user, $pass, $opt);
                break;
            case 'Authbasic':
                return File_Passwd_Authbasic::staticAuth($file, $user, $pass);
                break;
            case 'Authdigest':
                return File_Passwd_Authdigest::staticAuth(
                    $file,
                    $user,
                    $pass,
                    $opt
                );
                break;
        }
        return false;
    }
    
}
?>

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
* Manipulate CVS pserver passwd files.
* 
* <kbd><u>
*   A line of a CVS pserver passwd file consists of 2 to 3 colums:
* </u></kbd>
* <pre>
*   user1:1HCoDDWxK9tbM:sys_user1
*   user2:0O0DYYdzjCVxs
*   user3:MIW9UUoifhqRo:sys_user2
* </pre>
* 
* If the third column is specified, the CVS user named in the first column is 
* mapped to the corresponding system user named in the third column.
* That doesn't really affect us - just for your interest :)
* 
* <kbd><u>Output of listUser()</u></kbd>
* <pre>
*      array
*       + user =>  array
*                   + passwd => crypted_passwd
*                   + system => system_user
*       + user =>  array
*                   + passwd => crypted_passwd
*                   + system => system_user
* </pre>
* 
* @author   Michael Wallner <mike@iworks.at>
* @package  File_Passwd
* @version  $Revision$
* @access   public
*/
class File_Passwd_Cvs extends File_Passwd_Common {

    /**
    * Constructor
    *
    * @access public
    */
    function File_Passwd_Cvs($file = 'passwd'){
        $this->__construct($file);
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
    function save(){
        $contents = '';
        foreach ($this->_users as $user => $v){
            $contents .= "$user:{$v['passwd']}:{$v['system']}\n";
        }
        return $this->_save($contents);
    }
    
    /** 
    * Parse the CVS passwd file
    *
    * Returns a PEAR_Error if passwd file has invalid format.
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true on success or PEAR_Error
    */
    function parse() {
        $this->_users = array();
        foreach ($this->_contents as $line) {
            $user = explode(':', $entry);
            if (count($user) < 2) {
                return PEAR::raiseError('CVS passwd file has invalid format.');
            }
            list($user, $pass, $system) = $user;
            $this->_users[$user]['passwd'] = $pass;
            $this->_users[$user]['system'] = $system;
        }
        $this->_contents = array();
        return true;
    }

    /**
    * Add an user
    *
    * The username must start with an alphabetical character and must NOT
    * contain any other characters than alphanumerics, the underline and dash.
    * 
    * Returns a PEAR_Error if:
    *   o user already exists
    *   o user or system_user contains illegal characters
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true on success or PEAR_Error
    * @param  string    $user           the name of the user to add
    * @param  string    $pass           the password of the user tot add
    * @param  string    $system_user    the systemuser this user maps to
    */
    function addUser($user, $pass, $system_user = ''){
        if ($this->userExists($user)) {
            return PEAR::raiseError("User '$user' already exists.");
        }
        if (!preg_match('/[a-z]+[a-z0-9_-]*/i', $user)) {
            return PEAR::raiseError("User '$user' contains illegal characters.");
        }
        setType($syste_user, 'string');
        if (!preg_match('/[a-z]+[a-z0-9_-]*/i', $system_user)) {
            return PEAR::raiseError(
                "System user '$system_user' contains illegal characters."
            );
        }
        $this->_users[$user]['passwd'] = $this->_genPass($pass);
        $this->_users[$user]['system'] = $system_user;
        return true;
    }
    
    /**
    * Verify the password of a certain user
    *
    * Returns a PEAR_Error if the user doesn't exist.
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true if passwords equal, false ifthe don't or PEAR_Error
    * @param  string    $user   user whose password should be verified
    * @param  string    $pass   the plaintext password that should be verified
    */
    function verifyPasswd($user, $pass){
        if (!$this->userExist($user)) {
            return PEAR::raiseError("USer '$user' doesn't exist.");
        }
        $real = $this->_users[$user]['passwd'];
        return ($real === $this->_genPass($pass, $real));
    }
    
    /**
    * Change the password of a certain user
    *
    * Returns a PEAR_Error if user doesn't exist.
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true on success or PEAR_Error
    */
    function changePasswd($user, $pass){
        if (!$this->userExists($user)) {
            return PEAR::raiseError("User '$user' doesn't exist.");
        }
        $this->_users[$user]['passwd'] = $this->_genPass($pass);
        return true;
    }
    
    /**
    * Change the corresponding system user of a certain cvs user
    *
    * Returns a PEAR_Error if:
    *   o user doesn't exist
    *   o system user contains illegal characters
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true on success or PEAR_Error
    */
    function changeSysUser($user, $system){
        if (!$this->userExists($user)) {
            return PEAR::raiseError("User '$user' doesn't exist.");
        }
        if (!preg_match('/[a-z]+{a-z0-9_-]*/i', $system)) {
            return PEAR::raiseError(
                "System user '$system' contains illegal characters."
            );
        }
        $this->_users[$user]['system'] = $system;
        return true;
    }
    
    /**
    * Generate crypted password
    *
    * @throws PEAR_Error
    * @access public
    * @return string    the crypted password
    * @param  string    $pass   new plaintext password
    * @param  string    $salt   new crypted password from which to gain the salt
    */
    function _genPass($pass, $salt = null){
        $salt = substr((is_null($salt) ? md5(rand()) : $salt), 0,2);
        return crypt($pass, $salt);
    }
    
}
?>
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
* Manipulate AuthDigestFiles as used for HTTP Digest Authentication.
*
* <kbd><u>
*   Usage Example:
* </u></kbd>
* <code>
*   $htd = &File_Passwd::factory('Authdigest');
*   $htd->setFile('/www/mike/auth/.htdigest');
*   $htd->load();
*   $htd->addUser('mike', 'myRealm', 'secret');
*   $htd->save();
* </code>
*
* <kdb><u>
*   Output of listUser()
* </u></kbd>
* <pre>
*      array
*       + user  => array
*                   + realm => crypted_passwd
*                   + realm => crypted_passwd
*       + user  => array
*                   + realm => crypted_passwd
* </pre>
* 
* @author   Michael Wallner <mike@iworks.at>
* @package  File_Passwd
* @version  $Revision$
* @access   public
*/
class File_Passwd_Authdigest extends File_Passwd_Common {

    /** 
    * Path to AuthDigestFile
    *
    * @var string
    * @access private
    */
    var $_file = '.htdigest';

    /** 
    * Constructor
    * 
    * @access public
    * @param string $file       path to AuthDigestFile
    */
    function File_Passwd_Authdigest($file = '.htdigest') {
        $this->__construct($file);
    }

    /** 
    * Apply changes and rewrite AuthDigestFile
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
    * @return mixed true on success or a PEAR_Error
    */
    function save() {
        $content = '';
        if (count($this->_users)) {
            foreach ($this->_users as $user => $realm) {
                foreach ($realm as $r => $pass){
                  $content .= "$user:$r:$pass\n";
                }
            }
        }
        return $this->_save($content);
    }

    /** 
    * Add an user
    *
    * Returns a PEAR_Error if:
    *   o the user already exists in the supplied realm
    *   o the user or realm contain illegal characters
    * 
    * $user and $realm must start with an alphabetical charachter and must NOT
    * contain any other characters than alphanumerics, the underline and dash.
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true on success or a PEAR_Error
    * @param string $user   the user to add
    * @param string $realm  the realm the user should be in
    * @param string $pass   the plaintext password
    */
    function addUser($user, $realm, $pass) {
        if ($this->userInRealm($user, $realm)) {
            return PEAR::raiseError(
                "User '.$user.' already exists in realm '$realm'."
            );
        }
        if (!preg_match('/^[a-z]+[a-z0-9\-_]*$/i', $user)) {
            return PEAR::raiseError(
                "User '$user' contains illegal characters."
            );
        }
        if (!preg_match('/^[a-z]+[a-z0-9\-_]*$/i', $realm)) {
            return PEAR::raiseError(
                "Realm '$realm' contains illegal characters."
            );
        }
        $this->_users[$user][$realm] = md5("$user:$realm:$pass");
        return true;
    }

    /**
    * List all user of (a | all) realm(s)
    * 
    * Returns:
    *   o associative array of users of ONE realm if $inRealm was supplied
    *     <pre>
    *       realm1
    *        + user1
    *        + user2
    *        + user3
    *     </pre>
    *   o associative array of all realms with all users
    *     <pre>
    *       array
    *        + realm1 => array
    *                     + user1
    *                     + user2
    *                     + user3
    *        + realm2 => array
    *                     + user3
    *        + realm3 => array
    *                     + user1
    *                     + user2
    *     </pre>
    * 
    * @access public
    * @return array
    * @param string $inRealm    the realm to list users of;
    *                           if omitted, you'll get all realms
    */
    function listUserInRealm($inRealm = ''){
        $result = array();
        foreach ($this->_user as $user => $realms){
            foreach ($realms as $realm => $pass){
                if (!empty($inRealm) && ($inRealm !== $realm)) {
                    continue;
                }
                if (!isset($result[$realm])) {
                    $result[$realm] = array();
                }
                array_push($result[$realm], $user);
            }
        }
        return $result;
    }
    
    /** 
    * Change the password of a certain user
    *
    * Returns a PEAR_Error if:
    *   o user doesn't exist in the supplied realm
    *   o user or realm contains illegal characters
    * 
    * This method in fact adds the user whith the new password
    * after deleting the user.
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true on success or a PEAR_Error
    * @param string $user   the user whose password should be changed
    * @param string $realm  the realm the user is in
    * @param string $pass   the new plaintext password
    */
    function changePasswd($user, $realm, $pass) {
        if (PEAR::isError($error = $this->delUser($user, $realm))) {
            return $error;
        } else {
            return $this->addUser($user, $realm, $pass);
        }
    }

    /** 
    * Verifiy password
    *
    * Returns a PEAR_Error if the user doesn't exist in the supplied realm.
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true if passwords equal, false if they don't, or PEAR_Error
    * @param string $user   the user whose password should be verified
    * @param string $realm  the realm the user is in
    * @param string $pass   the plaintext password to verify
    */
    function verifyPasswd($user, $realm, $pass) {
        if (!$this->userInRealm($user, $realm)) {
            return PEAR::raiseError("User '$user' does not exist.");
        }
        return ($this->_users[$user][$realm] === md5("$user:$realm:$pass"));
    }

    /**
    * Ckeck if a certain user is in a specific realm
    * 
    * @throws PEAR_Error
    * @access public
    * @return boolean
    * @param string $user   the user to check
    * @param string $realm  the realm the user shuold be in
    */
    function userInRealm($user, $realm){
      return (isset($this->_users[$user][$realm]));
    }
    
    /**
    * Delete a certain user in a specific realm
    *
    * Returns a PEAR_Error if <var>$user</var> doesn't exist <var>$inRealm</var>.
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true on success or PEAR_Error
    * @param  string    $user       the user to remove
    * @param  string    $inRealm    the realm the user should be in
    */
    function delUserInRealm($user, $inRealm){
        if (!$this->userInRealm($user, $inRealm)) {
            return PEAR::raiseError("User '$user' is not in realm '$inRealm'.");
        }
        unset($this->_users[$user][$inRealm]);
        return true;
    }
    
    /** 
    * Parse the AuthDigestFile
    *
    * Returns a PEAR_Error if AuthDigestFile has invalid format.
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true on success or PEAR_Error
    */
    function parse() {
        $this->_users = array();
        foreach ($this->_contents as $line) {
            $user = explode(':', $entry);
            if (count($user) != 3) {
                return PEAR::raiseError('AuthDigestFile has invalid format.');
            }
            list($user, $realm, $pass) = $user;
            $this->_users[$user][$realm] = trim($pass);
        }
        $this->_contents = array();
        return true;
    }
}
?>
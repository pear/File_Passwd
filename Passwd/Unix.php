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
* Manipulate standard Unix passwd files.
* 
* @author   Michael Wallner <mike@php.net>
* @package  File_Passwd
*/

/**
* Requires File::Passwd::Common
*/
require_once('File/Passwd/Common.php');

/**
* Manipulate standard Unix passwd files.
* 
* <kbd><u>Usage Example:</u></kbd>
* <code>
*   $passwd = &File_Passwd::factory('Unix');
*   $passwd->setFile('/my/passwd/file');
*   $passwd->load();
*   $passwd->addUser('mike', 'secret');
*   $passwd->save();
* </code>
* 
* 
* <kbd><u>Output of listUser()</u></kbd>
* # using the 'name map':
* <pre>
*      array
*       + user  => array
*                   + pass  => crypted_passwd or 'x' if shadowed
*                   + uid   => user id
*                   + gid   => group id
*                   + gecos => comments
*                   + home  => home directory
*                   + shell => standard shell
* </pre>
* # without 'name map':
* <pre>
*      array
*       + user  => array
*                   + 0  => crypted_passwd
*                   + 1  => ...
*                   + 2  => ...
* </pre>
* 
* @author   Michael Wallner <mike@php.net>
* @package  File_Passwd
* @version  $Revision$
* @access   public
*/
class File_Passwd_Unix extends File_Passwd_Common {

    /**
    * A 'name map' wich refer to the extra properties
    *
    * @var array
    * @access private
    */
    var $_map = array('uid', 'gid', 'gecos', 'home', 'shell');
    
    /**
    * Whether to use the 'name map' or not
    *
    * @var boolean
    * @access private
    */
    var $_usemap = true;
    
    /**
    * Whether the passwords of this passwd file are shadowed in another file
    *
    * @var boolean
    * @access private
    */
    var $_shadowed = false;
    
    /**
    * Encryption mode, either md5 or des
    *
    * @var string
    * @access private
    */
    var $_mode = 'des';
    
    /**
    * Supported encryption modes
    * 
    * @var array
    * @access private
    */
    var $_modes = array('md5' => 'md5', 'des' => 'des');
    
    /**
    * Constructor
    *
    * @access public
    * @param  string    $file   path to passwd file
    */
    function File_Passwd_Unix($file = 'passwd'){
        $this->__construct($file);
    }
    
    /**
    * Apply changes an rewrite passwd file
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
        $content = '';
        foreach ($this->_users as $user => $array){
            $pass   = array_shift($array);
            $extra  = implode(':', $array);
            $content .= $user . ':' . $pass;
            if (!empty($extra)) {
                $content .= ':' . $extra;
            }
            $content .= "\n";
        }
        return $this->_save($content);
    }
    
    /**
    * Parse the Unix password file
    *
    * Returns a PEAR_Error if passwd file has invalid format.
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true on success or PEAR_Error
    */
    function parse(){
        $this->_users = array();
        foreach ($this->_contents as $line){
            $parts = explode(':', $line);
            if (count($parts) < 2) {
                return PEAR::raiseError(
                    FILE_PASSWD_E_INVALID_FORMAT_STR,
                    FILE_PASSWD_E_INVALID_FORMAT
                );
            }
            $user = array_shift($parts);
            $pass = array_shift($parts);
            if ($pass == 'x') {
                $this->_shadowed = true;
            }
            $values = array();
            if ($this->_usemap) {
                $values['pass'] = $pass;
                foreach ($parts as $i => $value){
                    if (isset($this->_map[$i])) {
                        $values[$this->_map[$i]] = $value;
                    } else {
                        $values[$i+1] = $value;
                    }
                }
            } else {
                $values = array_merge(array($pass), $parts);
            }
            $this->_users[$user] = $values;
            
        }
        $this->_contents = array();
        return true;
    }
    
    /**
    * Set the encryption mode
    * 
    * Supported encryption modes are des and md5.
    * 
    * Returns a PEAR_Error if supplied encryption mode is not supported.
    *
    * @see      setMode()
    * @see      listModes()
    * 
    * @throws   PEAR_Error
    * @access   public
    * @return   mixed   true on succes or PEAR_Error
    * @param    string  $mode   encryption mode to use; either md5 or des
    */
    function setMode($mode) {
        $mode = strToLower($mode);
        if (!isset($this->_modes[$mode])) {
            return PEAR::raiseError(
                sprintf(FILE_PASSWD_E_INVALID_ENC_MODE_STR, $mode),
                FILE_PASSWD_E_INVALID_ENC_MODE
            );
        }
        $this->_mode = $mode;
        return true;
    }
    
    /** 
    * Get supported encryption modes
    *
    * <pre>
    *   array
    *    + md5
    *    + des
    * </pre>
    * 
    * @see      setMode()
    * @see      getMode()
    * 
    * @access   public
    * @return   array
    */
    function listModes() {
        return $this->_modes;
    }

    /**
    * Get actual encryption mode
    *
    * @see      listModes()
    * @see      setMode()
    * 
    * @access   public
    * @return   string
    */
    function getMode(){
        return $this->_mode;
    }
    
    /**
    * Whether to use the 'name map' of the extra properties or not
    * 
    * Default Unix passwd files look like:
    * <pre>
    * user:password:user_id:group_id:gecos:home_dir:shell
    * </pre>
    * 
    * The default 'name map' for properties except user and password looks like:
    *   o uid
    *   o gid
    *   o gecos
    *   o home
    *   o shell
    * 
    * If you want to change the naming of the standard map use 
    * File_Passwd_Unix::setMap(array()).
    *
    * @see      setMap()
    * @see      getMap()
    * 
    * @access   public
    * @return   boolean always true if you set a value (true/false) OR
    *                   the actual value if called without param
    * 
    * @param    boolean $bool   whether to use the 'name map' or not
    */
    function useMap($bool = null){
        if (is_null($bool)) {
            return $this->_usemap;
        }
        $this->_usemap = (bool) $bool;
        return true;
    }
    
    /**
    * Set the 'name map' to use with the extra properties of the user
    * 
    * This map is used for naming the associative array of the extra properties.
    *
    * Returns a PEAR_Error if <var>$map</var> was not of type array.
    * 
    * @see      getMap()
    * @see      useMap()
    * 
    * @throws   PEAR_Error
    * @access   public
    * @return   mixed       true on success or PEAR_Error
    */
    function setMap($map = array()){
        if (!is_array($map)) {
            return PEAR::raiseError(
                sprintf(FILE_PASSWD_E_PARAM_MUST_BE_ARRAY_STR, '$map'),
                FILE_PASSWD_E_PARAM_MUST_BE_ARRAY
            );
        }
        $this->_map = $map;
        return true;
    }
    
    /**
    * Get the 'name map' which is used for the extra properties of the user
    *
    * @see      setMap()
    * @see      useMap()
    * 
    * @access public
    * @return array
    */
    function getMap(){
        return $this->_map;
    }
    
    /**
    * If the passwords of this passwd file are shadowed in another file.
    *
    * @access public
    * @return boolean
    */
    function isShadowed(){
        return $this->_shadowed;
    }
    
    /**
    * Add an user
    *
    * The username must start with an alphabetical character and must NOT
    * contain any other characters than alphanumerics, the underline and dash.
    * 
    * If you use the 'name map' you should also use these naming in
    * the supplied extra array, because your values would get mixed up
    * if they are in the wrong order, which is always true if you
    * DON'T use the 'name map'!
    * 
    * So be warned and USE the 'name map'!
    * 
    * If the passwd file is shadowed, the user will be added though, but
    * with an 'x' as password, and a PEAR_Error will be returned, too.
    * 
    * Returns a PEAR_Error if:
    *   o user already exists
    *   o user contains illegal characters
    *   o encryption mode is not supported
    *   o passwords are shadowed in another file
    *   o any element of the <var>$extra</var> array contains a colon (':')
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true on success or PEAR_Error
    * @param  string    $user   the name of the user to add
    * @param  string    $pass   the password of the user to add
    * @param  array     $extra  extra properties of user to add
    */
    function addUser($user, $pass, $extra = array()){
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
        if (!is_array($extra)) {
            setType($extra, 'array');
        }
        foreach ($extra as $e){
            if (strstr($e, ':')) {
            return PEAR::raiseError(
                sprintf(FILE_PASSWD_E_INVALID_CHARS_STR, 'Property ', $e),
                FILE_PASSWD_E_INVALID_CHARS
            );
            }
        }
        
        /**
        * If passwords of the passwd file are shadowed, 
        * the password of the user will be set to 'x'.
        */
        if ($this->_shadowed) {
            $pass = 'x';
        } else {
            $pass = $this->_genPass($pass);
            if (PEAR::isError($pass)) {
                return $pass;
            }
        }
        
        /**
        * If you don't use the 'name map' the user array will be numeric.
        */
        if (!$this->_usemap) {
            array_unshift($extra, $pass);
            $this->_users[$user] = $extra;
        } else {
            $map = $this->_map;
            array_unshift($map, 'pass');
            $extra['pass'] = $pass;
            foreach ($map as $key){
                $this->_users[$user][$key] = @$extra[$key];
            }
        }
        
        /**
        * Raise a PEAR_Error if passwords are shadowed.
        */
        if ($this->_shadowed) {
            return PEAR::raiseError(
                'Password has been set to \'x\' because they are '.
                'shadowed in another file.', 0
            );
        }
        return true;
    }
    
    /**
    * Modify properties of a certain user
    *
    * # DON'T MODIFY THE PASSWORD WITH THIS METHOD!
    * 
    * You should use this method only if the 'name map' is used, too.
    * 
    * Returns a PEAR_Error if:
    *   o user doesn't exist
    *   o any property contains a colon (':')
    * 
    * @see      changePasswd()
    * 
    * @throws   PEAR_Error
    * @access   public
    * @return   mixed       true on success or PEAR_Error
    * @param    string      $user           the user to modify
    * @param    array       $properties     an associative array of 
    *                                       properties to modify
    */
    function modUser($user, $properties = array()){
        if (!$this->userExists($user)) {
            return PEAR::raiseError(
                sprintf(FILE_PASSWD_E_EXISTS_NOT_STR, 'User ', $user),
                FILE_PASSWD_E_EXISTS_NOT
            );
        }
        if (!is_array($properties)) {
            setType($properties, 'array');
        }
        foreach ($properties as $key => $value){
            if (strstr($value, ':')) {
                return PEAR::raiseError(
                    sprintf(FILE_PASSWD_E_INVALID_CHARS_STR, 'User ', $user),
                    FILE_PASSWD_E_INVALID_CHARS
                );
            }
            $this->_users[$user][$key] = $value;
        }
        return true;
    }
    
    /**
    * Change the password of a certain user
    *
    * Returns a PEAR_Error if:
    *   o user doesn't exists
    *   o passwords are shadowed in another file
    *   o encryption mode is not supported
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed true on success or PEAR_Error
    * @param string $user   the user whose password should be changed
    * @param string $pass   the new plaintext password
    */
    function changePasswd($user, $pass){
        if ($this->_shadowed) {
            return PEAR::raiseError('Passwords of this passwd file are shadowed.', 0);
        }
        if (!$this->userExists($user)) {
            return PEAR::raiseError(
                sprintf(FILE_PASSWD_E_EXISTS_NOT_STR, 'User ', $user),
                FILE_PASSWD_E_EXISTS_NOT
            );
        }
        $pass = $this->_genPass($pass);
        if (PEAR::isError($pass)) {
            return $e;
        }
        if ($this->_usemap) {
            $this->_users[$user]['pass'] = $pass;
        } else {
            $this->_users[$user][0] = $pass;
        }
        return true;
    }
    
    /**
    * Verify the password of a certain user
    * 
    * Returns a PEAR_Error if:
    *   o user doesn't exist
    *   o encryption mode is not supported
    *
    * @throws PEAR_Error
    * @access public
    * @return mixed true if passwors equal, false if they don't or PEAR_Error
    * @param  string    $user   the user whose password should be verified
    * @param  string    $pass   the password to verify
    */
    function verifyPasswd($user, $pass){
        if (!$this->userExists($user)) {
            return PEAR::raiseError(
                sprintf(FILE_PASSWD_E_EXISTS_NOT_STR, 'User ', $user),
                FILE_PASSWD_E_EXISTS_NOT
            );
        }
        $real = 
            $this->_usemap ? 
            $this->_users[$user]['pass'] : 
            $this->_users[$user][0]
        ;
        return ($real === $this->_genPass($pass, $real));
    }
    
    /**
    * Generate crypted password from the plaintext password
    *
    * Returns a PEAR_Error if actual encryption mode is not supported.
    * 
    * @throws PEAR_Error
    * @access public
    * @return mixed     the crypted password or PEAR_Error
    * @param  string    $pass   the plaintext password
    * @param  string    $salt   the crypted password from which to gain the salt
    */
    function _genPass($pass, $salt = null){
        switch($this->_mode){
            case 'des': 
                $salt = substr((is_null($salt) ? md5(rand()) : $salt), 0,2);
                return crypt($pass, $salt);
                break;
            case 'md5': 
                if (is_null($salt)) {
                    return crypt($pass);
                }
                return crypt($pass, substr($salt, 0,12));
                break;
            default:
                return PEAR::raiseError(
                    sprintf(FILE_PASSWD_E_INVALID_ENC_MODE_STR, $this->_mode),
                    FILE_PASSWD_E_INVALID_ENC_MODE
                );
        }
    }
    
}
?>
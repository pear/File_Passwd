<?php
require_once 'File/Passwd.php';

/**
 * TestCase for File_PasswdTest class
 * Generated by PHPEdit.XUnit Plugin
 * 
 */
class File_PasswdTest extends PHPUnit_Framework_TestCase {
    /**
     * Called before the test functions will be executed this function is defined in PHPUnit_Framework_TestCase  and overwritten here
     * @access protected
     */
    function setUp(){
        // Declaring GLOBALS isn't the right way to do this, but I'm just
        // moving them from the top of the file to here as a quick means
        // to get the tests running.
        $GLOBALS['_EXT_'] = array('Unix', 'Cvs', 'Smb', 'Authbasic', 'Authdigest');
    }
    
    /**
     * Called after the test functions are executed this function is defined in PHPUnit_Framework_TestCase  and overwritten here
     * @access protected
     */
    function tearDown(){
        
    }
    
    /**
     * Regression test for File_Passwd.apiVersion method
     * @access public
     */
    function testapiVersion(){
        $this->assertEquals('1.0.0', File_Passwd::apiVersion());
    }
    
    /**
     * Regression test for File_Passwd.salt method
     * @access public
     */
    function testsalt(){
        $this->assertEquals(strlen(File_Passwd::salt()), strlen(File_Passwd::salt(2)));
        $regex = '/^[' . preg_quote($GLOBALS['_FILE_PASSWD_64'], '/') . ']+$/';
        $this->assertRegExp($regex, File_Passwd::salt(20));
    }
    
    /**
     * Regression test for File_Passwd.crypt_des method
     * @access public
     */
    function testcrypt_des(){
        $this->assertEquals(crypt('a','ab'), File_Passwd::crypt_des('a', 'ab'));
    }
    
    /**
     * Regression test for File_Passwd.crypt_md5 method
     * @access public
     */
    function testcrypt_md5(){
        $this->assertEquals(crypt('a','$1$ab'), File_Passwd::crypt_des('a', '$1$ab'));
    }
    
    /**
     * Regression test for File_Passwd.crypt_sha method
     * @access public
     */
    function testcrypt_sha(){
        $sha = '{SHA}2iNhTgJGmg18e9G9q1ycR0sZBNw=';
        $this->assertEquals($sha, File_Passwd::crypt_sha('ab'));
    }
    
    /**
     * Regression test for File_Passwd.crypt_apr_md5 method
     * @access public
     */
    function testcrypt_apr_md5(){
        $apr = '$apr1$ab$KfzLTsXi6eQkfErEn8CHY.';
        $this->assertEquals($apr, File_Passwd::crypt_apr_md5('ab', 'ab'));
    }
    
    /**
     * Regression test for File_Passwd.factory method
     * @access public
     */
    function testfactory(){
        foreach($GLOBALS['_EXT_'] as $ext){
            if ($ext == 'Smb') {
                if (!$fp = @fopen('Crypt/CHAP.php', 'r', true)) {
                    // Avoid require in Smb file causing fatal error.
                    continue;
                }
                fclose($fp);
            }
            $o = File_Passwd::factory($ext);
            $this->assertInstanceOf("File_Passwd_$ext", $o);
        }
    }
    
    /**
     * Regression test for File_Passwd.staticAuth method
     * @access public
     */
    function teststaticAuth(){
        foreach($GLOBALS['_EXT_'] as $ext){
            if ($ext == 'Smb') {
                if (!$fp = @fopen('Crypt/CHAP.php', 'r', true)) {
                    // Avoid require in Smb file causing fatal error.
                    continue;
                }
                fclose($fp);
            }

            $pwfile = dirname(__FILE__) . '/passwd.' . strToLower($ext) . '.txt';
            $option = (($ext == 'Authdigest') ? 'realm1' : (($ext == 'Smb') ? 'nt' : 'des'));
            $error = File_Passwd::staticAuth($ext, $pwfile, 'mike', 123, $option);
            if (PEAR::isError($error)) {
                $this->fail("File_Passwd_$ext::staticAuth() ". $error->getMessage());
            }
        }
        
    }
    
}

?>

<?php
require_once 'System.php';
require_once 'PHPUnit/Autoload.php';
require_once 'File/Passwd/Unix.php';

/**
 * TestCase for File_Passwd_UnixTest class
 * Generated by PHPEdit.XUnit Plugin
 * 
 */
class File_Passwd_UnixTest extends PHPUnit_Framework_TestCase {

    var $pwd;
    protected $exp_file;
    
    /**
     * Called before the test functions will be executed this function is defined in PHPUnit_Framework_TestCase  and overwritten here
     * @access protected
     */
    function setUp(){
        // Declaring GLOBALS isn't the right way to do this, but I'm just
        // moving them from the top of the file to here as a quick means
        // to get the tests running.
        $GLOBALS['tmpfile'] = System::mktemp();
        $GLOBALS['user']   = array(
                    'bug3348' => array(
                        'pass' =>   'wxLaOdcajuKoI',
                        'uid' =>    '500',
                        'gid' =>    '501',
                        'gecos' =>  'having # in gecos',
                        'home' =>   '/nonexistent',
                        'shell' =>  '/bin/false',
                    ),
                    'mike' => array(
                        'pass' =>   'q4M4mpfilkNnU',
                        'uid' =>    '501',
                        'gid' =>    '502',
                        'gecos' =>  'User1',
                        'home' =>   '/home/mike',
                        'shell' =>  '/bin/bash'
                    ),
                    'pete' => array(
                        'pass' =>   'dS80VTLQHZ6VM',
                        'uid' =>    '502',
                        'gid' =>    '503',
                        'gecos' =>  'User2',
                        'home' =>   '/home/pete',
                        'shell' =>  '/bin/sh'
                    ),
                    'mary' => array(
                        'pass' =>   'jHSiqFjaEiKPM',
                        'uid' =>    '503',
                        'gid' =>    '504',
                        'gecos' =>  'User3',
                        'home' =>   '/home/mary',
                        'shell' =>  '/bin/ksh'
                    ),
                );

        $this->exp_file = dirname(__FILE__) . '/passwd.unix.txt';
        $this->pwd = new File_Passwd_Unix();
    }
    
    /**
     * Called after the test functions are executed this function is defined in PHPUnit_Framework_TestCase  and overwritten here
     * @access protected
     */
    function tearDown(){
        $this->pwd = null;
    }
    
    /**
     * Regression test for File_Passwd_Unix.File_Passwd_Unix method
     * @access public
     */
    function testFile_Passwd_Unix(){
        $this->assertInstanceOf('File_Passwd_Unix', $this->pwd);
    }
    
    /**
     * Regression test for File_Passwd_Unix.save method
     * @access public
     */
    function testsave(){
        $this->pwd->setFile($GLOBALS['tmpfile']);
        $this->pwd->_users = $GLOBALS['user'];
        $r = $this->pwd->save();
        if (PEAR::isError($r)) {
            $this->fail($r->getMessage());
        }
        $this->assertTrue($r);
        $this->assertFileEquals($this->exp_file, $GLOBALS['tmpfile']);
    }
    
    /**
     * Regression test for File_Passwd_Unix.useMap method
     * @access public
     */
    function testuseMap(){
        $this->assertTrue($this->pwd->useMap());
        $this->assertTrue($this->pwd->useMap(false));
        $this->assertFalse($this->pwd->useMap());
        $this->assertTrue($this->pwd->useMap(true));
    }
    
    /**
     * Regression test for File_Passwd_Unix.setMap method
     * @access public
     */
    function testsetMap(){
        $array = array('uid','gid','gecos','home','shell');
        $new = array('none');
        $this->assertTrue($this->pwd->setMap($new));
        $this->assertTrue($this->pwd->getMap() == $new);
        $this->assertTrue($this->pwd->setMap($array));
        $this->assertTrue($this->pwd->getMap() == $array);
    }
    
    /**
     * Regression test for File_Passwd_Unix.getMap method
     * @access public
     */
    function testgetMap(){
        $array = array('uid','gid','gecos','home','shell');
        $this->assertTrue($array == $this->pwd->getMap());
    }
    
    /**
     * Regression test for File_Passwd_Unix.isShadowed method
     * @access public
     */
    function testisShadowed(){
        $this->assertFalse($this->pwd->isShadowed());
    }
    
    /**
     * Regression test for File_Passwd_Unix.addUser method
     * @access public
     */
    function testaddUser(){
        $r = $this->pwd->addUser('add', 'pass');
        if (PEAR::isError($r)) {
            $this->fail($r->getMessage());
        }
        $this->assertTrue($r, 'addUser() should return TRUE.');

        $r = $this->pwd->userExists('add');
        if (PEAR::isError($r)) {
            $this->fail($r->getMessage());
        }
        $this->assertTrue($r, 'Could not find user that was just added.');

        $user = $this->pwd->listUser('add');
        $array = array(
            'pass' => $this->pwd->_genPass('pass', $user['pass']),
            'uid' =>'',
            'gid' =>'',
            'gecos' =>'',
            'home' =>'',
            'shell' =>''
        );
        $this->assertEquals($array, $user);
    }
    
    /**
     * Regression test for File_Passwd_Unix.modUser method
     * @access public
     */
    function testmodUser(){
        $this->pwd->addUser('mod', 'pass', array('uid' => 555));
        $r = $this->pwd->modUser('mod', array('uid' => 600));
        if (PEAR::isError($r)) {
            $this->fail($r->getMessage());
        }
        $this->assertTrue($r, 'modUser() should return TRUE.');

        $user = $this->pwd->listUser('mod');
        $this->assertEquals(600, $user['uid']);
    }
    
    /**
     * Regression test for File_Passwd_Unix.changePasswd method
     * @access public
     */
    function testchangePasswd(){
        $this->pwd->addUser('change', 123);
        $r = $this->pwd->changePasswd('change', 'abc');
        if (PEAR::isError($r)) {
            $this->fail($r->getMessage());
        }
        $this->assertTrue($r, 'changePasswd() success did not return TRUE.');
        $r = $this->pwd->verifyPasswd('change', 'abc');
        if (PEAR::isError($r)) {
            $this->fail($r->getMessage());
        }
        $this->assertTrue($r, 'It seems password was not really changed.');
    }
    
    /**
     * Regression test for File_Passwd_Unix.verifyPasswd method
     * @access public
     */
    function testverifyPasswd(){
        $this->pwd->addUser('verify', 12345);
        $r = $this->pwd->verifyPasswd('verify', 12345);
        if (PEAR::isError($r)) {
            $this->fail($r->getMessage());
        }
        $this->assertTrue($r, 'verifyPassword(right password)');
        $r = $this->pwd->verifyPasswd('verify', 0);
        if (PEAR::isError($r)) {
            $this->fail($r->getMessage());
        }
        $this->assertFalse($r, 'verifyPassword(wrong password)');
        $r = $this->pwd->verifyPasswd('nobody', 0);
        if (!PEAR::isError($r)) {
            $this->fail('verifyPasswd() did not return error for nonexistent user.');
        }
        $this->assertEquals("User 'nobody' doesn't exist.", $r->getMessage());
    }
    
    /**
     * Regression test for File_Passwd_Unix._genPass method
     * @access public
     */
    function test_genPass(){
        $this->pwd->setMode('des');
        $this->assertEquals('12wGUVd8lAOJY', $this->pwd->_genPass('12','12'));
        $this->pwd->setMode('md5');
        $this->assertEquals('$1$45678901$8Dc8D8vusJXlDQUC7akws/', $this->pwd->_genPass('12', '$1$456789012'));
    }
    
    /**
     * Regression test for File_Passwd_Unix.getMode method
     * @access public
     */
    function testgetMode(){
        $this->pwd->setMode('md5');
        $this->assertEquals('md5', $this->pwd->getMode());
    }
    
    /**
     * Regression test for File_Passwd_Unix.listModes method
     * @access public
     */
    function testlistModes(){
        $this->assertEquals(
            array('des' => 'des', 'md5' => 'md5'),
            $this->pwd->listModes()
        );
    }
    
    /**
     * Regression test for File_Passwd_Unix.setMode method
     * @access public
     */
    function testsetMode(){
        $this->pwd->setMode('md5');
        $this->assertEquals('md5', $this->pwd->getMode());
        $r = $this->pwd->setMode('no');
        if (!PEAR::isError($r)) {
            $this->fail('setMode() did not return error for nonexistent mode.');
        }
        $this->assertEquals("Encryption mode 'no' not supported.", $r->getMessage());
    }
    
    /**
     * Regression test for File_Passwd_Unix.parse method
     * @access public
     */
    function testparse(){
        $this->pwd->setFile($this->exp_file);
        $r = $this->pwd->load();
        if (PEAR::isError($r)) {
            $this->fail($r->getMessage());
        }
        $this->assertTrue($r);
        $this->assertEquals($GLOBALS['user'], $this->pwd->_users);
    }
    
    function teststaticAuth(){
        $type = 'Unix';
        $r = File_Passwd::staticAuth($type, $this->exp_file, 'mike', 123, 'des');
        if (PEAR::isError($r)) {
            $this->fail($r->getMessage());
        }
        $this->assertTrue($r, 'right user, right password');

        $r = File_Passwd::staticAuth($type, $this->exp_file, 'mike', 'abc', 'des');
        if (PEAR::isError($r)) {
            $this->fail($r->getMessage());
        }
        $this->assertFalse($r, 'right user, wrong password');

        $r = File_Passwd::staticAuth($type, $this->exp_file, 'nonexist', 'asd', 'des');
        if (PEAR::isError($r)) {
            $this->fail($r->getMessage());
        }
        $this->assertFalse($r, 'nonexistent user');
    }
}

?>
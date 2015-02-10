<?php
require_once 'System.php';

function hash_nt($txt)
{
    return strToUpper(bin2hex($GLOBALS['msc']->ntPasswordHash($txt)));
}
function hash_lm($txt)
{
    return strToUpper(bin2hex($GLOBALS['msc']->lmPasswordHash($txt)));
}

/**
 * TestCase for File_Passwd_SmbTest class
 * Generated by PHPEdit.XUnit Plugin
 * 
 */
class File_Passwd_SmbTest extends PHPUnit_Framework_TestCase {

    var $pwd;
    protected $exp_file;
    
    /**
     * Called before the test functions will be executed this function is defined in PHPUnit_Framework_TestCase  and overwritten here
     * @access protected
     */
    function setUp(){
        if (!$fp = @fopen('Crypt/CHAP.php', 'r', true)) {
            $this->markTestSkipped('Crypt/CHAP.php is not installed.');
        }
        fclose($fp);

        if (!extension_loaded('mcrypt')) {
            $this->markTestSkipped('The mcrypt extension is not installed.');
        }

        require_once 'File/Passwd/Smb.php';

        // Declaring GLOBALS isn't the right way to do this, but I'm just
        // moving them from the top of the file to here as a quick means
        // to get the tests running.
        $GLOBALS['tmpfile'] = System::mktemp();
        $GLOBALS['msc']     = new Crypt_CHAP_MSv1();
        $GLOBALS['user']    = array(
            'mike' => array(
                'userid' => 501,
                'nthash' => hash_nt('123'),
                'lmhash' => hash_lm('123'),
                'flags'  => '[U          ]',
                'lct'    => 'LCT-3FA7AE9B',
                'comment'=> 'Michael Wallner'
            )
        );

        $this->exp_file = dirname(__FILE__) . '/passwd.smb.txt';
        $this->pwd = new File_Passwd_Smb();
    }
    
    /**
     * Called after the test functions are executed this function is defined in PHPUnit_Framework_TestCase  and overwritten here
     * @access protected
     */
    function tearDown(){
        $this->pwd = null;
        unset($this->pwd);
    }
    
    /**
     * Regression test for File_Passwd_Smb.File_Passwd_Smb method
     * @access public
     */
    function testFile_Passwd_Smb(){
        $this->assertInstanceOf('File_Passwd_Smb', $this->pwd);
    }
    
    /**
     * Regression test for File_Passwd_Smb.save method
     * @access public
     */
    function testsave(){
        $this->pwd->setFile($GLOBALS['tmpfile']);
        $this->pwd->addUser('mike', 123, array('userid' => 501, 'comment' => 'Michael Wallner'));
        $r = $this->pwd->save();

        $this->assertTrue($r, 'save() should return TRUE.');

        $exp = explode(':', file_get_contents($this->exp_file));
        $exp[5] = $this->pwd->_users['mike']['lct'];
        $act = explode(':', file_get_contents($GLOBALS['tmpfile']));
        $this->assertEquals($exp, $act);
    }
    
    /**
     * Regression test for File_Passwd_Smb.addUser method
     * @access public
     */
    function testaddUser(){
        $r = $this->pwd->addUser('add', 123, array('userid' => 502));

        $this->assertTrue($r, 'addUser() should return TRUE.');

        $r = $this->pwd->userExists('add');

        $this->assertTrue($r, 'Could not find user that was just added.');
    }
    
    /**
     * Regression test for File_Passwd_Smb.modUser method
     * @access public
     */
    function testmodUser(){
        $this->pwd->addUser('mod', 123, array('userid' => 555));
        $r = $this->pwd->modUser('mod', array('userid' => 600));

        $this->assertTrue($r, 'modUser() should return TRUE.');

        $user = $this->pwd->listUser('mod');
        $this->assertEquals(600, $user['userid']);
    }
    
    /**
     * Regression test for File_Passwd_Smb.changePasswd method
     * @access public
     */
    function testchangePasswd(){
        $this->pwd->addUser('change', 123, array('userid' => 504));
        $r = $this->pwd->changePasswd('change', 'abc');

        $this->assertTrue($r, 'changePasswd() success did not return TRUE.');
        $r = $this->pwd->verifyPasswd('change', 'abc');

        $this->assertTrue($r, 'It seems password was not really changed.');
    }
    
    /**
     * Regression test for File_Passwd_Smb.verifyEncryptedPasswd method
     * @access public
     */
    function testverifyEncryptedPasswd(){
        $this->pwd->addUser('encrypted', 'abc', array('userid' => 505));
        $pass = hash_nt('abc');
        $r = $this->pwd->verifyEncryptedPasswd('encrypted', $pass);

        $this->assertTrue($r, 'verifyEncryptedPassword(right password)');
        $r = $this->pwd->verifyEncryptedPasswd('encrypted', 'bogus');

        $this->assertFalse($r, 'verifyEncryptedPassword(wrong password)');
        $r = $this->pwd->verifyEncryptedPasswd('nobody', 0);
        if (!PEAR::isError($r)) {
            $this->fail('verifyEncryptedPasswd() did not return error for nonexistent user.');
        }
        $this->assertEquals("User 'nobody' doesn't exist.", $r->getMessage());
    }
    
    /**
     * Regression test for File_Passwd_Smb.verifyPasswd method
     * @access public
     */
    function testverifyPasswd(){
        $this->pwd->addUser('verify', 'abc', array('userid' => 506));
        $r = $this->pwd->verifyPasswd('verify', 'abc');

        $this->assertTrue($r, 'verifyPassword(right password)');
        $r = $this->pwd->verifyPasswd('verify', 'bogus');

        $this->assertFalse($r, 'verifyPassword(wrong password)');
        $r = $this->pwd->verifyPasswd('nobody', 0);
        if (!PEAR::isError($r)) {
            $this->fail('verifyPasswd() did not return error for nonexistent user.');
        }
        $this->assertEquals("User 'nobody' doesn't exist.", $r->getMessage());
    }
    
    /**
     * Regression test for File_Passwd_Smb.parse method
     * @access public
     */
    function testparse(){
        $this->pwd->setFile($this->exp_file);
        $r = $this->pwd->load();

        $this->assertTrue($r);
        $this->assertEquals($GLOBALS['user'], $this->pwd->_users);
    }
    
    /**
     * Regression test for File_Passwd_Smb.staticAuth method
     * @access public
     */
    function teststaticAuth(){
        $type = 'smb';
        $r = File_Passwd::staticAuth($type, $this->exp_file, 'mike', 123, 'nt');

        $this->assertTrue($r, 'right user, right password');

        $r = File_Passwd::staticAuth($type, $this->exp_file, 'mike', 'abc', 'nt');

        $this->assertFalse($r, 'right user, wrong password');

        $r = File_Passwd::staticAuth($type, $this->exp_file, 'nonexist', 'asd', 'nt');

        $this->assertFalse($r, 'nonexistent user');
    }
    
}

?>

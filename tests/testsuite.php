<?php
class TC {
    function runTest($name){
        include_once('test_' . strToLower($name) . '.php');
        echo "# Starting unit test for File_Passwd_$name:\n";
    	$tc = &new PhpUnit_TestSuite('File_Passwd_'.$name.'Test');
        $rs = PHPUnit::run($tc);
        echo $rs->toString() . "\n";
    }
}

TC::runTest('Common');
TC::runTest('Unix');
TC::runTest('Authbasic');
TC::runTest('Authdigest');
TC::runTest('Cvs');
?>
<?php

require_once('PEAR.php');

class TC {
    function runTest($name){
        $test = strToLower($name);
        include_once("test_$test.php");
        echo "# Starting unit test for $name:\n";
    	$tc = &new PhpUnit_TestSuite('File_Passwd'.($name!='File_Passwd' ? '_'.$name : '').'Test');
        $rs = PHPUnit::run($tc);
        echo $rs->toString() . "\n";
        flush();
    }
}
echo "\n";
TC::runTest('File_Passwd');
TC::runTest('Common');
TC::runTest('Smb');
TC::runTest('Cvs');
TC::runTest('Unix');
TC::runTest('Authbasic');
TC::runTest('Authdigest');
TC::runTest('Custom');
?>
<?php
ini_set('display_errors',1);
error_reporting(E_ALL);
require(__DIR__ . '/../classes.php');
function microtime_float() {return microtime(true);}

$t1 = microtime_float();
echo "Start time: $t1 sec \r\n";
$str = '';
for($a=1;$a<=1000;$a++) {
  $private = new PrivateKey();
  $wallet = new Wallet($private);
  $key=$private->getPrivateKey();
  $private_key=AddressCodec::WIF($key,'80',true,false);
  $deWif=AddressCodec::DeWIF($private_key,true,false);
  $addr=$wallet->getAddress();
  //echo "$addr,$private_key<br>\r\n";
  $str.=$a.',"'.$addr.'","'.$private_key.'"'."\r\n";
}
$t2 = microtime_float();
$time = $t2 - $t1;
$fname_addres = 'address_'.time().'.csv';
echo "End time: $t2 sec \r\n";
echo "Elapsed time: $time sec \r\n";
file_put_contents($fname_addres,$str);
echo "Saved the file: $fname_addres \r\n";

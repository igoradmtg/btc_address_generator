<?php
ini_set('display_errors',1);
error_reporting(E_ALL);
require(__DIR__ . '/../classes.php');

$addr = '17sGrxMRs9Mm3nzk4jhMyiN3HJ4o8aenqk';
$getInfo = new GetInfo($addr);

$fname_save = 'addressbalance_'.$addr.'.txt';
$info = $getInfo->blockchain_info_addressbalance($addr);
if ($info === false) {echo "Error: {$getInfo->last_error} \r\n";}
else {
  //echo '<pre>';print_r($info);echo '</pre>';
  file_put_contents($fname_save,$info);
  echo "Saved the file: $fname_save \r\n";
}

$fname_save = 'rawaddr_'.$addr.'.txt';
$info = $getInfo->blockchain_info_rawaddr($addr);
if ($info==false) {echo "Error: {$getInfo->last_error} \r\n";}
else {
  //echo '<pre>';print_r($info);echo '</pre>';
  file_put_contents($fname_save,print_r($info,true));
  echo "Saved the file: $fname_save \r\n";
}

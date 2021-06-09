# btc_address_generator

A simple script for generating BTC addresses, for creating offline wallets

## Requirements 

The current implementation requires the php gmp extension.  Future version will automaticly detect and switch between GMP and BCMATH

## Usage

Download files. 

### BTC address generator:

```PHP
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
```

### BTC get info

```PHP
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
```

If you find this usefull, please send me some

Bitcoin:17sGrxMRs9Mm3nzk4jhMyiN3HJ4o8aenqk

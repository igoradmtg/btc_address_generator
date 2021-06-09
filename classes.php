<?php

/*
 * Crypto Currency Address Codec Library
 * For use with Bitcoin and Zetacoin compatable crypto currency using the secp256k1 ECC curve
*/


class AddressCodec{
    /***
     * returns the Uncompressed DER encoded public key.
     *
     * @return String Hex
     */
    public static function Hex(Array $point){
        $derPubKey = '04' . $point['x'] . $point['y'];
        return $derPubKey;
    }

    /***
     * returns the public key coordinates as an array.
     * Input can be compressed or uncompressed DER Encoded Pubkey
     *
     * @return array
     */
    public static function Point($derPubKey){
        if(substr($derPubKey, 0, 2) == '04' && strlen($derPubKey) == 130){
            //uncompressed der encoded public key
            $x = substr($derPubKey, 2, 64);
            $y = substr($derPubKey, 66, 64);
            return array('x' => $x, 'y' => $y);
        }
        // Oops This is actually a compressed DER Public Key, send it to the correct function
        elseif((substr($derPubKey, 0, 2) == '02' || substr($derPubKey, 0, 2) == '03') && strlen($derPubKey) == 66){
            return self::Decompress($derPubKey);
        }
        else
        {
            throw new \Exception('Invalid derPubKey format : ' . $compressedDerPubKey);
        }
    }
    
    
    /***
     * returns the public key coordinates as an array.
     * Input can be compressed or uncompressed DER Encoded Pubkey
     *
     * @param $derPubKey
     * @return array
     * @throws \Exception
     */
    public static function Decompress($compressedDerPubKey) {
        if((substr($compressedDerPubKey, 0, 2) == '02' || substr($compressedDerPubKey, 0, 2) == '03') && strlen($compressedDerPubKey) == 66){
            //compressed der encoded public key
            $x = substr($compressedDerPubKey, 2, 64);
            // secp256k1
            $secp256k1 = new SECp256k1();
            $a = $secp256k1->a;
            $b = $secp256k1->b;
            $p = $secp256k1->p;
            // This is where the magic happens
            $y = PointMathGMP::calculateYWithX($x, $a, $b, $p, substr($compressedDerPubKey, 0, 2));
            return array('x' => $x, 'y' => $y);
        }
        // OOps.. This is actually a non-compressed DER Public Key, send it to the correct function
        elseif(substr($compressedDerPubKey, 0, 2) == '04' && strlen($compressedDerPubKey) == 130){
            return self::Point($compressedDerPubKey);
        }
        else{
            throw new \Exception('Invalid compressedDerPubKey format : ' . $compressedDerPubKey);
        }
    }
    /***
     * returns the compressed DER encoded public key.
     *
     * @return String Hex
     */
    public static function Compress($pubKey){
        if(gmp_strval(gmp_mod(gmp_init($pubKey['y'], 16), gmp_init(2, 10))) == 0)
            $compressedDerPubKey      = '02' . $pubKey['x'];    //if $pubKey['y'] is even
        else
            $compressedDerPubKey      = '03' . $pubKey['x'];    //if $pubKey['y'] is odd

        return $compressedDerPubKey;
    }

    /***
     * returns the HASH160 version of the Publick Key 
     * .
     *
     * @param string $derPubKey
     * @throws \Exception
     * @return String Hash160
     */
    public static function Hash($derPubKey){
        $sha256            = hash('sha256', hex2bin($derPubKey));
        $ripem160         = hash('ripemd160', hex2bin($sha256));
        return $ripem160;
    }

    /***
     * returns the Bitcoin address version of the Publick Key 
     * .
     *
     * @param string $hex
     * @throws \Exception
     * @return String Base58
     */
    public static function Encode($hex, $prefix = "00") {
        // The magical prefix
        $hex_with_prefix    = $prefix . $hex;
        
        //checksum
        $sha256            = hash('sha256', hex2bin($hex_with_prefix));
        $checksum        = hash('sha256', hex2bin($sha256));

        // Encode
        $address        = $hex_with_prefix . substr($checksum, 0, 8);
        $address        = Base58::Encode($address);

        return $address;
    }

    public static function Decode($address) {
        $hex_with_prefix_and_check = Base58::Decode($address);
        $prefix = substr($hex_with_prefix_and_check, 0, 2);
        $checksum = substr($hex_with_prefix_and_check, -8);
        $hex = substr($hex_with_prefix_and_check, 2, -8);
        return $hex;
    }

    /***
     * returns the private key under the Wallet Import Format
     *
     * @return String Base58
     * @throws \Exception
     */
    public static function WIF($private_key, $prefix = '80', $compressed = true,$is_reverse=true){
        if ($compressed) {$private_key = $private_key . '01';}
    if ($is_reverse) return strrev(self::Encode($private_key, $prefix));
    else return strval(self::Encode($private_key, $prefix));
    }

    public static function DeWIF($wif, $compressed = true,$is_reverse=true){
    if ($is_reverse) $base58 = strrev($wif);
    else $base58=strval($wif);
        $hex = self::Decode($base58);
        if ($compressed) {$hex = substr($hex, 0, -2);}
        return $hex;
    }
}

/*
 * Crypto Currency Address Validation Library
 * For use with Bitcoin and Zetacoin compatable crypto currency using the secp256k1 ECC curve
*/


class AddressValidation {

    /***
     * Tests if the address is valid or not.
     *
     * @param String Base58 $address
     * @return bool
     */
    public static function validateAddress($address){
        $address    = hex2bin(Base58::Decode($address));
        if(strlen($address) != 25)
            return false;
        $checksum   = substr($address, 21, 4);
        $rawAddress = substr($address, 0, 21);
        $sha256        = hash('sha256', $rawAddress);
        $sha256        = hash('sha256', hex2bin($sha256));

        if(substr(hex2bin($sha256), 0, 4) == $checksum)
            return true;
        else
            return false;
    }

    /***
     * Tests if the Wif key (Wallet Import Format) is valid or not.
     *
     * @param String Base58 $wif
     * @return bool
     */
    public static function validateWifKey($wif){
        $key            = Base58::Decode($wif, false);
        $length         = strlen($key);
        $firstSha256    = hash('sha256', hex2bin(substr($key, 0, $length - 8)));
        $secondSha256   = hash('sha256', hex2bin($firstSha256));
        if(substr($secondSha256, 0, 8) == substr($key, $length - 8, 8))
            return true;
        else
            return false;
    }
}

/*
 * Object Oriented implimentation to Base58.
 * For use with Bitcoin and Zetacoin compatable crypto currency using the secp256k1 ECC curve
*/

class Base58 {

    /***
     * Permutation table used for Base58 encoding and decoding.
     *
     * @param $char
     * @param bool $reverse
     * @return null
     */
    private static function permutation_lookup($char, $reverse = false){
        $table = array('1','2','3','4','5','6','7','8','9','A','B','C','D',
                       'E','F','G','H','J','K','L','M','N','P','Q','R','S','T','U','V','W',
                       'X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','m','n','o',
                       'p','q','r','s','t','u','v','w','x','y','z'
                 );

        if($reverse)
        {
            $reversedTable = array();
            foreach($table as $key => $element)
            {
                $reversedTable[$element] = $key;
            }

            if(isset($reversedTable[$char]))
                return $reversedTable[$char];
            else
                return null;
        }

        if(isset($table[$char]))
            return $table[$char];
        else
            return null;
    }

    /***
     * encode a hexadecimal string in Base58.
     *
     * @param String Hex $data
     * @param bool $littleEndian
     * @return String Base58
     * @throws \Exception
     */
    public static function Encode($data, $littleEndian = true){
        $res = '';
        $dataIntVal = gmp_init($data, 16);
        while(gmp_cmp($dataIntVal, gmp_init(0, 10)) > 0)
        {
            $qr = gmp_div_qr($dataIntVal, gmp_init(58, 10));
            $dataIntVal = $qr[0];
            $reminder = gmp_strval($qr[1]);
            if(!self::permutation_lookup($reminder))
            {
                throw new \Exception('Something went wrong during base58 encoding');
            }
            $res .= self::permutation_lookup($reminder);
        }

        //get number of leading zeros
        $leading = '';
        $i=0;
        while(substr($data, $i, 1) == '0')
        {
            if($i!= 0 && $i%2)
            {
                $leading .= '1';
            }
            $i++;
        }

        if($littleEndian)
            return strrev($res . $leading);
        else
            return $res.$leading;
    }

    /***
     * Decode a Base58 encoded string and returns it's value as a hexadecimal string
     *
     * @param $encodedData
     * @param bool $littleEndian
     * @return String Hex
     */
    public static function Decode($encodedData, $littleEndian = true){
        $res = gmp_init(0, 10);
        $length = strlen($encodedData);
        if($littleEndian)
        {
            $encodedData = strrev($encodedData);
        }

        for($i = $length - 1; $i >= 0; $i--)
        {
            $res = gmp_add(
                           gmp_mul(
                                   $res,
                                   gmp_init(58, 10)
                           ),
                           self::permutation_lookup(substr($encodedData, $i, 1), true)
                   );
        }

        $res = gmp_strval($res, 16);
        $i = $length - 1;
        while(substr($encodedData, $i, 1) == '1')
        {
            $res = '00' . $res;
            $i--;
        }

        if(strlen($res)%2 != 0)
        {
            $res = '0' . $res;
        }

        return $res;
    }
}

/*
 * Object orieted interface to Helpful Point Math Operations
 * Using the BCMATH library
*/

class PointMathBCMATH {

    /***
     * Computes the result of a point addition and returns the resulting point as an Array.
     *
     * @param Array $pt
     * @param $a
     * @param $p
     * @return Array Point
     * @throws \Exception
     */
    public static function doublePoint(Array $pt, $a, $p) {
        $nPt = array();

        // 2*ptY
        $pty2 = bcmul(2, $pt['y']);

        // ( 2*ptY )^-1
        $n_pty2 = self::inverse_mod($pty2, $p);

        // 3 * ptX^2
        $three_x2 = bcmul(3, bcpow($pt['x'], 2));

        // (3 * ptX^2 + a ) * ( 2*ptY )^-1
        $slope = bcmod(bcmul(bcadd($three_x2, $a), $n_pty2), $p);

        // slope^2 - 2 * ptX
        $nPt['x'] = bcmod(bcsub(bcpow($slope, 2), bcmul(2, $pt['x'])), $p);

        // slope * (ptX - nPtx) - ptY
        $nPt['y'] = bcmod(bcsub(bcmul($slope, bcsub($pt['x'], $nPt['x'])), $pt['y']), $p);

        if (bccomp(0, $nPt['y']) == 1) {
            $nPt['y'] = bcadd($p, $nPt['y']);
        }

        return $nPt;
    }

    /***
     * Computes the result of a point addition and returns the resulting point as an Array.
     *
     * @param Array $pt1
     * @param Array $pt2
     * @param $a
     * @param $p
     * @return Array Point
     * @throws \Exception
     */
    public static function addPoints(Array $pt1, Array $pt2, $a, $p) {

        $nPt = array();

        $gcd = self::bcgcd(bcsub($pt1['x'], $pt2['x']), $p);
        if($gcd != '1'){
            throw new \Exception('This library doesn\'t yet supports point at infinity.');
        }

        if (bcmod(bccomp($pt1['x'], $pt2['x']), $p) == 0) {
            if (bcmod(bcadd($pt1['y'], $pt2['y']), $p) == 0) {
                throw new \Exception('This library doesn\'t yet supports point at infinity.');
            } else {
                return self::doublePoint($pt1, $a, $p);
            }
        }

        // (pt1Y - pt2Y) * ( pt1X - pt2X )^-1
        $slope = bcmod(bcmul(bcsub($pt2['y'], $pt1['y']), self::inverse_mod(bcsub($pt2['x'], $pt1['x']), $p)), $p);

        // slope^2 - ptX1 - ptX2
        $nPt['x'] = bcmod(bcsub(bcsub(bcpow($slope, 2), $pt1['x']), $pt2['x']), $p);

        // slope * (ptX1 - nPtX) - ptY1
        $nPt['y'] = bcmod(bcsub(bcmul($slope, bcsub($pt1['x'], $nPt['x'])), $pt1['y']), $p);

        if (bccomp(0, $nPt['y']) == 1) {
            $nPt['y'] = bcadd($p, $nPt['y']);
        }

        return $nPt;
    }

    /***
     * Returns inverse mod.
     *
     * @param $a
     * @param $m
     * @return bbc math number
     */
    private static function inverse_mod($a, $m) {
        while (bccomp($a, 0) == -1) {
            $a = bcadd($m, $a);
        }
        while (bccomp($m, $a) == -1) {
            $a = bcmod($a, $m);
        }
        $c = $a;
        $d = $m;
        $uc = 1;
        $vc = 0;
        $ud = 0;
        $vd = 1;
        while (bccomp($c, 0) != 0) {
            $temp1 = $c;
            $q = bcdiv($d, $c, 0);
            $c = bcmod($d, $c);
            $d = $temp1;
            $temp2 = $uc;
            $temp3 = $vc;
            $uc = bcsub($ud, bcmul($q, $uc));
            $vc = bcsub($vd, bcmul($q, $vc));
            $ud = $temp2;
            $vd = $temp3;
        }
        $result = '';
        if (bccomp($d, 1) == 0) {
            if (bccomp($ud, 0) == 1)
                $result = $ud;
            else
                $result = bcadd($ud, $m);
        }else {
            throw new ErrorException("ERROR: $a and $m are NOT relatively prime.");
        }
        return $result;
    }

    /***
     * Compares Points if Identical.
     *
     * @param $pt1 Array(BC, BC)
     * @param $pt2 Array(BC, BC)
     * @return Array(BC, BC)
     */

    private static function comparePoint($pt1, $pt2){
        if (bccomp($pt1['x'], $pt2['x']) == 0 && bccomp($pt1['y'], $pt2['y']) == 0) {
            return 0;
        } else {
            return 1;
        }
    }

    // The Greatest Common Denominator of two large numbers, using BCMath functions.
    private static function bcgcd($value1, $value2) {
        
        if ($value1 < $value2)
        // Swap $value1 and $value2
        {
            $temp = $value1;
            $value1 = $value2;
            $value2 = $temp;
        }

        // We use the Euclid's algorithm
        // for finding the Greatest Common Denominator (GCD)
        $mod = 1;
        while ($mod != 0)
        {
            $mod = bcmod ($value1, $value2);
            $value1 = $value2;
            $value2 = $mod;
        }
        return $value1;

    } 

    /***
     * Returns Negated Point (Y).
     *
     * @param $point Array(BC, BC)
     * @return Array(BC, BC)
     */
    public static function negatePoint($point) { 
        return array('x' => $point['x'], 'y' => bcsub(0, $point['y'])); 
    }

    // These 2 function don't really belong here.

    // Checks is the given number (DEC String) is even
    public static function isEvenNumber($number) {
        return (((int)$number[strlen($number)-1]) & 1) == 0;
    }

}

/*
 * Object orieted interface to Helpful Point Math Operations
 * Using the GMP library
*/

class PointMathGMP {

    /***
     * Computes the result of a point addition and returns the resulting point as an Array.
     *
     * @param Array $pt
     * @return Array Point
     * @throws \Exception
     */
    public static function doublePoint(Array $pt, $a, $p){
        $gcd = gmp_strval(gmp_gcd(gmp_mod(gmp_mul(gmp_init(2, 10), $pt['y']), $p),$p));
        if($gcd != '1')
        {
            throw new \Exception('This library doesn\'t yet supports point at infinity. See https://github.com/BitcoinPHP/BitcoinECDSA.php/issues/9');
        }

        // SLOPE = (3 * ptX^2 + a )/( 2*ptY )
        // Equals (3 * ptX^2 + a ) * ( 2*ptY )^-1
        $slope = gmp_mod(
                         gmp_mul(
                                 gmp_invert(
                                            gmp_mod(
                                                    gmp_mul(
                                                            gmp_init(2, 10),
                                                            $pt['y']
                                                    ),
                                                    $p
                                            ),
                                            $p
                                 ),
                                 gmp_add(
                                         gmp_mul(
                                                 gmp_init(3, 10),
                                                 gmp_pow($pt['x'], 2)
                                         ),
                                         $a
                                 )
                         ),
                         $p
                );

        // nPtX = slope^2 - 2 * ptX
        // Equals slope^2 - ptX - ptX
        $nPt = array();
        $nPt['x'] = gmp_mod(
                            gmp_sub(
                                    gmp_sub(
                                            gmp_pow($slope, 2),
                                            $pt['x']
                                    ),
                                    $pt['x']
                            ),
                            $p
                    );

        // nPtY = slope * (ptX - nPtx) - ptY
        $nPt['y'] = gmp_mod(
                            gmp_sub(
                                    gmp_mul(
                                            $slope,
                                            gmp_sub(
                                                    $pt['x'],
                                                    $nPt['x']
                                            )
                                    ),
                                    $pt['y']
                            ),
                            $p
                    );

        return $nPt;
    }

    /***
     * Computes the result of a point addition and returns the resulting point as an Array.
     *
     * @param Array $pt1
     * @param Array $pt2
     * @return Array Point
     * @throws \Exception
     */
    public static function addPoints(Array $pt1, Array $pt2, $a, $p){
        if(gmp_cmp($pt1['x'], $pt2['x']) == 0  && gmp_cmp($pt1['y'], $pt2['y']) == 0) //if identical
        {
            return self::doublePoint($pt1, $a, $p);
        }

        $gcd = gmp_strval(gmp_gcd(gmp_sub($pt1['x'], $pt2['x']), $p));
        if($gcd != '1')
        {
            throw new \Exception('This library doesn\'t yet supports point at infinity. See https://github.com/BitcoinPHP/BitcoinECDSA.php/issues/9');
        }

        // SLOPE = (pt1Y - pt2Y)/( pt1X - pt2X )
        // Equals (pt1Y - pt2Y) * ( pt1X - pt2X )^-1
        $slope      = gmp_mod(
                              gmp_mul(
                                      gmp_sub(
                                              $pt1['y'],
                                              $pt2['y']
                                      ),
                                      gmp_invert(
                                                 gmp_sub(
                                                         $pt1['x'],
                                                         $pt2['x']
                                                 ),
                                                 $p
                                      )
                              ),
                              $p
                      );

        // nPtX = slope^2 - ptX1 - ptX2
        $nPt = array();
        $nPt['x']   = gmp_mod(
                              gmp_sub(
                                      gmp_sub(
                                              gmp_pow($slope, 2),
                                              $pt1['x']
                                      ),
                                      $pt2['x']
                              ),
                              $p
                      );

        // nPtX = slope * (ptX1 - nPtX) - ptY1
        $nPt['y']   = gmp_mod(
                              gmp_sub(
                                      gmp_mul(
                                              $slope,
                                              gmp_sub(
                                                      $pt1['x'],
                                                      $nPt['x']
                                              )
                                      ),
                                      $pt1['y']
                              ),
                              $p
                      );

        return $nPt;
    }

    /***
     * Computes the result of a point multiplication and returns the resulting point as an Array.
     *
     * @param String Hex $k
     * @param Array $pG (GMP, GMP)
     * @param $base (INT)
     * @throws \Exception
     * @return Array Point (GMP, GMP)
     */
    public static function mulPoint($k, Array $pG, $a, $b, $p, $base = null){
        //in order to calculate k*G
        if($base == 16 || $base == null || is_resource($base))
            $k = gmp_init($k, 16);
        if($base == 10)
            $k = gmp_init($k, 10);
        $kBin = gmp_strval($k, 2);

        $lastPoint = $pG;
        for($i = 1; $i < strlen($kBin); $i++)
        {
            if(substr($kBin, $i, 1) == 1 )
            {
                $dPt = self::doublePoint($lastPoint, $a, $p);
                $lastPoint = self::addPoints($dPt, $pG, $a, $p);
            }
            else
            {
                $lastPoint = self::doublePoint($lastPoint, $a, $p);
            }
        }
        if(!self::validatePoint(gmp_strval($lastPoint['x'], 16), gmp_strval($lastPoint['y'], 16), $a, $b, $p)){
            throw new \Exception('The resulting point is not on the curve.');
        }
        return $lastPoint;
    }

    /***
     * Calculates the square root of $a mod p and returns the 2 solutions as an array.
     *
     * @param $a
     * @return array|null
     * @throws \Exception
     */
    public static function sqrt($a, $p){
        if(gmp_legendre($a, $p) != 1)
        {
            //no result
            return null;
        }

        if(gmp_strval(gmp_mod($p, gmp_init(4, 10)), 10) == 3)
        {
            $sqrt1 = gmp_powm(
                            $a,
                            gmp_div_q(
                                gmp_add($p, gmp_init(1, 10)),
                                gmp_init(4, 10)
                            ),
                            $p
                    );
            // there are always 2 results for a square root
            // In an infinite number field you have -2^2 = 2^2 = 4
            // In a finite number field you have a^2 = (p-a)^2
            $sqrt2 = gmp_mod(gmp_sub($p, $sqrt1), $p);
            return array($sqrt1, $sqrt2);
        }
        else
        {
            throw new \Exception('P % 4 != 3 , this isn\'t supported yet.');
        }
    }

    /***
     * Calculate the Y coordinates for a given X coordinate.
     *
     * @param $x
     * @param null $derEvenOrOddCode
     * @return array|null|String
     */
    public static function calculateYWithX($x, $a, $b, $p, $derEvenOrOddCode = null){
        $x  = gmp_init($x, 16);
        $y2 = gmp_mod(
                      gmp_add(
                              gmp_add(
                                      gmp_powm($x, gmp_init(3, 10), $p),
                                      gmp_mul($a, $x)
                              ),
                              $b
                      ),
                      $p
              );

        $y = self::sqrt($y2, $p);

        if(!$y) //if there is no result
        {
            return null;
        }

        if(!$derEvenOrOddCode)
        {
            return $y;
        }

        else if($derEvenOrOddCode == '02') // even
        {
            $resY = null;
            if(false == gmp_strval(gmp_mod($y[0], gmp_init(2, 10)), 10))
                $resY = gmp_strval($y[0], 16);
            if(false == gmp_strval(gmp_mod($y[1], gmp_init(2, 10)), 10))
                $resY = gmp_strval($y[1], 16);
            if($resY)
            {
                while(strlen($resY) < 64)
                {
                    $resY = '0' . $resY;
                }
            }
            return $resY;
        }
        else if($derEvenOrOddCode == '03') // odd
        {
            $resY = null;
            if(true == gmp_strval(gmp_mod($y[0], gmp_init(2, 10)), 10))
                $resY = gmp_strval($y[0], 16);
            if(true == gmp_strval(gmp_mod($y[1], gmp_init(2, 10)), 10))
                $resY = gmp_strval($y[1], 16);
            if($resY)
            {
                while(strlen($resY) < 64)
                {
                    $resY = '0' . $resY;
                }
            }
            return $resY;
        }

        return null;
    }

    /***
     * Returns true if the point is on the curve and false if it isn't.
     *
     * @param $x
     * @param $y
     * @return bool
     */
    public static function validatePoint($x, $y, $a, $b, $p){
        $x  = gmp_init($x, 16);
        $y2 = gmp_mod(
                        gmp_add(
                            gmp_add(
                                gmp_powm($x, gmp_init(3, 10), $p),
                                gmp_mul($a, $x)
                            ),
                            $b
                        ),
                        $p
                    );
        $y = gmp_mod(gmp_pow(gmp_init($y, 16), 2), $p);

        if(gmp_cmp($y2, $y) == 0)
            return true;
        else
            return false;
    }

    /***
     * Returns Negated Point (Y).
     *
     * @param $point Array(GMP, GMP)
     * @return Array(GMP, GMP)
     */
    public static function negatePoint($point) { 
        return array('x' => $point['x'], 'y' => gmp_neg($point['y'])); 
    }

    // These 2 function don't really belong here.

    // Checks is the given number (DEC String) is even
    public static function isEvenNumber($number) {
        return (((int)$number[strlen($number)-1]) & 1) == 0;
    }
    // Converts BIN to GMP
    public static function bin2gmp($binStr) {
        $v = gmp_init('0');

        for ($i = 0; $i < strlen($binStr); $i++) {
            $v = gmp_add(gmp_mul($v, 256), ord($binStr[$i]));
        }

        return $v;
    }

}


/* 
 * Private Key
 * For Bitcoin/Zetacoin compatable Crypto Currency utilizing the secp256k1 curve
*/

 class PrivateKey{
 
    public $k;

    public function __construct($private_key = null){
        if (empty($private_key)){
            $this->generateRandomPrivateKey();
        }
        else{
            $this->setPrivateKey($private_key);
        }
    }

    /***
     * Generate a new random private key.
     * The extra parameter can be some random data typed down by the user or mouse movements to add randomness.
     *
     * @param string $extra
     * @throws \Exception
     */
    public function generateRandomPrivateKey($extra = 'FSQF5356dsdsqdfEFEQ3fq4q6dq4s5d'){
        $secp256k1 = new SECp256k1();
        $n = $secp256k1->n;

        //private key has to be passed as an hexadecimal number
        do { //generate a new random private key until to find one that is valid
            $bytes      = openssl_random_pseudo_bytes(256, $cStrong);
            $hex        = bin2hex($bytes);
            $random     = $hex . microtime(true).rand(100000000000, 1000000000000) . $extra;
            $this->k    = hash('sha256', $random);

            if(!$cStrong)
            {
                throw new \Exception('Your system is not able to generate strong enough random numbers');
            }

        } while(gmp_cmp(gmp_init($this->k, 16), gmp_sub($n, gmp_init(1, 10))) == 1);
    }

    /***
     * return the private key.
     *
     * @return String Hex
     */
    public function getPrivateKey(){
        return $this->k;
    }
    
    /***
     * set a private key.
     *
     * @param String Hex $k
     * @throws \Exception
     */
    public function setPrivateKey($k){
        $secp256k1 = new SECp256k1();
        $n = $secp256k1->n;
        
        //private key has to be passed as an hexadecimal number
        if(gmp_cmp(gmp_init($k, 16), gmp_sub($n, gmp_init(1, 10))) == 1)
        {
            throw new \Exception('Private Key is not in the 1,n-1 range');
        }
        $this->k = $k;
    }

    /***
     * returns the X and Y point coordinates of the public key.
     *
     * @return Array Point
     * @throws \Exception
     */
    public function getPubKeyPoints(){
        $secp256k1 = new SECp256k1();
        $G = $secp256k1->G;
        $a = $secp256k1->a;
        $b = $secp256k1->b;
        $p = $secp256k1->p;
        $k = $this->k;

        if(!isset($this->k))
        {
            throw new \Exception('No Private Key was defined');
        }

        $pubKey         = PointMathGMP::mulPoint($k,
                                          array('x' => $G['x'], 'y' => $G['y']),
                                          $a,
                                          $b,
                                          $p
                                 );

        $pubKey['x']    = gmp_strval($pubKey['x'], 16);
        $pubKey['y']    = gmp_strval($pubKey['y'], 16);

        while(strlen($pubKey['x']) < 64)
        {
            $pubKey['x'] = '0' . $pubKey['x'];
        }

        while(strlen($pubKey['y']) < 64)
        {
            $pubKey['y'] = '0' . $pubKey['y'];
        }

        return $pubKey;
    }

 }

/* 
 * The SECp256k1 curve
 * Fundamental ECC Function for Bitcoin/Zetacoin compatable Crypto Currency
*/

class SECp256k1 {
    public $a;
    public $b;
    public $p;
    public $n;
    public $G;

    public function __construct(){
        $this->a = gmp_init('0', 10);
        $this->b = gmp_init('7', 10);
        $this->p = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 16);
        $this->n = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);

        $this->G = array('x' => gmp_init('55066263022277343669578718895168534326250603453777594175500187360389116729240'),
                         'y' => gmp_init('32670510020758816978083085130507043184471273380659243275938904335757337482424'));
    }
}


/* 
 * Crypto Currency Message Signing and Verification
 * For Bitcoin/Zetacoin compatable Crypto Currency utilizing the secp256k1 curve
*/

class Signature {

    /***
     * Sign a hash with the private key that was set and returns signatures as an array (R,S)
     *
     * @param $hash
     * @param $k
     * @param null $nonce
     * @throws \Exception
     * @return Array
     */
    public static function getSignatureHashPoints($hash, $k, $nonce = null){
        $secp256k1 = new SECp256k1();
        $a = $secp256k1->a;
        $b = $secp256k1->b;
        $G = $secp256k1->G;
        $n = $secp256k1->n;
        $p = $secp256k1->p;

        if(empty($k))
        {
            throw new \Exception('No Private Key was defined');
        }

        if(null == $nonce)
        {
            $random     = openssl_random_pseudo_bytes(256, $cStrong);
            $random     = $random . microtime(true).rand(100000000000, 1000000000000);
            $nonce      = gmp_strval(gmp_mod(gmp_init(hash('sha256',$random), 16), $n), 16);
        }

        //first part of the signature (R).

        $rPt = PointMathGMP::mulPoint($nonce, $G, $a, $b, $p);
        $R    = gmp_strval($rPt ['x'], 16);

        while(strlen($R) < 64)
        {
            $R = '0' . $R;
        }

        //second part of the signature (S).
        //S = nonce^-1 (hash + privKey * R) mod p

        $S = gmp_strval(
                        gmp_mod(
                                gmp_mul(
                                        gmp_invert(
                                                   gmp_init($nonce, 16),
                                                   $n
                                        ),
                                        gmp_add(
                                                gmp_init($hash, 16),
                                                gmp_mul(
                                                        gmp_init($k, 16),
                                                        gmp_init($R, 16)
                                                )
                                        )
                                ),
                                $n
                        ),
                        16
             );

        if(strlen($S)%2)
        {
            $S = '0' . $S;
        }

        if(strlen($R)%2)
        {
            $R = '0' . $R;
        }

        return array('R' => $R, 'S' => $S);
    }

    /***
     * Sign a hash with the private key that was set and returns a DER encoded signature
     *
     * @param $hash
     * @param null $nonce
     * @return string
     */
    public static function signHash($hash, $k, $nonce = null){
        $points = self::getSignatureHashPoints($hash, $k, $nonce);

        $signature = '02' . dechex(strlen(hex2bin($points['R']))) . $points['R'] . '02' . dechex(strlen(hex2bin($points['S']))) . $points['S'];
        $signature = '30' . dechex(strlen(hex2bin($signature))) . $signature;

        return $signature;
    }



    /***
     * extract the public key from the signature and using the recovery flag.
     * see http://crypto.stackexchange.com/a/18106/10927
     * based on https://github.com/brainwallet/brainwallet.github.io/blob/master/js/bitcoinsig.js
     * possible public keys are r−1(sR−zG) and r−1(sR′−zG)
     * Recovery flag rules are :
     * binary number between 28 and 35 inclusive
     * if the flag is > 30 then the address is compressed.
     *
     * @param $flag (INT)
     * @param $R (HEX String)
     * @param $S (HEX String)
     * @param $hash (HEX String)
     * @return array
     */
    public static function getPubKeyWithRS($flag, $R, $S, $hash){
        $secp256k1 = new SECp256k1();
        $a = $secp256k1->a;
        $b = $secp256k1->b;
        $G = $secp256k1->G;
        $n = $secp256k1->n;
        $p = $secp256k1->p;

        $isCompressed = false;

        if ($flag < 27 || $flag >= 35) {
            return false;
        }

        if($flag >= 31) //if address is compressed
        {
            $isCompressed = true;
            $flag -= 4;
        }

        $recid = $flag - 27;

        //step 1.1
        $x = null;
        $x = gmp_add(
                     gmp_init($R, 16),
                     gmp_mul(
                             $n,
                             gmp_div_q( //check if j is equal to 0 or to 1.
                                        gmp_init($recid, 10),
                                        gmp_init(2, 10)
                             )
                     )
             );

        //step 1.3
        $y = null;
        if(1 == $flag % 2) //check if y is even.
        {

            $gmpY = PointMathGMP::calculateYWithX(gmp_strval($x, 16), $a, $b, $p, '02');

            if(null != $gmpY)

                $y = gmp_init($gmpY, 16);

        }
        else
        {

            $gmpY = PointMathGMP::calculateYWithX(gmp_strval($x, 16), $a, $b, $p, '03');
            if(null != $gmpY)
                $y = gmp_init($gmpY, 16);
        }


        if(null == $y)
            return null;

        $Rpt = array('x' => $x, 'y' => $y);

        //step 1.6.1
        //calculate r^-1 (S*Rpt - eG)

        $eG = PointMathGMP::mulPoint($hash, $G, $a, $b, $p);

        $Rinv = gmp_strval(gmp_invert(gmp_init($R, 16), $n), 16);

        // Possible issue
        $eG['y'] = gmp_mod(gmp_neg($eG['y']), $p);
        // Possible Fix
        //$eG['y'] = gmp_neg($eG['y']);

        $SR = PointMathGMP::mulPoint($S, $Rpt, $a, $b, $p);

        $sR_plus_eGNeg = PointMathGMP::addPoints($SR, $eG, $a, $p);

        $pubKey = PointMathGMP::mulPoint(
                            $Rinv,
                            $sR_plus_eGNeg,
                            $a, 
                            $b, 
                            $p
                  );

        $pubKey['x'] = gmp_strval($pubKey['x'], 16);
        $pubKey['y'] = gmp_strval($pubKey['y'], 16);

        while(strlen($pubKey['x']) < 64)
            $pubKey['x'] = '0' . $pubKey['x'];

        while(strlen($pubKey['y']) < 64)
            $pubKey['y'] = '0' . $pubKey['y'];

        if($isCompressed){
            $derPubKey = AddressCodec::Compress($pubKey);
        }
        else{
            $derPubKey = AddressCodec::Hex($pubKey);
        }

        if(self::checkSignaturePoints($derPubKey, $R, $S, $hash)){
            return $derPubKey;
        }
        else{
            return false;
        }

    }

    // Same as Below but accepts HEX strings
    public static function recoverPublicKey_HEX($flag, $R, $S, $hash){
        return self::recoverPublicKey(gmp_init($R,16), gmp_init($S,16), gmp_init($hash,16), $flag);
    }

    // $R, $S, and $hash are GMP
    // $recoveryFlags is INT
    public static function recoverPublicKey($R, $S, $hash, $recoveryFlags){
        $secp256k1 = new SECp256k1();
        $a = $secp256k1->a;
        $b = $secp256k1->b;
        $G = $secp256k1->G;
        $n = $secp256k1->n;
        $p = $secp256k1->p;

        $isYEven = ($recoveryFlags & 1) != 0;
        $isSecondKey = ($recoveryFlags & 2) != 0;

        // PointMathGMP::mulPoint wants HEX String
        $e = gmp_strval($hash, 16);
        $s = gmp_strval($S, 16);

        // Precalculate (p + 1) / 4 where p is the field order
        // $p_over_four is GMP
        static $p_over_four; // XXX just assuming only one curve/prime will be used
        if (!$p_over_four) {
            $p_over_four = gmp_div(gmp_add($p, 1), 4);
        }

        // 1.1 Compute x
        // $x is GMP
        if (!$isSecondKey) {
            $x = $R;
        } else {
            $x = gmp_add($R, $n);
        }

        // 1.3 Convert x to point
        // $alpha is GMP
        $alpha = gmp_mod(gmp_add(gmp_add(gmp_pow($x, 3), gmp_mul($a, $x)), $b), $p);
        // $beta is DEC String (INT)
        $beta = gmp_strval(gmp_powm($alpha, $p_over_four, $p));

        // If beta is even, but y isn't or vice versa, then convert it,
        // otherwise we're done and y == beta.
        if (PointMathGMP::isEvenNumber($beta) == $isYEven) {
            // gmp_sub function will convert the DEC String "$beta" into a GMP
            // $y is a GMP 
            $y = gmp_sub($p, $beta);
        } else {
            // $y is a GMP
            $y = gmp_init($beta);
        }

        // 1.4 Check that nR is at infinity (implicitly done in construtor) -- Not reallly
        // $Rpt is Array(GMP, GMP)
        $Rpt = array('x' => $x, 'y' => $y);

        // 1.6.1 Compute a candidate public key Q = r^-1 (sR - eG)
        // $rInv is a HEX String
        $rInv = gmp_strval(gmp_invert($R, $n), 16);

        // $eGNeg is Array (GMP, GMP)
        $eGNeg = PointMathGMP::negatePoint(PointMathGMP::mulPoint($e, $G, $a, $b, $p));

        $sR = PointMathGMP::mulPoint($s, $Rpt, $a, $b, $p);

        $sR_plus_eGNeg = PointMathGMP::addPoints($sR, $eGNeg, $a, $p);

        // $Q is Array (GMP, GMP)
        $Q = PointMathGMP::mulPoint($rInv, $sR_plus_eGNeg, $a, $b, $p);

        // Q is the derrived public key
        // $pubkey is Array (HEX String, HEX String)
        // Ensure it's always 64 HEX Charaters
        $pubKey['x'] = str_pad(gmp_strval($Q['x'], 16), 64, 0, STR_PAD_LEFT);
        $pubKey['y'] = str_pad(gmp_strval($Q['y'], 16), 64, 0, STR_PAD_LEFT);

        return $pubKey;
    }

    /***
     * Check signature with public key R & S values of the signature and the message hash.
     *
     * @param $pubKey
     * @param $R
     * @param $S
     * @param $hash
     * @return bool
     */
    public static function checkSignaturePoints($pubKey, $R, $S, $hash){
        $secp256k1 = new SECp256k1();
        $a = $secp256k1->a;
        $b = $secp256k1->b;
        $G = $secp256k1->G;
        $n = $secp256k1->n;
        $p = $secp256k1->p;

        $pubKeyPts = AddressCodec::Decompress($pubKey);

        // S^-1* hash * G + S^-1 * R * Qa

        // S^-1* hash
        $exp1 =  gmp_strval(
                            gmp_mul(
                                    gmp_invert(
                                               gmp_init($S, 16),
                                               $n
                                    ),
                                    gmp_init($hash, 16)
                            ),
                            16
                 );

        // S^-1* hash * G
        $exp1Pt = PointMathGMP::mulPoint($exp1, $G, $a, $b, $p);


        // S^-1 * R
        $exp2 =  gmp_strval(
                            gmp_mul(
                                    gmp_invert(
                                               gmp_init($S, 16),
                                                $n
                                    ),
                                    gmp_init($R, 16)
                            ),
                            16
                 );
        // S^-1 * R * Qa

        $pubKeyPts['x'] = gmp_init($pubKeyPts['x'], 16);
        $pubKeyPts['y'] = gmp_init($pubKeyPts['y'], 16);

        $exp2Pt = PointMathGMP::mulPoint($exp2, $pubKeyPts, $a, $b, $p);
        $resultingPt = PointMathGMP::addPoints($exp1Pt, $exp2Pt, $a, $p);

        $xRes = gmp_strval($resultingPt['x'], 16);

        while(strlen($xRes) < 64)
            $xRes = '0' . $xRes;

        if($xRes == $R)
            return true;
        else
            return false;
    }

    /***
     * checkSignaturePoints wrapper for DER signatures
     *
     * @param $pubKey
     * @param $signature
     * @param $hash
     * @return bool
     */
    public static function checkDerSignature($pubKey, $signature, $hash){
        $signature = hex2bin($signature);
        if('30' != bin2hex(substr($signature, 0, 1)))
            return false;

        $RLength = hexdec(bin2hex(substr($signature, 3, 1)));
        $R = bin2hex(substr($signature, 4, $RLength));

        $SLength = hexdec(bin2hex(substr($signature, $RLength + 5, 1)));
        $S = bin2hex(substr($signature, $RLength + 6, $SLength));

        //echo "\n\nsignature:\n";
        //print_r(bin2hex($signature));

        //echo "\n\nR:\n";
        //print_r($R);
        //echo "\n\nS:\n";
        //print_r($S);

        return self::checkSignaturePoints($pubKey, $R, $S, $hash);
    }

}

/* 
 * Crypto Currency Wallet
 * For Bitcoin/Zetacoin compatable Crypto Currency utilizing the secp256k1 curve
*/

class Wallet{

    private $PRIVATE_KEY;
    private $MESSAGE_MAGIC;
    private $NETWORK_PREFIX;
    private $NETWORK_NAME;

    public function __construct(PrivateKey $private_key = null, $networkPrefix = '00', $networkName = 'Bitcoin', $messageMagic = null){
        // Private key
        if(!empty($private_key)){
            $this->PRIVATE_KEY = $private_key;
        }

        // The prefix, network name, and message magic
        $this->setNetworkPrefix($networkPrefix);
        $this->setNetworkName($networkName);
        $this->setMessageMagic($messageMagic);
    }

    /***
     * Set the network prefix, '00' = main network, '6f' = test network.
     *
     * @param String Hex $prefix
     */
    public function setNetworkPrefix($prefix){
        // The prefix
        if(!empty($prefix)){
            $this->NETWORK_PREFIX = $prefix;
        }
    }

    /**
     * Returns the current network prefix, '00' = main network, '6f' = test network.
     *
     * @return String Hex
     */
    public function getNetworkPrefix(){
        return $this->NETWORK_PREFIX;
    }

    /***
     * Set the network name
     *
     * @param String $name
     */
    public function setNetworkName($name){
        // The network name
        if(!empty($name)){
            $this->NETWORK_NAME = $name;
        }
    }

    /**
     * Returns the current network name
     *
     * @return String
     */
    public function getNetworkName(){
        return $this->NETWORK_NAME;
    }

    /***
     * Set the magic message prefix
     *
     * @param String $magic
     */
    public function setMessageMagic($magic){
        // The signed message "magic" prefix.
            $this->MESSAGE_MAGIC = $magic;
    }

    /**
     * Returns the current magic message prefix
     *
     * @return String
     */
    public function getMessageMagic(){
        // Check if a custom messageMagic is being used
        if(!empty($this->MESSAGE_MAGIC)){
            // Use the custom one.
            $magic = $this->MESSAGE_MAGIC;
        }
        else{
            // Use the default which is: "[LINE_LEN] [NETWORK_NAME] Signed Message:\n"
            $default = $this->getNetworkName() . " Signed Message:\n";
            $magic = $this->numToVarIntString(strlen($default)) . $default;
        }
        return $magic;
    }

    /***
     * returns the compressed Bitcoin address generated from the private key.
     *
     * @param string $derPubKey
     * @return String Base58
     */
    public function getAddress(){
        $PubKeyPoints = $this->getPrivateKey()->getPubKeyPoints();
        $DERPubkey = AddressCodec::Compress($PubKeyPoints);
        return AddressCodec::Encode(AddressCodec::Hash($DERPubkey), $this->getNetworkPrefix());
    }
    
    public function getUncompressedAddress(){
        $PubKeyPoints = $this->getPrivateKey()->getPubKeyPoints();
        return AddressCodec::Hex(AddressCodec::Hash($PubKeyPoints));
    }

    private function getPrivateKey(){
        if(empty($this->PRIVATE_KEY)){
            throw new \Exception('Wallet does not have a private key');
        }
        else{
            return $this->PRIVATE_KEY;
        }
    }

    /***
     * Satoshi client's standard message signature implementation.
     *
     * @param $message
     * @param bool $compressed
     * @param null $nonce
     * @return string
     * @throws \Exception
     */
    public function signMessage($message, $compressed = true, $nonce = null){

        $hash = $this->hash256($this->getMessageMagic() . $this->numToVarIntString(strlen($message)). $message);
        $points = Signature::getSignatureHashPoints(
                                                $hash,
                                                $this->getPrivateKey()->getPrivateKey(),
                                                $nonce
                   );

        $R = $points['R'];
        $S = $points['S'];

        while(strlen($R) < 64)
            $R = '0' . $R;

        while(strlen($S) < 64)
            $S = '0' . $S;

        $res = "\n-----BEGIN " . strtoupper($this->getNetworkName()) . " SIGNED MESSAGE-----\n";
        $res .= $message;
        $res .= "\n-----BEGIN SIGNATURE-----\n";
        if(true == $compressed)
            $res .= $this->getAddress() . "\n";
        else
            $res .= $this->getUncompressedAddress() . "\n";

        $finalFlag = 0;
        for($i = 0; $i < 4; $i++)
        {
            $flag = 27;
            if(true == $compressed)
                $flag += 4;
            $flag += $i;

            $pubKeyPts =$this->getPrivateKey()->getPubKeyPoints();
            //echo "\nReal pubKey : \n";
            //print_r($pubKeyPts);

            $recoveredPubKey = Signature::getPubKeyWithRS($flag, $R, $S, $hash);
            //echo "\nRecovered PubKey : \n";
            //print_r($recoveredPubKey);

            if(AddressCodec::Compress($pubKeyPts) == $recoveredPubKey)
            {
                $finalFlag = $flag;
            }
        }

        //echo "Final flag : " . dechex($finalFlag) . "\n";
        if(0 == $finalFlag)
        {
            throw new \Exception('Unable to get a valid signature flag.');
        }


        $res .= base64_encode(hex2bin(dechex($finalFlag) . $R . $S));
        $res .= "\n-----END " . strtoupper($this->getNetworkName()) . " SIGNED MESSAGE-----";

        return $res;
    }

    /***
     * checks the signature of a bitcoin signed message.
     *
     * @param $rawMessage
     * @return bool
     */
    public function checkSignatureForRawMessage($rawMessage){
        //recover message.
        preg_match_all("#-----BEGIN " . strtoupper($this->getNetworkName()) . " SIGNED MESSAGE-----\n(.{0,})\n-----BEGIN SIGNATURE-----\n#USi", $rawMessage, $out);
        $message = $out[1][0];

        preg_match_all("#\n-----BEGIN SIGNATURE-----\n(.{0,})\n(.{0,})\n-----END " . strtoupper($this->getNetworkName()) . " SIGNED MESSAGE-----#USi", $rawMessage, $out);
        $address = $out[1][0];
        $signature = $out[2][0];

        // Alternate version
        //return $this->checkSignedMessage($address, $signature, $message);
        return $this->checkSignatureForMessage($address, $signature, $message);
    }

    /***
     * checks the signature of a bitcoin signed message.
     *
     * @param $address String
     * @param $encodedSignature String
     * @param $message String
     * @return bool
     */
    public function checkSignatureForMessage($address, $encodedSignature, $message){
        // $hash is HEX String
        $hash = $this->hash256($this->getMessageMagic() . $this->numToVarIntString(strlen($message)) . $message);

        //recover flag

        // $signature is BIN
        $signature = base64_decode($encodedSignature);

        // $flag is INT
        $flag = hexdec(bin2hex(substr($signature, 0, 1)));

        // Convert BIN to HEX String
        $R = bin2hex(substr($signature, 1, 32));
        $S = bin2hex(substr($signature, 33));

        $derPubKey = Signature::getPubKeyWithRS($flag, $R, $S, $hash);
        $recoveredAddress = AddressCodec::Encode(AddressCodec::Hash($derPubKey), $this->getNetworkPrefix());

        /* Alternate version
        $pubkeyPoint = Signature::recoverPublicKey_HEX($flag, $R, $S, $hash);
        $recoveredAddress = AddressCodec::Encode(AddressCodec::Hash(AddressCodec::Compress($pubkeyPoint)), $this->getNetworkPrefix());
        */

        if($address == $recoveredAddress)
            return true;
        else
            return false;
    }
    
    // Same as above - But not working correctly
    // All Paramaters are Strings
    public function checkSignedMessage($address, $encodedSignature, $message){
        // $signature is BIN
        $signature = base64_decode($encodedSignature, true);

        // $recoveryFlags is INT
        $recoveryFlags = ord($signature[0]) - 27;

        if ($recoveryFlags < 0 || $recoveryFlags > 7) {
            throw new InvalidArgumentException('invalid signature type');
        }

        // $isCompressed is BOOL
        $isCompressed = ($recoveryFlags & 4) != 0;

        // $hash is HEX String
        $hash = $this->hash256($this->getMessageMagic() . $this->numToVarIntString(strlen($message)) . $message);

        // Convert BIN to HEX String
        $R = gmp_init(bin2hex(substr($signature, 1, 32)), 16);
        $S = gmp_init(bin2hex(substr($signature, 33)), 16);

        $hash = gmp_init($hash, 16);

        // $pubkey is Array(HEX String, HEX String)
        $pubkeyPoint = Signature::recoverPublicKey($R, $S, $hash, $recoveryFlags);

        if ($isCompressed) {
            $recoveredAddress = AddressCodec::Compress($pubkeyPoint);
        }
        else{
            $recoveredAddress = AddressCodec::Hex($pubkeyPoint);
        }

        $recoveredAddress = AddressCodec::Encode(AddressCodec::Hash($recoveredAddress), $this->getNetworkPrefix());
        return $address === $recoveredAddress;
    }
    
    /***
     * Standard 256 bit hash function : double sha256
     *
     * @param $data
     * @return string
     */
    private function hash256($data){
        return hash('sha256', hex2bin(hash('sha256', $data)));
    }
    
    /***
     * Convert a number to a compact Int
     * taken from https://github.com/scintill/php-bitcoin-signature-routines/blob/master/verifymessage.php
     *
     * @param $i
     * @return string
     * @throws \Exception
     */
    private function numToVarIntString($i) {
        if ($i < 0xfd) {
            return chr($i);
        } else if ($i <= 0xffff) {
            return pack('Cv', 0xfd, $i);
        } else if ($i <= 0xffffffff) {
            return pack('CV', 0xfe, $i);
        } else {
            throw new \Exception('int too large');
        }
    }
}

/* 
 * Crypto Currency Wallet
 * For Bitcoin/Zetacoin compatable Crypto Currency utilizing the secp256k1 curve
*/

class GetInfo{
    
    public $last_error;
    private $PRIVATE_ADDR;
    
    
    public function __construct($address = '') {
        $this->PRIVATE_ADDR = $address;
    }

    /***
     * Get balance api https://blockchain.info/api/q
     *
     * @param $address String
     * @return string 
    */
    function blockchain_info_addressbalance() {
        
        if (empty($this->PRIVATE_ADDR)) return false;
        $url = 'https://blockchain.info/en/q/addressbalance/' . $this->PRIVATE_ADDR;
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL,$url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $server_output = curl_exec ($ch);
        curl_close ($ch);
        $this->last_error = $server_output;
        //echo $server_output;
        //echo '<pre>';print_r($server_output);echo '</pre>';
        return $server_output;
    }

    /***
     * Get balance api https://blockchain.info/rawaddr/$bitcoin_address
     *
     * @return string 
    */
    // 
    function blockchain_info_rawaddr($addr) {
        if (empty($this->PRIVATE_ADDR)) return false;
        $url = 'https://blockchain.info/rawaddr/' . $this->PRIVATE_ADDR;
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL,$url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $server_output = curl_exec ($ch);
        curl_close ($ch);
        $json=json_decode($server_output,true);
        $this->last_error=$server_output;
        //echo $server_output;
        //echo '<pre>';print_r($json);echo '</pre>';
        if ($json==false) {
            return false;
        }
        return $json;
    }
}
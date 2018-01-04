<?php
/**
 * Created by PhpStorm.
 * User: huizhi
 * Date: 2018/1/3
 * Time: 12:21
 */

namespace dekuan\derpctoken;


class JwtBuilder
{
    public static $aSupportedAlgs = array(
        'HS256' => array('hash_hmac', 'SHA256'),
        'HS512' => array('hash_hmac', 'SHA512'),
        'HS384' => array('hash_hmac', 'SHA384'),
        'RS256' => array('openssl', 'SHA256'),
        'RS384' => array('openssl', 'SHA384'),
        'RS512' => array('openssl', 'SHA512'),
    );

    public $errorInfo = [];


    protected $type = 'JWT';

    protected $alg = 'HS256';

    protected $Header = [];
    protected $Payload = [];
    public $sHeaderString = null;
    public $sPayload = null;
    public $sSignature = null;


    public function setJwtHeader($sType='JWT',$sAlg='HS256')
    {
        if( empty( $sType ) || empty( $sAlg ) ){
            return false;
        }
        $this->Header = ['alg'=>$sAlg,'typ'=>$sType];
        $this->alg = $sAlg;
        $this->sHeaderString = self::urlsafeB64Encode(json_encode($this->Header));
        return true;
    }



    public function setJwtPayload( $data )
    {
        $this->Payload = self::urlsafeB64Encode(json_encode( $data ));
        return true;
    }


    public function getJwtToken($aPayload,$sSecret,$sAlg)
    {
        if( !is_array( $aPayload ) && !is_object( $aPayload ) ){
            JwtBuilder::LogErr("payload 数据类型错误!");
            return false;
        }
        if( !is_array( $sSecret ) && !is_string( $sSecret ) ){
            var_dump($sSecret,111);
            JwtBuilder::LogErr("secret 类型错误！".( $sSecret ));
            return false;
        }
        if(!array_key_exists( $sAlg, JwtBuilder::$aSupportedAlgs ))
        {
            JwtBuilder::LogErr("不支持的加密类型！");
            return false;
        }
        $this->setJwtHeader();
        $this->setJwtPayload($aPayload);
        if( is_array( $sSecret ) ){
            $this->sSignature = JwtBuilder::sign( $this->sHeaderString.'.'.$this->Payload,$sSecret[0],$sAlg );
        } else{
            $this->sSignature = JwtBuilder::sign( $this->sHeaderString.'.'.$this->Payload,$sSecret,$sAlg );
        }

        return $this->sHeaderString.'.'.$this->Payload.'.'.$this->sSignature;
    }


    public function verifyJwtToken( $sToken, $sSecret, &$data = null )
    {
        if( empty( $sToken ) ){
            return false;
        }
        $aJwt = explode('.',$sToken);
        if (count($aJwt) != 3) {
            return false;
        }

        list($sHeader,$sPayload,$sSignature) = $aJwt;

        $aHeader = json_decode( self::urlsafeB64Decode( $sHeader ),true );
        $aPayload = json_decode( self::urlsafeB64Decode( $sPayload ),true );
        if( null === $aHeader || null === $aPayload ){
            $this->LogErr("编码错误");
            return false;
        }
        $timestamp = time();
        if( array_key_exists('alg',$aHeader) && array_key_exists( $aHeader['alg'],JwtBuilder::$aSupportedAlgs ) ){
            //check sign time
            if( array_key_exists(  'iat',$aPayload)  && $timestamp > $aPayload['iat'] ){
                $this->LogErr('签发日期错误：'.date( $sPayload['iat'] ));
                return false;
            }
            // check expire time
            if( array_key_exists(  'exp',$aPayload)  && $timestamp > $aPayload['exp'] ){
                $this->LogErr('token 过期：'.date( $sPayload['exp'] ));
                return false;
            }
            //check nbf, before nbf ,not valid
            if( array_key_exists(  'nbf',$aPayload)  && $timestamp < $aPayload['nbf'] ){
                $this->LogErr(date( $sPayload['nbf']."前不能使用" ));
                return false;
            }
            //check signature
            if( is_string( $sSecret ) ){
                if( $sSignature !== JwtBuilder::sign( $sHeader.'.'.$sPayload, $sSecret, $aHeader['alg'] ) ){
                    $this->LogErr("签名错误");
                    return false;
                }
                $data = $aPayload;
                return true;
            } elseif(is_array( $sSecret )) {
                foreach ( $sSecret as $secret )
                {
                    if( $sSignature === JwtBuilder::sign( $sHeader.'.'.$sPayload, $secret, $aHeader['alg'] ) ){
                        $data = $aPayload;
                        return true;
                    }
                }
                $this->LogErr("签名错误");
                return false;
            }

            return false;
        } else{
            $this->LogErr("不支持的签名算法/未找到前面算法");
            return false;
        }
    }


    public static function urlsafeB64Encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }


    public static function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }



    public static function sign($msg, $key, $alg = 'HS256')
    {
        if (empty(static::$aSupportedAlgs[$alg])) {
            return false;
        }
        list($function, $algorithm) = static::$aSupportedAlgs[$alg];
        $signature = '';
        switch($function) {
            case 'hash_hmac':
                $signature = hash_hmac($algorithm, $msg, $key, true);
                break;
            case 'openssl':
                $success = openssl_sign($msg, $sTmpSignature, $key, $algorithm);
                $success ? $signature = $sTmpSignature : null;
                break;
        }

        if('' !== $signature){
            return JwtBuilder::urlsafeB64Encode($signature);
        }

        return  false;
    }


    public static function jsonDecode($input)
    {
        if (version_compare(PHP_VERSION, '5.4.0', '>=') && !(defined('JSON_C_VERSION') && PHP_INT_SIZE > 4)) {
            /** In PHP >=5.4.0, json_decode() accepts an options parameter, that allows you
             * to specify that large ints (like Steam Transaction IDs) should be treated as
             * strings, rather than the PHP default behaviour of converting them to floats.
             */
            $obj = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);
        } else {
            /** Not all servers will support that, however, so for older versions we must
             * manually detect large ints in the JSON string and quote them (thus converting
             *them to strings) before decoding, hence the preg_replace() call.
             */
            $max_int_length = strlen((string) PHP_INT_MAX) - 1;
            $json_without_bigints = preg_replace('/:\s*(-?\d{'.$max_int_length.',})/', ': "$1"', $input);
            $obj = json_decode($json_without_bigints);
        }

        if (function_exists('json_last_error') && $errno = json_last_error()) {
            return false;
        } elseif ($obj === null && $input !== 'null') {
            return false;
        }
        return $obj;
    }


    protected function LogErr( $data )
    {
        array_push( $this->errorInfo, $data );
    }


    public function getErrInfo()
    {
        return $this->errorInfo;
    }




}
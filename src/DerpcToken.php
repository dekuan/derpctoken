<?php
namespace april\derpctoken;

class DerpcToken
{
    private $aServerList = [];

    public function __construct()
    {
        $this->aServerList = require_once "./server.php";
    }

    public function createToken( $sRole, $sInterfaceName, $aData = [] )
    {
        if( empty( $sRole ) || empty( $sInterfaceName ) ){
            return false;
        }

        $sToken = $this->_createToken( $sRole, $sInterfaceName, $aData );


    }

    public function verifyToken( $sToken, &$aData )
    {
        $bRet = false;
        return $bRet;

    }

    public function setConfig( $sRole, array $aServerList )
    {

    }



    private function _createToken( $sRole, $sInterfaceName, $aData )
    {
        $aHeader = [
            'typ'=> 'JWT',
            'alg'=> 'HS256'
        ];
        dd(hash_hmac('sha256',$aHeader,'111'));
        return 0;
    }



}
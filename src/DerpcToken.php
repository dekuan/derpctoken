<?php

namespace dekuan\derpctoken;

class DerpcToken
{

    public $aAllowRoles = [];

    private $aConfig = [];

    public function __construct()
    {
        $this->aConfig = require_once dirname(__FILE__) . "/./config.php";
        $this->aAllowRoles = require_once dirname(__FILE__) . "/./allow_roles.php";
    }

    /*
     * $sRole: 角色名称
     * $sInterfaceName：调用服务器接口名称
     * $aTranData： 传输的数据
     * */
    public function createToken($sRole, $sInterfaceName, $aTranData = [])
    {
        if (empty($sRole) || empty($sInterfaceName)) {
            return false;
        }

        $now = time();
        $expire_time = $this->aConfig['expire_time'];
        $payload = [
            'iss' => $this->aConfig['issuer'],//签发者
            'role' => $sRole,//角色
            'inter' => $this->_getInter( $sInterfaceName ),//调用的接口
            'data' => $aTranData,//传输的数据
            'exp' => $now + $expire_time,//有效期
            'nbf' => $now,//此时间点之前不可用
            'iat' => $now,//签发时间
            'jti' => microtime(true) . rand(0, 99999)
        ];
        $oJwt = new JwtBuilder();
        $sToken = $oJwt->getJwtToken($payload, $this->aConfig['secret'],$this->aConfig['alg']);


        return $sToken;
    }


    /*
     * $sToken：jwt
     * $aData:校验成功返回的数据
     * return bool;
     * */
    public function verifyToken($sToken, &$aData)
    {
        //校验签名
        $Jwt = new JwtBuilder();
        if(!$Jwt->verifyJwtToken($sToken, $this->aConfig['secret'],$aTmpData))
        {
            return false;
        }
        //验证角色和权限
        if( $this->checkRolePermission( $aTmpData ) ){
            $aData = $aTmpData['data'];
            return true;
        }
        return false;
    }


    /*
     * $role: string or array
     * $bAddOrDelete: bool
     * return: bool
     * */
    public function setRole( $role, $bAddOrDelete = true )
    {
        $bRet = false;
        if( is_bool( $bAddOrDelete ) ){
            if( is_string( $role ) ){
                $bRet =  $this->_setRole( $role, $bAddOrDelete );
            } elseif( is_array( $role ) && 0 < count( $role ) ) {
                foreach ( $role as $sRole )
                {
                    $this->_setRole( $sRole, $bAddOrDelete );
                }
                $bRet = true;
            }
        }

        return $bRet;
    }


    /*
     * 设置密钥
     * $sSecret: string
     * */
    public function setSecret( $sSecret)
    {
        if (!is_string($sSecret) || 0 == strlen($sSecret)) {
            return false;
        }
        $this->aConfig['secret'] = $sSecret;
        return true;
    }



    protected function checkRolePermission( $aJwtData )
    {
        if( is_array( $aJwtData ) && array_key_exists( 'role',$aJwtData ) &&
            array_key_exists( 'inter', $aJwtData) ){
            if( is_string($aJwtData['role']) && array_key_exists($aJwtData['role'], $this->aAllowRoles ) &&
                ($aJwtData['inter'] === $this->_getInter( $this->_getCurrentPath() ) ||
                    $aJwtData['inter'] === $this->_getInter( $this->_getCurrentPath(), true ) ) ){
                return true;
            }
        }

        return false;
    }



    private function _getCurrentPath()
    {
        if( is_array( $_SERVER ) && array_key_exists('REQUEST_URI', $_SERVER ) ){
            return $_SERVER['REQUEST_URI'];
        } else{
            return null;
        }
    }


    private function _getInter( $sInterfaceName,$bTheHourBefore = false )
    {
        if( is_string( $sInterfaceName ) ){
            if(!$bTheHourBefore){
                return md5( date("H Y-m-d").$sInterfaceName);
            } else{
                return md5( date("H Y-m-d",time()-3600).$sInterfaceName);
            }
        }
        elseif( null === $sInterfaceName )
        {
            if(!$bTheHourBefore){
                return md5( date("H Y-m-d"));
            } else{
                return md5( date("H Y-m-d",time()-3600));
            }
        }
        else{
            return false;
        }
    }





    private function _setRole( $sRole,$bAddOrDelete = true )
    {
        $bRet = false;
        if( is_string( $sRole ) && 0< strlen( $sRole ) ){
            $sRole = strtolower(trim($sRole));
            if( $bAddOrDelete && !array_key_exists( $sRole,$this->aAllowRoles ) ){
                $this->aAllowRoles[ $sRole ] = 1;
                $bRet = true;
            } elseif(!$bAddOrDelete && array_key_exists( $sRole,$this->aAllowRoles )){
                unset( $this->aAllowRoles[ $sRole ] );
                $bRet = true;
            }
        }
        return $bRet;
    }

}
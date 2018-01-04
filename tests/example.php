<?php

error_reporting(E_ALL | E_STRICT);
require_once dirname(__FILE__)."/../src/DerpcToken.php";
require_once dirname(__FILE__)."/../src/JwtBuilder.php";


$oToken = new \dekuan\derpctoken\DerpcToken();

$sToken = $oToken->createToken('admin','/api/test',['test'=>1]);

var_dump( $sToken );

$bVerifyResult =  $oToken->verifyToken( $sToken, $aTranData );

//此处因为是脚本运行，无法通过检验
var_dump( $bVerifyResult );

var_dump( $aTranData );

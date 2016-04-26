<?php
error_reporting(0);
header('Content-Type: text/html; charset=utf-8');
header('PHPWAF:BY_Virink');

if (!function_exists('getallheaders')) {
    function getallheaders() {
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
        }
        return $headers;
    }
}

$input = "GET : ".print_r( $_GET , true );
$input .= "POST : ".print_r( $_POST , true );
$input .= "Cookies : ".print_r( $_COOKIE , true );

if ( preg_match( "/select|insert|update|delete|and|or|eval|\'|\/\*|\*|\.\.\/|\.\/|union|into|load_file|outfile|sub|hex/i", $input ) ) 
{
    $data = "IP : ".$_SERVER["REMOTE_ADDR"]."\r\nREQUEST_METHOD : ".$_SERVER['REQUEST_METHOD'];
    $data .= "\r\n".$input;
    $data .= "Http-Request : " . print_r( getallheaders(), true ) . "\r\n";
    $log = "file:" . $_SERVER["SCRIPT_NAME"] . "\r\n" . $data . "\r\n";
    $logfn = $_SERVER["DOCUMENT_ROOT"] . "/webwaflog/log_" . date( "Y-m-d" ) . ".log";
    file_put_contents( $logfn, "### " . date( "Y-m-d H:m:s" ) . " ###\r\n" . $log . "\r\n", FILE_APPEND );
    die("不要黑我哟");
}

?>

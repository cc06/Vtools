<?php
@error_reporting(0);

function waf()
{
    if (!function_exists('getallheaders')) {
        function getallheaders() {
            foreach ($_SERVER as $name => $value) {
                if (substr($name, 0, 5) == 'HTTP_')
                    $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
            unset($header['Accept']);
            return $headers;
        }
    }

    $get = $_GET;
    $post = $_POST;
    $cookie = $_COOKIE;
    $header = getallheaders();
    $ip = $_SERVER["REMOTE_ADDR"];
    $method = $_SERVER['REQUEST_METHOD'];
    $filepath = $_SERVER["SCRIPT_NAME"];

    unset($header['Accept']);

    $input = array("Get"=>$get, "Post"=>$post, "Cookie"=>$cookie, "Header"=>$header);

    $pattern = "select|insert|update|delete|and|or|eval|\'|\/\*|\*|\.\.\/|\.\/|union|into|load_file|outfile|dumpfile|sub|hex";
    $pattern .= "|file_put_contents|fwrite|curl|system|eval|assert";
    $pattern .="|passthru|exec|system|chroot|scandir|chgrp|chown|shell_exec|proc_open|proc_get_status|popen|ini_alter|ini_restore";
    $pattern .="|`|dl|openlog|syslog|readlink|symlink|popepassthru|stream_socket_server|assert|pcntl_exec";
    $vpattern = explode("|",$pattern);

    $bool = false;
    foreach ($input as $k => $v) {
        foreach($vpattern as $value){
            foreach ($v as $kk => $vv) {
                if (preg_match( "/$value/i", $vv )){
                    $bool = true;
                    $log($input);
                    break;
                }
            }
            if($bool) break;
        }
        if($bool) break;
    }
        
}

function log($var){
    file_put_contents("log.txt", print_r($var), FILE_APPEND);
    // die
    // die();
    //
    // unset
    // unset($_GET);
    // unset($_POST);
    // unset($_COOKIE);
}
waf();
?>

<?php
error_reporting(0);
include_once('mysql.php');
//确定请求方法
$method = $_SERVER['REQUEST_METHOD'];
if ($method === 'GET'){
    $info = $_GET;
}
elseif($method === 'POST'){
    $info = $_POST;
}
else{
    die('none');
}

//将输入的值进行转义
if(!get_magic_quotes_gpc()){
    foreach($info as $k => $v){
        $info[$k] = addslashes($v);
    }
}


//检测sql注入中的关键字
function sql_injection_check($info){
    foreach($info as $k=>$v){
        if(preg_match("/union|select|order by|database|schema|version|outfile|dumpfile|updatexml|floor\(|extractvalue| and | or /i",$v)){
            //将预警信息写入数据库
            $path = $_SERVER['PHP_SELF'];
            $payload = $_SERVER['QUERY_STRING'];
            $alert_info = array('srcip'=>$_SERVER['REMOTE_ADDR'],'srcport'=>$_SERVER['REMOTE_PORT']);
            $alert_info = json_encode($alert_info);
            $sql = "insert into alert(level,sort,info,path,payload,date) values('3','sql-injection','$alert_info','$path','$payload',now())";
            $mysql = new Mysql();
            $mysql->insert($sql);
            //跳转到预警页面，并结束后续代码的执行
            die(header('Location:/sys/error.html'));                
        }
    }
    $headers = getallheaders();
    foreach($headers as $k=>$v){
        if(preg_match("/union|select|order by|database|schema|version|outfile|dumpfile|updatexml|floor\(|extractvalue| and | or /i",$v)){
                $path = $_SERVER['PHP_SELF']." : ".$k;
                $payload = $_SERVER['QUERY_STRING'];
                $alert_info = array('srcip'=>$_SERVER['REMOTE_ADDR'],'srcport'=>$_SERVER['REMOTE_PORT']);
                $alert_info = json_encode($alert_info);
                $sql = "insert into alert(level,sort,info,path,payload,date) values('3','header-sql-injection','$alert_info','$path','$payload',now())";
                $mysql = new Mysql();
                $mysql->insert($sql);
                //跳转到预警页面，并结束后续代码的执行
                die(header('Location:/sys/error.html'));  
            }
    }
}
sql_injection_check($info);

//检测xss中的关键字
function xss_check($info){
    foreach($info as $k=>$v){
        if(preg_match("/<|>|script|onclick|onerror|alert\(|javascript|iframe/i",$v)){
            //将预警信息写入数据库
            $path = $_SERVER['PHP_SELF'];
            $payload = $_SERVER['QUERY_STRING'];
            $alert_info = array('srcip'=>$_SERVER['REMOTE_ADDR'],'srcport'=>$_SERVER['REMOTE_PORT']);
            $alert_info = json_encode($alert_info);
            $sql = "insert into alert(level,sort,info,path,payload,date) values('2','xss','$alert_info','$path','$payload',now())";
            $mysql = new Mysql();
            $mysql->insert($sql);
            //跳转到预警页面，并结束后续代码的执行
            die(header('Location:/sys/error.html'));
        }
    }
    $headers = getallheaders();
    foreach($headers as $k=>$v){
        if(preg_match("/union|select|order by|database|schema|version|outfile|dumpfile|updatexml|floor\(|extractvalue| and | or /i",$v)){
                $path = $_SERVER['PHP_SELF']." : ".$k;
                $payload = $_SERVER['QUERY_STRING'];
                $alert_info = array('srcip'=>$_SERVER['REMOTE_ADDR'],'srcport'=>$_SERVER['REMOTE_PORT']);
                $alert_info = json_encode($alert_info);
                $sql = "insert into alert(level,sort,info,path,payload,date) values('2','header-sql-injection','$alert_info','$path','$payload',now())";
                $mysql = new Mysql();
                $mysql->insert($sql);
                //跳转到预警页面，并结束后续代码的执行
                die(header('Location:/sys/error.html'));  
            }
    }
    
    
}
xss_check($info);

//检测命令注入中的关键字
function order_injection_check($info){
    foreach($info as $k=>$v){
        if(preg_match("/;|\||\&|`\S+`|%0a|>/i",$v)){
            //将预警信息写入数据库
            $path = $_SERVER['PHP_SELF'];
            $payload = $_SERVER['QUERY_STRING'];
            $alert_info = array('srcip'=>$_SERVER['REMOTE_ADDR'],'srcport'=>$_SERVER['REMOTE_PORT']);
            $alert_info = json_encode($alert_info);
            $sql = "insert into alert(level,sort,info,path,payload,date) values('3','order injection','$alert_info','$path','$payload',now())";
            $mysql = new Mysql();
            $mysql->insert($sql);
            //跳转到预警页面，并结束后续代码的执行
            die(header('Location:/sys/error.html'));
        }
    }
}
order_injection_check($info);

//检测上传木马
function upload_check($info){
    //判断是否是上传文件
    if(empty($_FILES)){
        return 0;
    }
    //获取文件名，类型，暂存路径
    foreach($_FILES as $k=>$v){
        $tmpname = $v['tmp_name'];
    }
    //检查内容
    $content = file_get_contents($tmpname);
    if (preg_match("/assert|eval|system|exec|\$_GET|\$_POST/i",$content)){
        //将警告信息写入数据库
        $path = $_SERVER['PHP_SELF'];
        $alert_info = array('srcip'=>$_SERVER['REMOTE_ADDR'],'srcport'=>$_SERVER['REMOTE_PORT']);
        $alert_info = json_encode($alert_info);
        $sql = "insert into alert(level,sort,info,path,date) values('3','upload trojan','$alert_info','$path',now())";
        $mysql = new Mysql();
        $mysql->insert($sql);
        // move_uploaded_file($tmpname,"/tmp/upload/".$filename);
        die(header('Location:/sys/error.html'));
    }
}
upload_check($info);

//检测反序列化
function unserialize_check($info){
    foreach($info as $k=>$v){
        //通过规则进行匹配输入的是否为序列化后的值
        if(preg_match('/^\w+:\d+:{.+}$/',$v)){
            //将预警信息写入数据库
            $path = $_SERVER['PHP_SELF'];
            $payload = $_SERVER['QUERY_STRING'];
            $alert_info = array('srcip'=>$_SERVER['REMOTE_ADDR'],'srcport'=>$_SERVER['REMOTE_PORT']);
            $alert_info = json_encode($alert_info);
            $sql = "insert into alert(level,sort,info,path,payload,date) values('3','unsserialize-attack','$alert_info','$path','$payload',now())";
            $mysql = new Mysql();
            $mysql->insert($sql);
            //跳转到预警页面，并结束后续代码的执行
            die(header('Location:/sys/error.html'));
        }
    }
}
unserialize_check($info);

//检测SSRF
function ssrf_check($info){
    foreach($info as $k=>$v){
        if(preg_match('/gopher:|dict:|file:|http:/',$v)){
            //将预警信息写入数据库
            $path = $_SERVER['PHP_SELF'];
            $payload = $_SERVER['QUERY_STRING'];
            $alert_info = array('srcip'=>$_SERVER['REMOTE_ADDR'],'srcport'=>$_SERVER['REMOTE_PORT']);
            $alert_info = json_encode($alert_info);
            $sql = "insert into alert(level,sort,info,path,payload,date) values('3','unsserialize-attack','$alert_info','$path','$payload',now())";
            $mysql = new Mysql();
            $mysql->insert($sql);
            //跳转到预警页面，并结束后续代码的执行
            die(header('Location:/sys/error.html'));
        }
    }
}
ssrf_check($info);





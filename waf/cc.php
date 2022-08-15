<?php
include_once('mysql.php');

//获取当前访问者的远程IP
$ip = $_SERVER['REMOTE_ADDR'];
$mysql = new Mysql();
$res = $mysql->find("select * from cc where ip='$ip'");

//查询IP数据为空是为其添加一条数据
if(!empty($res)){
    $id = $res[0]['id'];
    $time = $res[0]['time'];
    $time_interval = time() - $res[0]['start'];
    //当两次访问的间隔时间超过5秒,重置时间
    if($time_interval > 5){
        $now_time = time();
        $mysql->insert("update cc set time=1,start=$now_time where ip='$ip'");
    }
    //当10秒内访问次数超过10次封IP,并删除数据库中的记录
    elseif($time >= 10){
        $mysql->insert("delete from cc where id=$id");
        //写入数据库
        $path = $_SERVER['PHP_SELF'];
        $alert_info = array('srcip'=>$ip,'srcport'=>$_SERVER['REMOTE_PORT']);
        $alert_info = json_encode($alert_info);
        $sql = "insert into alert(level,sort,info,path,date) values('3','cc-attack','$alert_info','$path',now())";
        $mysql->insert($sql);
        //抵用防火墙
        exec("sudo firewall-cmd --zone=public --add-rich-rule='rule family=ipv4 source address=$ip/32 reject'");
        //确保IP封禁成功
        while(1){
            $cmd = exec('firewall-cmd --list-all');
            if (strpos($cmd,$ip)){
                break;
            }
        }
    }
    //前面都不满足时，访问次数+1
    else{
        $mysql->insert("update cc set time=time+1 where ip='$ip'");
    }
}
else{
    $start = time();
    $mysql->insert("insert into cc(time,ip,start) values(1,'$ip',$start)");
}

?>
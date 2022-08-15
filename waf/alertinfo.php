<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script>
        setTimeout(function(){location.reload()},5000);
    </script>
    <style>
        body{text-align:center;}
        table{margin:auto;}
    </style>
</head>
<body style="background:#BBFFEE">
    <div style="font-size:40px">WAF实时监测中心</div>
    <div style="margin-top:10px">
        当前时间：<?php error_reporting(0);date_default_timezone_set('PRC');echo date("Y-m-d H:i:s",time()) ?>
    </div>
    <table border='1' style="margin-top:20px;background:#FFFFBB">
        <tr><th>id</th><th>level</th><th>sort</th><th>info</th><th>path</th><th>payload</th><th>date</th></tr>
        <?php
            error_reporting(0);
            include_once('mysql.php');
            $m = new Mysql();
            $res = $m->find('select * from alert');
            for($i=0;$i<sizeof($res);$i++){
                $id=$res[$i]['id'];
                $level=$res[$i]['level'];
                $sort=$res[$i]['sort'];
                $info=$res[$i]['info'];
                $path=$res[$i]['path'];
                $payload=$res[$i]['payload'];
                $date=$res[$i]['date'];
                echo "<tr><td>$id</td><td>$level</td><td>$sort</td><td>$info</td><td>$path</td><td>$payload</td><td>$date</td></tr>";
            }
        ?>
    </table>
</body>
</html>
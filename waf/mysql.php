<?php
class Mysql{
    var $conn;
    //实例化时自动连接数据库
    function __construct($host='localhost',$username='root',$password='123456',$database='test'){
        $this->conn = mysqli_connect($host,$username,$password,$database) or die("数据库连接失败");
    }

    //查询数据库
    function find($sql){
        $result = mysqli_query($this->conn,$sql);
        $rows = mysqli_fetch_all($result,MYSQLI_ASSOC);
        return $rows;
    }
    
    //插入数据库
    function insert($sql){
        $result = mysqli_query($this->conn,$sql);
    }

    //数据库断开连接
    function __destruct(){
        mysqli_close($this->conn) or die("数据库关闭失败");   
    }
}


### 改自 yinqiwen 大神的 github.com/yinqiwen/gscan 在此感谢<hr>

## 简单说明
IP 段写在 iprange.conf 文件里, 一行一个, 具体格式下面有写到<br>
自己扫的时候请删掉 iprange.conf 中自带的IP段, 因为这是测试用的, 不一定是真可用的

扫完的IP存放在 google_ip.txt 和类似 google_ip_20170714_18.24.55.txt 这种文件里<br>
分别是 goagent 和 goproxy 格式的

配置可以对照下面的说明改, 但一般不需要改, 直接点击程序运行即可

到 https://github.com/Kisesy/gscan_quic/releases 下载编译好的

或者到这里 https://gox.jpillora.com/ 自行编译, 编译时在第一个框里输入:
github.com/Kisesy/gscan_quic<br>
点击 [Show more] 按钮选中你的系统, 点击 Compile即可, 编译完到网页右边下载


# gscan

 一个Go语言实现的HTTPS IP可用性扫描工具， 主要作用于Google IP

## 用途
主要用于两种场景：

- 扫描修复Hosts：指定IP段， 以及输入的hosts文件，扫描可用的IP替换（保留不可替换的），生成新的Hosts文件
- 扫描可用IP：指定IP段，扫描可用于Google HTTPS的IP，结果可用于GSnova、GoAgent等代理工具

## 使用说明
如果对Go熟悉的，可以直接执行以下命令下载编译gscan：  

     go get -u github.com/yinqiwen/gscan

不了解Go的，可以直接下载example的`gscan.exe`, 不过无法保证和源码同步更新

gscan是一个命令行工具，支持两个参数，配置说明见后文：

    $ ./gscan.exe -h
    Usage of D:\Src\MyProjects\gscan\gscan.exe:
       -conf="./gscan.conf": Config file, json format
       -iprange="./iprange.conf": IP Range file
 


## 配置说明
一个完整的配置文件， json格式：

    {
     "ScanWorker" : 100,         //启动的扫描worker个数（GoRoutine）
     "ScanMinPingRTT" : 100,     //ping IP最小延迟，丢弃延迟很低的IP，延迟很低的IP不稳定，单位毫秒
     "ScanMaxPingRTT" : 800,     //ping IP最大延迟，丢弃延迟很大的IP，单位毫秒
     "ScanMaxSSLRTT":3000,       //最大SSL连接协商延迟
     "ScanCountPerIP" : 3,       //每个IP重试次数，每次都成功，才认为合法
 
     "Operation" : "ScanGoogleHosts",  //本次操作类型， 扫描IP或者扫描修复Hosts
  
     "ScanGoogleIP" :{
        "SSLCertVerifyHosts" : ["www.google.com.hk"],  //检查证书中域名
        "HTTPVerifyHosts" : ["www.google.com"],        //HEAD HTTP请求检查域名
        "RecordLimit" :     10,                       //输出IP个数限制
        "OutputSeparator":  "|",
        "OutputFile" :      "./google_ip.txt"         //结果输出文件
      },
  
     "ScanGoogleHosts":{
        "InputHosts":"./test/hosts.input",           //输入Hosts
        "OutputHosts": "./hosts.output",
        "HTTPVerifyHosts" : ["www.google.com", "www.google.com.hk", "mail.google.com", "code.google.com",
                            "drive.google.com", "plus.google.com", "play.google.com", "books.google.com",
                            "calendar.google.com", "sites.google.com"]    //需要HEAD HTTP请求检查域名
      } 
    }

IP段文件格式如下：

    #注释
    IPStart1-IPEnd1
    IPStart2-IPEnd2
    ...
    IPStartN-IPEndN


    下面几种都是支持的, 遇到错误IP格式是会跳过的
    
    1.9.23.0            单个IP
    1.9.23.0/24
    1.9.0.0/16
    
    1.9.22.0-1.9.23.0/24
    
    1.9.22.0/24-1.9.33.0/24
    
    1.9.22.0-255
    1.9.22.0-1.9.22.255
    1.9.22.0-1.9.33.255
    
    

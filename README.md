
# gscan-quic

 一个Go语言实现的HTTPS IP可用性扫描工具， 主要作用于 Google Quic IP 的扫描

## 简单说明
IP 段写在 iprange.conf 文件里, 一行一个<br>
自己扫的时候可以换掉 iprange.conf 中自带的IP段, 因为这是测试用的, 不一定是真可用的

**IP段文件格式如下：**
> (文件里除了注释符 # 以外, 不要出现其他特殊字符, 比如 // )

    #注释

    IPStart1-IPEnd1
    IPStart2-IPEnd2
    ...
    IPStartN-IPEndN

    # 下面几种都是支持的, 遇到错误IP格式是会跳过的
    # 但是一定是一行一个IP或一个IP段, 参考下面的格式

    1.9.23.0            
    1.9.23.0/24
    1.9.0.0/16
    
    1.9.22.0-1.9.23.0/24
    
    1.9.22.0/24-1.9.33.0/24
    
    1.9.22.0-255
    1.9.22.0-1.9.22.0
    1.9.22.0-1.9.22.255
    1.9.22.0-1.9.33.255

    1.9.22.111-1.9.22.111       会自动精简成1.9.22.111
    1.9.22.0/24-1.9.22.0/24     会自动精简成1.9.22.0/24

    # 支持 ipv6 格式

    2001:db8::1
    2001:db8::1/128

    # 支持 gop 的 "xxx","xxx" 和 goa 的 xxx|xxx 格式

    "1.9.22.0", "1.9.22.1","1.9.22.2",
    1.9.22.0|1.9.22.1|

    # IP段也是会自动去重的

    1.9.22.0-255
    1.9.0.0/16
    1.9.22.0-255
    1.9.22.0/24
    1.9.22.0-255
    1.9.22.0-1.9.22.100
    1.9.22.0-1.9.22.255
    1.9.0.0/16
    3.3.3.0/24
    3.3.0.0/16
    3.3.3.0-255
    1.1.1.0/24
    1.9.0.0/16

    # 上面几个经过去重只会留下
    3.3.0.0/16
    1.9.0.0/16
    1.1.1.0/24

扫完的IP存放在 google_ip.txt 和类似 google_ip_20170714_18.24.55.txt 这种文件里<br>
分别是 goagent 和 goproxy 格式的

> **注意:**

* 默认是有输出个数限制的, 可以设置配置文件里的RecordLimit

* 在扫描过程中是可以中断的, 只要按Ctrl+C就可以中断, 扫过的IP是会保留的

* 扫描IP段是随机的

## 下载
到 https://github.com/Kisesy/gscan_quic/releases 下载编译好的

## 配置说明
一个完整的配置文件, json格式, 里面不要写注释
(下面只是说明, 请以默认的配置文件为准)

    {
     "ScanWorker" : 100,         //启动的扫描worker个数（GoRoutine）
     "ScanMinPingRTT" : 100,     //ping IP最小延迟，丢弃延迟很低的IP，延迟很低的IP不稳定，单位毫秒
     "ScanMaxPingRTT" : 800,     //ping IP最大延迟，丢弃延迟很大的IP，单位毫秒
     "ScanMaxSSLRTT":3000,       //最大SSL连接协商延迟 ***这个就是延迟时间***
     "ScanCountPerIP" : 3,       //每个IP重试次数，每次都成功，才认为合法
 
     "Operation" : "ScanGoogleHosts",  //本次操作类型， 扫描IP或者扫描修复Hosts
  
     "ScanGoogleIP" :{
        "SSLCertVerifyHosts" : [""],  //检查证书中域名, 这个未使用
        "HTTPVerifyHosts" : ["dns.google.com"],        //HEAD HTTP请求检查域名 ***这个最好不要改***
        "RecordLimit" :     10,                       //***输出IP个数限制***
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



### 改自 yinqiwen 大神的 https://github.com/yinqiwen/gscan 在此感谢

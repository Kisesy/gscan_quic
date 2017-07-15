
# gscan-quic

 一个Go语言实现的HTTPS IP可用性扫描工具， 主要作用于 Google Quic IP 的扫描

## 简单说明
IP 段写在 iprange.conf 文件里, 一行一个<br>
自己扫的时候请删掉 iprange.conf 中自带的IP段, 因为这是测试用的, 不一定是真可用的

**IP段文件格式如下：**

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

扫完的IP存放在 google_ip.txt 和类似 google_ip_20170714_18.24.55.txt 这种文件里<br>
分别是 goagent 和 goproxy 格式的

**注意: 默认只输出100个, 但是可以对照最下面的配置说明改**

## 下载
到 https://github.com/Kisesy/gscan_quic/releases 下载编译好的, **但这里并不一定是最新版, 最好是自行编译**

## 自行编译
在 https://gox.jpillora.com/ 的第一个框里输入: github.com/Kisesy/gscan_quic<br>
点击 [Show more] 按钮选中你的系统, 点击 Compile即可, 编译完到网页右边下载


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



### 改自 yinqiwen 大神的 https://github.com/yinqiwen/gscan 在此感谢

# 红队知识仓库，不定期更新 
## 目录
- [仓库导航](#仓库导航)
 - [编解码/加密](#编解码加密)
- [IP/域名收集](#ip域名收集)
	- [确认真实IP地址](#确认真实ip地址)
	- [多个地点Ping服务器](#多个地点ping服务器)
	- [Whois注册信息反查](#whois注册信息反查)
	-  [DNS数据聚合查询](#dns数据聚合查询)
	- [TLS证书信息查询](#tls证书信息查询)
	- [网络空间搜索](#网络空间搜索)
	- [威胁情报平台](#威胁情报平台)
- [靶场](#靶场)
	- [CTF平台](#ctf平台)
	- [专项靶机平台](#专项靶机平台)
	- [综合靶机平台](#综合靶机平台)
- [信息收集](#信息收集)
  - [指纹识别](#指纹识别)
  - [扫描/爆破](#扫描爆破)
  - [爆破字典](#爆破字典)
  - [综合信息收集](#综合信息收集)
  - [内网信息收集](#内网信息收集)
- [漏洞研究](#漏洞研究)
	- [漏洞平台](#漏洞平台)
	- [漏洞知识库项目](#漏洞知识库项目)
	-  [公开知识库](#公开知识库)
	- [漏洞综述](#漏洞综述)
	- [漏洞挖掘](#漏洞挖掘)
	- [开源漏洞库](#开源漏洞库)
  - [POC/EXP](#pocexp)
- [内网渗透](#内网渗透)
  - [Bypass](#bypass)
  - [Payloads](#payloads)
  - [WebShell](#webshell)
  - [内网穿透](#内网穿透)
  - [开源蜜罐](#开源蜜罐)
  - [容器逃逸](#容器逃逸)
  - [其他](#其他)
- [移动端/物联网](#移动端物联网)
- [逆向分析](#逆向分析)
- [实用工具](#实用工具)
- [工具赋能](#工具赋能)
  - [Metasploit](#metasploit)
  - [Cobaltstrike](#cobaltstrike)
  - [Burpsuite](#burpsuite)
  - [Chrome crx](#chrome-crx)
  - [Xray](#xray)

# 仓库导航

* 反弹shell命令速查：[点击跳转](https://github.com/Threekiii/Awesome-Redteam/blob/master/tips/%E5%8F%8D%E5%BC%B9shell%E5%91%BD%E4%BB%A4%E9%80%9F%E6%9F%A5.md)

* 重要端口及服务速查：[点击跳转](https://github.com/Threekiii/Awesome-Redteam/blob/master/tips/%E9%87%8D%E8%A6%81%E7%AB%AF%E5%8F%A3%E5%8F%8A%E6%9C%8D%E5%8A%A1%E9%80%9F%E6%9F%A5.md)

* 安全厂商及其官网链接速查：[点击跳转](https://github.com/Threekiii/Awesome-Redteam/blob/master/tips/%E5%AE%89%E5%85%A8%E5%8E%82%E5%95%86%E5%8F%8A%E5%85%B6%E5%AE%98%E7%BD%91%E9%93%BE%E6%8E%A5%E9%80%9F%E6%9F%A5.txt)

* Apache项目及漏洞指纹速查：[点击跳转](https://github.com/Threekiii/Awesome-Redteam/blob/master/tips/Apache%E9%A1%B9%E7%9B%AE%E5%8F%8A%E6%BC%8F%E6%B4%9E%E6%8C%87%E7%BA%B9%E9%80%9F%E6%9F%A5.md) 

* 红队中易被攻击的一些重点系统漏洞整理（来源：棱角安全团队）：[点击跳转](https://github.com/Threekiii/Awesome-Redteam/blob/master/docs/%E7%BA%A2%E9%98%9F%E4%B8%AD%E6%98%93%E8%A2%AB%E6%94%BB%E5%87%BB%E7%9A%84%E4%B8%80%E4%BA%9B%E9%87%8D%E7%82%B9%E7%B3%BB%E7%BB%9F%E6%BC%8F%E6%B4%9E%E6%95%B4%E7%90%86.md)

# 编解码/加密

* 一个工具箱：[点击跳转](http://www.atoolbox.net/)

* CTF在线工具：[点击跳转](http://www.hiencode.com/)

* Unicode字符表：[点击跳转](https://www.52unicode.com/enclosed-alphanumerics-zifu)

* OK Tools在线工具：[点击跳转](https://github.com/wangyiwy/oktools)

* 千千秀字各种加密：[点击跳转](https://www.qqxiuzi.cn/daohang.htm)

* 在线MD5 Hash破解：[点击跳转](https://www.somd5.com/)

* XSSEE：在线综合编解码工具[点击跳转](https://evilcos.me/lab/xssee/)

* CyberChef：编解码及加密，可本地部署[点击跳转](https://github.com/gchq/CyberChef)

# IP/域名收集

  ## 确认真实IP地址

  * IP 138：[点击跳转](https://site.ip138.com/)

  * IP精准定位：[点击跳转](https://www.ipuu.net/#/home)

  * Security Trails：[点击跳转](https://securitytrails.com/)

  ## 多个地点Ping服务器

  * Chinaz：[点击跳转](https://ping.chinaz.com/)

  * DNS Check：[点击跳转](https://dnscheck.pingdom.com/)

  * Host Tracker：[点击跳转](https://www.host-tracker.com/)

  *  Webpage Test：[点击跳转](https://www.webpagetest.org/)

  ## Whois注册信息反查

  * 国际 Whois：[点击跳转](https://who.is/)

  * 站长之家 Whois：[点击跳转](https://whois.chinaz.com/)

  * 中国万网 Whois：[点击跳转](https://whois.aliyun.com/)

  ## DNS数据聚合查询

  * DNS DB：[点击跳转](https://dnsdb.io/zh-cn)

  * Hacker Target：[点击跳转](https://hackertarget.com/find-dns-host-records)

  * DNS Dumpster：[点击跳转](https://dnsdumpster.com)

  ## TLS证书信息查询

  * Censys：[点击跳转](https://censys.io)

  * 证书透明度监控：[点击跳转](https://developers.facebook.com/tools/ct)

  * Certificate Search：[点击跳转](https://crt.sh)

  ## IP地址段收集

  * CNNIC中国互联网信息中心：[点击跳转](http://ipwhois.cnnic.net.cn)

  ## 网络空间搜索

  * 谛听：[点击跳转](https://www.ditecting.com/)

  * Fofa：[点击跳转](https://fofa.info/)

  * Shodan：[点击跳转](https://www.shodan.io/)

  * ZoomEye：[点击跳转](https://www.zoomeye.org/)

  * 360网络空间测绘：[点击跳转](https://quake.360.cn/quake/#/index)

  ## 威胁情报平台

  * Virustotal：[点击跳转](https://www.virustotal.com/gui/home/upload)

  * 360威胁情报：[点击跳转](https://ti.360.net/#/homepage)

  * 火线安全平台：[点击跳转](https://www.huoxian.cn)

  * 安恒威胁情报：[点击跳转](https://ti.dbappsecurity.com.cn/)


  * 奇安信威胁情报：[点击跳转](https://ti.qianxin.com/)

  * 微步在线威胁情报：[点击跳转](https://x.threatbook.cn/)

  * 腾讯哈勃分析系统：[点击跳转](https://habo.qq.com/tool/index)

  * Hacking8安全信息流：[点击跳转](https://i.hacking8.com/)

# 靶场

  ## CTF平台
  
  * i春秋：[点击跳转](https://www.ichunqiu.com/competition)

  * 封神台：[点击跳转](https://hack.zkaq.cn/)

  * catflag：[点击跳转](http://ctf.vfree.ltd/)

  * BugKu：[点击跳转](https://ctf.bugku.com/)

  * BUUCTF：[点击跳转](https://buuoj.cn/)

  * CTF Wiki：[点击跳转](https://ctf-wiki.org/)

  * BMZ CTF：[点击跳转](http://www.bmzclub.cn/)

  * CTF Hub：[点击跳转](https://www.ctfhub.com/)

  * 攻防世界：[点击跳转](https://adworld.xctf.org.cn/)

  * CTF Time：[点击跳转](https://ctftime.org/)

  * CTF Show：[点击跳转](https://ctf.show/)

  * NSSCTF：[点击跳转](https://www.ctfer.vip/)

  * CTF Tools：[点击跳转](https://github.com/zardus/ctf-tools)

  * PWN Hub：[点击跳转](https://pwnhub.cn/)

  * Hacker 101：[点击跳转](https://www.hacker101.com/)

  * Wgpsec CTF：[点击跳转](https://ctf.wgpsec.org/)

  * PwnTheBox：[点击跳转](https://www.pwnthebox.com/)

  * 合天网安实验室：[点击跳转](https://www.hetianlab.com/)

  * 中学生CTF练习平台：[点击跳转](http://www.zxsctf.com/)

  ## 专项靶机平台

  * Sqli-labs：SQL注入 [点击跳转](https://github.com/Audi-1/sqli-labs)

  * Xss-labs：XSS注入 [点击跳转](https://github.com/do0dl3/xss-labs)

  * Upload-labs：上传漏洞 [点击跳转](https://github.com/c0ny1/upload-labs)

  ## 综合靶机平台

  * DVWA：[点击跳转](https://github.com/digininja/DVWA)

  * WebGoat：[点击跳转](https://github.com/WebGoat/WebGoat)

  * HackTheBox：[点击跳转](https://www.hackthebox.com/)

  * OWASP Top10：[点击跳转](https://owasp.org/www-project-juice-shop/)

  * Vulstudy：docker快速搭建共17个漏洞靶场 [点击跳转](https://github.com/c0ny1/vulstudy)

# 信息收集

  ## 指纹识别

  * 云悉指纹识别：[点击跳转](http://www.yunsee.cn/)

  * 御剑web指纹识别程序：[点击跳转](https://www.webshell.cc/4697.html)

  * Wapplyzer：Chrome插件 跨平台网站分析工具 [点击跳转](https://github.com/AliasIO/Wappalyzer)

  * TideFinger：提取了多个开源指纹识别工具的规则库并进行了规则重组 [点击跳转](https://github.com/TideSec/TideFinger)
  ## 扫描/爆破

  * Hydra：弱密码爆破 [点击跳转](https://github.com/vanhauser-thc/thc-hydra)

  * dirmap：目录扫描/爆破 [点击跳转](https://github.com/H4ckForJob/dirmap)

  * Arjun：HTTP参数扫描器 [点击跳转](https://github.com/s0md3v/Arjun)

  * ksubdomain：子域名爆破 [点击跳转](https://github.com/knownsec/ksubdomain)

  * dirsearch：目录扫描/爆破 [点击跳转](https://github.com/maurosoria/dirsearch)

  * Gobuster：URI/DNS/WEB爆破 [点击跳转](https://github.com/OJ/gobuster)


  ## 爆破字典

  * fuzzDicts：Web渗透Fuzz字典[点击跳转]( https://github.com/TheKingOfDuck/fuzzDicts)

  * PentesterSpecialDict：渗透测试工程师精简化字典 [点击跳转](https://github.com/ppbibo/PentesterSpecialDict)

  * Dictionary-Of-Pentesting：渗透测试、SRC漏洞挖掘、爆破、Fuzzing等常用字典 [点击跳转](https://github.com/insightglacier/Dictionary-Of-Pentesting)

  ## 综合信息收集

  * AlliN：[点击跳转](https://github.com/P1-Team/AlliN)

  * Kunyu：[点击跳转](https://github.com/knownsec/Kunyu)

  * ShuiZe：[点击跳转](https://github.com/0x727/ShuiZe_0x727)

  * OneForAll：[点击跳转](https://github.com/shmilylty/OneForAll)

  * Fofa Viewer：[点击跳转](https://github.com/wgpsec/fofa_viewer)

  ## 内网信息收集

  * fscan：内网综合扫描工具 [点击跳转](https://github.com/shadow1ng/fscan)

  * EHole：红队重点攻击系统指纹探测工具 [点击跳转](https://github.com/EdgeSecurityTeam/EHole)

  * hping3：端口扫描 高速 发包量少 结果准确无蜜罐 [点击跳转](https://github.com/antirez/hping)

  * Ladon：用于大型网络渗透的多线程插件化综合扫描工具 [点击跳转](https://github.com/k8gege/Ladon)

# 漏洞研究

  ## 漏洞平台

  * Vulhub：[点击跳转](https://vulhub.org/)

  * 乌云镜像：[点击跳转](http://wooyun.2xss.cc/)

  * HackerOne：[点击跳转](https://www.hackerone.com/)

  * Exploit Database：[点击跳转](https://www.exploit-db.com/)

  * 知道创宇漏洞平台：[点击跳转](https://www.seebug.org/)

  ## 漏洞知识库项目

    * Vulnerability Wiki：[点击跳转](https://github.com/Threekiii/Vulnerability-Wiki)

    >Vulnerability Wiki，一个基于docsify开发的漏洞知识库项目，集成了Vulhub、Peiqi、0sec、Wooyun（待更新）等开源漏洞库。可以通过docsify自定义部署（推荐docsify部署），也可以通过docker快速部署。


  ## 公开知识库


  * 先知社区：[点击跳转](https://xz.aliyun.com/)

  * 狼组公开知识库：[点击跳转](https://wiki.wgpsec.org/)


  * 零组文库：零组已停运，非官方 [点击跳转](https://0-wiki.com/)

  * 404星链计划：知道创宇 404 实验室[点击跳转]( https://github.com/knownsec/404StarLink)

  * MITRE ATT＆CK：网络攻击中使用的已知对抗战术和技术 [点击跳转](https://attack.mitre.org/matrices/enterprise/)

  ## 漏洞综述

  * 未授权访问漏洞总结：[点击跳转](http://luckyzmj.cn/posts/15dff4d3.html#toc-heading-3)

  ## 漏洞挖掘

  * Linux_Exploit_Suggester：[点击跳转](https://github.com/InteliSecureLabs/Linux_Exploit_Suggester)

  * Windows-Exploit-Suggester：[点击跳转](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

  ## 开源漏洞库

  * PeiQi：[点击跳转](http://wiki.peiqi.tech/)

  * Vulhub：[点击跳转](https://vulhub.org/)

  * POChouse：[点击跳转](https://github.com/DawnFlame/POChouse)

  * Vulnerability：[点击跳转](https://github.com/EdgeSecurityTeam/Vulnerability)


  ## POC/EXP

  * ysoserial：Java反序列化 [点击跳转](https://github.com/frohoff/ysoserial)

  * Penetration_Testing_POC：[点击跳转](https://github.com/Mr-xn/Penetration_Testing_POC)

  * Vulmap：漏洞扫描和验证工具 [点击跳转](https://github.com/zhzyker/vulmap)


  * CMS-Hunter：CMS漏洞测试用例集合 [点击跳转](https://github.com/SecWiki/CMS-Hunter)

  * Some-PoC-oR-ExP：各种漏洞PoC、ExP的收集或编写 [点击跳转](https://github.com/coffeehb/Some-PoC-oR-ExP)

# 内网渗透

  ## Bypass

  * JSFuck：[点击跳转](http://www.jsfuck.com/)

  * PHPFuck：[点击跳转](https://github.com/splitline/PHPFuck)


  ## Payloads

  * PayloadsAllTheThings：[点击跳转](https://github.com/swisskyrepo/PayloadsAllTheThings)

  * PHP Generic Gadget Chains：PHP反序列化Payload [点击跳转](https://github.com/ambionics/phpggc)

  * java.lang.Runtime.exec() Payload：java Payload在线生成 [点击跳转](https://www.bugku.net/runtime-exec-payloads/)

  ## WebShell

  * Behinder 冰蝎：[点击跳转](https://github.com/rebeyond/Behinder)

    > Behinder3：kali + java 11.0.14 或 windows10 + java
    > 1.8.0_91，注意，该环境下Behinder2无法正常运行 Behinder2：windows10 + java 1.8.0_91

  * Godzilla 哥斯拉：[点击跳转](https://github.com/BeichenDream/Godzilla)

  * Webshell收集项目：[点击跳转](https://github.com/tennc/webshell)

  ## 内网穿透

  * FRP：55k star项目 [点击跳转](https://github.com/fatedier/frp)

  * Proxychains：kali代理工具 [点击跳转](https://github.com/haad/proxychains)

  * Proxifier：windows代理工具 [点击跳转](https://www.proxifier.com/)

  * Neo-reGeorg：tunnel快速部署 [点击跳转](https://github.com/L-codes/Neo-reGeorg)

  * NPS：通过web端管理，无需配置文件 [点击跳转](https://github.com/ehang-io/nps)

  ## 开源蜜罐

  * HFish：一款安全、简单可信赖的跨平台蜜罐软件，允许商业和个人用户免费使用 [点击跳转](https://github.com/hacklcx/HFish)

  ## 容器逃逸

  * CDK：容器渗透 [点击跳转](https://github.com/cdk-team/CDK)

  ## 其他

  * Responder：实现获取NTLM Hash等功能 [点击跳转](https://github.com/SpiderLabs/Responder)

  * The art of command line：快速掌握命令行 [点击跳转](https://github.com/jlevy/the-art-of-command-line)

  * PsTools：PsExec.exe功能同Impacket中的psexec.py [点击跳转](https://docs.microsoft.com/en-us/sysinternals/downloads/pstools)

  * Impacket：其中的psexec.py通过用户名和密码远程连接到目标服务器 [点击跳转](https://github.com/SecureAuthCorp/impacket)

# 移动端/物联网

  * CrackMinApp：反编译微信小程序 [点击跳转](https://github.com/Cherrison/CrackMinApp)

  * AppInfoScanner：移动端信息收集 [点击跳转](https://github.com/kelvinBen/AppInfoScanner)

  * IoT-vulhub：IoT 版固件漏洞复现环境 [点击跳转](https://github.com/firmianay/IoT-vulhub)

# 逆向分析

  * PEiD：查壳工具 [点击跳转](https://www.aldeid.com/wiki/PEiD)

  * 逆向分析工具集：[点击跳转](https://pythonarsenal.com/)

  * Py2exe：Python打包工具 [点击跳转](https://www.py2exe.org/)

  * PyInstaller：Python打包工具 [点击跳转](https://github.com/pyinstaller/pyinstaller)

# 实用工具

  * XSS Chop：[点击跳转](https://xsschop.chaitin.cn/demo/)

  * WebShell查杀：[点击跳转](https://n.shellpub.com/)

  * Webshell Chop：[点击跳转](https://webshellchop.chaitin.cn/demo/)

  * 在线正则表达式：[点击跳转](https://c.runoob.com/front-end/854/)

  * 在线代码格式标准化：[点击跳转](http://web.chacuo.net/formatsh)

  * DNS log：DNS oob平台 [点击跳转](http://dnslog.cn/)

  * Ceye DNS：DNS oob平台 [点击跳转](http://ceye.io/)

  * Google Hacking Database：[点击跳转](https://www.exploit-db.com/google-hacking-database)

  * Explain Shell：Shell命令解析 [点击跳转](https://explainshell.com/)

  * Wayback Machine：网页缓存查询 [点击跳转](https://archive.org/web)

  * HTML5 Security Cheatsheet：XSS攻击向量学习/参考 [点击跳转](https://html5sec.org/)

# 工具插件

  ## Metasploit

  * Metasploit：[点击跳转](https://github.com/rapid7/metasploit-framework)

  ## Cobaltstrike

  * ElevateKit：提权插件 [点击跳转](https://github.com/rsmudge/ElevateKit)

  * LSTAR：综合后渗透插件 [点击跳转](https://github.com/lintstar/LSTAR)

  * Erebus：后渗透测试插件 [点击跳转](https://github.com/DeEpinGh0st/Erebus)

  * Awesome CobaltStrike：CobaltStrike知识库 [点击跳转](https://github.com/zer0yu/Awesome-CobaltStrike)

  ## Burpsuite

  * Log4j2Scan：Log4j主动扫描 [点击跳转](https://github.com/whwlsfb/Log4j2Scan)

  * HaE：高亮标记与信息提取辅助型插件 [点击跳转](https://github.com/gh0stkey/HaE)

  ## Chrome crx

  * Hack Bar：渗透神器No.1 [点击跳转](https://github.com/0140454/hackbar)

  * Hunter：查找网页暴露邮箱 [点击跳转](https://hunter.io/chrome)

  * EditThisCookie：修改Cookie [点击跳转](https://www.editthiscookie.com/)

  * Proxy SwitchyOmega：快速切换代理 [点击跳转](https://github.com/FelisCatus/SwitchyOmega)

  * Wappalyzer：识别网站技术/框架/语言 [点击跳转](https://www.wappalyzer.com/)

  * Disable JavaScript：禁用JavaScript绕过弹窗 [点击跳转](https://github.com/dpacassi/disable-javascript)

  * FindSomething：在网页的源代码或js中寻找有用信息 [点击跳转](https://github.com/ResidualLaugh/FindSomething)

  ## Xray

  * Xray：安全评估工具 [点击跳转](https://github.com/chaitin/xray)



# 本文内容来自网络个人稍加整理如有侵权联系本人删除

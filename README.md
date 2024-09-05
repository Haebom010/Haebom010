port: 7890
socks-port: 7891
redir-port: 9797
tproxy-port: 9898
mode: rule
allow-lan: true
unified-delay: false
bind-address: '*'
# info / warning / error / debug / silent
log-level: silent
ipv6: false
geodata-mode: true
geodata-loader: memconservative
external-controller: 0.0.0.0:9090 
# external-controller-tls: 0.0.0.0:9091 # RESTful API HTTPS device
# secret: "123456"
external-ui: ./dashboard/dist
# tcp-concurrent: false
# inbound-tfo: false
# global-client-fingerprint: chrome
# interface-name: "rmnet_data+"
# routing-mark: 233
geox-url:
  mmdb: "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country-only-cn-private.mmdb"
  geoip: "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/cn.dat"
  geosite: "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat"
 # mmdb: "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb"
 # geoip: "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat"
 # geosite: "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat"
find-process-mode: always

profile:
  store-selected: true
  store-fake-ip: false

sniffer:
  enable: true
  ## 对 redir-host 类型识别的流量进行强制嗅探
  ## 如：Tun、Redir 和 TProxy 并 DNS 为 redir-host 皆属于
  force-dns-mapping: false
  parse-pure-ip: false
  override-destination: false
  sniff:
    TLS:
      ports: [443, 8443]
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
  force-domain:
    - +.play-fe.googleapis.com
    - +.play.googleapis.com
  # skip-domain:
    # # - +.google.com
  sniffing:
    - tls
    - http
  port-whitelist:
    - "80"
    - "443"

dns:
  enable: true
  prefer-h3: false
  use-hosts: false
  use-system-hosts: false
  listen: 0.0.0.0:1053
  ipv6: false
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
 # 可选值 fake-ip / redir-host
  enhanced-mode: redir-host
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '*.lan'
    - localhost.ptlogin2.qq.com
  nameserver-policy:
    'www.baidu.com': '114.114.114.114'
    '+.internal.crop.com': '10.0.0.1'
    'geosite:cn': https://doh.pub/dns-query
  nameserver:
    - https://dns.google/dns-query
    - https://cloudflare-dns.com/dns-query
  fallback:
    - https://dns.google/dns-query
    - https://cloudflare-dns.com/dns-query
    - https://1.0.0.1/dns-query
    - https://1.1.1.1/dns-query
    - https://public.dns.iij.jp/dns-query
    - https://doh.dns.sb/dns-query
    - tls://dns.google
  proxy-server-nameserver:
    - https://doh.pub/dns-query
    - '[2404:c0:1000::a:0:1]'
    - '[2400:9800:2:2::245]'
    - '[2400:9800:2:2::246]'
  fallback-filter:
    geoip: false
    geoip-code: CN
    geosite:
      - gfw
    ipcidr:
      - 240.0.0.0/4
    domain:
      - +.google.com
      - +.facebook.com
      - +.xn--ngstr-lra8j.com
      - +.youtube.com
      - +.telegram.com
      - +.twitter.com
      - +.github.com
      - +.onedrive.live.com
      - +.play-fe.googleapis.com
      - +.play.googleapis.com
      - +.xn--ngstr-lra8j.com
      - +.accounts.google.com
      - +.google.cn
      - +.googleapis.cn
      - +.googleapis.com
      - +.gvt1.com
      - +.17995api.com
      - +.17996api.com
      - +.easebar.com
      - +.netease.com
      - +.play-lh.googleusercontent.com
      - +.sololv.gcdn.netmarble.com
      - +.apis.netmarble.com
      - +.nmss.gcdn.netmarble.com
      - +.netmarbleslog.netmarble.com

hosts:
  # block update system android
  'ota.googlezip.net': 127.0.0.1
  'ota-cache1.googlezip.net': 127.0.0.1
  'ota-cache2.googlezip.net': 127.0.0.1

proxies:

proxy-providers:
  playstore:
    type: http
    url: "https://drive.google.com/uc?export=download&id=1YOl06HzS1om1VUAR6HYtwYItDdwumtMZ"
    path: ./proxy_providers/playstore.yaml
    interval: 800
    health-check:
      enable: true
      url: http://www.gstatic.com/generate_204
      interval: 900

proxy-groups:
  - name: Thai proxies
    type: select
    use:
      - playstore

rule-providers:
  Playstore:
    type: http
    behavior: classical
    url: "https://drive.google.com/uc?export=download&id=1vCLT7dR3pHvvQV_j-0JmTSLpSaxrJSKK"
    path: ./ruleset/Playstore.yaml
    interval: 400

rules:
  # 自定义规则
  - DOMAIN-KEYWORD,ip-api.com,Thai proxies
  - DOMAIN-KEYWORD,ip.skk.moe,Thai proxies
  - DOMAIN-KEYWORD,ip.sb,Thai proxies
  - DOMAIN-KEYWORD,ipapi.co,Thai proxies
  - DOMAIN-KEYWORD,ip-api.com,Thai proxies
  - DOMAIN-KEYWORD,api.ip.sb,Thai proxies
  - DOMAIN-KEYWORD,IPInfo.io,Thai proxies
  - DOMAIN-KEYWORD,ipip.net,Thai proxies
  - DOMAIN-KEYWORD,skk.moe,Thai proxies
  - AND,((DST-PORT,443),(NETWORK,UDP),(IP-CIDR,172.217.163.46/16)),REJECT
  - AND,((DST-PORT,443),(NETWORK,UDP),(IP-CIDR,142.250.204.46/16)),REJECT
  - AND,((DST-PORT,443),(NETWORK,UDP),(IP-CIDR,142.251.204.46/16)),REJECT
  - AND,((DST-PORT,443),(NETWORK,UDP),(RULE-SET,Playstore)),REJECT
  - AND,((NETWORK,UDP),(RULE-SET,Playstore)),REJECT
  #- DOMAIN,playatoms-pa.googleapis.com,Thai proxies
  #- DOMAIN,safebrowsing.googleapis.com,Thai proxies
  #- DOMAIN,play.google.com,Thai proxies
  #- DOMAIN,people-pa.googleapis.com,Thai proxies
  #- DOMAIN,drive.usercontent.google.com,Thai proxies
  #- DOMAIN,android.googleapis.com,Thai proxies
  #- DOMAIN,instantmessaging-pa.googleapis.com,Thai proxies
  #- DOMAIN,phonedeviceverification-pa.googleapis.com,Thai proxies
  #- DOMAIN,prod-lt-playstoregatewayadapter-pa.googleapis.com,Thai proxies
  - RULE-SET,Playstore,Thai proxies

  - DOMAIN-SUFFIX,1password.com,DIRECT
  - DOMAIN-SUFFIX,vultr.com,DIRECT
  - DOMAIN-SUFFIX,mb3admin.com,DIRECT
  - DOMAIN-SUFFIX,rixcloud.io,DIRECT
  - DOMAIN-SUFFIX,tempestapp.io,DIRECT
  - DOMAIN-SUFFIX,baidu.com,DIRECT
  - DOMAIN-SUFFIX,baidu-int.com,DIRECT
  - DOMAIN-SUFFIX,erebor.douban.com,DIRECT
  - DOMAIN,mtalk.google.com,DIRECT
  - DOMAIN,alt1-mtalk.google.com,DIRECT
  - DOMAIN,alt2-mtalk.google.com,DIRECT
  - DOMAIN,alt3-mtalk.google.com,DIRECT
  - DOMAIN,alt4-mtalk.google.com,DIRECT
  - DOMAIN,alt5-mtalk.google.com,DIRECT
  - DOMAIN,alt6-mtalk.google.com,DIRECT
  - DOMAIN,alt7-mtalk.google.com,DIRECT
  - DOMAIN,alt8-mtalk.google.com,DIRECT
  - DOMAIN,alt9-mtalk.google.com,DIRECT
  - DOMAIN,captive.apple.com,DIRECT
  - DOMAIN,time-ios.apple.com,DIRECT
  - DOMAIN-SUFFIX,gateway.push-apple.com.akadns.net,DIRECT
  - DOMAIN-SUFFIX,push.apple.com,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,DIRECT

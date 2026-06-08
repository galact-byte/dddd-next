// Package cdn identifies whether a domain sits behind a CDN/WAF, primarily so a
// scan can tell the operator that a resolved IP is an edge node, not the origin.
//
// Detection is CNAME-suffix based, ported from SleepingBag945/dddd's utils/cdn.
// Its value over httpx's IP-range cdncheck is the curated database of Chinese
// CDN providers (Alibaba, Tencent, Wangsu, Baidu, Huawei, ...) that IP-range
// checks miss.
//
// Two of the original's heuristics are deliberately dropped: "any IPv6 domain"
// and "multiple A records + a CNAME". Both produce false positives, and since a
// CDN verdict can exclude a host from scanning, a false positive means a missed
// target — the opposite of what this tool is for. We keep only high-precision
// signals: a known CDN IP, a known CDN CNAME suffix, or a cdn/waf CNAME keyword.
package cdn

import (
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// dnsServers are public resolvers queried for the CNAME chain. The first to
// answer wins.
var dnsServers = []string{
	"223.5.5.5:53",
	"114.114.114.114:53",
	"119.29.29.29:53",
	"180.76.76.76:53",
}

// Result is a CDN verdict for one domain.
type Result struct {
	Domain   string
	IsCDN    bool
	Provider string
	IPs      []net.IP
}

// Check resolves domain and reports whether it is fronted by a CDN/WAF.
func Check(domain string) Result {
	res := Result{Domain: domain}

	ips, err := net.LookupIP(domain)
	if err == nil {
		res.IPs = ips
		if isCDN, name := matchByIP(ips); isCDN {
			res.IsCDN, res.Provider = true, name
			return res
		}
	}

	cnames, err := lookupCNAME(domain)
	if err != nil {
		return res
	}
	if isCDN, name := matchByCNAME(cnames); isCDN {
		res.IsCDN, res.Provider = true, name
	}
	return res
}

// matchByIP flags IPs that belong to a known CDN address.
func matchByIP(ips []net.IP) (bool, string) {
	for _, ip := range ips {
		for _, item := range ipItems {
			if ip.String() == item.ip {
				return true, item.name
			}
		}
	}
	return false, ""
}

// matchByCNAME flags a CNAME chain that ends in a known CDN suffix or carries a
// cdn/waf keyword. Pure function — unit-tested without DNS.
func matchByCNAME(cnames []string) (bool, string) {
	for _, cname := range cnames {
		lower := strings.ToLower(cname)
		for _, item := range domainItems {
			if strings.Contains(lower, item.Domain) {
				return true, item.Name
			}
		}
		if strings.Contains(lower, "cdn") {
			return true, "CNAME keyword: cdn"
		}
		if strings.Contains(lower, "waf") {
			return true, "CNAME keyword: waf"
		}
	}
	return false, ""
}

func lookupCNAME(domain string) ([]string, error) {
	var lastErr error
	for _, server := range dnsServers {
		cnames, err := lookupCNAMEWithServer(domain, server)
		if err == nil {
			return cnames, nil // first responding resolver wins (original had no failover)
		}
		lastErr = err
	}
	return nil, lastErr
}

// lookupCNAMEWithServer asks one resolver for domain's A record and collects
// every CNAME the answer chain passes through.
func lookupCNAMEWithServer(domain, server string) ([]string, error) {
	c := dns.Client{Timeout: 5 * time.Second}
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	r, _, err := c.Exchange(&m, server)
	if err != nil {
		return nil, err
	}
	var cnames []string
	for _, ans := range r.Answer {
		if rec, ok := ans.(*dns.CNAME); ok {
			cnames = append(cnames, rec.Target)
		}
	}
	return cnames, nil
}

type domainItem struct {
	Domain string
	Name   string
}

type ipItem struct {
	ip   string
	name string
}

var ipItems = []ipItem{
	{"223.4.77.85", "ALLELINK"},
}

var domainItems = []domainItem{
	{"15cdn.com", "腾正安全加速（原 15CDN）"},
	{"tzcdn.cn", "腾正安全加速（原 15CDN）"},
	{"cedexis.net", "Cedexis GSLB"},
	{"cdxcn.cn", "Cedexis GSLB (For China)"},
	{"qhcdn.com", "360 云 CDN"},
	{"qh-cdn.com", "360 云 CDN"},
	{"qihucdn.com", "360 云 CDN"},
	{"360cdn.com", "360 云 CDN"},
	{"360cloudwaf.com", "奇安信网站卫士"},
	{"360anyu.com", "奇安信网站卫士"},
	{"360safedns.com", "奇安信网站卫士"},
	{"360wzws.com", "奇安信网站卫士"},
	{"akamai.net", "Akamai CDN"},
	{"akamaiedge.net", "Akamai CDN"},
	{"ytcdn.net", "Akamai CDN"},
	{"edgesuite.net", "Akamai CDN"},
	{"akamaitech.net", "Akamai CDN"},
	{"akamaitechnologies.com", "Akamai CDN"},
	{"edgekey.net", "Akamai CDN"},
	{"tl88.net", "易通锐进（Akamai 中国）"},
	{"cloudfront.net", "AWS CloudFront"},
	{"worldcdn.net", "CDN.NET"},
	{"worldssl.net", "CDN.NET / CDNSUN / ONAPP"},
	{"cdn77.org", "CDN77"},
	{"panthercdn.com", "CDNetworks"},
	{"cdnga.net", "CDNetworks"},
	{"cdngc.net", "CDNetworks"},
	{"gccdn.net", "CDNetworks"},
	{"gccdn.cn", "CDNetworks"},
	{"akamaized.net", "Akamai CDN"},
	{"126.net", "网易云 CDN"},
	{"163jiasu.com", "网易云 CDN"},
	{"amazonaws.com", "AWS Cloud"},
	{"cdn77.net", "CDN77"},
	{"cdnify.io", "CDNIFY"},
	{"cdnsun.net", "CDNSUN"},
	{"bdydns.com", "百度云 CDN"},
	{"ccgslb.com.cn", "蓝汛 CDN"},
	{"ccgslb.net", "蓝汛 CDN"},
	{"ccgslb.com", "蓝汛 CDN"},
	{"ccgslb.cn", "蓝汛 CDN"},
	{"c3cache.net", "蓝汛 CDN"},
	{"c3dns.net", "蓝汛 CDN"},
	{"chinacache.net", "蓝汛 CDN"},
	{"wswebcdn.com", "网宿 CDN"},
	{"lxdns.com", "网宿 CDN"},
	{"wswebpic.com", "网宿 CDN"},
	{"cloudflare.net", "Cloudflare"},
	{"akadns.net", "Akamai CDN"},
	{"chinanetcenter.com", "网宿 CDN"},
	{"customcdn.com.cn", "网宿 CDN"},
	{"customcdn.cn", "网宿 CDN"},
	{"51cdn.com", "网宿 CDN"},
	{"wscdns.com", "网宿 CDN"},
	{"cdn20.com", "网宿 CDN"},
	{"wsdvs.com", "网宿 CDN"},
	{"wsglb0.com", "网宿 CDN"},
	{"speedcdns.com", "网宿 CDN"},
	{"wtxcdn.com", "网宿 CDN"},
	{"wsssec.com", "网宿 WAF CDN"},
	{"fastly.net", "Fastly"},
	{"fastlylb.net", "Fastly"},
	{"hwcdn.net", "Stackpath (原 Highwinds)"},
	{"incapdns.net", "Incapsula CDN"},
	{"kxcdn.com.", "KeyCDN"},
	{"lswcdn.net", "LeaseWeb CDN"},
	{"mwcloudcdn.com", "QUANTIL (网宿)"},
	{"mwcname.com", "QUANTIL (网宿)"},
	{"azureedge.net", "Microsoft Azure CDN"},
	{"msecnd.net", "Microsoft Azure CDN"},
	{"mschcdn.com", "Microsoft Azure CDN"},
	{"v0cdn.net", "Microsoft Azure CDN"},
	{"azurewebsites.net", "Microsoft Azure App Service"},
	{"azurewebsites.windows.net", "Microsoft Azure App Service"},
	{"trafficmanager.net", "Microsoft Azure Traffic Manager"},
	{"cloudapp.net", "Microsoft Azure"},
	{"chinacloudsites.cn", "世纪互联蓝云（Azure 中国）"},
	{"spdydns.com", "云端智度融合 CDN"},
	{"jiashule.com", "知道创宇云安全加速乐CDN"},
	{"jiasule.org", "知道创宇云安全加速乐CDN"},
	{"365cyd.cn", "知道创宇创宇盾"},
	{"huaweicloud.com", "华为云WAF高防云盾"},
	{"cdnhwc1.com", "华为云 CDN"},
	{"cdnhwc2.com", "华为云 CDN"},
	{"cdnhwc3.com", "华为云 CDN"},
	{"dnion.com", "帝联科技"},
	{"ewcache.com", "帝联科技"},
	{"globalcdn.cn", "帝联科技"},
	{"tlgslb.com", "帝联科技"},
	{"fastcdn.com", "帝联科技"},
	{"flxdns.com", "帝联科技"},
	{"dlgslb.cn", "帝联科技"},
	{"newdefend.cn", "牛盾云安全"},
	{"ffdns.net", "CloudXNS"},
	{"aocdn.com", "可靠云 CDN"},
	{"bsgslb.cn", "白山云 CDN"},
	{"qingcdn.com", "白山云 CDN"},
	{"bsclink.cn", "白山云 CDN"},
	{"trpcdn.net", "白山云 CDN"},
	{"anquan.io", "牛盾云安全"},
	{"cloudglb.com", "快网 CDN"},
	{"fastweb.com", "快网 CDN"},
	{"fastwebcdn.com", "快网 CDN"},
	{"cloudcdn.net", "快网 CDN"},
	{"fwcdn.com", "快网 CDN"},
	{"fwdns.net", "快网 CDN"},
	{"hadns.net", "快网 CDN"},
	{"hacdn.net", "快网 CDN"},
	{"cachecn.com", "快网 CDN"},
	{"qingcache.com", "青云 CDN"},
	{"qingcloud.com", "青云 CDN"},
	{"frontwize.com", "青云 CDN"},
	{"msscdn.com", "美团云 CDN"},
	{"800cdn.com", "西部数码"},
	{"tbcache.com", "阿里云 CDN"},
	{"aliyun-inc.com", "阿里云 CDN"},
	{"aliyuncs.com", "阿里云 CDN"},
	{"alikunlun.net", "阿里云 CDN"},
	{"alikunlun.com", "阿里云 CDN"},
	{"alicdn.com", "阿里云 CDN"},
	{"aligaofang.com", "阿里云盾高防"},
	{"yundunddos.com", "阿里云盾高防"},
	{"cdngslb.com", "阿里云 CDN"},
	{"yunjiasu-cdn.net", "百度云加速"},
	{"momentcdn.com", "魔门云 CDN"},
	{"aicdn.com", "又拍云"},
	{"qbox.me", "七牛云"},
	{"qiniu.com", "七牛云"},
	{"qiniudns.com", "七牛云"},
	{"jcloudcs.com", "京东云 CDN"},
	{"jdcdn.com", "京东云 CDN"},
	{"qianxun.com", "京东云 CDN"},
	{"jcloudlb.com", "京东云 CDN"},
	{"jcloud-cdn.com", "京东云 CDN"},
	{"maoyun.tv", "猫云融合 CDN"},
	{"maoyundns.com", "猫云融合 CDN"},
	{"xgslb.net", "WebLuker (蓝汛)"},
	{"ucloud.cn", "UCloud CDN"},
	{"ucloud.com.cn", "UCloud CDN"},
	{"cdndo.com", "UCloud CDN"},
	{"zenlogic.net", "Zenlayer CDN"},
	{"ogslb.com", "Zenlayer CDN"},
	{"uxengine.net", "Zenlayer CDN"},
	{"tan14.net", "TAN14 CDN"},
	{"verycloud.cn", "VeryCloud 云分发"},
	{"verycdn.net", "VeryCloud 云分发"},
	{"verygslb.com", "VeryCloud 云分发"},
	{"xundayun.cn", "SpeedyCloud CDN"},
	{"xundayun.com", "SpeedyCloud CDN"},
	{"speedycloud.cc", "SpeedyCloud CDN"},
	{"mucdn.net", "Verizon CDN (Edgecast)"},
	{"nucdn.net", "Verizon CDN (Edgecast)"},
	{"alphacdn.net", "Verizon CDN (Edgecast)"},
	{"systemcdn.net", "Verizon CDN (Edgecast)"},
	{"edgecastcdn.net", "Verizon CDN (Edgecast)"},
	{"zetacdn.net", "Verizon CDN (Edgecast)"},
	{"coding.io", "Coding Pages"},
	{"coding.me", "Coding Pages"},
	{"gitlab.io", "GitLab Pages"},
	{"github.io", "GitHub Pages"},
	{"herokuapp.com", "Heroku SaaS"},
	{"googleapis.com", "Google Cloud Storage"},
	{"netdna.com", "Stackpath (原 MaxCDN)"},
	{"netdna-cdn.com", "Stackpath (原 MaxCDN)"},
	{"netdna-ssl.com", "Stackpath (原 MaxCDN)"},
	{"cdntip.com", "腾讯云 CDN"},
	{"dnsv1.com", "腾讯云 CDN"},
	{"tencdns.net", "腾讯云 CDN"},
	{"dayugslb.com", "腾讯云大禹 BGP 高防"},
	{"tcdnvod.com", "腾讯云视频 CDN"},
	{"tdnsv5.com", "腾讯云 CDN"},
	{"ksyuncdn.com", "金山云 CDN"},
	{"ks-cdn.com", "金山云 CDN"},
	{"ksyuncdn-k1.com", "金山云 CDN"},
	{"netlify.com", "Netlify"},
	{"zeit.co", "ZEIT Now Smart CDN"},
	{"zeit-cdn.net", "ZEIT Now Smart CDN"},
	{"b-cdn.net", "Bunny CDN"},
	{"lsycdn.com", "蓝视云 CDN"},
	{"scsdns.com", "逸云科技云加速 CDN"},
	{"quic.cloud", "QUIC.Cloud"},
	{"flexbalancer.net", "FlexBalancer"},
	{"gcdn.co", "G-Core Labs"},
	{"sangfordns.com", "深信服 AD 应用交付"},
	{"stspg-customer.com", "StatusPage.io"},
	{"turbobytes.net", "TurboBytes Multi-CDN"},
	{"turbobytes-cdn.com", "TurboBytes Multi-CDN"},
	{"att-dsa.net", "AT&T CDN"},
	{"azioncdn.net", "Azion Edge"},
	{"belugacdn.com", "BelugaCDN"},
	{"cachefly.net", "CacheFly CDN"},
	{"inscname.net", "Instart CDN"},
	{"insnw.net", "Instart CDN"},
	{"internapcdn.net", "Internap CDN"},
	{"footprint.net", "CenturyLink CDN (原 Level 3)"},
	{"llnwi.net", "Limelight Network"},
	{"llnwd.net", "Limelight Network"},
	{"unud.net", "Limelight Network"},
	{"lldns.net", "Limelight Network"},
	{"stackpathdns.com", "Stackpath CDN"},
	{"stackpathcdn.com", "Stackpath CDN"},
	{"mncdn.com", "Medianova"},
	{"rncdn1.com", "Reflected Networks"},
	{"simplecdn.net", "Reflected Networks"},
	{"swiftserve.com", "Conversant SwiftServe CDN"},
	{"bitgravity.com", "Tata communications CDN"},
	{"zenedge.net", "Oracle Dyn WAF (原 Zenedge)"},
	{"biliapi.com", "Bilibili 业务 GSLB"},
	{"hdslb.net", "Bilibili 高可用负载均衡"},
	{"hdslb.com", "Bilibili 高可用负载均衡"},
	{"xwaf.cn", "极御云安全"},
	{"shifen.com", "百度地域负载均衡"},
	{"sinajs.cn", "新浪静态域名"},
	{"tencent-cloud.net", "腾讯地域负载均衡"},
	{"elemecdn.com", "饿了么静态域名与地域负载均衡"},
	{"sinaedge.com", "新浪融合CDN负载均衡"},
	{"sina.com.cn", "新浪融合CDN负载均衡"},
	{"sinacdn.com", "新浪云 CDN"},
	{"sinasws.com", "新浪云 CDN"},
	{"saebbs.com", "新浪云 SAE"},
	{"websitecname.cn", "美橙互联建站之星"},
	{"cdncenter.cn", "美橙互联CDN"},
	{"vhostgo.com", "西部数码虚拟主机"},
	{"jsd.cc", "上海云盾YUNDUN"},
	{"powercdn.cn", "动力在线CDN"},
	{"21vokglb.cn", "世纪互联云快线"},
	{"21vianet.com.cn", "世纪互联云快线"},
	{"21okglb.cn", "世纪互联云快线"},
	{"21speedcdn.com", "世纪互联云快线"},
	{"21cvcdn.com", "世纪互联云快线"},
	{"okcdn.com", "世纪互联云快线"},
	{"okglb.com", "世纪互联云快线"},
	{"cdnetworks.net", "北京同兴万点"},
	{"txnetworks.cn", "北京同兴万点"},
	{"cdnnetworks.com", "北京同兴万点"},
	{"txcdn.cn", "北京同兴万点"},
	{"cdnunion.net", "上海万根（CDN 联盟）"},
	{"cdnunion.com", "上海万根（CDN 联盟）"},
	{"mygslb.com", "上海万根（YaoCDN）"},
	{"cdnudns.com", "上海万根（YaoCDN）"},
	{"sprycdn.com", "上海万根（YaoCDN）"},
	{"chuangcdn.com", "创世云融合 CDN"},
	{"aocde.com", "创世云融合 CDN"},
	{"ctxcdn.cn", "中国电信天翼云CDN"},
	{"yfcdn.net", "云帆加速CDN"},
	{"mmycdn.cn", "蛮蛮云 CDN"},
	{"chinamaincloud.com", "蛮蛮云 CDN"},
	{"cnispgroup.com", "中联数据"},
	{"cdnle.com", "新乐视云联 CDN"},
	{"gosuncdn.com", "高升控股CDN"},
	{"mmtrixopt.com", "mmTrix性能魔方"},
	{"cloudfence.cn", "蓝盾云CDN"},
	{"ngaagslb.cn", "新流云"},
	{"p2cdn.com", "星域云P2P CDN"},
	{"00cdn.com", "星域云P2P CDN"},
	{"sankuai.com", "美团云负载均衡"},
	{"lccdn.org", "领智云 CDN"},
	{"nscloudwaf.com", "绿盟云 WAF"},
	{"2cname.com", "网堤安全"},
	{"ucloudgda.com", "UCloud 罗马全球加速"},
	{"google.com", "Google Web 业务"},
	{"1e100.net", "Google Web 业务"},
	{"ncname.com", "NodeCache"},
	{"alipaydns.com", "蚂蚁金服地域负载均衡"},
	{"wscloudcdn.com", "全速云（网宿）CloudEdge"},
	{"saaswaf.com", "安恒信息玄武盾"},
	{"dbappwaf.cn", "安恒信息玄武盾"},
	{"cloudcdns.com", "云盾CDN"},
	{"yundundns.com", "云盾CDN"},
	{"yundunwaf2.com", "阿里云盾"},
}

package wrappers

// #include "wrappers_config.h"
// #cgo CFLAGS: -I/usr/local/include/ -I/opt/homebrew/include/
// #cgo LDFLAGS: -L/usr/local/lib -L/opt/homebrew/lib -lndpi -lm -pthread
// #include "nDPI_wrapper_impl.h"
import "C"
import (
	"sync"
	"unsafe"

	"github.com/dreadl0ck/go-dpi/types"
	"github.com/gopacket/gopacket"
	"github.com/pkg/errors"
)

// ndpiCodeToProtocol maps the nDPI protocol codes to go-dpi protocols.
// Generated from nDPI commit e9751cec26d80fe2d88706d4f7521a63ec12b3bb - 468 protocols (IDs 0-467)
var ndpiCodeToProtocol = map[uint32]types.Protocol{
	0:   types.Unknown,
	1:   types.FTP_CONTROL,
	2:   types.MAIL_POP,
	3:   types.MAIL_SMTP,
	4:   types.MAIL_IMAP,
	5:   types.DNS,
	6:   types.IPP,
	7:   types.HTTP,
	8:   types.MDNS,
	9:   types.NTP,
	10:  types.NETBIOS,
	11:  types.NFS,
	12:  types.SSDP,
	13:  types.BGP,
	14:  types.SNMP,
	15:  types.XDMCP,
	16:  types.SMBV1,
	17:  types.SYSLOG,
	18:  types.DHCP,
	19:  types.POSTGRES,
	20:  types.MYSQL,
	21:  types.MS_OUTLOOK,
	22:  types.VK,
	23:  types.MAIL_POPS,
	24:  types.TAILSCALE,
	25:  types.YANDEX,
	26:  types.NTOP,
	27:  types.COAP,
	28:  types.VMWARE,
	29:  types.MAIL_SMTPS,
	30:  types.DTLS,
	31:  types.UBNTAC2,
	32:  types.BFCP,
	33:  types.YANDEX_MAIL,
	34:  types.YANDEX_MUSIC,
	35:  types.GNUTELLA,
	36:  types.EDONKEY,
	37:  types.BITTORRENT,
	38:  types.MSTEAMS_CALL,
	39:  types.SIGNAL,
	40:  types.MEMCACHED,
	41:  types.SMBV23,
	42:  types.MINING,
	43:  types.NEST_LOG_SINK,
	44:  types.MODBUS,
	45:  types.WHATSAPP_CALL,
	46:  types.DATASAVER,
	47:  types.XBOX,
	48:  types.QQ,
	49:  types.TIKTOK,
	50:  types.RTSP,
	51:  types.MAIL_IMAPS,
	52:  types.ICECAST,
	53:  types.CPHA,
	54:  types.IQIYI,
	55:  types.ZATTOO,
	56:  types.YANDEX_MARKET,
	57:  types.YANDEX_DISK,
	58:  types.DISCORD,
	59:  types.ADOBE_CONNECT,
	60:  types.MONGODB,
	61:  types.PLURALSIGHT,
	62:  types.YANDEX_CLOUD,
	63:  types.OCSP,
	64:  types.VXLAN,
	65:  types.IRC,
	66:  types.MERAKI_CLOUD,
	67:  types.JABBER,
	68:  types.NATS,
	69:  types.AMONG_US,
	70:  types.YAHOO,
	71:  types.DISNEYPLUS,
	72:  types.HART_IP,
	73:  types.IP_VRRP,
	74:  types.STEAM,
	75:  types.MELSEC,
	76:  types.WORLDOFWARCRAFT,
	77:  types.TELNET,
	78:  types.STUN,
	79:  types.IPSEC,
	80:  types.IP_GRE,
	81:  types.IP_ICMP,
	82:  types.IP_IGMP,
	83:  types.IP_EGP,
	84:  types.IP_SCTP,
	85:  types.IP_OSPF,
	86:  types.IP_IP_IN_IP,
	87:  types.RTP,
	88:  types.RDP,
	89:  types.VNC,
	90:  types.TUMBLR,
	91:  types.TLS,
	92:  types.SSH,
	93:  types.USENET,
	94:  types.MGCP,
	95:  types.IAX,
	96:  types.TFTP,
	97:  types.AFP,
	98:  types.YANDEX_METRIKA,
	99:  types.YANDEX_DIRECT,
	100: types.SIP,
	101: types.TRUPHONE,
	102: types.IP_ICMPV6,
	103: types.DHCPV6,
	104: types.ARMAGETRON,
	105: types.CROSSFIRE,
	106: types.DOFUS,
	107: types.BLACKNUT,
	108: types.BOOSTEROID,
	109: types.GUILDWARS2,
	110: types.AMAZON_ALEXA,
	111: types.KERBEROS,
	112: types.LDAP,
	113: types.NEXON,
	114: types.MSSQL_TDS,
	115: types.PPTP,
	116: types.IP_AH,
	117: types.IP_ESP,
	118: types.SLACK,
	119: types.FACEBOOK,
	120: types.TWITTER,
	121: types.DROPBOX,
	122: types.GMAIL,
	123: types.GOOGLE_MAPS,
	124: types.YOUTUBE,
	125: types.MOZILLA,
	126: types.GOOGLE,
	127: types.MS_RPCH,
	128: types.NETFLOW,
	129: types.SFLOW,
	130: types.HTTP_CONNECT,
	131: types.HTTP_PROXY,
	132: types.CITRIX,
	133: types.NETFLIX,
	134: types.LASTFM,
	135: types.WAZE,
	136: types.YOUTUBE_UPLOAD,
	137: types.HULU,
	138: types.CHECKMK,
	139: types.AJP,
	140: types.APPLE,
	141: types.WEBEX,
	142: types.WHATSAPP,
	143: types.APPLE_ICLOUD,
	144: types.VIBER,
	145: types.APPLE_ITUNES,
	146: types.RADIUS,
	147: types.WINDOWS_UPDATE,
	148: types.TEAMVIEWER,
	149: types.EGD,
	150: types.HCL_NOTES,
	151: types.SAP,
	152: types.GTP,
	153: types.WSD,
	154: types.LLMNR,
	155: types.TOCA_BOCA,
	156: types.SPOTIFY,
	157: types.FACEBOOK_MESSENGER,
	158: types.H323,
	159: types.OPENVPN,
	160: types.NOE,
	161: types.CISCOVPN,
	162: types.TEAMSPEAK,
	163: types.TOR,
	164: types.SKINNY,
	165: types.RTCP,
	166: types.RSYNC,
	167: types.ORACLE,
	168: types.CORBA,
	169: types.CANONICAL,
	170: types.WHOIS_DAS,
	171: types.SD_RTN,
	172: types.SOCKS,
	173: types.NINTENDO,
	174: types.RTMP,
	175: types.FTP_DATA,
	176: types.WIKIPEDIA,
	177: types.ZMQ,
	178: types.AMAZON,
	179: types.EBAY,
	180: types.CNN,
	181: types.MEGACO,
	182: types.RESP,
	183: types.PINTEREST,
	184: types.OSPF,
	185: types.TELEGRAM,
	186: types.COD_MOBILE,
	187: types.PANDORA,
	188: types.QUIC,
	189: types.ZOOM,
	190: types.EAQ,
	191: types.OOKLA,
	192: types.AMQP,
	193: types.KAKAOTALK,
	194: types.KAKAOTALK_VOICE,
	195: types.TWITCH,
	196: types.DOH_DOT,
	197: types.WECHAT,
	198: types.MPEGTS,
	199: types.SNAPCHAT,
	200: types.SINA,
	201: types.GOOGLE_MEET,
	202: types.IFLIX,
	203: types.GITHUB,
	204: types.BJNP,
	205: types.REDDIT,
	206: types.WIREGUARD,
	207: types.SMPP,
	208: types.DNSCRYPT,
	209: types.TINC,
	210: types.DEEZER,
	211: types.INSTAGRAM,
	212: types.MICROSOFT,
	213: types.BLIZZARD,
	214: types.TEREDO,
	215: types.HOTSPOT_SHIELD,
	216: types.IMO,
	217: types.GOOGLE_DRIVE,
	218: types.OCS,
	219: types.MICROSOFT_365,
	220: types.CLOUDFLARE,
	221: types.MS_ONE_DRIVE,
	222: types.MQTT,
	223: types.RX,
	224: types.APPLESTORE,
	225: types.OPENDNS,
	226: types.GIT,
	227: types.DRDA,
	228: types.PLAYSTORE,
	229: types.SOMEIP,
	230: types.FIX,
	231: types.PLAYSTATION,
	232: types.PASTEBIN,
	233: types.LINKEDIN,
	234: types.SOUNDCLOUD,
	235: types.VALVE_SDR,
	236: types.LISP,
	237: types.DIAMETER,
	238: types.APPLE_PUSH,
	239: types.GOOGLE_SERVICES,
	240: types.AMAZON_VIDEO,
	241: types.GOOGLE_DOCS,
	242: types.WHATSAPP_FILES,
	243: types.TARGUS_GETDATA,
	244: types.DNP3,
	245: types.IEC60870,
	246: types.BLOOMBERG,
	247: types.CAPWAP,
	248: types.ZABBIX,
	249: types.S7COMM,
	250: types.MSTEAMS,
	251: types.WEBSOCKET,
	252: types.ANYDESK,
	253: types.SOAP,
	254: types.APPLE_SIRI,
	255: types.SNAPCHAT_CALL,
	256: types.HPVIRTGRP,
	257: types.GENSHIN_IMPACT,
	258: types.ACTIVISION,
	259: types.FORTICLIENT,
	260: types.Z3950,
	261: types.LIKEE,
	262: types.GITLAB,
	263: types.AVAST_SECUREDNS,
	264: types.CASSANDRA,
	265: types.AMAZON_AWS,
	266: types.SALESFORCE,
	267: types.VIMEO,
	268: types.FACEBOOK_VOIP,
	269: types.SIGNAL_VOIP,
	270: types.FUZE,
	271: types.GTP_U,
	272: types.GTP_C,
	273: types.GTP_PRIME,
	274: types.ALIBABA,
	275: types.CRASHLYSTICS,
	276: types.MICROSOFT_AZURE,
	277: types.ICLOUD_PRIVATE_RELAY,
	278: types.ETHERNET_IP,
	279: types.BADOO,
	280: types.ACCUWEATHER,
	281: types.GOOGLE_CLASSROOM,
	282: types.HSRP,
	283: types.CYBERSECURITY,
	284: types.GOOGLE_CLOUD,
	285: types.TENCENT,
	286: types.RAKNET,
	287: types.XIAOMI,
	288: types.EDGECAST,
	289: types.CACHEFLY,
	290: types.SOFTETHER,
	291: types.MPEGDASH,
	292: types.DAZN,
	293: types.GOTO,
	294: types.RSH,
	295: types.ONEKXUN,
	296: types.IP_PGM,
	297: types.IP_PIM,
	298: types.COLLECTD,
	299: types.TUNNELBEAR,
	300: types.CLOUDFLARE_WARP,
	301: types.I3D,
	302: types.RIOTGAMES,
	303: types.PSIPHON,
	304: types.ULTRASURF,
	305: types.THREEMA,
	306: types.ALICLOUD,
	307: types.AVAST,
	308: types.TIVOCONNECT,
	309: types.KISMET,
	310: types.FASTCGI,
	311: types.FTPS,
	312: types.NATPMP,
	313: types.SYNCTHING,
	314: types.CRYNET,
	315: types.LINE,
	316: types.LINE_CALL,
	317: types.APPLETVPLUS,
	318: types.DIRECTV,
	319: types.HBO,
	320: types.VUDU,
	321: types.SHOWTIME,
	322: types.DAILYMOTION,
	323: types.LIVESTREAM,
	324: types.TENCENTVIDEO,
	325: types.IHEARTRADIO,
	326: types.TIDAL,
	327: types.TUNEIN,
	328: types.SIRIUSXMRADIO,
	329: types.MUNIN,
	330: types.ELASTICSEARCH,
	331: types.TUYA_LP,
	332: types.TPLINK_SHP,
	333: types.SOURCE_ENGINE,
	334: types.BACNET,
	335: types.OICQ,
	336: types.HOTS,
	337: types.FACEBOOK_REEL_STORY,
	338: types.SRTP,
	339: types.OPERA_VPN,
	340: types.EPICGAMES,
	341: types.GEFORCENOW,
	342: types.NVIDIA,
	343: types.BITCOIN,
	344: types.PROTONVPN,
	345: types.APACHE_THRIFT,
	346: types.ROBLOX,
	347: types.SERVICE_LOCATION,
	348: types.MULLVAD,
	349: types.HTTP2,
	350: types.HAPROXY,
	351: types.RMCP,
	352: types.CAN,
	353: types.PROTOBUF,
	354: types.ETHEREUM,
	355: types.TELEGRAM_VOIP,
	356: types.SINA_WEIBO,
	357: types.TESLA_SERVICES,
	358: types.PTPV2,
	359: types.RTPS,
	360: types.OPC_UA,
	361: types.S7COMM_PLUS,
	362: types.FINS,
	363: types.ETHERSIO,
	364: types.UMAS,
	365: types.BECKHOFF_ADS,
	366: types.ISO9506_1_MMS,
	367: types.IEEE_C37118,
	368: types.ETHERSBUS,
	369: types.MONERO,
	370: types.DCERPC,
	371: types.PROFINET_IO,
	372: types.HISLIP,
	373: types.UFTP,
	374: types.OPENFLOW,
	375: types.JSON_RPC,
	376: types.WEBDAV,
	377: types.APACHE_KAFKA,
	378: types.NOMACHINE,
	379: types.IEC62056,
	380: types.HL7,
	381: types.CEPH,
	382: types.GOOGLE_CHAT,
	383: types.ROUGHTIME,
	384: types.PIA,
	385: types.KCP,
	386: types.DOTA2,
	387: types.MUMBLE,
	388: types.YOJIMBO,
	389: types.ELECTRONICARTS,
	390: types.STOMP,
	391: types.RADMIN,
	392: types.RAFT,
	393: types.CIP,
	394: types.GEARMAN,
	395: types.TENCENTGAMES,
	396: types.GAIJIN,
	397: types.C1222,
	398: types.HUAWEI,
	399: types.HUAWEI_CLOUD,
	400: types.DLEP,
	401: types.BFD,
	402: types.NETEASE_GAMES,
	403: types.PATHOFEXILE,
	404: types.GOOGLE_CALL,
	405: types.PFCP,
	406: types.FLUTE,
	407: types.LOLWILDRIFT,
	408: types.TESO,
	409: types.LDP,
	410: types.KNXNET_IP,
	411: types.BLUESKY,
	412: types.MASTODON,
	413: types.THREADS,
	414: types.VIBER_VOIP,
	415: types.ZUG,
	416: types.JRMI,
	417: types.RIPE_ATLAS,
	418: types.HLS,
	419: types.CLICKHOUSE,
	420: types.NANO,
	421: types.OPENWIRE,
	422: types.CNP_IP,
	423: types.ATG,
	424: types.TRDP,
	425: types.LUSTRE,
	426: types.NORDVPN,
	427: types.SURFSHARK,
	428: types.CACTUSVPN,
	429: types.WINDSCRIBE,
	430: types.SONOS,
	431: types.DINGTALK,
	432: types.PALTALK,
	433: types.NAVER,
	434: types.SHEIN,
	435: types.TEMU,
	436: types.TAOBAO,
	437: types.MIKROTIK,
	438: types.DICOM,
	439: types.PARAMOUNTPLUS,
	440: types.YANDEX_ALICE,
	441: types.VIVOX,
	442: types.DIGITALOCEAN,
	443: types.RUTUBE,
	444: types.LAGOFAST,
	445: types.GEARUP_BOOSTER,
	446: types.RUMBLE,
	447: types.UBIQUITY,
	448: types.MSDO,
	449: types.ROCKSTAR_GAMES,
	450: types.KICK,
	451: types.HAMACHI,
	452: types.GLBP,
	453: types.EASYWEATHER,
	454: types.MUDFISH,
	455: types.TRISTATION,
	456: types.SAMSUNG_SDP,
	457: types.MATTER,
	458: types.AWS_COGNITO,
	459: types.AWS_API_GATEWAY,
	460: types.AWS_KINESIS,
	461: types.AWS_EC2,
	462: types.AWS_EMR,
	463: types.AWS_S3,
	464: types.AWS_CLOUDFRONT,
	465: types.AWS_DYNAMODB,
	466: types.ESPN,
	467: types.AKAMAI,
}

// Total protocols: 468 (IDs 0-467)

// NDPIWrapperName is the identification of the nDPI library.
const NDPIWrapperName = "nDPI"

// NDPIWrapperProvider provides NDPIWrapper with the implementations of the
// methods to use.
type NDPIWrapperProvider struct {
	ndpiInitialize    func() int32
	ndpiDestroy       func()
	ndpiPacketProcess func(gopacket.Packet, unsafe.Pointer) int32
	ndpiAllocFlow     func(gopacket.Packet) unsafe.Pointer
	ndpiFreeFlow      func(unsafe.Pointer)
}

// NDPIWrapper is the wrapper for the nDPI deep inspection library,
// providing the methods used to interface with it from go-dpi.
type NDPIWrapper struct {
	provider *NDPIWrapperProvider
	mu       sync.Mutex // Protects concurrent access to nDPI C library (not thread-safe)
}

// getPacketNdpiData is a helper that extracts the PCAP packet header and packet
// data pointer from a gopacket.Packet, as needed by nDPI.
// Returns nil pktDataPtr if packet has no data to prevent segfault.
func getPacketNdpiData(packet gopacket.Packet) (pktHeader C.struct_pcap_pkthdr, pktDataPtr *C.u_char) {
	seconds := packet.Metadata().Timestamp.Second()
	capLen := packet.Metadata().CaptureLength
	packetLen := packet.Metadata().Length
	pktDataSlice := packet.Data()
	pktHeader.ts.tv_sec = C.long(seconds)
	pktHeader.ts.tv_usec = 0
	pktHeader.caplen = C.bpf_u_int32(capLen)
	pktHeader.len = C.bpf_u_int32(packetLen)

	// Safety check: prevent segfault when accessing empty slice
	// Packets without data (e.g., TCP control packets) should not be processed
	if len(pktDataSlice) > 0 {
		pktDataPtr = (*C.u_char)(unsafe.Pointer(&pktDataSlice[0]))
	} else {
		pktDataPtr = nil
	}
	return
}

// NewNDPIWrapper constructs an NDPIWrapper with the default implementation
// for its methods.
func NewNDPIWrapper() *NDPIWrapper {
	return &NDPIWrapper{
		provider: &NDPIWrapperProvider{
			ndpiInitialize: func() int32 { return int32(C.ndpiInitialize()) },
			ndpiDestroy:    func() { C.ndpiDestroy() },
			ndpiPacketProcess: func(packet gopacket.Packet, ndpiFlow unsafe.Pointer) int32 {
				// Safety check: don't process packets without data
				if len(packet.Data()) == 0 {
					return 0 // Return "unknown" protocol code
				}
				pktHeader, pktDataPtr := getPacketNdpiData(packet)
				// Double-check pktDataPtr is not nil before calling C code
				if pktDataPtr == nil {
					return 0
				}
				return int32(C.ndpiPacketProcess(&pktHeader, pktDataPtr, ndpiFlow))
			},
			ndpiAllocFlow: func(packet gopacket.Packet) unsafe.Pointer {
				// Safety check: don't allocate flow for packets without data
				if len(packet.Data()) == 0 {
					return nil
				}
				pktHeader, pktDataPtr := getPacketNdpiData(packet)
				// Double-check pktDataPtr is not nil before calling C code
				if pktDataPtr == nil {
					return nil
				}
				return C.ndpiGetFlow(&pktHeader, pktDataPtr)
			},
			ndpiFreeFlow: func(ndpiFlow unsafe.Pointer) {
				// Safety check: don't free nil pointers
				if ndpiFlow != nil {
					C.ndpiFreeFlow(ndpiFlow)
				}
			},
		},
	}
}

// InitializeWrapper initializes the nDPI wrapper.
func (wrapper *NDPIWrapper) InitializeWrapper() int {
	return int((*wrapper.provider).ndpiInitialize())
}

// DestroyWrapper destroys the nDPI wrapper.
func (wrapper *NDPIWrapper) DestroyWrapper() error {
	(*wrapper.provider).ndpiDestroy()
	return nil
}

// ClassifyFlow classifies a flow using the nDPI library. It returns the
// detected protocol and any error.
func (wrapper *NDPIWrapper) ClassifyFlow(flow *types.Flow) (class *types.Classification, err error) {
	packets := flow.GetPackets()
	class = &types.Classification{}
	class.Proto = types.Unknown
	if len(packets) > 0 {
		// Find the first packet with data to initialize the flow
		var firstPacketWithData gopacket.Packet
		for _, pkt := range packets {
			if len(pkt.Data()) > 0 {
				firstPacketWithData = pkt
				break
			}
		}

		// If no packets have data, we can't classify
		if firstPacketWithData == nil {
			return
		}

		// Lock mutex to protect concurrent access to nDPI C library
		// The nDPI library uses global state and is not thread-safe
		wrapper.mu.Lock()
		defer wrapper.mu.Unlock()

		ndpiFlow := (*wrapper.provider).ndpiAllocFlow(firstPacketWithData)
		// Check if flow allocation failed (can happen if packet has no valid data)
		if ndpiFlow == nil {
			return
		}
		defer (*wrapper.provider).ndpiFreeFlow(ndpiFlow)
		for _, ppacket := range packets {
			// Skip packets without data to prevent segfault
			if len(ppacket.Data()) == 0 {
				continue
			}

			ndpiProto := (*wrapper.provider).ndpiPacketProcess(ppacket, ndpiFlow)
			if proto, found := ndpiCodeToProtocol[uint32(ndpiProto)]; found && proto != types.Unknown {
				class.Proto = proto
				return
			} else if ndpiProto < 0 {
				switch ndpiProto {
				case -10:
					return class, errors.New("nDPI wrapper does not support IPv6")
				case -11:
					return class, errors.New("Received fragmented packet")
				case -12:
					return class, errors.New("Error creating nDPI flow")
				default:
					return class, errors.New("nDPI unknown error")
				}
			}
		}
	}
	return
}

// GetWrapperName returns the name of the wrapper, in order to identify which
// wrapper provided a classification.
func (wrapper *NDPIWrapper) GetWrapperName() types.ClassificationSource {
	return NDPIWrapperName
}

// GetSupportedProtocols returns all protocols supported by nDPI.
func (wrapper *NDPIWrapper) GetSupportedProtocols() []types.Protocol {
	protocols := make([]types.Protocol, 0, len(ndpiCodeToProtocol))
	seen := make(map[types.Protocol]bool)

	for _, protocol := range ndpiCodeToProtocol {
		if !seen[protocol] && protocol != types.Unknown {
			protocols = append(protocols, protocol)
			seen[protocol] = true
		}
	}

	return protocols
}

package wrappers

// #include "wrappers_config.h"
// #ifndef DISABLE_LPI
// #cgo CXXFLAGS: -std=c++11 -I/usr/local/include -I/opt/homebrew/include
// #cgo LDFLAGS: -L/usr/local/lib -L/opt/homebrew/lib -lprotoident -ltrace
// #endif
// #include "LPI_wrapper_impl.hpp"
// #include <stdlib.h>
import "C"
import (
	"unsafe"

	"github.com/dreadl0ck/go-dpi/types"
)

// lpiCodeToCategory maps the LPI protocol codes to go-dpi protocols.
var lpiCodeToCategory = map[uint32]types.Category{
	0:  types.CATEGORY_WEB,           /* HTTP-based protocols */
	1:  types.CATEGORY_CHAT,          /* Instant messaging and chatrooms */
	2:  types.CATEGORY_MAIL,          /* E-mail */
	3:  types.CATEGORY_P2P,           /* Peer-to-peer uploads and downloads */
	4:  types.CATEGORY_P2P_STRUCTURE, /* Maintenance of P2P networks */
	5:  types.CATEGORY_KEY_EXCHANGE,  /* Protocols used to exchange and manage cryptographic keys, e.g. ISAKMP */
	6:  types.CATEGORY_ECOMMERCE,     /* Financial transaction protocols */
	7:  types.CATEGORY_GAMING,        /* Game protocols */
	8:  types.CATEGORY_ENCRYPT,       /* Encrypted traffic that is not clearly part of another category */
	9:  types.CATEGORY_MONITORING,    /* Network measurement / monitoring */
	10: types.CATEGORY_NEWS,          /* Newsgroup protocols, e.g. NNTP */
	11: types.CATEGORY_MALWARE,       /* Viruses, trojans etc. */
	12: types.CATEGORY_SECURITY,      /* Antivirus and firewall updates */
	13: types.CATEGORY_ANTISPAM,      /* Anti-spam software update protocols */
	14: types.CATEGORY_VOIP,          /* Voice chat and Internet telephony protocols */
	15: types.CATEGORY_TUNNELLING,    /* Tunnelling protocols */
	16: types.CATEGORY_NAT,           /* NAT traversal protocols */
	17: types.CATEGORY_STREAMING,     /* Streaming media protocols */
	18: types.CATEGORY_SERVICES,      /* Basic services, e.g. DNS, NTP */
	19: types.CATEGORY_DATABASES,     /* Database remote access protocols */
	20: types.CATEGORY_FILES,         /* Non-P2P file transfer protocols */
	21: types.CATEGORY_REMOTE,        /* Remote access, e.g. SSH, telnet */
	22: types.CATEGORY_TELCO,         /* Telco services aside from VOIP, e.g SMS protocols */
	23: types.CATEGORY_P2PTV,         /* P2P TV, e.g. PPLive */
	24: types.CATEGORY_RCS,           /* Revision Control */
	25: types.CATEGORY_LOGGING,       /* Logging */
	26: types.CATEGORY_PRINTING,      /* Network printing */
	27: types.CATEGORY_TRANSLATION,   /* Language translation */
	28: types.CATEGORY_CDN,           /* CDN protocols, e.g. Akamai */
	29: types.CATEGORY_CLOUD,         /* Cloud computing/storage protocols */
	30: types.CATEGORY_NOTIFICATION,  /* Notification / messaging protocols */
	31: types.CATEGORY_SERIALISATION, /* Transfer of programming "objects" */
	32: types.CATEGORY_BROADCAST,     /* Protocols usually broadcast to the local network */
	33: types.CATEGORY_LOCATION,      /* Location-related services / GPS */
	34: types.CATEGORY_CACHING,       /* Proxy cache protocols and similar */
	35: types.CATEGORY_MOBILE_APP,    /* Mobile apps that don't fit any other category */
	36: types.CATEGORY_ICS,           /* Industrial control system protocols */
	37: types.CATEGORY_IPCAMERAS,     /* IP Surveillance Camera protocols */
	38: types.CATEGORY_MESSAGE_QUEUE, /* Message queuing protocols */
	39: types.CATEGORY_EDUCATIONAL,   /* Educational applications, e.g. virtual classrooms */
	40: types.CATEGORY_ICMP,          /* ICMP */
	41: types.CATEGORY_MIXED,         /* Different protos in each direction */
	42: types.CATEGORY_NOPAYLOAD,     /* No payload observed */
	43: types.CATEGORY_UNSUPPORTED,   /* Transport protocol unsupported */
	44: types.CATEGORY_UNKNOWN,       /* Protocol could not be identified */
	45: types.CATEGORY_NO_CATEGORY,   /* Protocol has not been placed into a category yet */
}

// lpiCodeToProtocol maps the LPI protocol codes to go-dpi protocols.
var lpiCodeToProtocol = map[uint32]types.Protocol{
	/* TCP Protocols */
	0:   types.HTTP,
	1:   types.SMTP,
	2:   types.BITTORRENT,
	3:   types.IRC,
	4:   types.NCSOFT, /* NCSoft proprietary protocol */
	5:   types.DC,     /* DirectConnect */
	6:   types.EMULE,
	7:   types.GNUTELLA,
	8:   types.SSH,
	9:   types.HTTPS,
	10:  types.RAZOR, /* Razor database updates */
	11:  types.POP3,
	12:  types.SSL, /* SSL that isn't HTTPS */
	13:  types.MSN,
	14:  types.DNS,
	15:  types.IMAP,
	16:  types.RTSP,
	17:  types.ID, /* Identification protocol */
	18:  types.YAHOO,
	19:  types.ICQ,
	20:  types.TELNET,
	21:  types.RDP,      /* Windows remote desktop protocol */
	22:  types.TDS,      /* MS SQL Server protocol */
	23:  types.RPC_SCAN, /* Port 135 exploit attempt */
	24:  types.SMB,      /* Server Message Block protocol e.g. samba */
	25:  types.WARCRAFT3,
	26:  types.ETRUST,      /* Updates for the eTrust virus scanner */
	27:  types.FTP_CONTROL, /* FTP control e.g. port 21 or 2121 */
	28:  types.FTP_DATA,
	29:  types.EYE,  /* Yahoo Game Server Browser */
	30:  types.ARES, /* Ares peer-to-peer protocol */
	31:  types.NNTP, /* Newsfeeds */
	32:  types.NAPSTER,
	33:  types.BNCS,         /* Battle.net Chat Server */
	34:  types.RFB,          /* Remote Frame Buffer protocol */
	35:  types.YAHOO_WEBCAM, /* Webcam over Yahoo Messenger */
	36:  types.ICA,          /* Citrix ICA */
	37:  types.NETBIOS,
	38:  types.KMS, /* Possibly a vista activation service */
	39:  types.MS_DS,
	40:  types.SIP, /* Session Initiation Protocol*/
	41:  types.MZINGA,
	42:  types.GOKUCHAT,
	43:  types.XUNLEI,
	44:  types.DXP,
	45:  types.HAMACHI,
	46:  types.BLIZZARD,
	47:  types.MSNV,       /* MSN Voice */
	48:  types.BITEXT,     /* BitTorrent extensions */
	49:  types.MITGLIEDER, /* Mitglieder trojan */
	50:  types.TOR,        /* TOR (The Onion Router) */
	51:  types.MYSQL,
	52:  types.HTTP_TUNNEL, /* Tunnelling via HTTP */
	53:  types.RSYNC,
	54:  types.NOTES_RPC,        /* Lotus Notes RPC (Domino) */
	55:  types.AZUREUS,          /* Azureus Extension */
	56:  types.PANDO,            /* Pando P2P protocol */
	57:  types.FLASH,            /* Flash Player specific behaviour */
	58:  types.STEAM,            /* Steam TCP download, i.e. downloading games */
	59:  types.TRACKMANIA,       /* Trackmania control protocol */
	60:  types.CONQUER,          /* Conquer Online game */
	61:  types.RTMP,             /* Adobe RTMP */
	62:  types.TIP,              /* Transaction Internet Protocol */
	63:  types.NONSTANDARD_HTTP, /* HTTP on unconventional port numbers */
	64:  types.HARVEYS,          /* Photo transfers for Harveys Real Estate */
	65:  types.SHOUTCAST,
	66:  types.HTTP_BADPORT, /* HTTP over port 443, leading to failure */
	67:  types.POSTGRESQL,   /* Postgresql protocol */
	68:  types.WOW,          /* World of Warcraft */
	69:  types.M4U,          /* Message4U (Aus SMS service) */
	70:  types.RBLS,         /* Realtime Block List updates */
	71:  types.OPENVPN,
	72:  types.TELECOMKEY,   /* Proto used to talk to telecomkey.com */
	73:  types.IMAPS,        /* IMAP over SSL */
	74:  types.MSNC,         /* MSN Client Protocol */
	75:  types.YAHOO_ERROR,  /* Yahoo method of dealing with HTTP errors */
	76:  types.IMESH,        /* iMesh */
	77:  types.PPTP,         /* MS Tunnelling protocol */
	78:  types.AFP,          /* Apple Filing Protocol */
	79:  types.PDBOX,        /* Korean P2P TV protocol */
	80:  types.EA_GAMES,     /* EA Games protocol */
	81:  types.ZYNGA,        /* Protocol used by Zynga games */
	82:  types.CLUBBOX,      /* Another Korean file sharing protocol */
	83:  types.WINMX,        /* WinMX */
	84:  types.INVALID_BT,   /* Bittorrent in one direction but not other */
	85:  types.WEBLOGIC,     /* Weblogic server */
	86:  types.INVALID_HTTP, /* HTTP server sending raw HTML */
	87:  types.COD_WAW,      /* Call of Duty: World at War TCP */
	88:  types.MP2P,
	89:  types.SVN,
	90:  types.SOCKS5,
	91:  types.SOCKS4,
	92:  types.INVALID_SMTP,
	93:  types.MMS,       /* Microsoft Media Server */
	94:  types.CISCO_VPN, /* Cisco VPN protocol */
	95:  types.WEB_JUNK,  /* Clients communicating with web servers using non-HTTP */
	96:  types.CVS,
	97:  types.LDAP,         /* LDAP */
	98:  types.INVALID_POP3, /* POP commands send to an SMTP server */
	99:  types.TEAMVIEWER,
	100: types.XMPP,       /* a.k.a. Jabber */
	101: types.SECONDLIFE, /* SecondLife over TCP */
	102: types.KASEYA,
	103: types.KASPERSKY,
	104: types.JEDI, /* Citrix Jedi */
	105: types.CGP,  /* Citrix CGP */
	106: types.YOUKU,
	107: types.STUN,
	108: types.XYMON,
	109: types.MUNIN,
	110: types.TROJAN_WIN32_GENERIC_SB,
	111: types.PALTALK,
	112: types.ZABBIX,
	113: types.AKAMAI,
	114: types.GAMESPY,
	115: types.WUALA,
	116: types.TROJAN_ZEROACCESS,
	117: types.DVRNS,
	118: types.CHATANGO,
	119: types.OMEGLE,
	120: types.TELNET_EXPLOIT,
	121: types.POP3S, /* POP3 over TLS/SSL */
	122: types.PSN_STORE,
	123: types.SKYPE_TCP,  /* Skype TCP sessions */
	124: types.APPLE_PUSH, /* Apple push notifications */
	125: types.XMPPS,      /* XMPP over TLS/SSL */
	126: types.SMTPS,      /* Legacy Secure SMTP */
	127: types.NNTPS,      /* NNTP over TLS/SSL */
	128: types.JAVA,       /* Serialised Java Objects */
	129: types.IPOP,       /* IP over P2P */
	130: types.SPOTIFY,
	131: types.RUNESCAPE,
	132: types.WHOIS,
	133: types.VIBER,
	134: types.FRING,
	135: types.PALRINGO,
	136: types.CRYPTIC, /* Games by Cryptic */
	137: types.SUPL,
	138: types.MINECRAFT,
	139: types.TPKT,
	140: types.QVOD,
	141: types.KIK,
	142: types.WHATSAPP,
	143: types.WECHAT,
	144: types.FUNSHION,
	145: types.BTSYNC,
	146: types.SPEEDTEST,
	147: types.GIT,
	148: types.DUELING_NETWORK,
	149: types.LINE,
	150: types.AMP,
	151: types.SPDY,
	152: types.YAHOO_GAMES,
	153: types.DELL_BACKUP,
	154: types.REVOLVER_NBLBT,
	155: types.CRASHPLAN,
	156: types.CLASH_OF_CLANS,
	157: types.TRION,
	158: types.MONGO,
	159: types.LLP2P,
	160: types.HEARTHSTONE,
	161: types.DIABLO3,
	162: types.CACAOWEB,
	163: types.TAOBAO, /* Custom protocol seen on Taobao CDN */
	164: types.TERA,
	165: types.SILKROADONLINE, /* Korean MMO */
	166: types.GOOGLE_HANGOUTS,
	167: types.HOLA,
	168: types.GUILDWARS2,
	169: types.QQ,
	170: types.TETRISONLINE,
	171: types.TWITCH_IRC, /* IRC specific to twitch.tv */
	172: types.QQLIVE,
	173: types.TENCENT_GAMES, /* Games operated by Tencent */
	174: types.VODLOCKER,
	175: types.TELEGRAM,
	176: types.XUNLEI_ACCEL,
	177: types.SAFEGUARD360, /* Chinese anti-virus */
	178: types.NORTON_BACKUP,
	179: types.BADBAIDU, /* Weird 1 byte flows from Baidu browser */
	180: types.KAKAO,
	181: types.WEIBO,
	182: types.TENSAFE,
	183: types.KANKAN,
	184: types.AIRDROID,
	185: types.KUAIBO,
	186: types.DIANPING,
	187: types.XIAMI,
	188: types.QQDOWNLOAD,
	189: types.ZERO_FACEBOOK,
	190: types.FINALFANTASY_XIV,
	191: types.FACEBOOK_MESSENGER,
	192: types.YY,
	193: types.NETCAT_CCTV,
	194: types.ZOOM,
	195: types.S7COMM,
	196: types.MAXICLOUD,
	197: types.GLUPTEBA,
	198: types.WNS,
	199: types.PANDATV,
	200: types.FACEBOOK_TURN,
	201: types.DESTINY,
	202: types.QCLOUD_ILVB,
	203: types.BITCOIN,
	204: types.LIFEFORGE,
	205: types.ACESTREAM,
	206: types.MAPLESTORY_CHINA,
	207: types.NDT_TPUT,
	208: types.RELAY,
	209: types.DOUYU,
	210: types.IDRIVE_SYNC,
	211: types.TWITCASTING,
	212: types.THE_DIVISION,
	213: types.BLACKDESERT,
	214: types.REALVNC,
	215: types.DOGECOIN,
	216: types.FUCKCOIN,
	217: types.OURWORLD,
	218: types.GRAAL_ONLINE_ERA,
	219: types.APPEAR_IN,
	220: types.VAINGLORY,
	221: types.WEIQI,
	222: types.FOURD,
	223: types.TANKIX,
	224: types.IPSHARKK,
	225: types.NET_MFP,
	226: types.SPEEDIN,
	227: types.CROSSFIRE,
	228: types.DASH,
	229: types.AIRMEDIA,
	230: types.GIOP,
	231: types.VPN_UNLIMITED,
	232: types.TENFIVECOIN,
	233: types.BAOFENG,
	234: types.TALESRUNNER,
	235: types.ANTCOIN,
	236: types.FBCDN_SSL,
	237: types.SAPROUTER,
	238: types.FLIGGY,
	239: types.SMITE,
	240: types.VPNROBOT,
	241: types.VMWARE,
	242: types.DOUYU_CHAT,
	243: types.JX3ONLINE,
	244: types.LITECOIN,
	245: types.STRATUM,
	246: types.WIZARD101,
	247: types.KINGOFGLORY,
	248: types.SAS_ZOMBIE_ASSAULT_4,
	249: types.DNF,
	250: types.IHEXIN,
	251: types.NAVER_P2P,
	252: types.GCAFE_UPDATER,
	253: types.BWSYNC,
	254: types.TANKIONLINE,
	255: types.REALMOFTHEMADGOD,
	256: types.PATHOFEXILE,
	257: types.SSJJ,
	258: types.SPEEDIFY,
	259: types.NSQ,
	260: types.SKYFORGE,
	261: types.HOTS,
	262: types.NOMACHINE,
	263: types.QQSPEEDMOBILE,
	264: types.DAHUA,
	265: types.UTHERVERSE,
	266: types.HEROES300,
	267: types.FILENORI,
	268: types.IPFS,
	269: types.REMOTE_MANIPULATOR,
	270: types.WEBEX_STUN,
	271: types.RRTV,
	272: types.RABBITMQ,
	273: types.ICEP,
	274: types.BEAM,
	275: types.VHDP2P,
	276: types.CLASSIN,
	277: types.UDP,
	278: types.UDP_SIP,
	279: types.UDP_BTDHT,
	280: types.UDP_GNUTELLA,
	281: types.UDP_DNS,
	282: types.UDP_DHCP,
	283: types.UDP_QUAKE,
	284: types.UDP_STEAM,
	285: types.UDP_STEAM_FRIENDS,
	286: types.UDP_STEAM_INHOMEBROADCAST,
	287: types.UDP_WIN_MESSAGE,
	288: types.UDP_GAMESPY,
	289: types.UDP_EMULE,
	290: types.UDP_EYE,
	291: types.UDP_RTP,
	292: types.UDP_MSN_VIDEO,
	293: types.UDP_COD, /* Call of Duty game protocol */
	294: types.UDP_NTP,
	295: types.UDP_MP2P,        /* MP2P protocol (Piolet, Manolito etc.) */
	296: types.UDP_SPAMFIGHTER, /* SpamFighter */
	297: types.UDP_TRACEROUTE,
	298: types.UDP_SECONDLIFE,
	299: types.UDP_HL,        /* Halflife, includes derivatives such as CounterStrike and Garry's Mod */
	300: types.UDP_XLSP,      /* XLSP - Xbox Live */
	301: types.UDP_DEMONWARE, /* Company that does game networking */
	302: types.UDP_IMESH,     /* iMesh */
	303: types.UDP_OPASERV,   /* Opaserv worm */
	304: types.UDP_STUN,      /* STUN NAT traversal */
	305: types.UDP_SQLEXP,    /* MS SQL Server worm, called SQLExp */
	306: types.UDP_MSN_CACHE, /* MSN cache callback protocol */
	307: types.UDP_DIABLO2,   /* Diablo 2 game protocol */
	308: types.UDP_IPV6,      /* IPv6 tunnelled directly over UDP */
	309: types.UDP_ORBIT,     /* Orbit downloader */
	310: types.UDP_TEREDO,
	311: types.UDP_KADEMLIA,  /* Unknown flavour of kademlia */
	312: types.UDP_PANDO,     /* Pando DHT and Peer Exchange */
	313: types.UDP_ESP,       /* ESP/IPSec encapsulated in UDP */
	314: types.UDP_PSN,       /* Playstation Network */
	315: types.UDP_REAL,      /* RDT - the Real Data Transport protocol */
	316: types.UDP_GNUTELLA2, /* Gnutella2 */
	317: types.UDP_PYZOR,     /* Python implementation of Razor */
	318: types.UDP_SKYPE,
	319: types.UDP_ISAKMP, /* ref: RFC 2408 */
	320: types.UDP_SNMP,
	321: types.UDP_BACKWEB, /* BackWeb Polite Protocol */
	322: types.UDP_STARCRAFT,
	323: types.UDP_XFIRE_P2P,  /* Xfire P2P protocol */
	324: types.UDP_THQ,        /* Protocol used by THQ games */
	325: types.UDP_NEWERTH,    /* Heroes of Newerth */
	326: types.UDP_LINKPROOF,  /* Linkproof device packets */
	327: types.UDP_WORM_22105, /* Chinese worm that uses port 22105 */
	328: types.UDP_QQ,         /* Tencent QQ */
	329: types.UDP_SLP,        /* Service Location Protocol, RFC 2608 */
	330: types.UDP_ESO,        /* Games using Ensemble Studios Online */
	331: types.UDP_SSDP,
	332: types.UDP_NETBIOS,  /* Netbios lookup */
	333: types.UDP_CP_RDP,   /* Checkpoint RDP */
	334: types.UDP_VENTRILO, /* Ventrilo VoiceChat */
	335: types.UDP_MTA,      /* Multitheftauto */
	336: types.UDP_PPLIVE,
	337: types.UDP_JEDI_ACADEMY, /* Jedi Academy game */
	338: types.UDP_MOH,          /* Medal of Honor game */
	339: types.UDP_TREMULOUS,    /* Tremulous - free OSS FPS */
	340: types.UDP_VIVOX,        /* Vivox voice chat */
	341: types.UDP_IPMSG,        /* IPMsg messenger */
	342: types.UDP_TEAMSPEAK,
	343: types.UDP_DC,       /* DirectConnect UDP commands */
	344: types.UDP_FREECHAL, /* FreeChal P2P */
	345: types.UDP_XUNLEI,
	346: types.UDP_KAZAA,
	347: types.UDP_NORTON,    /* Norton Antivirus probe */
	348: types.UDP_CISCO_VPN, /* Cisco VPN (port 10000) */
	349: types.UDP_RTCP,
	350: types.UDP_UNREAL, /* Unreal server query protocol */
	351: types.UDP_TFTP,
	352: types.UDP_GARENA,   /* A gaming platform */
	353: types.UDP_PPSTREAM, /* PPStream - Chinese P2PTV */
	354: types.UDP_FORTINET, /* Fortinet update protocol */
	355: types.UDP_TVANTS,   /* TVants P2PTV - no longer active */
	356: types.UDP_STORM_WORM,
	357: types.UDP_BATTLEFIELD, /* Battlefield series of games */
	358: types.UDP_SOPCAST,
	359: types.UDP_SERIALNUMBERD,
	360: types.UDP_LDAP_AD,
	361: types.UDP_RTMFP,
	362: types.UDP_L2TP,
	363: types.UDP_SYSLOG,
	364: types.UDP_AKAMAI,
	365: types.UDP_RADIUS,
	366: types.UDP_HAMACHI,
	367: types.UDP_BJNP, /* Canon BJNP printing protocol */
	368: types.UDP_KASPERSKY,
	369: types.UDP_GSM,
	370: types.UDP_JEDI, /* Citrix Jedi */
	371: types.UDP_YOUKU,
	372: types.UDP_YOUDAO_DICT,
	373: types.UDP_DRIVESHARE,
	374: types.UDP_CIRN, /* Carpathia Intelligent Routing Network */
	375: types.UDP_NEVERWINTER,
	376: types.UDP_QQLIVE,
	377: types.UDP_TEAMVIEWER,
	378: types.UDP_ARES,
	379: types.UDP_EPSON,
	380: types.UDP_AKAMAI_TRANSFER,
	381: types.UDP_DCC,
	382: types.UDP_AMANDA,
	383: types.UDP_NETFLOW,
	384: types.UDP_ZEROACCESS,
	385: types.UDP_VXWORKS_EXPLOIT,
	386: types.UDP_APPLE_FACETIME_INIT,
	387: types.UDP_STEAM_LOCALBROADCAST, /* Protocol used by Steam to discover clients on the local network */
	388: types.UDP_LANSYNC,              /* LANSync, used by DropBox */
	389: types.UDP_BTSYNC,
	390: types.UDP_MSOFFICE_MAC, /* MS Office for Mac anti-piracy */
	391: types.UDP_SPOTIFY_BROADCAST,
	392: types.UDP_MDNS, /* Multicast DNS */
	393: types.UDP_FASP,
	394: types.UDP_RAKNET,
	395: types.UDP_OPENVPN,
	396: types.UDP_NOE, /* Alcatel's New Office Environment */
	397: types.UDP_VIBER,
	398: types.UDP_DTLS,
	399: types.UDP_ICP,
	400: types.UDP_LOL,        /* League of Legends */
	401: types.UDP_SANANDREAS, /* San Andreas Multiplayer */
	402: types.UDP_MFNP,       /* Canon MFNP Printer protocol */
	403: types.UDP_FUNSHION,
	404: types.UDP_QUIC,
	405: types.UDP_AVAST_DNS,
	406: types.UDP_DB2,
	407: types.UDP_NATPMP,
	408: types.UDP_GPRS_TUNNEL,
	409: types.UDP_WECHAT,
	410: types.UDP_NOCTION,
	411: types.UDP_ARMA_SERVER, /* Includes DayZ */
	412: types.UDP_PLANETSIDE2,
	413: types.UDP_RWTH_AACHEN, /* RWTH-Aachen University research */
	414: types.UDP_BMDP,        /* Part of Microsoft ADS */
	415: types.UDP_DOTA2,
	416: types.UDP_LINE,
	417: types.UDP_ZOOM,
	418: types.UDP_HEROES_GENERALS, /* Heroes and Generals */
	419: types.UDP_WARTHUNDER,
	420: types.UDP_H1Z1,
	421: types.UDP_CS_GLOBAL_OFFENSIVE,
	422: types.UDP_NTP_REFLECT, /* NTP reflection attack */
	423: types.UDP_PUNKBUSTER,
	424: types.UDP_ROBOCRAFT,
	425: types.UDP_CISCO_SSLVPN,
	426: types.UDP_ACERCLOUD,
	427: types.UDP_360CN,
	428: types.UDP_WOLF_ET,
	429: types.UDP_KUGOU,
	430: types.UDP_XUNLEI_JSQ,
	431: types.UDP_KANKAN,
	432: types.UDP_QQPCMGR,
	433: types.UDP_DIANPING,
	434: types.UDP_XUNYOU,
	435: types.UDP_FORTICLIENT_SSLVPN,
	436: types.UDP_DISCORD,
	437: types.UDP_NETCORE,
	438: types.UDP_ARMA3_SERVER,
	439: types.UDP_BAIDU_YUN_P2P,
	440: types.UDP_YY,
	441: types.UDP_OVERWATCH,
	442: types.UDP_BACNET,
	443: types.UDP_ARK_SURVIVAL,
	444: types.UDP_360P2P,
	445: types.UDP_PORTMAP_RPC,
	446: types.UDP_NINTENDO,
	447: types.UDP_CHIVALRY,
	448: types.UDP_DOYO,
	449: types.UDP_NETCAT_CCTV,
	450: types.UDP_N2PING,
	451: types.UDP_RAMSEY_DASH,
	452: types.UDP_UBISOFT_GAMES,
	453: types.UDP_THE_CREW,
	454: types.UDP_TURBOVPN,
	455: types.UDP_GEARSOFWAR,
	456: types.UDP_RDP,
	457: types.UDP_HOTS,
	458: types.UDP_VPNMASTER,
	459: types.UDP_DIANSHIJIA,
	460: types.UDP_PS4_REMOTEPLAY,
	461: types.UDP_STARCITIZEN,
	462: types.UDP_WEBEX,
	463: types.UDP_HALO_ONLINE,
	464: types.UDP_GOTOMEETING,
	465: types.UDP_CROSSOUT,
	466: types.UDP_UMEYE,
	467: types.UDP_RISING_STORM,
	468: types.UDP_CROSSFIRE,
	469: types.UDP_MERAKICLOUD,
	470: types.UDP_SNAPVPN,
	471: types.UDP_DAHUA,
	472: types.UDP_STARLEAF,
	473: types.UDP_FOSCAM,
	474: types.UDP_DESTINY,
	475: types.UDP_BAOFENG,
	476: types.UDP_TORCHLIGHT2,
	477: types.UDP_SMITE,
	478: types.UDP_COUNTERSTRIKE_16,
	479: types.UDP_VPNROBOT,
	480: types.UDP_TF2,
	481: types.UDP_GANGSOFSPACE,
	482: types.UDP_COMBATARMS,
	483: types.UDP_COMBATARMS_P2P,
	484: types.UDP_PANIPANI,
	485: types.UDP_FEITWO,
	486: types.UDP_MOONHUNTERS,
	487: types.UDP_HELIBORNE,
	488: types.UDP_KINGOFGLORY,
	489: types.UDP_ASSETTO_CORSA,
	490: types.UDP_CACAOWEB,
	491: types.UDP_ZALO_CALL,
	492: types.UDP_PALADINS,
	493: types.UDP_CHARGEN_EXPLOIT,
	494: types.UDP_TOX,
	495: types.UDP_HOLLA,
	496: types.UDP_RRSHARE,
	497: types.UDP_QQSPEEDMOBILE,
	498: types.UDP_LOADOUT,
	499: types.UDP_GANGLIA,
	500: types.UDP_TALESRUNNER,
	501: types.UDP_FREEFIRE,
	502: types.UDP_HEROES_EVOLVED,
	503: types.UDP_RULES_OF_SURVIVAL,
	504: types.UDP_CONTRACT_WARS,
	505: types.UDP_ARD,
	506: types.UDP_QVOD,
	507: types.UDP_YUANFUDAO,
	508: types.UDP_ROCKET_LEAGUE,
	509: types.UDP_CLOUDFLARE_WARP,
	510: types.UDP_WIREGUARD,
	511: types.UDP_COD_MOBILE,
	512: types.UDP_NVIDIA_GAMESTREAM,
	513: types.UDP_CLASSIN,
	514: types.REJECTION, /* All responses are 0x02 */
	//515: types.MYSTERY_9000,	/* Occurs on tcp port 9000 */
	//516: types.MYSTERY_PSPR,
	//517: types.MYSTERY_8000,
	//518: types.MYSTERY_IG,
	//519: types.MYSTERY_CONN,
	//520: types.MYSTERY_SYMANTEC,
	//521: types.MYSTERY_RXXF,
	//522: types.UDP_MYSTERY_0D,
	//523: types.UDP_MYSTERY_99,
	//524: types.UDP_MYSTERY_8000,
	//525: types.UDP_MYSTERY_45,
	//526: types.UDP_MYSTERY_0660,
	//527: types.UDP_MYSTERY_E9,
	//528: types.UDP_MYSTERY_QQ,
	//529: types.UDP_MYSTERY_61_72,
	//530: types.UDP_MYSTERY_05,
	531: types.ICMP,
	532: types.INVALID, /* No single valid protocol */
	533: types.NO_PAYLOAD,
	534: types.NO_FIRSTPKT,
	535: types.UNSUPPORTED,
	536: types.UNKNOWN,
}

// LPIWrapperName is the identification of the libprotoident library.
const LPIWrapperName = "libprotoident"

// LPIWrapper is the wrapper for the LPI protocol identification library,
// providing the methods used to interface with it from go-dpi.
type LPIWrapper struct{}

// NewLPIWrapper constructs a new LPIWrapper.
func NewLPIWrapper() *LPIWrapper {
	return &LPIWrapper{}
}

// InitializeWrapper initializes the libprotoident wrapper.
func (wrapper *LPIWrapper) InitializeWrapper() int {
	return int(C.lpiInitLibrary())
}

// DestroyWrapper destroys the libprotoident wrapper.
func (wrapper *LPIWrapper) DestroyWrapper() error {
	C.lpiDestroyLibrary()
	return nil
}

// ClassifyFlow classifies a flow using the libprotoident library. It returns
// the detected protocol and any error.
func (wrapper *LPIWrapper) ClassifyFlow(flow *types.Flow) (*types.Classification, error) {
	lpiFlow := C.lpiCreateFlow()
	defer C.lpiFreeFlow(lpiFlow)
	for _, packet := range flow.GetPackets() {
		pktData := packet.Data()
		// Skip packets without data to prevent segfault
		if len(pktData) == 0 {
			continue
		}
		dataPtr := unsafe.Pointer(&pktData[0])
		C.lpiAddPacketToFlow(lpiFlow, dataPtr, C.ushort(len(pktData)), C.int(flow.GetDirection(packet)))
	}
	lpiResult := (*C.struct_lpiResult)(unsafe.Pointer(C.lpiGuessProtocol(lpiFlow)))
	defer C.free(unsafe.Pointer(lpiResult))

	protoCode := uint32(lpiResult.proto)
	catCode := uint32(lpiResult.category)

	cat := lpiCodeToCategory[catCode]
	proto, found := lpiCodeToProtocol[protoCode]

	// If protocol code is not in map, check category to determine appropriate fallback
	if !found {
		// Map unmapped protocols based on their category
		switch cat {
		case types.CATEGORY_NOPAYLOAD:
			proto = types.NO_PAYLOAD
		case types.CATEGORY_UNSUPPORTED:
			proto = types.UNSUPPORTED
		case types.CATEGORY_UNKNOWN:
			proto = types.Unknown
		default:
			// For other categories with unmapped protocol codes, return unknown
			proto = types.Unknown
		}
	}

	return &types.Classification{
		Proto: proto,
		Class: cat,
	}, nil
}

// GetWrapperName returns the name of the wrapper, in order to identify which
// wrapper provided a classification.
func (wrapper *LPIWrapper) GetWrapperName() types.ClassificationSource {
	return LPIWrapperName
}

// GetSupportedCategories returns all categories supported by libprotoident.
func (wrapper *LPIWrapper) GetSupportedCategories() []types.Category {
	categories := make([]types.Category, 0, len(lpiCodeToCategory))
	seen := make(map[types.Category]bool)

	for _, category := range lpiCodeToCategory {
		if !seen[category] {
			categories = append(categories, category)
			seen[category] = true
		}
	}

	return categories
}

// GetSupportedProtocols returns all protocols supported by libprotoident.
func (wrapper *LPIWrapper) GetSupportedProtocols() []types.Protocol {
	protocols := make([]types.Protocol, 0, len(lpiCodeToProtocol))
	seen := make(map[types.Protocol]bool)

	for _, protocol := range lpiCodeToProtocol {
		if !seen[protocol] {
			protocols = append(protocols, protocol)
			seen[protocol] = true
		}
	}

	return protocols
}

#include "HTTP.h"

#include "Kernel.h"
#include "Memory.h"
#include "Network.h"
#include "Pack.h"
#include "Str.h"

static char http_404_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>404 Not Found</TITLE>\r\n</HEAD><BODY>\r\n<H1>Not Found</H1>\r\nThe requested URL $TARGET$ was not found on this server.<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";
static char http_403_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>403 Forbidden</TITLE>\r\n</HEAD><BODY>\r\n<H1>Forbidden</H1>\r\nYou don't have permission to access $TARGET$\r\non this server.<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";
static char http_500_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>500 Server Error</TITLE>\r\n</HEAD><BODY>\r\n<H1>Server Error</H1>\r\nServer Error<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";
static char http_501_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>501 Method Not Implemented</TITLE>\r\n</HEAD><BODY>\r\n<H1>Method Not Implemented</H1>\r\n$METHOD$ to $TARGET$ not supported.<P>\r\nInvalid method in request $METHOD$ $TARGET$ $VERSION$<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";

// MIME list from https://www.freeformatter.com/mime-types-list.html
static const HTTP_MIME_TYPE http_mime_types[] =
{
	{".x3d", "application/vnd.hzn-3d-crossword"},
	{".3gp", "video/3gpp"},
	{".3g2", "video/3gpp2"},
	{".mseq", "application/vnd.mseq"},
	{".pwn", "application/vnd.3m.post-it-notes"},
	{".plb", "application/vnd.3gpp.pic-bw-large"},
	{".psb", "application/vnd.3gpp.pic-bw-small"},
	{".pvb", "application/vnd.3gpp.pic-bw-var"},
	{".tcap", "application/vnd.3gpp2.tcap"},
	{".7z", "application/x-7z-compressed"},
	{".abw", "application/x-abiword"},
	{".ace", "application/x-ace-compressed"},
	{".acc", "application/vnd.americandynamics.acc"},
	{".acu", "application/vnd.acucobol"},
	{".atc", "application/vnd.acucorp"},
	{".adp", "audio/adpcm"},
	{".aab", "application/x-authorware-bin"},
	{".aam", "application/x-authorware-map"},
	{".aas", "application/x-authorware-seg"},
	{".air", "application/vnd.adobe.air-application-installer-package+zip"},
	{".swf", "application/x-shockwave-flash"},
	{".fxp", "application/vnd.adobe.fxp"},
	{".pdf", "application/pdf"},
	{".ppd", "application/vnd.cups-ppd"},
	{".dir", "application/x-director"},
	{".xdp", "application/vnd.adobe.xdp+xml"},
	{".xfdf", "application/vnd.adobe.xfdf"},
	{".aac", "audio/x-aac"},
	{".ahead", "application/vnd.ahead.space"},
	{".azf", "application/vnd.airzip.filesecure.azf"},
	{".azs", "application/vnd.airzip.filesecure.azs"},
	{".azw", "application/vnd.amazon.ebook"},
	{".ami", "application/vnd.amiga.ami"},
	{".apk", "application/vnd.android.package-archive"},
	{".cii", "application/vnd.anser-web-certificate-issue-initiation"},
	{".fti", "application/vnd.anser-web-funds-transfer-initiation"},
	{".atx", "application/vnd.antix.game-component"},
	{".dmg", "application/x-apple-diskimage"},
	{".mpkg", "application/vnd.apple.installer+xml"},
	{".aw", "application/applixware"},
	{".les", "application/vnd.hhe.lesson-player"},
	{".swi", "application/vnd.aristanetworks.swi"},
	{".s", "text/x-asm"},
	{".atomcat", "application/atomcat+xml"},
	{".atomsvc", "application/atomsvc+xml"},
	{".atom", "application/atom+xml"},
	{".ac", "application/pkix-attr-cert"},
	{".aif", "audio/x-aiff"},
	{".avi", "video/x-msvideo"},
	{".aep", "application/vnd.audiograph"},
	{".dxf", "image/vnd.dxf"},
	{".dwf", "model/vnd.dwf"},
	{".par", "text/plain-bas"},
	{".bcpio", "application/x-bcpio"},
	{".bin", "application/octet-stream"},
	{".bmp", "image/bmp"},
	{".torrent", "application/x-bittorrent"},
	{".cod", "application/vnd.rim.cod"},
	{".mpm", "application/vnd.blueice.multipass"},
	{".bmi", "application/vnd.bmi"},
	{".sh", "application/x-sh"},
	{".btif", "image/prs.btif"},
	{".rep", "application/vnd.businessobjects"},
	{".bz", "application/x-bzip"},
	{".bz2", "application/x-bzip2"},
	{".csh", "application/x-csh"},
	{".c", "text/x-c"},
	{".cdxml", "application/vnd.chemdraw+xml"},
	{".css", "text/css"},
	{".cdx", "chemical/x-cdx"},
	{".cml", "chemical/x-cml"},
	{".csml", "chemical/x-csml"},
	{".cdbcmsg", "application/vnd.contact.cmsg"},
	{".cla", "application/vnd.claymore"},
	{".c4g", "application/vnd.clonk.c4group"},
	{".sub", "image/vnd.dvb.subtitle"},
	{".cdmia", "application/cdmi-capability"},
	{".cdmic", "application/cdmi-container"},
	{".cdmid", "application/cdmi-domain"},
	{".cdmio", "application/cdmi-object"},
	{".cdmiq", "application/cdmi-queue"},
	{".c11amc", "application/vnd.cluetrust.cartomobile-config"},
	{".c11amz", "application/vnd.cluetrust.cartomobile-config-pkg"},
	{".ras", "image/x-cmu-raster"},
	{".dae", "model/vnd.collada+xml"},
	{".csv", "text/csv"},
	{".cpt", "application/mac-compactpro"},
	{".wmlc", "application/vnd.wap.wmlc"},
	{".cgm", "image/cgm"},
	{".ice", "x-conference/x-cooltalk"},
	{".cmx", "image/x-cmx"},
	{".xar", "application/vnd.xara"},
	{".cmc", "application/vnd.cosmocaller"},
	{".cpio", "application/x-cpio"},
	{".clkx", "application/vnd.crick.clicker"},
	{".clkk", "application/vnd.crick.clicker.keyboard"},
	{".clkp", "application/vnd.crick.clicker.palette"},
	{".clkt", "application/vnd.crick.clicker.template"},
	{".clkw", "application/vnd.crick.clicker.wordbank"},
	{".wbs", "application/vnd.criticaltools.wbs+xml"},
	{".cryptonote", "application/vnd.rig.cryptonote"},
	{".cif", "chemical/x-cif"},
	{".cmdf", "chemical/x-cmdf"},
	{".cu", "application/cu-seeme"},
	{".cww", "application/prs.cww"},
	{".curl", "text/vnd.curl"},
	{".dcurl", "text/vnd.curl.dcurl"},
	{".mcurl", "text/vnd.curl.mcurl"},
	{".scurl", "text/vnd.curl.scurl"},
	{".car", "application/vnd.curl.car"},
	{".pcurl", "application/vnd.curl.pcurl"},
	{".cmp", "application/vnd.yellowriver-custom-menu"},
	{".dssc", "application/dssc+der"},
	{".xdssc", "application/dssc+xml"},
	{".deb", "application/x-debian-package"},
	{".uva", "audio/vnd.dece.audio"},
	{".uvi", "image/vnd.dece.graphic"},
	{".uvh", "video/vnd.dece.hd"},
	{".uvm", "video/vnd.dece.mobile"},
	{".uvu", "video/vnd.uvvu.mp4"},
	{".uvp", "video/vnd.dece.pd"},
	{".uvs", "video/vnd.dece.sd"},
	{".uvv", "video/vnd.dece.video"},
	{".dvi", "application/x-dvi"},
	{".seed", "application/vnd.fdsn.seed"},
	{".dtb", "application/x-dtbook+xml"},
	{".res", "application/x-dtbresource+xml"},
	{".ait", "application/vnd.dvb.ait"},
	{".svc", "application/vnd.dvb.service"},
	{".eol", "audio/vnd.digital-winds"},
	{".djvu", "image/vnd.djvu"},
	{".dtd", "application/xml-dtd"},
	{".mlp", "application/vnd.dolby.mlp"},
	{".wad", "application/x-doom"},
	{".dpg", "application/vnd.dpgraph"},
	{".dra", "audio/vnd.dra"},
	{".dfac", "application/vnd.dreamfactory"},
	{".dts", "audio/vnd.dts"},
	{".dtshd", "audio/vnd.dts.hd"},
	{".dwg", "image/vnd.dwg"},
	{".geo", "application/vnd.dynageo"},
	{".es", "application/ecmascript"},
	{".mag", "application/vnd.ecowin.chart"},
	{".mmr", "image/vnd.fujixerox.edmics-mmr"},
	{".rlc", "image/vnd.fujixerox.edmics-rlc"},
	{".exi", "application/exi"},
	{".mgz", "application/vnd.proteus.magazine"},
	{".epub", "application/epub+zip"},
	{".eml", "message/rfc822"},
	{".nml", "application/vnd.enliven"},
	{".xpr", "application/vnd.is-xpr"},
	{".xif", "image/vnd.xiff"},
	{".xfdl", "application/vnd.xfdl"},
	{".emma", "application/emma+xml"},
	{".ez2", "application/vnd.ezpix-album"},
	{".ez3", "application/vnd.ezpix-package"},
	{".fst", "image/vnd.fst"},
	{".fvt", "video/vnd.fvt"},
	{".fbs", "image/vnd.fastbidsheet"},
	{".fe_launch", "application/vnd.denovo.fcselayout-link"},
	{".f4v", "video/x-f4v"},
	{".flv", "video/x-flv"},
	{".fpx", "image/vnd.fpx"},
	{".npx", "image/vnd.net-fpx"},
	{".flx", "text/vnd.fmi.flexstor"},
	{".fli", "video/x-fli"},
	{".ftc", "application/vnd.fluxtime.clip"},
	{".fdf", "application/vnd.fdf"},
	{".f", "text/x-fortran"},
	{".mif", "application/vnd.mif"},
	{".fm", "application/vnd.framemaker"},
	{".fh", "image/x-freehand"},
	{".fsc", "application/vnd.fsc.weblaunch"},
	{".fnc", "application/vnd.frogans.fnc"},
	{".ltf", "application/vnd.frogans.ltf"},
	{".ddd", "application/vnd.fujixerox.ddd"},
	{".xdw", "application/vnd.fujixerox.docuworks"},
	{".xbd", "application/vnd.fujixerox.docuworks.binder"},
	{".oas", "application/vnd.fujitsu.oasys"},
	{".oa2", "application/vnd.fujitsu.oasys2"},
	{".oa3", "application/vnd.fujitsu.oasys3"},
	{".fg5", "application/vnd.fujitsu.oasysgp"},
	{".bh2", "application/vnd.fujitsu.oasysprs"},
	{".spl", "application/x-futuresplash"},
	{".fzs", "application/vnd.fuzzysheet"},
	{".g3", "image/g3fax"},
	{".gmx", "application/vnd.gmx"},
	{".gtw", "model/vnd.gtw"},
	{".txd", "application/vnd.genomatix.tuxedo"},
	{".ggb", "application/vnd.geogebra.file"},
	{".ggt", "application/vnd.geogebra.tool"},
	{".gdl", "model/vnd.gdl"},
	{".gex", "application/vnd.geometry-explorer"},
	{".gxt", "application/vnd.geonext"},
	{".g2w", "application/vnd.geoplan"},
	{".g3w", "application/vnd.geospace"},
	{".gsf", "application/x-font-ghostscript"},
	{".bdf", "application/x-font-bdf"},
	{".gtar", "application/x-gtar"},
	{".texinfo", "application/x-texinfo"},
	{".gnumeric", "application/x-gnumeric"},
	{".kml", "application/vnd.google-earth.kml+xml"},
	{".kmz", "application/vnd.google-earth.kmz"},
	{".gqf", "application/vnd.grafeq"},
	{".gif", "image/gif"},
	{".gv", "text/vnd.graphviz"},
	{".gac", "application/vnd.groove-account"},
	{".ghf", "application/vnd.groove-help"},
	{".gim", "application/vnd.groove-identity-message"},
	{".grv", "application/vnd.groove-injector"},
	{".gtm", "application/vnd.groove-tool-message"},
	{".tpl", "application/vnd.groove-tool-template"},
	{".vcg", "application/vnd.groove-vcard"},
	{".h261", "video/h261"},
	{".h263", "video/h263"},
	{".h264", "video/h264"},
	{".hpid", "application/vnd.hp-hpid"},
	{".hps", "application/vnd.hp-hps"},
	{".hdf", "application/x-hdf"},
	{".rip", "audio/vnd.rip"},
	{".hbci", "application/vnd.hbci"},
	{".jlt", "application/vnd.hp-jlyt"},
	{".pcl", "application/vnd.hp-pcl"},
	{".hpgl", "application/vnd.hp-hpgl"},
	{".hvs", "application/vnd.yamaha.hv-script"},
	{".hvd", "application/vnd.yamaha.hv-dic"},
	{".hvp", "application/vnd.yamaha.hv-voice"},
	{".sfd-hdstx", "application/vnd.hydrostatix.sof-data"},
	{".stk", "application/hyperstudio"},
	{".hal", "application/vnd.hal+xml"},
	{".htm", "text/html; charset=utf-8"},
	{".html", "text/html; charset=utf-8"},
	{".irm", "application/vnd.ibm.rights-management"},
	{".sc", "application/vnd.ibm.secure-container"},
	{".ics", "text/calendar"},
	{".icc", "application/vnd.iccprofile"},
	{".ico", "image/x-icon"},
	{".igl", "application/vnd.igloader"},
	{".ief", "image/ief"},
	{".ivp", "application/vnd.immervision-ivp"},
	{".ivu", "application/vnd.immervision-ivu"},
	{".rif", "application/reginfo+xml"},
	{".3dml", "text/vnd.in3d.3dml"},
	{".spot", "text/vnd.in3d.spot"},
	{".igs", "model/iges"},
	{".i2g", "application/vnd.intergeo"},
	{".cdy", "application/vnd.cinderella"},
	{".xpw", "application/vnd.intercon.formnet"},
	{".fcs", "application/vnd.isac.fcs"},
	{".ipfix", "application/ipfix"},
	{".cer", "application/pkix-cert"},
	{".pki", "application/pkixcmp"},
	{".crl", "application/pkix-crl"},
	{".pkipath", "application/pkix-pkipath"},
	{".igm", "application/vnd.insors.igm"},
	{".rcprofile", "application/vnd.ipunplugged.rcprofile"},
	{".irp", "application/vnd.irepository.package+xml"},
	{".jad", "text/vnd.sun.j2me.app-descriptor"},
	{".jar", "application/java-archive"},
	{".class", "application/java-vm"},
	{".jnlp", "application/x-java-jnlp-file"},
	{".ser", "application/java-serialized-object"},
	{".java", "text/x-java-source"},
	{".js", "application/javascript"},
	{".json", "application/json"},
	{".joda", "application/vnd.joost.joda-archive"},
	{".jpm", "video/jpm"},
	{".jpg", "image/jpeg"},
	{".jpeg", "image/jpeg"},
	{".pjpeg", "image/pjpeg"},
	{".jpgv", "video/jpeg"},
	{".ktz", "application/vnd.kahootz"},
	{".mmd", "application/vnd.chipnuts.karaoke-mmd"},
	{".karbon", "application/vnd.kde.karbon"},
	{".chrt", "application/vnd.kde.kchart"},
	{".kfo", "application/vnd.kde.kformula"},
	{".flw", "application/vnd.kde.kivio"},
	{".kon", "application/vnd.kde.kontour"},
	{".kpr", "application/vnd.kde.kpresenter"},
	{".ksp", "application/vnd.kde.kspread"},
	{".kwd", "application/vnd.kde.kword"},
	{".htke", "application/vnd.kenameaapp"},
	{".kia", "application/vnd.kidspiration"},
	{".kne", "application/vnd.kinar"},
	{".sse", "application/vnd.kodak-descriptor"},
	{".lasxml", "application/vnd.las.las+xml"},
	{".latex", "application/x-latex"},
	{".lbd", "application/vnd.llamagraphics.life-balance.desktop"},
	{".lbe", "application/vnd.llamagraphics.life-balance.exchange+xml"},
	{".jam", "application/vnd.jam"},
	{"0.123", "application/vnd.lotus-1-2-3"},
	{".apr", "application/vnd.lotus-approach"},
	{".pre", "application/vnd.lotus-freelance"},
	{".nsf", "application/vnd.lotus-notes"},
	{".org", "application/vnd.lotus-organizer"},
	{".scm", "application/vnd.lotus-screencam"},
	{".lwp", "application/vnd.lotus-wordpro"},
	{".lvp", "audio/vnd.lucent.voice"},
	{".m3u", "audio/x-mpegurl"},
	{".m4v", "video/x-m4v"},
	{".hqx", "application/mac-binhex40"},
	{".portpkg", "application/vnd.macports.portpkg"},
	{".mgp", "application/vnd.osgeo.mapguide.package"},
	{".mrc", "application/marc"},
	{".mrcx", "application/marcxml+xml"},
	{".mxf", "application/mxf"},
	{".nbp", "application/vnd.wolfram.player"},
	{".ma", "application/mathematica"},
	{".mathml", "application/mathml+xml"},
	{".mbox", "application/mbox"},
	{".mc1", "application/vnd.medcalcdata"},
	{".mscml", "application/mediaservercontrol+xml"},
	{".cdkey", "application/vnd.mediastation.cdkey"},
	{".mwf", "application/vnd.mfer"},
	{".mfm", "application/vnd.mfmp"},
	{".msh", "model/mesh"},
	{".mads", "application/mads+xml"},
	{".mets", "application/mets+xml"},
	{".mods", "application/mods+xml"},
	{".meta4", "application/metalink4+xml"},
	{".mcd", "application/vnd.mcd"},
	{".flo", "application/vnd.micrografx.flo"},
	{".igx", "application/vnd.micrografx.igx"},
	{".es3", "application/vnd.eszigno3+xml"},
	{".mdb", "application/x-msaccess"},
	{".asf", "video/x-ms-asf"},
	{".exe", "application/x-msdownload"},
	{".cil", "application/vnd.ms-artgalry"},
	{".cab", "application/vnd.ms-cab-compressed"},
	{".ims", "application/vnd.ms-ims"},
	{".application", "application/x-ms-application"},
	{".clp", "application/x-msclip"},
	{".mdi", "image/vnd.ms-modi"},
	{".eot", "application/vnd.ms-fontobject"},
	{".xls", "application/vnd.ms-excel"},
	{".xlam", "application/vnd.ms-excel.addin.macroenabled.12"},
	{".xlsb", "application/vnd.ms-excel.sheet.binary.macroenabled.12"},
	{".xltm", "application/vnd.ms-excel.template.macroenabled.12"},
	{".xlsm", "application/vnd.ms-excel.sheet.macroenabled.12"},
	{".chm", "application/vnd.ms-htmlhelp"},
	{".crd", "application/x-mscardfile"},
	{".lrm", "application/vnd.ms-lrm"},
	{".mvb", "application/x-msmediaview"},
	{".mny", "application/x-msmoney"},
	{".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
	{".sldx", "application/vnd.openxmlformats-officedocument.presentationml.slide"},
	{".ppsx", "application/vnd.openxmlformats-officedocument.presentationml.slideshow"},
	{".potx", "application/vnd.openxmlformats-officedocument.presentationml.template"},
	{".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
	{".xltx", "application/vnd.openxmlformats-officedocument.spreadsheetml.template"},
	{".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
	{".dotx", "application/vnd.openxmlformats-officedocument.wordprocessingml.template"},
	{".obd", "application/x-msbinder"},
	{".thmx", "application/vnd.ms-officetheme"},
	{".onetoc", "application/onenote"},
	{".pya", "audio/vnd.ms-playready.media.pya"},
	{".pyv", "video/vnd.ms-playready.media.pyv"},
	{".ppt", "application/vnd.ms-powerpoint"},
	{".ppam", "application/vnd.ms-powerpoint.addin.macroenabled.12"},
	{".sldm", "application/vnd.ms-powerpoint.slide.macroenabled.12"},
	{".pptm", "application/vnd.ms-powerpoint.presentation.macroenabled.12"},
	{".ppsm", "application/vnd.ms-powerpoint.slideshow.macroenabled.12"},
	{".potm", "application/vnd.ms-powerpoint.template.macroenabled.12"},
	{".mpp", "application/vnd.ms-project"},
	{".pub", "application/x-mspublisher"},
	{".scd", "application/x-msschedule"},
	{".xap", "application/x-silverlight-app"},
	{".stl", "application/vnd.ms-pki.stl"},
	{".cat", "application/vnd.ms-pki.seccat"},
	{".vsd", "application/vnd.visio"},
	{".vsdx", "application/vnd.visio2013"},
	{".wm", "video/x-ms-wm"},
	{".wma", "audio/x-ms-wma"},
	{".wax", "audio/x-ms-wax"},
	{".wmx", "video/x-ms-wmx"},
	{".wmd", "application/x-ms-wmd"},
	{".wpl", "application/vnd.ms-wpl"},
	{".wmz", "application/x-ms-wmz"},
	{".wmv", "video/x-ms-wmv"},
	{".wvx", "video/x-ms-wvx"},
	{".wmf", "application/x-msmetafile"},
	{".trm", "application/x-msterminal"},
	{".doc", "application/msword"},
	{".docm", "application/vnd.ms-word.document.macroenabled.12"},
	{".dotm", "application/vnd.ms-word.template.macroenabled.12"},
	{".wri", "application/x-mswrite"},
	{".wps", "application/vnd.ms-works"},
	{".xbap", "application/x-ms-xbap"},
	{".xps", "application/vnd.ms-xpsdocument"},
	{".mid", "audio/midi"},
	{".mpy", "application/vnd.ibm.minipay"},
	{".afp", "application/vnd.ibm.modcap"},
	{".rms", "application/vnd.jcp.javame.midlet-rms"},
	{".tmo", "application/vnd.tmobile-livetv"},
	{".prc", "application/x-mobipocket-ebook"},
	{".mbk", "application/vnd.mobius.mbk"},
	{".dis", "application/vnd.mobius.dis"},
	{".plc", "application/vnd.mobius.plc"},
	{".mqy", "application/vnd.mobius.mqy"},
	{".msl", "application/vnd.mobius.msl"},
	{".txf", "application/vnd.mobius.txf"},
	{".daf", "application/vnd.mobius.daf"},
	{".fly", "text/vnd.fly"},
	{".mpc", "application/vnd.mophun.certificate"},
	{".mpn", "application/vnd.mophun.application"},
	{".mj2", "video/mj2"},
	{".mpga", "audio/mpeg"},
	{".mxu", "video/vnd.mpegurl"},
	{".mpeg", "video/mpeg"},
	{".m21", "application/mp21"},
	{".mp4a", "audio/mp4"},
	{".mp4", "video/mp4"},
	{".mp4", "application/mp4"},
	{".m3u8", "application/vnd.apple.mpegurl"},
	{".mus", "application/vnd.musician"},
	{".msty", "application/vnd.muvee.style"},
	{".mxml", "application/xv+xml"},
	{".ngdat", "application/vnd.nokia.n-gage.data"},
	{".n-gage", "application/vnd.nokia.n-gage.symbian.install"},
	{".ncx", "application/x-dtbncx+xml"},
	{".nc", "application/x-netcdf"},
	{".nlu", "application/vnd.neurolanguage.nlu"},
	{".dna", "application/vnd.dna"},
	{".nnd", "application/vnd.noblenet-directory"},
	{".nns", "application/vnd.noblenet-sealer"},
	{".nnw", "application/vnd.noblenet-web"},
	{".rpst", "application/vnd.nokia.radio-preset"},
	{".rpss", "application/vnd.nokia.radio-presets"},
	{".n3", "text/n3"},
	{".edm", "application/vnd.novadigm.edm"},
	{".edx", "application/vnd.novadigm.edx"},
	{".ext", "application/vnd.novadigm.ext"},
	{".gph", "application/vnd.flographit"},
	{".ecelp4800", "audio/vnd.nuera.ecelp4800"},
	{".ecelp7470", "audio/vnd.nuera.ecelp7470"},
	{".ecelp9600", "audio/vnd.nuera.ecelp9600"},
	{".oda", "application/oda"},
	{".ogx", "application/ogg"},
	{".oga", "audio/ogg"},
	{".ogv", "video/ogg"},
	{".dd2", "application/vnd.oma.dd2+xml"},
	{".oth", "application/vnd.oasis.opendocument.text-web"},
	{".opf", "application/oebps-package+xml"},
	{".qbo", "application/vnd.intu.qbo"},
	{".oxt", "application/vnd.openofficeorg.extension"},
	{".osf", "application/vnd.yamaha.openscoreformat"},
	{".weba", "audio/webm"},
	{".webm", "video/webm"},
	{".odc", "application/vnd.oasis.opendocument.chart"},
	{".otc", "application/vnd.oasis.opendocument.chart-template"},
	{".odb", "application/vnd.oasis.opendocument.database"},
	{".odf", "application/vnd.oasis.opendocument.formula"},
	{".odft", "application/vnd.oasis.opendocument.formula-template"},
	{".odg", "application/vnd.oasis.opendocument.graphics"},
	{".otg", "application/vnd.oasis.opendocument.graphics-template"},
	{".odi", "application/vnd.oasis.opendocument.image"},
	{".oti", "application/vnd.oasis.opendocument.image-template"},
	{".odp", "application/vnd.oasis.opendocument.presentation"},
	{".otp", "application/vnd.oasis.opendocument.presentation-template"},
	{".ods", "application/vnd.oasis.opendocument.spreadsheet"},
	{".ots", "application/vnd.oasis.opendocument.spreadsheet-template"},
	{".odt", "application/vnd.oasis.opendocument.text"},
	{".odm", "application/vnd.oasis.opendocument.text-master"},
	{".ott", "application/vnd.oasis.opendocument.text-template"},
	{".ktx", "image/ktx"},
	{".sxc", "application/vnd.sun.xml.calc"},
	{".stc", "application/vnd.sun.xml.calc.template"},
	{".sxd", "application/vnd.sun.xml.draw"},
	{".std", "application/vnd.sun.xml.draw.template"},
	{".sxi", "application/vnd.sun.xml.impress"},
	{".sti", "application/vnd.sun.xml.impress.template"},
	{".sxm", "application/vnd.sun.xml.math"},
	{".sxw", "application/vnd.sun.xml.writer"},
	{".sxg", "application/vnd.sun.xml.writer.global"},
	{".stw", "application/vnd.sun.xml.writer.template"},
	{".otf", "application/x-font-otf"},
	{".osfpvg", "application/vnd.yamaha.openscoreformat.osfpvg+xml"},
	{".dp", "application/vnd.osgi.dp"},
	{".pdb", "application/vnd.palm"},
	{".p", "text/x-pascal"},
	{".paw", "application/vnd.pawaafile"},
	{".pclxl", "application/vnd.hp-pclxl"},
	{".efif", "application/vnd.picsel"},
	{".pcx", "image/x-pcx"},
	{".psd", "image/vnd.adobe.photoshop"},
	{".prf", "application/pics-rules"},
	{".pic", "image/x-pict"},
	{".chat", "application/x-chat"},
	{".p10", "application/pkcs10"},
	{".p12", "application/x-pkcs12"},
	{".p7m", "application/pkcs7-mime"},
	{".p7s", "application/pkcs7-signature"},
	{".p7r", "application/x-pkcs7-certreqresp"},
	{".p7b", "application/x-pkcs7-certificates"},
	{".p8", "application/pkcs8"},
	{".plf", "application/vnd.pocketlearn"},
	{".pnm", "image/x-portable-anymap"},
	{".pbm", "image/x-portable-bitmap"},
	{".pcf", "application/x-font-pcf"},
	{".pfr", "application/font-tdpfr"},
	{".pgn", "application/x-chess-pgn"},
	{".pgm", "image/x-portable-graymap"},
	{".png", "image/png"},
	{".png", "image/x-citrix-png"},
	{".png", "image/x-png"},
	{".ppm", "image/x-portable-pixmap"},
	{".pskcxml", "application/pskc+xml"},
	{".pml", "application/vnd.ctc-posml"},
	{".ai", "application/postscript"},
	{".pfa", "application/x-font-type1"},
	{".pbd", "application/vnd.powerbuilder6"},
	{".pgp", "application/pgp-encrypted"},
	{".pgp", "application/pgp-signature"},
	{".box", "application/vnd.previewsystems.box"},
	{".ptid", "application/vnd.pvi.ptid1"},
	{".pls", "application/pls+xml"},
	{".str", "application/vnd.pg.format"},
	{".ei6", "application/vnd.pg.osasli"},
	{".dsc", "text/prs.lines.tag"},
	{".psf", "application/x-font-linux-psf"},
	{".qps", "application/vnd.publishare-delta-tree"},
	{".wg", "application/vnd.pmi.widget"},
	{".qxd", "application/vnd.quark.quarkxpress"},
	{".esf", "application/vnd.epson.esf"},
	{".msf", "application/vnd.epson.msf"},
	{".ssf", "application/vnd.epson.ssf"},
	{".qam", "application/vnd.epson.quickanime"},
	{".qfx", "application/vnd.intu.qfx"},
	{".qt", "video/quicktime"},
	{".rar", "application/x-rar-compressed"},
	{".ram", "audio/x-pn-realaudio"},
	{".rmp", "audio/x-pn-realaudio-plugin"},
	{".rsd", "application/rsd+xml"},
	{".rm", "application/vnd.rn-realmedia"},
	{".bed", "application/vnd.realvnc.bed"},
	{".mxl", "application/vnd.recordare.musicxml"},
	{".musicxml", "application/vnd.recordare.musicxml+xml"},
	{".rnc", "application/relax-ng-compact-syntax"},
	{".rdz", "application/vnd.data-vision.rdz"},
	{".rdf", "application/rdf+xml"},
	{".rp9", "application/vnd.cloanto.rp9"},
	{".jisp", "application/vnd.jisp"},
	{".rtf", "application/rtf"},
	{".rtx", "text/richtext"},
	{".link66", "application/vnd.route66.link66+xml"},
	{".rss", "application/rss+xml"},
	{".shf", "application/shf+xml"},
	{".st", "application/vnd.sailingtracker.track"},
	{".svg", "image/svg+xml"},
	{".sus", "application/vnd.sus-calendar"},
	{".sru", "application/sru+xml"},
	{".setpay", "application/set-payment-initiation"},
	{".setreg", "application/set-registration-initiation"},
	{".sema", "application/vnd.sema"},
	{".semd", "application/vnd.semd"},
	{".semf", "application/vnd.semf"},
	{".see", "application/vnd.seemail"},
	{".snf", "application/x-font-snf"},
	{".spq", "application/scvp-vp-request"},
	{".spp", "application/scvp-vp-response"},
	{".scq", "application/scvp-cv-request"},
	{".scs", "application/scvp-cv-response"},
	{".sdp", "application/sdp"},
	{".etx", "text/x-setext"},
	{".movie", "video/x-sgi-movie"},
	{".ifm", "application/vnd.shana.informed.formdata"},
	{".itp", "application/vnd.shana.informed.formtemplate"},
	{".iif", "application/vnd.shana.informed.interchange"},
	{".ipk", "application/vnd.shana.informed.package"},
	{".tfi", "application/thraud+xml"},
	{".shar", "application/x-shar"},
	{".rgb", "image/x-rgb"},
	{".slt", "application/vnd.epson.salt"},
	{".aso", "application/vnd.accpac.simply.aso"},
	{".imp", "application/vnd.accpac.simply.imp"},
	{".twd", "application/vnd.simtech-mindmapper"},
	{".csp", "application/vnd.commonspace"},
	{".saf", "application/vnd.yamaha.smaf-audio"},
	{".mmf", "application/vnd.smaf"},
	{".spf", "application/vnd.yamaha.smaf-phrase"},
	{".teacher", "application/vnd.smart.teacher"},
	{".svd", "application/vnd.svd"},
	{".rq", "application/sparql-query"},
	{".srx", "application/sparql-results+xml"},
	{".gram", "application/srgs"},
	{".grxml", "application/srgs+xml"},
	{".ssml", "application/ssml+xml"},
	{".skp", "application/vnd.koan"},
	{".sgml", "text/sgml"},
	{".sdc", "application/vnd.stardivision.calc"},
	{".sda", "application/vnd.stardivision.draw"},
	{".sdd", "application/vnd.stardivision.impress"},
	{".smf", "application/vnd.stardivision.math"},
	{".sdw", "application/vnd.stardivision.writer"},
	{".sgl", "application/vnd.stardivision.writer-global"},
	{".sm", "application/vnd.stepmania.stepchart"},
	{".sit", "application/x-stuffit"},
	{".sitx", "application/x-stuffitx"},
	{".sdkm", "application/vnd.solent.sdkm+xml"},
	{".xo", "application/vnd.olpc-sugar"},
	{".au", "audio/basic"},
	{".wqd", "application/vnd.wqd"},
	{".sis", "application/vnd.symbian.install"},
	{".smi", "application/smil+xml"},
	{".xsm", "application/vnd.syncml+xml"},
	{".bdm", "application/vnd.syncml.dm+wbxml"},
	{".xdm", "application/vnd.syncml.dm+xml"},
	{".sv4cpio", "application/x-sv4cpio"},
	{".sv4crc", "application/x-sv4crc"},
	{".sbml", "application/sbml+xml"},
	{".tsv", "text/tab-separated-values"},
	{".tiff", "image/tiff"},
	{".tao", "application/vnd.tao.intent-module-archive"},
	{".tar", "application/x-tar"},
	{".tcl", "application/x-tcl"},
	{".tex", "application/x-tex"},
	{".tfm", "application/x-tex-tfm"},
	{".tei", "application/tei+xml"},
	{".txt", "text/plain; charset=utf-8"},
	{".md", "text/markdown; charset=utf-8"},
	{".dxp", "application/vnd.spotfire.dxp"},
	{".sfs", "application/vnd.spotfire.sfs"},
	{".tsd", "application/timestamped-data"},
	{".tpt", "application/vnd.trid.tpt"},
	{".mxs", "application/vnd.triscape.mxs"},
	{".t", "text/troff"},
	{".tra", "application/vnd.trueapp"},
	{".ttf", "application/x-font-ttf"},
	{".ttl", "text/turtle"},
	{".umj", "application/vnd.umajin"},
	{".uoml", "application/vnd.uoml+xml"},
	{".unityweb", "application/vnd.unity"},
	{".ufd", "application/vnd.ufdl"},
	{".uri", "text/uri-list"},
	{".utz", "application/vnd.uiq.theme"},
	{".ustar", "application/x-ustar"},
	{".uu", "text/x-uuencode"},
	{".vcs", "text/x-vcalendar"},
	{".vcf", "text/x-vcard"},
	{".vcd", "application/x-cdlink"},
	{".vsf", "application/vnd.vsf"},
	{".wrl", "model/vrml"},
	{".vcx", "application/vnd.vcx"},
	{".mts", "model/vnd.mts"},
	{".vtu", "model/vnd.vtu"},
	{".vis", "application/vnd.visionary"},
	{".viv", "video/vnd.vivo"},
	{".ccxml", "application/ccxml+xml"},
	{".vxml", "application/voicexml+xml"},
	{".src", "application/x-wais-source"},
	{".wbxml", "application/vnd.wap.wbxml"},
	{".wbmp", "image/vnd.wap.wbmp"},
	{".wav", "audio/x-wav"},
	{".davmount", "application/davmount+xml"},
	{".woff", "application/x-font-woff"},
	{".wspolicy", "application/wspolicy+xml"},
	{".webp", "image/webp"},
	{".wtb", "application/vnd.webturbo"},
	{".wgt", "application/widget"},
	{".hlp", "application/winhlp"},
	{".wml", "text/vnd.wap.wml"},
	{".wmls", "text/vnd.wap.wmlscript"},
	{".wmlsc", "application/vnd.wap.wmlscriptc"},
	{".wpd", "application/vnd.wordperfect"},
	{".stf", "application/vnd.wt.stf"},
	{".wsdl", "application/wsdl+xml"},
	{".xbm", "image/x-xbitmap"},
	{".xpm", "image/x-xpixmap"},
	{".xwd", "image/x-xwindowdump"},
	{".der", "application/x-x509-ca-cert"},
	{".fig", "application/x-xfig"},
	{".xhtml", "application/xhtml+xml"},
	{".xml", "application/xml"},
	{".xdf", "application/xcap-diff+xml"},
	{".xenc", "application/xenc+xml"},
	{".xer", "application/patch-ops-error+xml"},
	{".rl", "application/resource-lists+xml"},
	{".rs", "application/rls-services+xml"},
	{".rld", "application/resource-lists-diff+xml"},
	{".xslt", "application/xslt+xml"},
	{".xop", "application/xop+xml"},
	{".xpi", "application/x-xpinstall"},
	{".xspf", "application/xspf+xml"},
	{".xul", "application/vnd.mozilla.xul+xml"},
	{".xyz", "chemical/x-xyz"},
	{".yaml", "text/yaml"},
	{".yang", "application/yang"},
	{".yin", "application/yin+xml"},
	{".zir", "application/vnd.zul"},
	{".zip", "application/zip"},
	{".zmm", "application/vnd.handheld-entertainment+xml"},
	{".zaz", "application/vnd.zzazz.deck+xml"},
};

// Detect HTTP MIME type from filename
char *GetMimeTypeFromFileName(char *filename)
{
	UINT i;
	const UINT num = sizeof(http_mime_types) / sizeof(HTTP_MIME_TYPE);
	if (filename == NULL)
	{
		return NULL;
	}

	for (i = 0; i < num; ++i)
	{
		const HTTP_MIME_TYPE *a = &http_mime_types[i];

		if (EndWith(filename, a->Extension))
		{
			return a->MimeType;
		}
	}

	return NULL;
}

// Generate the date and time string for the HTTP header
void GetHttpDateStr(char *str, UINT size, UINT64 t)
{
	SYSTEMTIME s;
	static char *wday[] =
	{
		"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
	};
	static char *month[] =
	{
		"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
		"Nov", "Dec",
	};
	// Validate arguments
	if (str == NULL)
	{
		return;
	}
	UINT64ToSystem(&s, t);

	Format(str, size, "%s, %02u %s %04u %02u:%02u:%02u GMT",
		wday[s.wDayOfWeek], s.wDay, month[s.wMonth - 1], s.wYear,
		s.wHour, s.wMinute, s.wSecond);
}

// Replace unsafe characters in target
void ReplaceUnsafeCharInHttpTarget(char *target)
{
	UINT i;
	for(i = 0; target[i] ; i++) {
		if(target[i] == '<')
			target[i] = '(';
		else if(target[i] == '>')
			target[i] = ')';
	}
}

// Create an HTTP header
HTTP_HEADER *NewHttpHeader(char *method, char *target, char *version)
{
	return NewHttpHeaderEx(method, target, version, false);
}
HTTP_HEADER *NewHttpHeaderEx(char *method, char *target, char *version, bool no_sort)
{
	HTTP_HEADER *header;
	// Validate arguments
	if (method == NULL || target == NULL || version == NULL)
	{
		return NULL;
	}

	header = ZeroMalloc(sizeof(HTTP_HEADER));

	header->Method = CopyStr(method);
	header->Target = CopyStr(target);
	header->Version = CopyStr(version);
	header->ValueList = NewListFast(no_sort ? NULL : CompareHttpValue);

	return header;
}

// Release the HTTP header
void FreeHttpHeader(HTTP_HEADER *header)
{
	UINT i;
	HTTP_VALUE **values;
	// Validate arguments
	if (header == NULL)
	{
		return;
	}

	Free(header->Method);
	Free(header->Target);
	Free(header->Version);

	values = ToArray(header->ValueList);
	for (i = 0;i < LIST_NUM(header->ValueList);i++)
	{
		FreeHttpValue(values[i]);
	}
	Free(values);

	ReleaseList(header->ValueList);

	Free(header);
}

// Create a new HTTP value
HTTP_VALUE *NewHttpValue(char *name, char *data)
{
	HTTP_VALUE *v;
	// Validate arguments
	if (name == NULL || data == NULL)
	{
		return NULL;
	}

	v = ZeroMalloc(sizeof(HTTP_VALUE));

	v->Name = CopyStr(name);
	v->Data = CopyStr(data);

	Trim(v->Name);
	Trim(v->Data);

	return v;
}

// Release the HTTP value
void FreeHttpValue(HTTP_VALUE *value)
{
	// Validate arguments
	if (value == NULL)
	{
		return;
	}

	Free(value->Data);
	Free(value->Name);

	Free(value);
}

// Comparison function of the HTTP value
int CompareHttpValue(void *p1, void *p2)
{
	HTTP_VALUE *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	v1 = *(HTTP_VALUE **)p1;
	v2 = *(HTTP_VALUE **)p2;
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}
	return StrCmpi(v1->Name, v2->Name);
}

// Look for an HTTP value in an HTTP header
HTTP_VALUE *GetHttpValue(HTTP_HEADER *header, char *name)
{
	HTTP_VALUE *v, t;
	// Validate arguments
	if (header == NULL || name == NULL)
	{
		return NULL;
	}

	t.Name = name;
	v = Search(header->ValueList, &t);
	if (v == NULL)
	{
		return NULL;
	}

	return v;
}

// Add an HTTP value to the HTTP header
void AddHttpValue(HTTP_HEADER *header, HTTP_VALUE *value)
{
	// Validate arguments
	if (header == NULL || value == NULL)
	{
		return;
	}

	if (LIST_NUM(header->ValueList) < HTTP_HEADER_MAX_LINES)
	{
		Insert(header->ValueList, value);
	}
	else
	{
		FreeHttpValue(value);
	}
}

// Adds the HTTP value contained in the string to the HTTP header
bool AddHttpValueStr(HTTP_HEADER* header, char *string)
{
	HTTP_VALUE *value = NULL;
	UINT pos = 0;
	char *value_name = NULL;
	char *value_data = NULL;

	// Validate arguments
	if (header == NULL || IsEmptyStr(string))
	{
		return false;
	}

	// Sanitize string
	EnSafeHttpHeaderValueStr(string, ' ');

	// Get the position of the colon
	pos = SearchStr(string, ":", 0);
	if (pos == INFINITE)
	{
		// The colon does not exist
		return false;
	}

	if ((pos + 1) >= StrLen(string))
	{
		// There is no data
		return false;
	}

	// Divide into the name and the data
	value_name = Malloc(pos + 1);
	Copy(value_name, string, pos);
	value_name[pos] = 0;
	value_data = &string[pos + 1];

	value = NewHttpValue(value_name, value_data);
	if (value == NULL)
	{
		Free(value_name);
		return false;
	}

	Free(value_name);

	AddHttpValue(header, value);

	return true;
}

// Get the Content-Length value from the HTTP header
UINT GetContentLength(HTTP_HEADER *header)
{
	UINT ret;
	HTTP_VALUE *v;
	// Validate arguments
	if (header == NULL)
	{
		return 0;
	}

	v = GetHttpValue(header, "Content-Length");
	if (v == NULL)
	{
		return 0;
	}

	ret = ToInt(v->Data);

	return ret;
}

// Send HTTP data
bool PostHttp(SOCK *s, HTTP_HEADER *header, void *post_data, UINT post_size)
{
	char *header_str;
	BUF *b;
	bool ret;
	// Validate arguments
	if (s == NULL || header == NULL || (post_size != 0 && post_data == NULL))
	{
		return false;
	}

	// Check whether the Content-Length exists?
	if (GetHttpValue(header, "Content-Length") == NULL)
	{
		char tmp[MAX_SIZE];
		// Add because it does not exist
		ToStr(tmp, post_size);
		AddHttpValue(header, NewHttpValue("Content-Length", tmp));
	}

	// Convert the header to string
	header_str = HttpHeaderToStr(header);
	if (header_str == NULL)
	{
		return false;
	}
	b = NewBuf();
	WriteBuf(b, header_str, StrLen(header_str));
	Free(header_str);

	// Append the data
	WriteBuf(b, post_data, post_size);

	// Send
	ret = SendAll(s, b->Buf, b->Size, s->SecureMode);

	FreeBuf(b);

	return ret;
}

// Convert an HTTP header to a string
char *HttpHeaderToStr(HTTP_HEADER *header)
{
	BUF *b;
	char *tmp;
	UINT i;
	char *s;
	// Validate arguments
	if (header == NULL)
	{
		return NULL;
	}

	tmp = Malloc(HTTP_HEADER_LINE_MAX_SIZE);
	b = NewBuf();

	// Header
	Format(tmp, HTTP_HEADER_LINE_MAX_SIZE,
		"%s %s %s\r\n", header->Method, header->Target, header->Version);
	WriteBuf(b, tmp, StrLen(tmp));

	// Value
	for (i = 0;i < LIST_NUM(header->ValueList);i++)
	{
		HTTP_VALUE *v = (HTTP_VALUE *)LIST_DATA(header->ValueList, i);
		Format(tmp, HTTP_HEADER_LINE_MAX_SIZE,
			"%s: %s\r\n", v->Name, v->Data);
		WriteBuf(b, tmp, StrLen(tmp));
	}

	// Trailing newline
	WriteBuf(b, "\r\n", 2);
	s = Malloc(b->Size + 1);
	Copy(s, b->Buf, b->Size);
	s[b->Size] = 0;

	FreeBuf(b);
	Free(tmp);

	return s;
}

// Send the HTTP header
bool SendHttpHeader(SOCK *s, HTTP_HEADER *header)
{
	char *str;
	bool ret;
	// Validate arguments
	if (s == NULL || header == NULL)
	{
		return false;
	}

	// Convert to string
	str = HttpHeaderToStr(header);

	// Transmission
	ret = SendAll(s, str, StrLen(str), s->SecureMode);

	Free(str);

	return ret;
}

// Receive an HTTP header
HTTP_HEADER *RecvHttpHeader(SOCK *s)
{
	TOKEN_LIST *token = NULL;
	char *str = NULL;
	HTTP_HEADER *header = NULL;
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}

	// Get the first line
	str = RecvLine(s, HTTP_HEADER_LINE_MAX_SIZE);
	if (str == NULL)
	{
		return NULL;
	}

	// Split into tokens
	token = ParseToken(str, " ");

	FreeSafe(PTR_TO_PTR(str));

	if (token->NumTokens < 3)
	{
		FreeToken(token);
		return NULL;
	}

	// Creating a header object
	header = NewHttpHeader(token->Token[0], token->Token[1], token->Token[2]);
	FreeToken(token);

	if (StrCmpi(header->Version, "HTTP/0.9") == 0)
	{
		// The header ends with this line
		return header;
	}

	// Get the subsequent lines
	while (true)
	{
		str = RecvLine(s, HTTP_HEADER_LINE_MAX_SIZE);
		Trim(str);
		if (IsEmptyStr(str))
		{
			// End of header
			FreeSafe(PTR_TO_PTR(str));
			break;
		}

		if (AddHttpValueStr(header, str) == false)
		{
			FreeSafe(PTR_TO_PTR(str));
			FreeHttpHeader(header);
			header = NULL;
			break;
		}

		FreeSafe(PTR_TO_PTR(str));
	}

	return header;
}

// Send a PACK to the server
bool HttpClientSend(SOCK *s, PACK *p)
{
	BUF *b;
	bool ret;
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char ip_str[MAX_SIZE];

	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return false;
	}

	IPToStr(ip_str, sizeof(ip_str), &s->RemoteIP);

	CreateDummyValue(p);

	b = PackToBuf(p);
	if (b == NULL)
	{
		return false;
	}

	h = NewHttpHeader("POST", HTTP_VPN_TARGET, "HTTP/1.1");

	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());
	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Host", ip_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE2));

	ret = PostHttp(s, h, b->Buf, b->Size);

	FreeHttpHeader(h);
	FreeBuf(b);

	return ret;
}

// Receive a PACK from the server
PACK *HttpClientRecv(SOCK *s)
{
	BUF *b;
	PACK *p;
	HTTP_HEADER *h;
	UINT size;
	UCHAR *tmp;
	HTTP_VALUE *v;
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}

	h = RecvHttpHeader(s);
	if (h == NULL)
	{
		return NULL;
	}

	if (StrCmpi(h->Method, "HTTP/1.1") != 0 ||
		StrCmpi(h->Target, "200") != 0)
	{
		FreeHttpHeader(h);
		return NULL;
	}

	v = GetHttpValue(h, "Content-Type");
	if (v == NULL || StrCmpi(v->Data, HTTP_CONTENT_TYPE2) != 0)
	{
		FreeHttpHeader(h);
		return NULL;
	}

	size = GetContentLength(h);
	if (size == 0 || size > MAX_PACK_SIZE)
	{
		FreeHttpHeader(h);
		return NULL;
	}

	tmp = MallocEx(size, true);
	if (RecvAll(s, tmp, size, s->SecureMode) == false)
	{
		Free(tmp);
		FreeHttpHeader(h);
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, tmp, size);
	Free(tmp);
	FreeHttpHeader(h);

	SeekBuf(b, 0, 0);
	p = BufToPack(b);
	FreeBuf(b);

	return p;
}

// Send a PACK to the client
bool HttpServerSend(SOCK *s, PACK *p)
{
	BUF *b;
	bool ret;
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return false;
	}

	CreateDummyValue(p);

	b = PackToBuf(p);
	if (b == NULL)
	{
		return false;
	}

	h = NewHttpHeader("HTTP/1.1", "200", "OK");

	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());
	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE2));

	ret = PostHttp(s, h, b->Buf, b->Size);

	FreeHttpHeader(h);
	FreeBuf(b);

	return ret;
}

// Receive a PACK from the client
PACK *HttpServerRecv(SOCK *s)
{
	return HttpServerRecvEx(s, 0);
}
PACK *HttpServerRecvEx(SOCK *s, UINT max_data_size)
{
	BUF *b;
	PACK *p;
	HTTP_HEADER *h;
	UINT size;
	UCHAR *tmp;
	HTTP_VALUE *v;
	UINT num_noop = 0;
	if (max_data_size == 0) max_data_size = HTTP_PACK_MAX_SIZE;
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}

START:
	h = RecvHttpHeader(s);
	if (h == NULL)
	{
		goto BAD_REQUEST;
	}

	if (StrCmpi(h->Method, "POST") != 0 ||
		StrCmpi(h->Target, HTTP_VPN_TARGET) != 0 ||
		StrCmpi(h->Version, "HTTP/1.1") != 0)
	{
		FreeHttpHeader(h);
		goto BAD_REQUEST;
	}

	v = GetHttpValue(h, "Content-Type");
	if (v == NULL || StrCmpi(v->Data, HTTP_CONTENT_TYPE2) != 0)
	{
		FreeHttpHeader(h);
		goto BAD_REQUEST;
	}

	size = GetContentLength(h);
	if (size == 0 || (size > max_data_size))
	{
		FreeHttpHeader(h);
		goto BAD_REQUEST;
	}

	tmp = MallocEx(size, true);
	if (RecvAll(s, tmp, size, s->SecureMode) == false)
	{
		Free(tmp);
		FreeHttpHeader(h);
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, tmp, size);
	Free(tmp);
	FreeHttpHeader(h);

	SeekBuf(b, 0, 0);
	p = BufToPack(b);
	FreeBuf(b);

	// Determine whether it's a NOOP
	if (PackGetInt(p, "noop") != 0)
	{
		Debug("recv: noop\n");
		FreePack(p);

		p = PackError(0);
		PackAddInt(p, "noop", 1);
		if (HttpServerSend(s, p) == false)
		{
			FreePack(p);
			return NULL;
		}

		FreePack(p);

		num_noop++;

		if (num_noop > MAX_NOOP_PER_SESSION)
		{
			return NULL;
		}

		goto START;
	}

	return p;

BAD_REQUEST:
	// Return an error
	return NULL;
}

// Send "403 Forbidden" error
bool HttpSendForbidden(SOCK *s, char *target, char *server_id)
{
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char *str;
	UINT str_size;
	char port_str[MAX_SIZE];
	bool ret;
	char host[MAX_SIZE];
	UINT port;
	// Validate arguments
	if (s == NULL || target == NULL)
	{
		return false;
	}

	// Get the host name
	//GetMachineName(host, MAX_SIZE);
	Zero(host, sizeof(host));
	IPToStr(host, sizeof(host), &s->LocalIP);
	// Get the port number
	port = s->LocalPort;

	// Creating a header
	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	h = NewHttpHeader("HTTP/1.1", "403", "Forbidden");

	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE));

	// Creating a Data
	str_size = sizeof(http_403_str) * 2 + StrLen(target) + StrLen(host);
	str = Malloc(str_size);
	StrCpy(str, str_size, http_403_str);

	// TARGET
	ReplaceUnsafeCharInHttpTarget(target);
	ReplaceStri(str, str_size, str, "$TARGET$", target);

	// HOST
	ReplaceStri(str, str_size, str, "$HOST$", host);

	// PORT
	ToStr(port_str, port);
	ReplaceStri(str, str_size, str, "$PORT$", port_str);

	// Transmission
	ret = PostHttp(s, h, str, StrLen(str));

	FreeHttpHeader(h);
	Free(str);

	return ret;
}

// Send "404 Not Found" error
bool HttpSendNotFound(SOCK *s, char *target)
{
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char *str;
	UINT str_size;
	char port_str[MAX_SIZE];
	bool ret;
	char host[MAX_SIZE];
	UINT port;
	// Validate arguments
	if (s == NULL || target == NULL)
	{
		return false;
	}

	// Get the host name
	//GetMachineName(host, MAX_SIZE);
	Zero(host, sizeof(host));
	IPToStr(host, sizeof(host), &s->LocalIP);
	// Get the port number
	port = s->LocalPort;

	// Creating a header
	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	h = NewHttpHeader("HTTP/1.1", "404", "Not Found");

	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE));

	// Creating a Data
	str_size = sizeof(http_404_str) * 2 + StrLen(target) + StrLen(host);
	str = Malloc(str_size);
	StrCpy(str, str_size, http_404_str);

	// TARGET
	ReplaceUnsafeCharInHttpTarget(target);
	ReplaceStri(str, str_size, str, "$TARGET$", target);

	// HOST
	ReplaceStri(str, str_size, str, "$HOST$", host);

	// PORT
	ToStr(port_str, port);
	ReplaceStri(str, str_size, str, "$PORT$", port_str);

	// Transmission
	ret = PostHttp(s, h, str, StrLen(str));

	FreeHttpHeader(h);
	Free(str);

	return ret;
}

// Send "501 Not Implemented" error
bool HttpSendNotImplemented(SOCK *s, char *method, char *target, char *version)
{
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char *str;
	UINT str_size;
	char port_str[MAX_SIZE];
	bool ret;
	char host[MAX_SIZE];
	UINT port;
	// Validate arguments
	if (s == NULL || target == NULL)
	{
		return false;
	}

	// Get the host name
	//GetMachineName(host, MAX_SIZE);
	Zero(host, sizeof(host));
	IPToStr(host, sizeof(host), &s->LocalIP);
	// Get the port number
	port = s->LocalPort;

	// Creating a header
	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	h = NewHttpHeader("HTTP/1.1", "501", "Method Not Implemented");

	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE));

	// Creating a Data
	str_size = sizeof(http_501_str) * 2 + StrLen(target) + StrLen(host) + StrLen(method) + StrLen(version);
	str = Malloc(str_size);
	StrCpy(str, str_size, http_501_str);

	// TARGET
	ReplaceUnsafeCharInHttpTarget(target);
	ReplaceStri(str, str_size, str, "$TARGET$", target);

	// HOST
	ReplaceStri(str, str_size, str, "$HOST$", host);

	// PORT
	ToStr(port_str, port);
	ReplaceStri(str, str_size, str, "$PORT$", port_str);

	// METHOD
	ReplaceStri(str, str_size, str, "$METHOD$", method);

	// VERSION
	ReplaceStri(str, str_size, str, "$VERSION$", version);

	// Transmission
	ret = PostHttp(s, h, str, StrLen(str));

	FreeHttpHeader(h);
	Free(str);

	return ret;
}

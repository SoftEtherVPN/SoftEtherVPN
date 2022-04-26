// SoftEther VPN Source Code - Stable Edition Repository
// Cedar Communication Module
// 
// SoftEther VPN Server, Client and Bridge are free software under the Apache License, Version 2.0.
// 
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// Copyright (c) all contributors on SoftEther VPN project in GitHub.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// This stable branch is officially managed by Daiyuu Nobori, the owner of SoftEther VPN Project.
// Pull requests should be sent to the Developer Edition Master Repository on https://github.com/SoftEtherVPN/SoftEtherVPN
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
// 
// DISCLAIMER
// ==========
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN, UNDER
// JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY, MERGE, PUBLISH,
// DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS SOFTWARE, THAT ANY
// JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS SOFTWARE OR ITS CONTENTS,
// AGAINST US (SOFTETHER PROJECT, SOFTETHER CORPORATION, DAIYUU NOBORI OR OTHER
// SUPPLIERS), OR ANY JURIDICAL DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND
// OF USING, COPYING, MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING,
// AND/OR SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO EXCLUSIVE
// JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO, JAPAN. YOU MUST WAIVE
// ALL DEFENSES OF LACK OF PERSONAL JURISDICTION AND FORUM NON CONVENIENS.
// PROCESS MAY BE SERVED ON EITHER PARTY IN THE MANNER AUTHORIZED BY APPLICABLE
// LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS YOU HAVE
// A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY CRIMINAL LAWS OR CIVIL
// RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS SOFTWARE IN OTHER COUNTRIES IS
// COMPLETELY AT YOUR OWN RISK. THE SOFTETHER VPN PROJECT HAS DEVELOPED AND
// DISTRIBUTED THIS SOFTWARE TO COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING
// CIVIL RIGHTS INCLUDING PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER
// COUNTRIES' LAWS OR CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES.
// WE HAVE NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+ COUNTRIES
// AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE WORLD, WITH
// DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY COUNTRIES' LAWS, REGULATIONS
// AND CIVIL RIGHTS TO MAKE THE SOFTWARE COMPLY WITH ALL COUNTRIES' LAWS BY THE
// PROJECT. EVEN IF YOU WILL BE SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A
// PUBLIC SERVANT IN YOUR COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE
// LIABLE TO RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT JUST A
// STATEMENT FOR WARNING AND DISCLAIMER.
// 
// READ AND UNDERSTAND THE 'WARNING.TXT' FILE BEFORE USING THIS SOFTWARE.
// SOME SOFTWARE PROGRAMS FROM THIRD PARTIES ARE INCLUDED ON THIS SOFTWARE WITH
// LICENSE CONDITIONS WHICH ARE DESCRIBED ON THE 'THIRD_PARTY.TXT' FILE.
// 
// 
// SOURCE CODE CONTRIBUTION
// ------------------------
// 
// Your contribution to SoftEther VPN Project is much appreciated.
// Please send patches to us through GitHub.
// Read the SoftEther VPN Patch Acceptance Policy in advance:
// http://www.softether.org/5-download/src/9.patch
// 
// 
// DEAR SECURITY EXPERTS
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// softether-vpn-security [at] softether.org
// 
// Please note that the above e-mail address is not a technical support
// inquiry address. If you need technical assistance, please visit
// http://www.softether.org/ and ask your question on the users forum.
// 
// Thank you for your cooperation.
// 
// 
// NO MEMORY OR RESOURCE LEAKS
// ---------------------------
// 
// The memory-leaks and resource-leaks verification under the stress
// test has been passed before release this source code.


// Protocol.c
// SoftEther protocol related routines

#include "CedarPch.h"

static UCHAR ssl_packet_start[3] = {0x17, 0x03, 0x00};

// MIME list from https://www.freeformatter.com/mime-types-list.html
static HTTP_MIME_TYPE http_mime_types[] =
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

// Get HTTP MIME type from filename
char *GetMimeTypeFromFileName(char *filename)
{
	UINT i;
	UINT num = sizeof(http_mime_types) / sizeof(HTTP_MIME_TYPE);
	if (filename == NULL)
	{
		return NULL;
	}

	for (i = 0;i < num;i++)
	{
		HTTP_MIME_TYPE *a = &http_mime_types[i];

		if (EndWith(filename, a->Extension))
		{
			return a->MimeType;
		}
	}

	return NULL;
}

// Download and save intermediate certificates if necessary
bool DownloadAndSaveIntermediateCertificatesIfNecessary(X *x)
{
	LIST *o;
	bool ret = false;
	// Validate arguments
	if (x == NULL)
	{
		return false;
	}

	if (x->root_cert)
	{
		return true;
	}

	o = NewCertList(true);

	ret = TryGetRootCertChain(o, x, true, NULL);

	FreeCertList(o);

	return ret;
}

// Attempt to fetch the full chain of the specified cert
bool TryGetRootCertChain(LIST *o, X *x, bool auto_save, X **found_root_x)
{
	bool ret = false;
	LIST *chain = NULL;
	LIST *current_chain_dir = NULL;
	// Validate arguments
	if (o == NULL || x == NULL)
	{
		return false;
	}

	chain = NewCertList(false);

	ret = TryGetParentCertFromCertList(o, x, chain);

	if (ret)
	{
		UINT i;
		DIRLIST *dir;
		wchar_t dirname[MAX_SIZE];
		wchar_t exedir[MAX_SIZE];

		GetExeDirW(exedir, sizeof(exedir));
		CombinePathW(dirname, sizeof(dirname), exedir, L"chain_certs");
		MakeDirExW(dirname);

		if (auto_save)
		{
			// delete the current auto_save files
			dir = EnumDirW(dirname);
			if (dir != NULL)
			{
				for (i = 0;i < dir->NumFiles;i++)
				{
					DIRENT *e = dir->File[i];

					if (e->Folder == false)
					{
						if (UniStartWith(e->FileNameW, AUTO_DOWNLOAD_CERTS_PREFIX))
						{
							wchar_t tmp[MAX_SIZE];

							CombinePathW(tmp, sizeof(tmp), dirname, e->FileNameW);

							FileDeleteW(tmp);
						}
					}
				}

				FreeDir(dir);
			}
		}

		current_chain_dir = NewCertList(false);
		AddAllChainCertsToCertList(current_chain_dir);

		for (i = 0;i < LIST_NUM(chain);i++)
		{
			wchar_t tmp[MAX_SIZE];
			X *xx = LIST_DATA(chain, i);

			GetAllNameFromName(tmp, sizeof(tmp), xx->subject_name);

			Debug("depth = %u, subject = %S\n", i, tmp);

			if (auto_save && CompareX(x, xx) == false && IsXInCertList(current_chain_dir, xx) == false)
			{
				wchar_t fn[MAX_PATH];
				char hex_a[128];
				wchar_t hex[128];
				UCHAR hash[SHA1_SIZE];
				wchar_t tmp[MAX_SIZE];
				BUF *b;

				GetXDigest(xx, hash, true);
				BinToStr(hex_a, sizeof(hex_a), hash, SHA1_SIZE);
				StrToUni(hex, sizeof(hex), hex_a);

				UniStrCpy(fn, sizeof(fn), AUTO_DOWNLOAD_CERTS_PREFIX);
				UniStrCat(fn, sizeof(fn), hex);
				UniStrCat(fn, sizeof(fn), L".cer");

				CombinePathW(tmp, sizeof(tmp), dirname, fn);

				b = XToBuf(xx, true);

				DumpBufW(b, tmp);

				FreeBuf(b);
			}

			if (xx->root_cert)
			{
				if (found_root_x != NULL)
				{
					*found_root_x = CloneX(xx);
				}
			}
		}
	}

	FreeCertList(chain);

	FreeCertList(current_chain_dir);

	return ret;
}

// Try get the parent cert
bool TryGetParentCertFromCertList(LIST *o, X *x, LIST *found_chain)
{
	bool ret = false;
	X *r;
	bool do_free = false;
	// Validate arguments
	if (o == NULL || x == NULL || found_chain == NULL)
	{
		return false;
	}

	if (LIST_NUM(found_chain) >= FIND_CERT_CHAIN_MAX_DEPTH)
	{
		return false;
	}

	Add(found_chain, CloneX(x));

	if (x->root_cert)
	{
		return true;
	}

	r = FindCertIssuerFromCertList(o, x);

	if (r == NULL)
	{
		if (IsEmptyStr(x->issuer_url) == false)
		{
			r = DownloadCert(x->issuer_url);

			if (CheckXEx(x, r, true, true) && CompareX(x, r) == false)
			{
				// found
				do_free = true;
			}
			else
			{
				// invalid
				FreeX(r);
				r = NULL;
			}
		}
	}

	if (r != NULL)
	{
		ret = TryGetParentCertFromCertList(o, r, found_chain);
	}

	if (do_free)
	{
		FreeX(r);
	}

	return ret;
}

// Find the issuer of the cert from the cert list
X *FindCertIssuerFromCertList(LIST *o, X *x)
{
	UINT i;
	// Validate arguments
	if (o == NULL || x == NULL)
	{
		return NULL;
	}

	if (x->root_cert)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		X *xx = LIST_DATA(o, i);

		if (CheckXEx(x, xx, true, true))
		{
			if (CompareX(x, xx) == false)
			{
				return xx;
			}
		}
	}

	return NULL;
}

// Download a cert by using HTTP
X *DownloadCert(char *url)
{
	BUF *b;
	URL_DATA url_data;
	X *ret = NULL;
	// Validate arguments
	if (IsEmptyStr(url))
	{
		return NULL;
	}

	Debug("Trying to download a cert from %s ...\n", url);

	if (ParseUrl(&url_data, url, false, NULL) == false)
	{
		Debug("Download failed.\n");
		return NULL;
	}

	b = HttpRequestEx(&url_data, NULL, CERT_HTTP_DOWNLOAD_TIMEOUT, CERT_HTTP_DOWNLOAD_TIMEOUT,
		NULL, false, NULL, NULL, NULL, NULL, NULL, CERT_HTTP_DOWNLOAD_MAXSIZE);

	if (b == NULL)
	{
		Debug("Download failed.\n");
		return NULL;
	}

	ret = BufToX(b, IsBase64(b));

	FreeBuf(b);

	Debug("Download ok.\n");
	return ret;
}

// New cert list
LIST *NewCertList(bool load_root_and_chain)
{
	LIST *o;

	o = NewList(NULL);

	if (load_root_and_chain)
	{
		AddAllRootCertsToCertList(o);
		AddAllChainCertsToCertList(o);
	}

	return o;
}

// Free cert list
void FreeCertList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		X *x = LIST_DATA(o, i);

		FreeX(x);
	}

	ReleaseList(o);
}

// Check whether the cert is in the cert list
bool IsXInCertList(LIST *o, X *x)
{
	UINT i;
	// Validate arguments
	if (o == NULL || x == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		X *xx = LIST_DATA(o, i);

		if (CompareX(x, xx))
		{
			return true;
		}
	}

	return false;
}

// Add a cert to the cert list
void AddXToCertList(LIST *o, X *x)
{
	// Validate arguments
	if (o == NULL || x == NULL)
	{
		return;
	}

	if (IsXInCertList(o, x))
	{
		return;
	}

	if (CheckXDateNow(x) == false)
	{
		return;
	}

	Add(o, CloneX(x));
}

// Add all chain certs to the cert list
void AddAllChainCertsToCertList(LIST *o)
{
	wchar_t dirname[MAX_SIZE];
	wchar_t exedir[MAX_SIZE];
	DIRLIST *dir;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	GetExeDirW(exedir, sizeof(exedir));

	CombinePathW(dirname, sizeof(dirname), exedir, L"chain_certs");

	MakeDirExW(dirname);

	dir = EnumDirW(dirname);

	if (dir != NULL)
	{
		UINT i;

		for (i = 0;i < dir->NumFiles;i++)
		{
			DIRENT *e = dir->File[i];

			if (e->Folder == false)
			{
				wchar_t tmp[MAX_SIZE];
				X *x;

				CombinePathW(tmp, sizeof(tmp), dirname, e->FileNameW);

				x = FileToXW(tmp);

				if (x != NULL)
				{
					AddXToCertList(o, x);

					FreeX(x);
				}
			}
		}

		FreeDir(dir);
	}
}

// Add all root certs to the cert list
void AddAllRootCertsToCertList(LIST *o)
{
	BUF *buf;
	PACK *p;
	UINT num_ok = 0, num_error = 0;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	buf = ReadDump(ROOT_CERTS_FILENAME);
	if (buf == NULL)
	{
		return;
	}

	p = BufToPack(buf);

	if (p != NULL)
	{
		UINT num = PackGetIndexCount(p, "cert");
		UINT i;

		for (i = 0;i < num;i++)
		{
			bool ok = false;
			BUF *b = PackGetBufEx(p, "cert", i);

			if (b != NULL)
			{
				X *x = BufToX(b, false);

				if (x != NULL)
				{
					AddXToCertList(o, x);

					ok = true;

					FreeX(x);
				}

				FreeBuf(b);
			}

			if (ok)
			{
				num_ok++;
			}
			else
			{
				num_error++;
			}
		}

		FreePack(p);
	}

	FreeBuf(buf);

	Debug("AddAllRootCertsToCertList: ok=%u error=%u total_list_len=%u\n", num_ok, num_error, LIST_NUM(o));
}

// Convert the date of YYYYMMDD format to a number
UINT64 ShortStrToDate64(char *str)
{
	UINT v;
	SYSTEMTIME st;
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	v = ToInt(str);

	Zero(&st, sizeof(st));

	st.wYear = (v % 100000000) / 10000;
	st.wMonth = (v % 10000) / 100;
	st.wDay = v % 100;

	return SystemToUINT64(&st);
}

// Handle the response that is returned from the server in the update client
void UpdateClientThreadProcessResults(UPDATE_CLIENT *c, BUF *b)
{
	bool exit = false;
	// Validate arguments
	if (c == NULL || b == NULL)
	{
		return;
	}

	SeekBufToBegin(b);

	while (true)
	{
		char *line = CfgReadNextLine(b);
		if (line == NULL)
		{
			break;
		}

		Trim(line);

		if (StartWith(line, "#") == false && IsEmptyStr(line) == false)
		{
			TOKEN_LIST *t = ParseTokenWithNullStr(line, " \t");

			if (t != NULL)
			{
				if (t->NumTokens >= 5)
				{
					if (StrCmpi(t->Token[0], c->FamilyName) == 0)
					{
						// Match
						UINT64 date = ShortStrToDate64(t->Token[1]);
						if (date != 0)
						{
							UINT build = ToInt(t->Token[2]);
							if (build != 0)
							{
								if (build > c->MyBuild && build > c->LatestBuild && build > c->Setting.LatestIgnoreBuild)
								{
									c->Callback(c, build, date, t->Token[3], t->Token[4], &c->HaltFlag, c->Param);

									c->LatestBuild = build;

									exit = true;
								}
							}
						}
					}
				}

				FreeToken(t);
			}
		}

		Free(line);

		if (exit)
		{
			break;
		}
	}
}

// Update client main process
void UpdateClientThreadMain(UPDATE_CLIENT *c)
{
	char url[MAX_SIZE];
	char id[MAX_SIZE];
	URL_DATA data;
	BUF *cert_hash;
	UINT ret = 0;
	BUF *recv;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	// Generate the URL
	Format(url, sizeof(url), IsUseAlternativeHostname() ? UPDATE_SERVER_URL_CHINA : UPDATE_SERVER_URL_GLOBAL, c->FamilyName, c->SoftwareName, c->MyBuild, c->MyLanguage);

	if (IsEmptyStr(c->ClientId) == false)
	{
		Format(id, sizeof(id), "&id=%s", c->ClientId);
		StrCat(url, sizeof(url), id);
	}

	// Get a text file at this URL
	if (ParseUrl(&data, url, false, NULL) == false)
	{
		return;
	}

	cert_hash = StrToBin(UPDATE_SERVER_CERT_HASH);

	StrCpy(data.SniString, sizeof(data.SniString), DDNS_SNI_VER_STRING);

	recv = HttpRequestEx3(&data, NULL, UPDATE_CONNECT_TIMEOUT, UPDATE_COMM_TIMEOUT, &ret, false, NULL, NULL,
		NULL, ((cert_hash != NULL && (cert_hash->Size % SHA1_SIZE) == 0) ? cert_hash->Buf : NULL),
		(cert_hash != NULL ? (cert_hash->Size / SHA1_SIZE) : 0),
		(bool *)&c->HaltFlag, 0, NULL, NULL);

	FreeBuf(cert_hash);

	if (recv != NULL)
	{
		UpdateClientThreadProcessResults(c, recv);

		FreeBuf(recv);
	}
}

// Update client main thread
void UpdateClientThreadProc(THREAD *thread, void *param)
{
	UPDATE_CLIENT *c = (UPDATE_CLIENT *)param;
	bool first_loop = true;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	while (true)
	{
		// Termination check
		if (c->HaltFlag)
		{
			break;
		}

		if (first_loop == false)
		{
			// Wait for the foreground
			if (c->IsForegroundCb != NULL)
			{
				while (true)
				{
					if (c->HaltFlag)
					{
						break;
					}

					if (c->IsForegroundCb(c, c->Param))
					{
						break;
					}

					Wait(c->HaltEvent, 1000);
				}
			}
		}

		first_loop = false;

		if (c->HaltFlag)
		{
			break;
		}

		if (c->Setting.DisableCheck == false)
		{
			UpdateClientThreadMain(c);
		}

		// Wait until the next attempt
		Wait(c->HaltEvent, GenRandInterval(UPDATE_CHECK_INTERVAL_MIN, UPDATE_CHECK_INTERVAL_MAX));
	}
}

// Update the configuration of the update client
void SetUpdateClientSetting(UPDATE_CLIENT *c, UPDATE_CLIENT_SETTING *s)
{
	bool old_disable;
	// Validate arguments
	if (c == NULL || s == NULL)
	{
		return;
	}

	old_disable = c->Setting.DisableCheck;

	Copy(&c->Setting, s, sizeof(UPDATE_CLIENT_SETTING));

	Set(c->HaltEvent);
}

// Start the update client
UPDATE_CLIENT *NewUpdateClient(UPDATE_NOTIFY_PROC *cb, UPDATE_ISFOREGROUND_PROC *isforeground_cb, void *param, char *family_name, char *software_name, wchar_t *software_title, UINT my_build, UINT64 my_date, char *my_lang, UPDATE_CLIENT_SETTING *current_setting, char *client_id)
{
	UPDATE_CLIENT *c;
	// Validate arguments
	if (family_name == NULL || software_title == NULL || software_name == NULL || my_build == 0 ||
		my_lang == NULL || current_setting == NULL || cb == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(UPDATE_CLIENT));

	c->Callback = cb;
	c->IsForegroundCb = isforeground_cb;

	StrCpy(c->ClientId, sizeof(c->ClientId), client_id);
	StrCpy(c->FamilyName, sizeof(c->FamilyName), family_name);
	StrCpy(c->SoftwareName, sizeof(c->SoftwareName), software_name);
	UniStrCpy(c->SoftwareTitle, sizeof(c->SoftwareTitle), software_title);
	c->MyBuild = my_build;
	c->MyDate = my_date;
	StrCpy(c->MyLanguage, sizeof(c->MyLanguage), my_lang);

	Copy(&c->Setting, current_setting, sizeof(c->Setting));

	c->Param = param;

	c->HaltEvent = NewEvent();

	// Create a thread
	c->Thread = NewThread(UpdateClientThreadProc, c);

	return c;
}

// Terminate the update client
void FreeUpdateClient(UPDATE_CLIENT *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	// Thread stop
	c->HaltFlag = true;
	Set(c->HaltEvent);

	// Wait for thread termination
	WaitThread(c->Thread, INFINITE);

	ReleaseThread(c->Thread);
	ReleaseEvent(c->HaltEvent);

	Free(c);
}

// Generate unique IDs for each machine
void GenerateMachineUniqueHash(void *data)
{
	BUF *b;
	char name[64];
	OS_INFO *osinfo;
	UINT64 iphash = 0;
	// Validate arguments
	if (data == NULL)
	{
		return;
	}

	iphash = GetHostIPAddressListHash();

	b = NewBuf();
	GetMachineName(name, sizeof(name));

	osinfo = GetOsInfo();

	WriteBuf(b, name, StrLen(name));

	WriteBufInt64(b, iphash);

	WriteBuf(b, &osinfo->OsType, sizeof(osinfo->OsType));
	WriteBuf(b, osinfo->KernelName, StrLen(osinfo->KernelName));
	WriteBuf(b, osinfo->KernelVersion, StrLen(osinfo->KernelVersion));
	WriteBuf(b, osinfo->OsProductName, StrLen(osinfo->OsProductName));
	WriteBuf(b, &osinfo->OsServicePack, sizeof(osinfo->OsServicePack));
	WriteBuf(b, osinfo->OsSystemName, StrLen(osinfo->OsSystemName));
	WriteBuf(b, osinfo->OsVendorName, StrLen(osinfo->OsVendorName));
	WriteBuf(b, osinfo->OsVersion, StrLen(osinfo->OsVersion));

	Hash(data, b->Buf, b->Size, true);

	FreeBuf(b);
}

// Convert a node information to a string
void NodeInfoToStr(wchar_t *str, UINT size, NODE_INFO *info)
{
	char client_ip[128], server_ip[128], proxy_ip[128], unique_id[128];
	// Validate arguments
	if (str == NULL || info == NULL)
	{
		return;
	}

	IPToStr4or6(client_ip, sizeof(client_ip), info->ClientIpAddress, info->ClientIpAddress6);
	IPToStr4or6(server_ip, sizeof(server_ip), info->ServerIpAddress, info->ServerIpAddress6);
	IPToStr4or6(proxy_ip, sizeof(proxy_ip), info->ProxyIpAddress, info->ProxyIpAddress6);
	BinToStr(unique_id, sizeof(unique_id), info->UniqueId, sizeof(info->UniqueId));

	UniFormat(str, size, _UU("LS_NODE_INFO_TAG"), info->ClientProductName,
		Endian32(info->ClientProductVer), Endian32(info->ClientProductBuild),
		info->ServerProductName, Endian32(info->ServerProductVer), Endian32(info->ServerProductBuild),
		info->ClientOsName, info->ClientOsVer, info->ClientOsProductId,
		info->ClientHostname, client_ip, Endian32(info->ClientPort),
		info->ServerHostname, server_ip, Endian32(info->ServerPort),
		info->ProxyHostname, proxy_ip, Endian32(info->ProxyPort),
		info->HubName, unique_id);
}

// Comparison of node information
bool CompareNodeInfo(NODE_INFO *a, NODE_INFO *b)
{
	// Validate arguments
	if (a == NULL || b == NULL)
	{
		return false;
	}

	if (StrCmp(a->ClientProductName, b->ClientProductName) != 0)
	{
		return false;
	}
	if (a->ClientProductVer != b->ClientProductVer)
	{
		return false;
	}
	if (a->ClientProductBuild != b->ClientProductBuild)
	{
		return false;
	}
	if (StrCmp(a->ServerProductName, b->ServerProductName) != 0)
	{
		return false;
	}
	if (a->ServerProductVer != b->ServerProductVer)
	{
		return false;
	}
	if (a->ServerProductBuild != b->ServerProductBuild)
	{
		return false;
	}
	if (StrCmp(a->ClientOsName, b->ClientOsName) != 0)
	{
		return false;
	}
	if (StrCmp(a->ClientOsVer, b->ClientOsVer) != 0)
	{
		return false;
	}
	if (StrCmp(a->ClientOsProductId, b->ClientOsProductId) != 0)
	{
		return false;
	}
	if (StrCmp(a->ClientHostname, b->ClientHostname) != 0)
	{
		return false;
	}
	if (a->ClientIpAddress != b->ClientIpAddress)
	{
		return false;
	}
	if (StrCmp(a->ServerHostname, b->ServerHostname) != 0)
	{
		return false;
	}
	if (a->ServerIpAddress != b->ServerIpAddress)
	{
		return false;
	}
	if (a->ServerPort != b->ServerPort)
	{
		return false;
	}
	if (StrCmp(a->ProxyHostname, b->ProxyHostname) != 0)
	{
		return false;
	}
	if (a->ProxyIpAddress != b->ProxyIpAddress)
	{
		return false;
	}
	if (a->ProxyPort != b->ProxyPort)
	{
		return false;
	}
	if (StrCmp(a->HubName, b->HubName) != 0)
	{
		return false;
	}
	if (Cmp(a->UniqueId, b->UniqueId, 16) != 0)
	{
		return false;
	}

	return true;
}

// Accept the password change
UINT ChangePasswordAccept(CONNECTION *c, PACK *p)
{
	CEDAR *cedar;
	UCHAR random[SHA1_SIZE];
	char hubname[MAX_HUBNAME_LEN + 1];
	char username[MAX_USERNAME_LEN + 1];
	UCHAR secure_old_password[SHA1_SIZE];
	UCHAR new_password[SHA1_SIZE];
	UCHAR new_password_ntlm[SHA1_SIZE];
	UCHAR check_secure_old_password[SHA1_SIZE];
	UINT ret = ERR_NO_ERROR;
	HUB *hub;
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	Copy(random, c->Random, SHA1_SIZE);
	if (PackGetStr(p, "hubname", hubname, sizeof(hubname)) == false ||
		PackGetStr(p, "username", username, sizeof(username)) == false ||
		PackGetData2(p, "secure_old_password", secure_old_password, sizeof(secure_old_password)) == false ||
		PackGetData2(p, "new_password", new_password, sizeof(new_password)) == false)
	{
		return ERR_PROTOCOL_ERROR;
	}

	if (PackGetData2(p, "new_password_ntlm", new_password_ntlm, MD5_SIZE) == false)
	{
		Zero(new_password_ntlm, sizeof(new_password_ntlm));
	}

	cedar = c->Cedar;

	LockHubList(cedar);
	{
		hub = GetHub(cedar, hubname);
	}
	UnlockHubList(cedar);

	if (hub == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		char tmp[MAX_SIZE];

		if (GetHubAdminOption(hub, "deny_change_user_password") != 0)
		{
			ReleaseHub(hub);
			return ERR_NOT_ENOUGH_RIGHT;
		}

		IPToStr(tmp, sizeof(tmp), &c->FirstSock->RemoteIP);
		HLog(hub, "LH_CHANGE_PASSWORD_1", c->Name, tmp);

		AcLock(hub);
		{
			USER *u = AcGetUser(hub, username);
			if (u == NULL)
			{
				HLog(hub, "LH_CHANGE_PASSWORD_2", c->Name, username);
				ret = ERR_OLD_PASSWORD_WRONG;
			}
			else
			{
				Lock(u->lock);
				{
					if (u->AuthType	!= AUTHTYPE_PASSWORD)
					{
						// Not a password authentication
						HLog(hub, "LH_CHANGE_PASSWORD_3", c->Name, username);
						ret = ERR_USER_AUTHTYPE_NOT_PASSWORD;
					}
					else
					{
						bool fix_password = false;
						if (u->Policy != NULL)
						{
							fix_password = u->Policy->FixPassword;
						}
						else
						{
							if (u->Group != NULL)
							{
								if (u->Group->Policy != NULL)
								{
									fix_password = u->Group->Policy->FixPassword;
								}
							}
						}
						if (fix_password == false)
						{
							// Confirmation of the old password
							AUTHPASSWORD *pw = (AUTHPASSWORD *)u->AuthData;

							SecurePassword(check_secure_old_password, pw->HashedKey, random);
							if (Cmp(check_secure_old_password, secure_old_password, SHA1_SIZE) != 0)
							{
								// Old password is incorrect
								ret = ERR_OLD_PASSWORD_WRONG;
								HLog(hub, "LH_CHANGE_PASSWORD_4", c->Name, username);
							}
							else
							{
								// Write a new password
								if (Cmp(pw->HashedKey, new_password, SHA1_SIZE) != 0 || IsZero(pw->NtLmSecureHash, MD5_SIZE))
								{
									Copy(pw->HashedKey, new_password, SHA1_SIZE);
									Copy(pw->NtLmSecureHash, new_password_ntlm, MD5_SIZE);
									IncrementServerConfigRevision(cedar->Server);
								}
								HLog(hub, "LH_CHANGE_PASSWORD_5", c->Name, username);
							}
						}
						else
						{
							// Password change is prohibited
							ret = ERR_NOT_ENOUGH_RIGHT;
						}
					}
				}
				Unlock(u->lock);

				ReleaseUser(u);
			}
		}
		AcUnlock(hub);
		ReleaseHub(hub);
	}

	return ret;
}

// Change the password
UINT ChangePassword(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, char *username, char *old_pass, char *new_pass)
{
	UINT ret = ERR_NO_ERROR;
	UCHAR old_password[SHA1_SIZE];
	UCHAR secure_old_password[SHA1_SIZE];
	UCHAR new_password[SHA1_SIZE];
	UCHAR new_password_ntlm[MD5_SIZE];
	SOCK *sock;
	SESSION *s;
	// Validate arguments
	if (cedar == NULL || o == NULL || hubname == NULL || username == NULL || old_pass == NULL || new_pass == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}


	// Create a session
	s = NewRpcSessionEx(cedar, o, &ret, NULL);

	if (s != NULL)
	{
		PACK *p = NewPack();

		sock = s->Connection->FirstSock;

		HashPassword(old_password, username, old_pass);
		SecurePassword(secure_old_password, old_password, s->Connection->Random);
		HashPassword(new_password, username, new_pass);
		GenerateNtPasswordHash(new_password_ntlm, new_pass);

		PackAddClientVersion(p, s->Connection);

		PackAddStr(p, "method", "password");
		PackAddStr(p, "hubname", hubname);
		PackAddStr(p, "username", username);
		PackAddData(p, "secure_old_password", secure_old_password, SHA1_SIZE);
		PackAddData(p, "new_password", new_password, SHA1_SIZE);
		PackAddData(p, "new_password_ntlm", new_password_ntlm, MD5_SIZE);

		if (HttpClientSend(sock, p))
		{
			PACK *p = HttpClientRecv(sock);
			if (p == NULL)
			{
				ret = ERR_DISCONNECTED;
			}
			else
			{
				ret = GetErrorFromPack(p);
			}
			FreePack(p);
		}
		else
		{
			ret = ERR_DISCONNECTED;
		}
		FreePack(p);

		ReleaseSession(s);
	}

	return ret;
}

// Enumerate HUBs
TOKEN_LIST *EnumHub(SESSION *s)
{
	SOCK *sock;
	TOKEN_LIST *ret;
	PACK *p;
	UINT num;
	UINT i;
	// Validate arguments
	if (s == NULL || s->Connection == NULL)
	{
		return NULL;
	}

	sock = s->Connection->FirstSock;
	if (sock == NULL)
	{
		return NULL;
	}

	// Set the Timeout
	SetTimeout(sock, 10000);

	p = NewPack();
	PackAddStr(p, "method", "enum_hub");

	PackAddClientVersion(p, s->Connection);

	if (HttpClientSend(sock, p) == false)
	{
		FreePack(p);
		return NULL;
	}
	FreePack(p);

	p = HttpClientRecv(sock);
	if (p == NULL)
	{
		return NULL;
	}

	num = PackGetInt(p, "NumHub");
	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->NumTokens = num;
	ret->Token = ZeroMalloc(sizeof(char *) * num);
	for (i = 0;i < num;i++)
	{
		char tmp[MAX_SIZE];
		if (PackGetStrEx(p, "HubName", tmp, sizeof(tmp), i))
		{
			ret->Token[i] = CopyStr(tmp);
		}
	}
	FreePack(p);

	return ret;
}

// Server accepts a connection from client
bool ServerAccept(CONNECTION *c)
{
	bool ret = false;
	UINT err;
	PACK *p;
	char username_real[MAX_SIZE];
	char method[MAX_SIZE];
	char hubname[MAX_SIZE];
	char username[MAX_SIZE];
	char groupname[MAX_SIZE];
	UCHAR session_key[SHA1_SIZE];
	UCHAR ticket[SHA1_SIZE];
	RC4_KEY_PAIR key_pair;
	UINT authtype;
	POLICY *policy;
	UINT assigned_vlan_id = 0;
	UCHAR assigned_ipc_mac_address[6];
	HUB *hub;
	SESSION *s = NULL;
	UINT64 user_expires = 0;
	bool use_encrypt;
	bool use_compress;
	bool half_connection;
	UINT adjust_mss;
	bool use_udp_acceleration_client;
	UINT client_udp_acceleration_max_version = 1;
	UINT udp_acceleration_version = 1;
	UINT client_rudp_bulk_max_version = 1;
	UINT rudp_bulk_version = 1;
	bool support_hmac_on_udp_acceleration_client = false;
	bool support_udp_accel_fast_disconnect_detect;
	bool use_hmac_on_udp_acceleration = false;
	bool supress_return_pack_error = false;
	IP udp_acceleration_client_ip;
	UCHAR udp_acceleration_client_key[UDP_ACCELERATION_COMMON_KEY_SIZE_V1];
	UCHAR udp_acceleration_client_key_v2[UDP_ACCELERATION_COMMON_KEY_SIZE_V2];
	UINT udp_acceleration_client_port;
	bool use_fast_rc4;
	bool admin_mode = false;
	UINT direction;
	UINT max_connection;
	UINT timeout;
	bool no_reconnect_to_session = false;
	bool farm_controller = false;
	bool farm_member = false;
	bool farm_mode = false;
	bool require_bridge_routing_mode;
	bool require_monitor_mode;
	bool support_bulk_on_rudp = false;
	bool support_hmac_on_bulk_of_rudp = false;
	bool support_udp_recovery = false;
	bool enable_bulk_on_rudp = false;
	bool enable_udp_recovery = false;
	bool enable_hmac_on_bulk_of_rudp = false;
	bool use_client_license = false, use_bridge_license = false;
	bool local_host_session = false;
	char sessionname[MAX_SESSION_NAME_LEN + 1];
	bool is_server_or_bridge = false;
	bool qos = false;
	bool cluster_dynamic_secure_nat = false;
	bool no_save_password = false;
	NODE_INFO node;
	wchar_t *msg = NULL;
	bool suppress_client_update_notification = false;
	USER *loggedin_user_object = NULL;
	FARM_MEMBER *f = NULL;
	SERVER *server = NULL;
	POLICY ticketed_policy;
	UCHAR unique[SHA1_SIZE], unique2[SHA1_SIZE];
	CEDAR *cedar;
	RPC_WINVER winver;
	UINT client_id;
	bool no_more_users_in_server = false;
	UCHAR mschap_v2_server_response_20[20];
	UINT ms_chap_error = 0;
	bool is_empty_password = false;
	char *error_detail = NULL;
	char *error_detail_2 = NULL;
	char ctoken_hash_str[64];
	EAP_CLIENT *release_me_eap_client = NULL;

	// Validate arguments
	if (c == NULL)
	{
		return false;
	}

	GenerateMachineUniqueHash(unique2);

	Zero(ctoken_hash_str, sizeof(ctoken_hash_str));

	Zero(assigned_ipc_mac_address, sizeof(assigned_ipc_mac_address));

	Zero(mschap_v2_server_response_20, sizeof(mschap_v2_server_response_20));

	Zero(&udp_acceleration_client_ip, sizeof(udp_acceleration_client_ip));
	udp_acceleration_client_port = 0;
	Zero(udp_acceleration_client_key, sizeof(udp_acceleration_client_key));
	Zero(udp_acceleration_client_key_v2, sizeof(udp_acceleration_client_key_v2));

	Zero(&winver, sizeof(winver));

	StrCpy(groupname, sizeof(groupname), "");
	StrCpy(sessionname, sizeof(sessionname), "");

	if (IsZero(c->CToken_Hash, SHA1_SIZE) == false)
	{
		BinToStr(ctoken_hash_str, sizeof(ctoken_hash_str), c->CToken_Hash, SHA1_SIZE);
	}

	cedar = c->Cedar;

	// Get the license status

	no_more_users_in_server = SiTooManyUserObjectsInServer(cedar->Server, true);

	c->Status = CONNECTION_STATUS_NEGOTIATION;

	if (c->Cedar->Server != NULL)
	{
		SERVER *s = c->Cedar->Server;
		server = s;

		if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
		{
			farm_member = true;
			farm_mode = true;
		}

		if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			farm_controller = true;
			farm_mode = true;
		}
	}

	// Receive the signature
	Debug("Downloading Signature...\n");
	error_detail_2 = NULL;
	if (ServerDownloadSignature(c, &error_detail_2) == false)
	{
		if (c->Type == CONNECTION_TYPE_ADMIN_RPC)
		{
			c->Err = ERR_NO_ERROR;
		}

		if (error_detail_2 == NULL)
		{
			error_detail = "ServerDownloadSignature";
		}
		else
		{
			error_detail = error_detail_2;
		}

		supress_return_pack_error = true;

		goto CLEANUP;
	}

	// Send a Hello packet
	Debug("Uploading Hello...\n");
	if (ServerUploadHello(c) == false)
	{
		error_detail = "ServerUploadHello";
		goto CLEANUP;
	}

	// Receive the authentication data
	Debug("Auth...\n");

	p = HttpServerRecv(c->FirstSock);
	if (p == NULL)
	{
		// The connection disconnected
		c->Err = ERR_DISCONNECTED;
		error_detail = "RecvAuth1";
		goto CLEANUP;
	}

	if (err = GetErrorFromPack(p))
	{
		// An error has occured
		FreePack(p);
		c->Err = err;
		error_detail = "RecvAuth2";
		goto CLEANUP;
	}

	// Get the method
	if (GetMethodFromPack(p, method, sizeof(method)) == false)
	{
		// Protocol error
		FreePack(p);
		c->Err = ERR_PROTOCOL_ERROR;
		error_detail = "GetMethodFromPack";
		goto CLEANUP;
	}

	// Brand string for the connection limit
	{
		char tmp[20];
		char *branded_ctos = _SS("BRANDED_C_TO_S");
		PackGetStr(p, "branded_ctos", tmp, sizeof(tmp));

		if(StrCmpi(method, "login") == 0 && StrLen(branded_ctos) > 0 && StrCmpi(branded_ctos, tmp) != 0)
		{
			FreePack(p);
			c->Err = ERR_BRANDED_C_TO_S;
			goto CLEANUP;
		}
	}

	// Get the client version
	PackGetStr(p, "client_str", c->ClientStr, sizeof(c->ClientStr));
	c->ClientVer = PackGetInt(p, "client_ver");
	c->ClientBuild = PackGetInt(p, "client_build");

	if (SearchStrEx(c->ClientStr, "server", 0, false) != INFINITE ||
		SearchStrEx(c->ClientStr, "bridge", 0, false) != INFINITE)
	{
		is_server_or_bridge = true;
	}

	// Get the client Windows version
	InRpcWinVer(&winver, p);

	DecrementNoSsl(c->Cedar, &c->FirstSock->RemoteIP, 2);

	if (StrCmpi(method, "login") == 0)
	{
		bool auth_ret = false;

		Debug("Login...\n");
		c->Status = CONNECTION_STATUS_USERAUTH;

		c->Type = CONNECTION_TYPE_LOGIN;

		if (no_more_users_in_server)
		{
			// There are many users than are allowed in the VPN Server
			FreePack(p);
			c->Err = ERR_TOO_MANY_USER;
			error_detail = "ERR_TOO_MANY_USER";
			goto CLEANUP;
		}

		// Such as the client name
		if (PackGetStr(p, "hello", c->ClientStr, sizeof(c->ClientStr)) == false)
		{
			StrCpy(c->ClientStr, sizeof(c->ClientStr), "Unknown");
		}
		c->ServerVer = CEDAR_VER;
		c->ServerBuild = CEDAR_BUILD;

		// Get the NODE_INFO
		Zero(&node, sizeof(node));
		InRpcNodeInfo(&node, p);

		// Protocol
		c->Protocol = GetProtocolFromPack(p);
		if (c->Protocol == CONNECTION_UDP)
		{
			// Release the structure of the TCP connection
			if (c->Tcp)
			{
				ReleaseList(c->Tcp->TcpSockList);
				Free(c->Tcp);
			}
		}

		if (GetServerCapsBool(c->Cedar->Server, "b_vpn_client_connect") == false)
		{
			// VPN client is unable to connect
			FreePack(p);
			c->Err = ERR_NOT_SUPPORTED;
			goto CLEANUP;
		}



		// Login
		if (GetHubnameAndUsernameFromPack(p, username, sizeof(username), hubname, sizeof(hubname)) == false)
		{
			// Protocol error
			FreePack(p);
			c->Err = ERR_PROTOCOL_ERROR;
			error_detail = "GetHubnameAndUsernameFromPack";
			goto CLEANUP;
		}

		if (farm_member)
		{
			bool ok = false;
			UINT authtype;

			authtype = GetAuthTypeFromPack(p);
			if (StrCmpi(username, ADMINISTRATOR_USERNAME) == 0 &&
				authtype == AUTHTYPE_PASSWORD)
			{
				ok = true;
			}

			if (authtype == AUTHTYPE_TICKET)
			{
				ok = true;
			}

			if (ok == false)
			{
				// Logging on directly to server farm members by
				// non-Administrators are prohibited
				FreePack(p);
				SLog(c->Cedar, "LS_FARMMEMBER_NOT_ADMIN", c->Name, hubname, ADMINISTRATOR_USERNAME, username);
				c->Err = ERR_ACCESS_DENIED;
				goto CLEANUP;
			}
		}

		Debug("Username = %s, HubName = %s\n", username, hubname);
		LockHubList(c->Cedar);
		{
			hub = GetHub(c->Cedar, hubname);
		}
		UnlockHubList(c->Cedar);
		if (hub == NULL)
		{
			// The HUB does not exist
			FreePack(p);
			c->Err = ERR_HUB_NOT_FOUND;
			SLog(c->Cedar, "LS_HUB_NOT_FOUND", c->Name, hubname);
			error_detail = "ERR_HUB_NOT_FOUND";
			goto CLEANUP;
		}

		if (hub->ForceDisableComm)
		{
			// Commnunication function is disabled
			FreePack(p);
			c->Err = ERR_SERVER_CANT_ACCEPT;
			error_detail = "ERR_COMM_DISABLED";
			ReleaseHub(hub);
			goto CLEANUP;
		}

		if (GetGlobalServerFlag(GSF_DISABLE_AC) == 0)
		{
			if (hub->HubDb != NULL && c->FirstSock != NULL)
			{
				IP ip;

				Copy(&ip, &c->FirstSock->RemoteIP, sizeof(IP));

				if (IsIpDeniedByAcList(&ip, hub->HubDb->AcList))
				{
					char ip_str[64];
					// Access denied
					ReleaseHub(hub);
					hub = NULL;
					FreePack(p);
					c->Err = ERR_IP_ADDRESS_DENIED;
					IPToStr(ip_str, sizeof(ip_str), &ip);
					SLog(c->Cedar, "LS_IP_DENIED", c->Name, ip_str);
					goto CLEANUP;
				}
			}
		}

		Lock(hub->lock);
		{
			UINT cert_size = 0;
			void *cert_buf = NULL;
			USER *user;
			USERGROUP *group;
			char plain_password[MAX_PASSWORD_LEN + 1];
			RADIUS_LOGIN_OPTION radius_login_opt;

			if (hub->Halt || hub->Offline)
			{
				// HUB is off-line
				FreePack(p);
				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_HUB_STOPPING;
				goto CLEANUP;
			}

			Zero(&radius_login_opt, sizeof(radius_login_opt));

			if (hub->Option != NULL)
			{
				radius_login_opt.In_CheckVLanId = hub->Option->AssignVLanIdByRadiusAttribute;
				radius_login_opt.In_DenyNoVlanId = hub->Option->DenyAllRadiusLoginWithNoVlanAssign;
				if (hub->Option->UseHubNameAsRadiusNasId)
				{
					StrCpy(radius_login_opt.NasId, sizeof(radius_login_opt.NasId), hubname);
				}
			}

			// Get the various flags
			use_encrypt = PackGetInt(p, "use_encrypt") == 0 ? false : true;
			use_compress = PackGetInt(p, "use_compress") == 0 ? false : true;
			max_connection = PackGetInt(p, "max_connection");
			half_connection = PackGetInt(p, "half_connection") == 0 ? false : true;
			use_fast_rc4 = PackGetInt(p, "use_fast_rc4") == 0 ? false : true;
			qos = PackGetInt(p, "qos") ? true : false;
			client_id = PackGetInt(p, "client_id");
			adjust_mss = PackGetInt(p, "adjust_mss");
			use_udp_acceleration_client = PackGetBool(p, "use_udp_acceleration");
			client_udp_acceleration_max_version = PackGetInt(p, "udp_acceleration_max_version");
			if (client_udp_acceleration_max_version == 0)
			{
				client_udp_acceleration_max_version = 1;
			}
			client_rudp_bulk_max_version = PackGetInt(p, "rudp_bulk_max_version");
			if (client_rudp_bulk_max_version == 0)
			{
				client_rudp_bulk_max_version = 1;
			}
			support_hmac_on_udp_acceleration_client = PackGetBool(p, "support_hmac_on_udp_acceleration");
			support_udp_accel_fast_disconnect_detect = PackGetBool(p, "support_udp_accel_fast_disconnect_detect");
			support_bulk_on_rudp = PackGetBool(p, "support_bulk_on_rudp");
			support_hmac_on_bulk_of_rudp = PackGetBool(p, "support_hmac_on_bulk_of_rudp");
			support_udp_recovery = PackGetBool(p, "support_udp_recovery");

			if (c->IsInProc)
			{
				char tmp[MAX_SIZE];
				UINT64 ptr;

				ptr = PackGetInt64(p, "release_me_eap_client");
				if (ptr != 0)
				{
					release_me_eap_client = (EAP_CLIENT *)ptr;
				}

				PackGetStr(p, "inproc_postfix", c->InProcPrefix, sizeof(c->InProcPrefix));
				Zero(tmp, sizeof(tmp));
				PackGetStr(p, "inproc_cryptname", tmp, sizeof(tmp));
				c->InProcLayer = PackGetInt(p, "inproc_layer");

				if (c->FirstSock != NULL)
				{
					if (IsEmptyStr(c->InProcPrefix) == false)
					{
						Format(c->FirstSock->UnderlayProtocol, sizeof(c->FirstSock->UnderlayProtocol),
							SOCK_UNDERLAY_INPROC_EX, c->InProcPrefix);

						AddProtocolDetailsStr(c->FirstSock->UnderlayProtocol,
							sizeof(c->FirstSock->UnderlayProtocol),
							c->InProcPrefix);
					}
				}

				if (c->CipherName != NULL)
				{
					Free(c->CipherName);
				}

				c->CipherName = NULL;

				if (IsEmptyStr(tmp) == false)
				{
					c->CipherName = CopyStr(tmp);
					use_encrypt = true;
				}

				use_udp_acceleration_client = false;

				Format(radius_login_opt.In_VpnProtocolState, sizeof(radius_login_opt.In_VpnProtocolState),
					"L%u:%s", c->InProcLayer, c->InProcPrefix);
			}
			else
			{
				if (c->CipherName != NULL)
				{
					Free(c->CipherName);
				}
				c->CipherName = NULL;

				if (c->FirstSock != NULL && IsEmptyStr(c->FirstSock->CipherName) == false)
				{
					c->CipherName = CopyStr(c->FirstSock->CipherName);
				}

				Format(radius_login_opt.In_VpnProtocolState, sizeof(radius_login_opt.In_VpnProtocolState),
					"L%u:%s", IPC_LAYER_2, "SEVPN");
			}

			if (support_bulk_on_rudp && c->FirstSock != NULL && c->FirstSock->IsRUDPSocket &&
				c->FirstSock->BulkRecvKey != NULL && c->FirstSock->BulkSendKey != NULL)
			{
				// Allow UDP bulk transfer if the client side supports
				// in the case of using R-UDP Socket
				enable_bulk_on_rudp = true;

				enable_hmac_on_bulk_of_rudp = support_hmac_on_bulk_of_rudp;
			}

			if (support_udp_recovery && c->FirstSock != NULL && c->FirstSock->IsRUDPSocket)
			{
				// Allow UDP recovery
				enable_udp_recovery = true;
			}

			if (use_udp_acceleration_client)
			{
				PackGetData2(p, "udp_acceleration_client_key", udp_acceleration_client_key, UDP_ACCELERATION_COMMON_KEY_SIZE_V1);
				PackGetData2(p, "udp_acceleration_client_key_v2", udp_acceleration_client_key_v2, UDP_ACCELERATION_COMMON_KEY_SIZE_V2);

				// Get the parameters for the UDP acceleration function
				if (PackGetIp(p, "udp_acceleration_client_ip", &udp_acceleration_client_ip) == false)
				{
					use_udp_acceleration_client = false;
				}
				else
				{
					if (IsZeroIp(&udp_acceleration_client_ip))
					{
						Copy(&udp_acceleration_client_ip, &c->FirstSock->RemoteIP, sizeof(IP));
					}
					udp_acceleration_client_port = PackGetInt(p, "udp_acceleration_client_port");
					if (udp_acceleration_client_port == 0)
					{
						use_udp_acceleration_client = false;
					}
				}

				use_hmac_on_udp_acceleration = support_hmac_on_udp_acceleration_client;
			}

			Debug("use_udp_acceleration_client = %u\n", use_udp_acceleration_client);
			Debug("use_hmac_on_udp_acceleration = %u\n", use_hmac_on_udp_acceleration);

			// Request mode
			require_bridge_routing_mode = PackGetBool(p, "require_bridge_routing_mode");
			require_monitor_mode = PackGetBool(p, "require_monitor_mode");
			if (require_monitor_mode)
			{
				qos = false;
			}

			if (is_server_or_bridge)
			{
				require_bridge_routing_mode = true;
			}

			// Client unique ID
			Zero(unique, sizeof(unique));
			if (PackGetDataSize(p, "unique_id") == SHA1_SIZE)
			{
				PackGetData(p, "unique_id", unique);
			}

			// Get the authentication method
			authtype = GetAuthTypeFromPack(p);

			if (1)
			{
				// Log
				char ip1[64], ip2[64], verstr[64];
				wchar_t *authtype_str = _UU("LH_AUTH_UNKNOWN");
				switch (authtype)
				{
				case CLIENT_AUTHTYPE_ANONYMOUS:
					authtype_str = _UU("LH_AUTH_ANONYMOUS");
					break;
				case CLIENT_AUTHTYPE_PASSWORD:
					authtype_str = _UU("LH_AUTH_PASSWORD");
					break;
				case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
					authtype_str = _UU("LH_AUTH_PLAIN_PASSWORD");
					break;
				case CLIENT_AUTHTYPE_CERT:
					authtype_str = _UU("LH_AUTH_CERT");
					break;
				case AUTHTYPE_TICKET:
					authtype_str = _UU("LH_AUTH_TICKET");
					break;
				case AUTHTYPE_OPENVPN_CERT:
					authtype_str = _UU("LH_AUTH_OPENVPN_CERT");
					break;
				}
				IPToStr(ip1, sizeof(ip1), &c->FirstSock->RemoteIP);
				IPToStr(ip2, sizeof(ip2), &c->FirstSock->LocalIP);

				Format(verstr, sizeof(verstr), "%u.%02u", c->ClientVer / 100, c->ClientVer % 100);

				HLog(hub, "LH_CONNECT_CLIENT", c->Name, ip1, c->FirstSock->RemoteHostname, c->FirstSock->RemotePort,
					c->ClientStr, verstr, c->ClientBuild, authtype_str, username);
			}

			// Attempt an anonymous authentication first
			auth_ret = SamAuthUserByAnonymous(hub, username);

			if (auth_ret)
			{
				if (c->IsInProc)
				{
					IPC_MSCHAP_V2_AUTHINFO mschap;
					char password_tmp[MAX_SIZE];

					Zero(&mschap, sizeof(mschap));

					Zero(password_tmp, sizeof(password_tmp));
					PackGetStr(p, "plain_password", password_tmp, sizeof(password_tmp));

					if (ParseAndExtractMsChapV2InfoFromPassword(&mschap, password_tmp))
					{
						// Because the server don't know the NTLM hashed password, the bet to the possibility of
						// the same character to the user name and empty, search a password of different
						// versions of the upper and lower case characters in the case of anonymous authentication.
						// Returns the MS-CHAPv2 response by using the password if there is a match.
						// Fail the authentication if no match is found.
						// (Because, if return a false MS-CHAPv2 Response, PPP client cause an error)
						LIST *o = NewListFast(NULL);
						char tmp1[MAX_SIZE];
						char tmp2[MAX_SIZE];
						char tmp3[MAX_SIZE];
						char tmp4[MAX_SIZE];
						char *response_pw;
						char psk[MAX_SIZE];

						ParseNtUsername(mschap.MsChapV2_PPPUsername, tmp1, sizeof(tmp1), tmp2, sizeof(tmp2), false);
						ParseNtUsername(mschap.MsChapV2_PPPUsername, tmp3, sizeof(tmp3), tmp4, sizeof(tmp4), true);

						Add(o, "");
						Add(o, "-");
						Add(o, ".");
						Add(o, "*");
						Add(o, "?");
						Add(o, " ");
						Add(o, "p");
						Add(o, "guest");
						Add(o, "anony");
						Add(o, "anonymouse");
						Add(o, "password");
						Add(o, "passwd");
						Add(o, "pass");
						Add(o, "pw");
						Add(o, mschap.MsChapV2_PPPUsername);
						Add(o, tmp1);
						Add(o, tmp2);
						Add(o, tmp3);
						Add(o, tmp4);

						Zero(psk, sizeof(psk));

						if (c->Cedar->Server != NULL)
						{
							SERVER *s = c->Cedar->Server;

							if (s->IPsecServer != NULL)
							{
								StrCpy(psk, sizeof(psk), s->IPsecServer->Services.IPsec_Secret);

								Add(o, psk);
							}
						}

						response_pw = MsChapV2DoBruteForce(&mschap, o);

						ReleaseList(o);

						if (response_pw != NULL)
						{
							UCHAR challenge8[8];
							UCHAR nt_hash[16];
							UCHAR nt_hash_hash[16];

							GenerateNtPasswordHash(nt_hash, response_pw);
							GenerateNtPasswordHashHash(nt_hash_hash, nt_hash);
							MsChapV2_GenerateChallenge8(challenge8, mschap.MsChapV2_ClientChallenge, mschap.MsChapV2_ServerChallenge,
								mschap.MsChapV2_PPPUsername);
							MsChapV2Server_GenerateResponse(mschap_v2_server_response_20, nt_hash_hash,
								mschap.MsChapV2_ClientResponse, challenge8);

							Free(response_pw);
						}
						else
						{
							auth_ret = false;
						}
					}
				}

				if (auth_ret)
				{
					// User authentication success by anonymous authentication
					HLog(hub, "LH_AUTH_OK", c->Name, username);
					is_empty_password = true;
				}
			}

			if (auth_ret == false)
			{
				// Attempt other authentication methods if anonymous authentication fails
				switch (authtype)
				{
				case CLIENT_AUTHTYPE_ANONYMOUS:
					// Anonymous authentication (this have been already attempted)
					break;

				case AUTHTYPE_TICKET:
					// Ticket authentication
					if (PackGetDataSize(p, "ticket") == SHA1_SIZE)
					{
						PackGetData(p, "ticket", ticket);

						auth_ret = SiCheckTicket(hub, ticket, username, sizeof(username), username_real, sizeof(username_real),
							&ticketed_policy, sessionname, sizeof(sessionname), groupname, sizeof(groupname));
					}
					break;

				case CLIENT_AUTHTYPE_PASSWORD:
					// Password authentication
					if (PackGetDataSize(p, "secure_password") == SHA1_SIZE)
					{
						POLICY *pol = NULL;
						UCHAR secure_password[SHA1_SIZE];
						Zero(secure_password, sizeof(secure_password));
						if (PackGetDataSize(p, "secure_password") == SHA1_SIZE)
						{
							PackGetData(p, "secure_password", secure_password);
						}
						auth_ret = SamAuthUserByPassword(hub, username, c->Random, secure_password, NULL, NULL, NULL);

						pol = SamGetUserPolicy(hub, username);
						if (pol != NULL)
						{
							no_save_password = pol->NoSavePassword;
							Free(pol);
						}

						if(auth_ret){
							// Check whether the password was empty
							UCHAR hashed_empty_password[SHA1_SIZE];
							UCHAR secure_empty_password[SHA1_SIZE];
							HashPassword(hashed_empty_password, username, "");
							SecurePassword(secure_empty_password, hashed_empty_password, c->Random);
							if(Cmp(secure_password, secure_empty_password, SHA1_SIZE)==0){
								is_empty_password = true;
							}
						}
					}
					break;

				case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
					{
						POLICY *pol = NULL;

						// Plaintext password authentication
						Zero(plain_password, sizeof(plain_password));
						PackGetStr(p, "plain_password", plain_password, sizeof(plain_password));
						if (c->IsInProc == false && StartWith(plain_password, IPC_PASSWORD_MSCHAPV2_TAG))
						{
							// Do not allow the MS-CHAPv2 authentication other than IPC sessions
							Zero(plain_password, sizeof(plain_password));
						}

						if (auth_ret == false)
						{
							// Attempt a password authentication of normal user
							UCHAR secure_password[SHA1_SIZE];
							UCHAR hash_password[SHA1_SIZE];
							bool is_mschap = StartWith(plain_password, IPC_PASSWORD_MSCHAPV2_TAG);

							HashPassword(hash_password, username, plain_password);
							SecurePassword(secure_password, hash_password, c->Random);

							if (is_mschap == false)
							{
								auth_ret = SamAuthUserByPassword(hub, username, c->Random, secure_password, NULL, NULL, NULL);
							}
							else
							{
								auth_ret = SamAuthUserByPassword(hub, username, c->Random, secure_password,
									plain_password, mschap_v2_server_response_20, &ms_chap_error);
							}

							if (auth_ret && pol == NULL)
							{
								pol = SamGetUserPolicy(hub, username);
							}
						}

						if (auth_ret == false)
						{
							// Attempt external authentication registered users
							bool fail_ext_user_auth = false;
							if (GetGlobalServerFlag(GSF_DISABLE_RADIUS_AUTH) != 0)
							{
								fail_ext_user_auth = true;
							}

							if (fail_ext_user_auth == false)
							{
								auth_ret = SamAuthUserByPlainPassword(c, hub, username, plain_password, false, mschap_v2_server_response_20, &radius_login_opt);
							}

							if (auth_ret && pol == NULL)
							{
								pol = SamGetUserPolicy(hub, username);
							}
						}

						if (auth_ret == false)
						{
							// Attempt external authentication asterisk user
							bool b = false;
							bool fail_ext_user_auth = false;

							if (GetGlobalServerFlag(GSF_DISABLE_RADIUS_AUTH) != 0)
							{
								fail_ext_user_auth = true;
							}

							if (fail_ext_user_auth == false)
							{
								AcLock(hub);
								{
									b = AcIsUser(hub, "*");
								}
								AcUnlock(hub);

								// If there is asterisk user, log on as the user
								if (b)
								{
									auth_ret = SamAuthUserByPlainPassword(c, hub, username, plain_password, true, mschap_v2_server_response_20, &radius_login_opt);
									if (auth_ret && pol == NULL)
									{
										pol = SamGetUserPolicy(hub, "*");
									}
								}
							}
						}

						if (pol != NULL)
						{
							no_save_password = pol->NoSavePassword;
							Free(pol);
						}

						if(auth_ret){
							// Check whether the password was empty
							if(IsEmptyStr(plain_password)){
								is_empty_password = true;
							}
						}
					}
					break;

				case CLIENT_AUTHTYPE_CERT:
					if (GetGlobalServerFlag(GSF_DISABLE_CERT_AUTH) == 0)
					{
						// Certificate authentication
						cert_size = PackGetDataSize(p, "cert");
						if (cert_size >= 1 && cert_size <= 100000)
						{
							cert_buf = ZeroMalloc(cert_size);
							if (PackGetData(p, "cert", cert_buf))
							{
								UCHAR sign[4096 / 8];
								UINT sign_size = PackGetDataSize(p, "sign");
								if (sign_size <= sizeof(sign) && sign_size >= 1)
								{
									if (PackGetData(p, "sign", sign))
									{
										BUF *b = NewBuf();
										X *x;
										WriteBuf(b, cert_buf, cert_size);
										x = BufToX(b, false);
										if (x != NULL && x->is_compatible_bit &&
											sign_size == (x->bits / 8))
										{
											K *k = GetKFromX(x);
											// Verify the signature received from the client
											if (RsaVerifyEx(c->Random, SHA1_SIZE, sign, k, x->bits))
											{
												// Confirmed that the client has had this certificate
												// certainly because the signature matched.
												// Check whether the certificate is valid.
												auth_ret = SamAuthUserByCert(hub, username, x);
												if (auth_ret)
												{
													// Copy the certificate
													c->ClientX = CloneXFast(x);
												}
											}
											else
											{
												// Authentication failure
											}
											FreeK(k);
										}
										FreeX(x);
										FreeBuf(b);
									}
								}
							}
							Free(cert_buf);
						}
					}
					else
					{
						// Certificate authentication is not supported in the open source version
						HLog(hub, "LH_AUTH_CERT_NOT_SUPPORT_ON_OPEN_SOURCE", c->Name, username);
						Unlock(hub->lock);
						ReleaseHub(hub);
						FreePack(p);
						c->Err = ERR_AUTHTYPE_NOT_SUPPORTED;
						goto CLEANUP;
					}
					break;

				case AUTHTYPE_OPENVPN_CERT:
					// For OpenVPN; mostly same as CLIENT_AUTHTYPE_CERT, but without
					// signature verification, because it was already performed during TLS handshake.
					if (c->IsInProc)
					{
						// Certificate authentication
						cert_size = PackGetDataSize(p, "cert");
						if (cert_size >= 1 && cert_size <= 100000)
						{
							cert_buf = ZeroMalloc(cert_size);
							if (PackGetData(p, "cert", cert_buf))
							{
								BUF *b = NewBuf();
								X *x;
								WriteBuf(b, cert_buf, cert_size);
								x = BufToX(b, false);
								if (x != NULL && x->is_compatible_bit)
								{
									Debug("Got to SamAuthUserByCert %s\n", username); // XXX
									// Check whether the certificate is valid.
									auth_ret = SamAuthUserByCert(hub, username, x);
									if (auth_ret)
									{
										// Copy the certificate
										c->ClientX = CloneXFast(x);
									}
								}
								FreeX(x);
								FreeBuf(b);
							}
							Free(cert_buf);
						}
					}
					else
					{
						// OpenVPN certificate authentication cannot be used directly by external clients
						Unlock(hub->lock);
						ReleaseHub(hub);
						FreePack(p);
						c->Err = ERR_AUTHTYPE_NOT_SUPPORTED;
						goto CLEANUP;
					}
					break;

				default:
					// Unknown authentication method
					Unlock(hub->lock);
					ReleaseHub(hub);
					FreePack(p);
					c->Err = ERR_AUTHTYPE_NOT_SUPPORTED;
					error_detail = "ERR_AUTHTYPE_NOT_SUPPORTED";
					goto CLEANUP;
				}

				if (auth_ret == false)
				{
					// Authentication failure
					HLog(hub, "LH_AUTH_NG", c->Name, username);
				}
				else
				{
					// Authentication success
					HLog(hub, "LH_AUTH_OK", c->Name, username);
				}
			}

			if (auth_ret == false)
			{
				// Authentication failure
				Unlock(hub->lock);
				ReleaseHub(hub);
				FreePack(p);
				c->Err = ERR_AUTH_FAILED;
				if (ms_chap_error != 0)
				{
					c->Err = ms_chap_error;
				}
				error_detail = "ERR_AUTH_FAILED";
				goto CLEANUP;
			}
			else
			{
				if(is_empty_password)
				{
					SOCK *s = c->FirstSock;
					if (s != NULL && s->RemoteIP.addr[0] != 127)
					{
						if(StrCmpi(username, ADMINISTRATOR_USERNAME) == 0 || 
							GetHubAdminOption(hub, "deny_empty_password") != 0)
						{
							// When the password is empty, remote connection is not acceptable
							HLog(hub, "LH_LOCAL_ONLY", c->Name, username);

							Unlock(hub->lock);
							ReleaseHub(hub);
							FreePack(p);
							c->Err = ERR_NULL_PASSWORD_LOCAL_ONLY;
							error_detail = "ERR_NULL_PASSWORD_LOCAL_ONLY";
							goto CLEANUP;
						}
					}
				}
			}

			policy = NULL;

			// Authentication success
			FreePack(p);

			// Check the assigned VLAN ID
			if (radius_login_opt.Out_IsRadiusLogin)
			{
				if (radius_login_opt.In_CheckVLanId)
				{
					if (radius_login_opt.Out_VLanId != 0)
					{
						assigned_vlan_id = radius_login_opt.Out_VLanId;
					}

					if (radius_login_opt.In_DenyNoVlanId && assigned_vlan_id == 0 || assigned_vlan_id >= 4096)
					{
						// Deny this session
						Unlock(hub->lock);
						ReleaseHub(hub);
						c->Err = ERR_ACCESS_DENIED;
						error_detail = "In_DenyNoVlanId";
						goto CLEANUP;
					}
				}
			}

			// Check the assigned MAC Address
			if (radius_login_opt.Out_IsRadiusLogin)
			{
				Copy(assigned_ipc_mac_address, radius_login_opt.Out_VirtualMacAddress, 6);
			}

			if (StrCmpi(username, ADMINISTRATOR_USERNAME) != 0)
			{
				// Get the policy
				if (farm_member == false)
				{
					bool is_asterisk_user = false;

					// In the case of not a farm member
					user = AcGetUser(hub, username);
					if (user == NULL)
					{
						user = AcGetUser(hub, "*");
						if (user == NULL)
						{
							// User acquisition failure
							Unlock(hub->lock);
							ReleaseHub(hub);
							c->Err = ERR_ACCESS_DENIED;
							error_detail = "AcGetUser";
							goto CLEANUP;
						}

						is_asterisk_user = true;
					}

					policy = NULL;

					Lock(user->lock);
					{
						if (is_asterisk_user == false)
						{
							UCHAR associated_mac_address[6];

							// Get the associated virtual MAC address
							if (GetUserMacAddressFromUserNote(associated_mac_address, user->Note))
							{
								if (IsZero(assigned_ipc_mac_address, 6))
								{
									Copy(assigned_ipc_mac_address, associated_mac_address, 6);
								}
							}
						}

						// Get the expiration date
						user_expires = user->ExpireTime;

						StrCpy(username_real, sizeof(username_real), user->Name);
						group = user->Group;
						if (group != NULL)
						{
							AddRef(group->ref);

							Lock(group->lock);
							{
								// Get the group name
								StrCpy(groupname, sizeof(groupname), group->Name);
							}
							Unlock(group->lock);
						}

						if (user->Policy != NULL)
						{
							policy = ClonePolicy(user->Policy);
						}
						else
						{
							if (group)
							{
								Lock(group->lock);
								{
									if (group->Policy != NULL)
									{
										policy = ClonePolicy(group->Policy);
									}
								}
								Unlock(group->lock);
							}
						}

						if (group != NULL)
						{
							ReleaseGroup(group);
						}
					}
					Unlock(user->lock);
					loggedin_user_object = user;
				}
				else
				{
					// In the case of farm member
					policy = ClonePolicy(&ticketed_policy);
				}
			}
			else
			{
				// Administrator mode
				admin_mode = true;
				StrCpy(username_real, sizeof(username_real), ADMINISTRATOR_USERNAME);

				policy = ClonePolicy(GetDefaultPolicy());
				policy->NoBroadcastLimiter = true;
				policy->MonitorPort = true;
			}

			if (policy == NULL)
			{
				// Use the default policy
				policy = ClonePolicy(GetDefaultPolicy());
			}

			if (policy->MaxConnection == 0)
			{
				policy->MaxConnection = MAX_TCP_CONNECTION;
			}

			if (policy->TimeOut == 0)
			{
				policy->TimeOut = 20;
			}

			if (qos)
			{
				// VoIP / QoS
				if (policy->NoQoS)
				{
					// Policy does not allow QoS
					qos = false;
				}
				if (GetServerCapsBool(c->Cedar->Server, "b_support_qos") == false)
				{
					// Server does not support QoS
					qos = false;
					policy->NoQoS = true;
				}
				if (GetHubAdminOption(hub, "deny_qos") != 0)
				{
					// It is prohibited in the management options
					qos = false;
					policy->NoQoS = true;
				}
			}

			if (GetHubAdminOption(hub, "max_bitrates_download") != 0)
			{
				if (policy->MaxDownload == 0)
				{
					policy->MaxDownload = GetHubAdminOption(hub, "max_bitrates_download");
				}
				else
				{
					UINT r = GetHubAdminOption(hub, "max_bitrates_download");
					policy->MaxDownload = MIN(policy->MaxDownload, r);
				}
			}

			if (GetHubAdminOption(hub, "max_bitrates_upload") != 0)
			{
				if (policy->MaxUpload == 0)
				{
					policy->MaxUpload = GetHubAdminOption(hub, "max_bitrates_upload");
				}
				else
				{
					UINT r = GetHubAdminOption(hub, "max_bitrates_upload");
					policy->MaxUpload = MIN(policy->MaxUpload, r);
				}
			}

			if (GetHubAdminOption(hub, "deny_bridge") != 0)
			{
				policy->NoBridge = true;
			}

			if (GetHubAdminOption(hub, "deny_routing") != 0)
			{
				policy->NoRouting = true;
			}

			if (c->IsInProc)
			{
				policy->NoBridge = false;
				policy->NoRouting = false;
			}

			if (hub->Option->ClientMinimumRequiredBuild > c->ClientBuild &&
				 InStrEx(c->ClientStr, "client", false))
			{
				// Build number of the client is too small
				HLog(hub, "LH_CLIENT_VERSION_OLD", c->Name, c->ClientBuild, hub->Option->ClientMinimumRequiredBuild);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_VERSION_INVALID;
				Free(policy);
				error_detail = "ERR_VERSION_INVALID";
				goto CLEANUP;
			}

			if (hub->Option->RequiredClientId != 0 &&
				hub->Option->RequiredClientId != client_id && 
				InStrEx(c->ClientStr, "client", false))
			{
				// Build number of the client is too small
				HLog(hub, "LH_CLIENT_ID_REQUIRED", c->Name, client_id, hub->Option->RequiredClientId);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_CLIENT_ID_REQUIRED;
				error_detail = "ERR_CLIENT_ID_REQUIRED";
				Free(policy);
				goto CLEANUP;
			}

			if ((policy->NoSavePassword) || (policy->AutoDisconnect != 0))
			{
				if (c->ClientBuild < 6560 && InStrEx(c->ClientStr, "client", false))
				{
					// If NoSavePassword policy is specified,
					// only supported client can connect
					HLog(hub, "LH_CLIENT_VERSION_OLD", c->Name, c->ClientBuild, 6560);

					Unlock(hub->lock);
					ReleaseHub(hub);
					c->Err = ERR_VERSION_INVALID;
					error_detail = "ERR_VERSION_INVALID";
					Free(policy);
					goto CLEANUP;
				}
			}

			if (user_expires != 0 && user_expires <= SystemTime64())
			{
				// User expired
				HLog(hub, "LH_USER_EXPIRES", c->Name, username);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_ACCESS_DENIED;
				error_detail = "LH_USER_EXPIRES";
				Free(policy);
				goto CLEANUP;
			}

			if (policy->Access == false)
			{
				// Access is denied
				HLog(hub, "LH_POLICY_ACCESS_NG", c->Name, username);

				Unlock(hub->lock);
				ReleaseHub(hub);
				error_detail = "LH_POLICY_ACCESS_NG";
				c->Err = ERR_ACCESS_DENIED;
				Free(policy);
				goto CLEANUP;
			}

			// Determine the contents of the policy by comparing to
			// option presented by client or deny the connection.
			// Confirm the connectivity in the monitor-mode first
			if (require_monitor_mode && policy->MonitorPort == false)
			{
				// Can not connect in the monitor port mode
				HLog(hub, "LH_POLICY_MONITOR_MODE", c->Name);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_MONITOR_MODE_DENIED;
				Free(policy);
				error_detail = "ERR_MONITOR_MODE_DENIED";
				goto CLEANUP;
			}

			if (policy->MonitorPort)
			{
				if (require_monitor_mode == false)
				{
					policy->MonitorPort = false;
				}
			}

			if (policy->MonitorPort)
			{
				qos = false;
			}

			// Determine whether it can be connected by a bridge / routing mode next
			if (require_bridge_routing_mode &&
				(policy->NoBridge && policy->NoRouting))
			{
				// Can not be connected by a bridge / routing mode
				HLog(hub, "LH_POLICY_BRIDGE_MODE", c->Name);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_BRIDGE_MODE_DENIED;
				error_detail = "ERR_BRIDGE_MODE_DENIED";
				Free(policy);
				goto CLEANUP;
			}

			if (require_bridge_routing_mode == false)
			{
				policy->NoBridge = true;
				policy->NoRouting = true;
			}

			if (Cmp(unique, unique2, SHA1_SIZE) == 0)
			{
				// It's a localhost session
				local_host_session = true;
			}

			if (local_host_session == false)
			{
				// Make further judgment whether localhost session
				SOCK *s = c->FirstSock;

				if (s != NULL)
				{
					if (IsIPMyHost(&s->RemoteIP))
					{
						// It's a localhost session
						local_host_session = true;
					}
				}
			}

			if (local_host_session)
			{
				// Permit routing or bridging in the case of localhost session
				policy->NoBridge = false;
				policy->NoRouting = false;
			}

			if (local_host_session == false)
			{

				if (policy->NoBridge == false || policy->NoRouting == false)
				{
					use_bridge_license = true;
				}
				else
				{
					use_client_license = true;
				}
			}


			if (server != NULL && server->ServerType != SERVER_TYPE_FARM_MEMBER &&
				policy != NULL)
			{
				if (GetServerCapsBool(hub->Cedar->Server, "b_support_limit_multilogin"))
				{
					// Check if the number of concurrent multiple logins limit is specified in the policy
					RPC_ENUM_SESSION t;
					UINT i, num;
					UINT max_logins = policy->MultiLogins;
					UINT ao = GetHubAdminOption(hub, "max_multilogins_per_user");

					if (ao != 0)
					{
						if (max_logins != 0)
						{
							max_logins = MIN(max_logins, ao);
						}
						else
						{
							max_logins = ao;
						}
					}

					if (max_logins != 0)
					{
						Zero(&t, sizeof(t));
						StrCpy(t.HubName, sizeof(t.HubName), hub->Name);

						Unlock(hub->lock);

						SiEnumSessionMain(server, &t);

						Lock(hub->lock);

						num = 0;

						for (i = 0;i < t.NumSession;i++)
						{
							RPC_ENUM_SESSION_ITEM *e = &t.Sessions[i];

							if (e->BridgeMode == false && e->Layer3Mode == false && e->LinkMode == false && e->CurrentNumTcp != 0)
							{
								if (StrCmpi(e->Username, username) == 0 &&
									(IsZero(e->UniqueId, 16) || Cmp(e->UniqueId, node.UniqueId, 16) != 0))
								{
									num++;
								}
							}
						}

						FreeRpcEnumSession(&t);

						if (num >= max_logins)
						{
							// Can not connect any more
							Unlock(hub->lock);

							// Dump a detailed error log
							HLog(hub, "LH_TOO_MANY_MULTILOGINS",
								c->Name,
								username, max_logins, num);

							ReleaseHub(hub);
							c->Err = ERR_TOO_MANY_USER_SESSION;
							Free(policy);
							goto CLEANUP;
						}
					}
				}
			}

			if (loggedin_user_object != NULL)
			{
				// Update the user information
				Lock(loggedin_user_object->lock);
				{
					loggedin_user_object->LastLoginTime = SystemTime64();
				}
				Unlock(loggedin_user_object->lock);
			}

			// Update the number of log-ins
			hub->LastCommTime = hub->LastLoginTime = SystemTime64();

			if (farm_controller)
			{
				wchar_t *msg = GetHubMsg(hub);

				Unlock(hub->lock);

				Lock(cedar->CedarSuperLock);

				// In the case of farm controller, choose a farm members to host this HUB
				LockList(server->FarmMemberList);
				{
					HLog(hub, "LH_FARM_SELECT_1", c->Name);
					f = SiGetHubHostingMember(server, hub, admin_mode, c);

					if (f == NULL)
					{
						// Failed in the selection
						HLog(hub, "LH_FARM_SELECT_2", c->Name);
						UnlockList(server->FarmMemberList);
						Unlock(cedar->CedarSuperLock);
						ReleaseHub(hub);
						c->Err = ERR_COULD_NOT_HOST_HUB_ON_FARM;
						Free(policy);
						Free(msg);
						goto CLEANUP;
					}
					else
					{
						if (f->Me == false)
						{
							UCHAR ticket[SHA1_SIZE];
							PACK *p;
							BUF *b;
							UINT i;

							SLog(c->Cedar, "LH_FARM_SELECT_4", c->Name, f->hostname);

							// Create a session on the selected server farm member
							Rand(ticket, sizeof(ticket));
							SiCallCreateTicket(server, f, hub->Name,
								username, username_real, policy, ticket, Inc(hub->SessionCounter), groupname);

							p = NewPack();
							PackAddInt(p, "Redirect", 1);
							PackAddIp32(p, "Ip", f->Ip);
							for (i = 0;i < f->NumPort;i++)
							{
								PackAddIntEx(p, "Port", f->Ports[i], i, f->NumPort);
							}
							PackAddData(p, "Ticket", ticket, sizeof(ticket));

							if (true)
							{
								char *utf = CopyUniToUtf(msg);

								PackAddData(p, "Msg", utf, StrLen(utf));

								Free(utf);
							}

							b = XToBuf(f->ServerCert, false);
							PackAddBuf(p, "Cert", b);
							FreeBuf(b);

							UnlockList(server->FarmMemberList);
							Unlock(cedar->CedarSuperLock);
							ReleaseHub(hub);

							HttpServerSend(c->FirstSock, p);
							FreePack(p);

							c->Err = 0;
							Free(policy);

							FreePack(HttpServerRecv(c->FirstSock));
							Free(msg);
							goto CLEANUP;
						}
						else
						{
							HLog(hub, "LH_FARM_SELECT_3", c->Name);
							// Continue the process because myself was selected
							UnlockList(server->FarmMemberList);
							Unlock(cedar->CedarSuperLock);
							f->Point = SiGetPoint(server);
							Lock(hub->lock);
							Free(msg);
						}
					}
				}
			}

			if (admin_mode == false)
			{
				// Check the maximum number of connections of the HUB
				if (hub->Option->MaxSession != 0 &&
					hub->Option->MaxSession <= Count(hub->NumSessions))
				{
					// Can not connect any more
					Unlock(hub->lock);

					HLog(hub, "LH_MAX_SESSION", c->Name, hub->Option->MaxSession);

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					error_detail = "ERR_HUB_IS_BUSY";
					goto CLEANUP;
				}
			}

			if (use_encrypt == false && c->FirstSock->IsReverseAcceptedSocket)
			{
				// On VPN Azure, SSL encryption is mandated.
				use_encrypt = true;
			}

			if (use_client_license || use_bridge_license)
			{
				// Examine whether not to conflict with the limit of simultaneous connections
				// number of sessions defined by the Virtual HUB management options
				if (
					(GetHubAdminOption(hub, "max_sessions") != 0 &&
					(Count(hub->NumSessionsClient) + Count(hub->NumSessionsBridge)) >= GetHubAdminOption(hub, "max_sessions"))
					||
					(hub->Option->MaxSession != 0 &&
					(Count(hub->NumSessionsClient) + Count(hub->NumSessionsBridge)) >= hub->Option->MaxSession))
				{
					// Can not connect any more
					Unlock(hub->lock);

					HLog(hub, "LH_MAX_SESSION", c->Name, GetHubAdminOption(hub, "max_sessions"));

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					goto CLEANUP;
				}
			}

			if (use_client_license)
			{
				// Examine whether not to conflict with the limit of simultaneous connections
				// number of sessions(client) defined by the Virtual HUB management options
				if (((GetHubAdminOption(hub, "max_sessions_client_bridge_apply") != 0
					) &&
					Count(hub->NumSessionsClient) >= GetHubAdminOption(hub, "max_sessions_client") && hub->Cedar->Server != NULL && hub->Cedar->Server->ServerType != SERVER_TYPE_FARM_MEMBER)
					||
					(hub->FarmMember_MaxSessionClientBridgeApply &&
					Count(hub->NumSessionsClient) >= hub->FarmMember_MaxSessionClient))
				{
					// Can not connect any more
					Unlock(hub->lock);

					HLog(hub, "LH_MAX_SESSION_CLIENT", c->Name, GetHubAdminOption(hub, "max_sessions_client"));

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					goto CLEANUP;
				}
			}

			if (use_bridge_license)
			{
				// Examine whether not to conflict with the limit of simultaneous connections
				// number of sessions(bridge) defined by the Virtual HUB management options
				if (((GetHubAdminOption(hub, "max_sessions_client_bridge_apply") != 0
					) &&
					Count(hub->NumSessionsBridge) >= GetHubAdminOption(hub, "max_sessions_bridge") && hub->Cedar->Server != NULL && hub->Cedar->Server->ServerType != SERVER_TYPE_FARM_MEMBER)
					||
					(hub->FarmMember_MaxSessionClientBridgeApply &&
					Count(hub->NumSessionsBridge) >= hub->FarmMember_MaxSessionBridge))
				{
					// Can not connect any more
					Unlock(hub->lock);

					HLog(hub, "LH_MAX_SESSION_BRIDGE", c->Name, GetHubAdminOption(hub, "max_sessions_bridge"));

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					goto CLEANUP;
				}
			}

			if (Count(hub->Cedar->CurrentSessions) >= GetServerCapsInt(hub->Cedar->Server, "i_max_sessions"))
			{
				// Can not connect any more
				Unlock(hub->lock);

				HLog(hub, "LH_MAX_SESSION_2", c->Name, GetServerCapsInt(hub->Cedar->Server, "i_max_sessions"));

				ReleaseHub(hub);
				c->Err = ERR_HUB_IS_BUSY;
				Free(policy);
				goto CLEANUP;
			}

			// Increment the current number of connections
			Inc(hub->NumSessions);
			if (use_bridge_license)
			{
				Inc(hub->NumSessionsBridge);
			}

			if (use_client_license)
			{
				Inc(hub->NumSessionsClient);
			}
			Inc(hub->Cedar->CurrentSessions);

			// Calculate the time-out period
			timeout = policy->TimeOut * 1000;	// Convert milliseconds to seconds
			if (timeout == 0)
			{
				timeout = TIMEOUT_DEFAULT;
			}
			timeout = MIN(timeout, TIMEOUT_MAX);
			timeout = MAX(timeout, TIMEOUT_MIN);

			// Update the max_connection according to the policy
			max_connection = MIN(max_connection, policy->MaxConnection);
			max_connection = MIN(max_connection, MAX_TCP_CONNECTION);
			max_connection = MAX(max_connection, 1);

			if (c->FirstSock->IsRUDPSocket)
			{
				// In the case of TCP-over-UDP
				half_connection = false;

				// Disable the QoS
				qos = false;

				if (enable_udp_recovery == false)
				{
					// Disable the session reconnection feature
					no_reconnect_to_session = true;
					max_connection = 1;
				}
				else
				{
					// If the UDP recovery is enabled, permit the session re-connection feature (for 2)
					no_reconnect_to_session = false;
					max_connection = NUM_TCP_CONNECTION_FOR_UDP_RECOVERY;
				}
			}

			if (half_connection)
			{
				// Number of connections should be more than 2 in the case of Half Connection
				max_connection = MAX(max_connection, 2);
			}

			if (qos)
			{
				// Number of connections is set to 2 or more when using the VoIP / QoS
				max_connection = MAX(max_connection, 2);
				if (half_connection)
				{
					max_connection = MAX(max_connection, 4);
				}
			}

			c->Status = CONNECTION_STATUS_ESTABLISHED;

			// Remove the connection from Cedar
			DelConnection(c->Cedar, c);

			// VLAN ID
			if (assigned_vlan_id != 0)
			{
				if (policy->VLanId == 0)
				{
					policy->VLanId = assigned_vlan_id;
				}
			}

			// Create a Session
			StrLower(username);
			s = NewServerSessionEx(c->Cedar, c, hub, username, policy, c->IsInProc,
				(c->IsInProc && IsZero(assigned_ipc_mac_address, 6) == false) ? assigned_ipc_mac_address : NULL);

			s->EnableUdpRecovery = enable_udp_recovery;
			s->LocalHostSession = local_host_session;
			s->NormalClient = true;

			IPToStr(s->ClientIP, sizeof(s->ClientIP), &c->ClientIp);
			s->ClientPort = c->ClientPort;

			if (c->FirstSock->IsRUDPSocket)
			{
				// R-UDP session
				s->IsRUDPSession = true;
				s->RUdpMss = c->FirstSock->RUDP_OptimizedMss;
				Debug("Optimized MSS Value for R-UDP: %u\n", s->RUdpMss);
				AddProtocolDetailsKeyValueInt(s->ProtocolDetails, sizeof(s->ProtocolDetails),
					"RUDP_MSS", s->RUdpMss);
			}

			if (enable_bulk_on_rudp)
			{
				// Allow bulk transfer on R-UDP
				s->EnableBulkOnRUDP = true;
				s->EnableHMacOnBulkOfRUDP = enable_hmac_on_bulk_of_rudp;
			}

			s->IsAzureSession = c->FirstSock->IsReverseAcceptedSocket;

			StrCpy(s->UnderlayProtocol, sizeof(s->UnderlayProtocol), c->FirstSock->UnderlayProtocol);

			AddProtocolDetailsStr(s->ProtocolDetails, sizeof(s->ProtocolDetails), c->FirstSock->ProtocolDetails);

			if (server != NULL)
			{
				s->NoSendSignature = server->NoSendSignature;
			}

			if (c->IsInProc)
			{
				s->NoSendSignature = true;
			}

			if (c->IsInProc && StrCmpi(c->InProcPrefix, OPENVPN_IPC_POSTFIX_L3) == 0)
			{
				// OpenVPN L3 session
				s->IsOpenVPNL3Session = true;
			}

			if (c->IsInProc && StrCmpi(c->InProcPrefix, OPENVPN_IPC_POSTFIX_L2) == 0)
			{
				// OpenVPN L2 session
				s->IsOpenVPNL2Session = true;
			}

			// Determine whether the use of UDP acceleration mode
			if (use_udp_acceleration_client)
			{
				s->UseUdpAcceleration = true;

				s->UdpAccelFastDisconnectDetect = support_udp_accel_fast_disconnect_detect;

				// TODO: determine UDP Accel version
				udp_acceleration_version = 1;
				if (client_udp_acceleration_max_version >= 2)
				{
					udp_acceleration_version = 2;
				}
			}

			// TODO: determine RUDP Bulk version
			if (client_rudp_bulk_max_version >= 2)
			{
				rudp_bulk_version = 2;
			}

			s->BulkOnRUDPVersion = rudp_bulk_version;

			if (s->EnableBulkOnRUDP)
			{
				AddProtocolDetailsKeyValueInt(s->ProtocolDetails, sizeof(s->ProtocolDetails),
					"RUDP_Bulk_Ver",
					s->BulkOnRUDPVersion);
			}

			if (hub->Option != NULL && hub->Option->DisableUdpAcceleration)
			{
				s->UseUdpAcceleration = false;
			}

			if (IsZeroIP(&c->FirstSock->Reverse_MyServerGlobalIp) == false &&
				CmpIpAddr(&c->FirstSock->Reverse_MyServerGlobalIp, &c->FirstSock->RemoteIP) == 0)
			{
				// Disable forcibly the UDP acceleration mode if VPN Server and VPN Client
				// are in same LAN in the case of using VPN Azure.
				// (Or this may cause infinite loop of packet)
				s->UseUdpAcceleration = false;
			}

			if (s->UseUdpAcceleration)
			{
				s->UseHMacOnUdpAcceleration = use_hmac_on_udp_acceleration;
			}

			Debug("UseUdpAcceleration = %u\n", s->UseUdpAcceleration);
			Debug("UseHMacOnUdpAcceleration = %u\n", s->UseHMacOnUdpAcceleration);
			Debug("UdpAccelerationVersion = %u\n", s->UdpAccelerationVersion);

			if (s->UseUdpAcceleration)
			{
				bool no_nat_t = false;


				// Initialize the UDP acceleration function
				s->UdpAccel = NewUdpAccel(c->Cedar, (c->FirstSock->IsRUDPSocket ? NULL : &c->FirstSock->LocalIP), false, c->FirstSock->IsRUDPSocket, no_nat_t);
				if (s->UdpAccel == NULL)
				{
					s->UseUdpAcceleration = false;
					Debug("NewUdpAccel Failed.\n");
				}
				else
				{
					s->UdpAccel->Version = udp_acceleration_version;

					if (UdpAccelInitServer(s->UdpAccel,
						s->UdpAccel->Version == 2 ? udp_acceleration_client_key_v2 : udp_acceleration_client_key,
						&udp_acceleration_client_ip, udp_acceleration_client_port,
						&c->FirstSock->RemoteIP) == false)
					{
						Debug("UdpAccelInitServer Failed.\n");
						s->UseUdpAcceleration = false;
					}

					s->UdpAccel->FastDetect = s->UdpAccelFastDisconnectDetect;

					if (use_encrypt == false)
					{
						s->UdpAccel->PlainTextMode = true;
					}

					s->UdpAccel->UseHMac = s->UseHMacOnUdpAcceleration;

					AddProtocolDetailsKeyValueInt(s->ProtocolDetails, sizeof(s->ProtocolDetails),
						"UDPAccel_Ver",
						s->UdpAccel->Version);

					if (s->UdpAccel->Version >= 2)
					{
						AddProtocolDetailsStr(s->ProtocolDetails, sizeof(s->ProtocolDetails),
							Aead_ChaCha20Poly1305_Ietf_IsOpenSSL() ? 
							"ChachaPoly_OpenSSL" : "ChachaPoly_Self");
					}

					AddProtocolDetailsKeyValueInt(s->ProtocolDetails, sizeof(s->ProtocolDetails),
						"UDPAccel_MSS",
						UdpAccelCalcMss(s->UdpAccel));
				}
			}

			s->UseClientLicense = use_client_license;
			s->UseBridgeLicense = use_bridge_license;

			s->AdjustMss = adjust_mss;
			if (s->AdjustMss != 0)
			{
				Debug("AdjustMSS: %u\n", s->AdjustMss);
				AddProtocolDetailsKeyValueInt(s->ProtocolDetails, sizeof(s->ProtocolDetails),
					"AdjustMSS", s->AdjustMss);
			}

			s->IsBridgeMode = (policy->NoBridge == false) || (policy->NoRouting == false);
			s->IsMonitorMode = policy->MonitorPort;

			// Decide whether IPv6 session
			s->IPv6Session = false;

			if (node.ClientIpAddress == 0)
			{
				s->IPv6Session = true;
			}

			if (use_bridge_license)
			{
				Inc(s->Cedar->AssignedBridgeLicense);
			}

			if (use_client_license)
			{
				Inc(s->Cedar->AssignedClientLicense);
			}

			if (server != NULL)
			{
				// Update the total allocation of the number of licenses for Server structure
				if (server->ServerType == SERVER_TYPE_STANDALONE)
				{
					// Update only stand-alone mode
					// (Periodically poll in the cluster controller mode)
					server->CurrentAssignedClientLicense = Count(s->Cedar->AssignedClientLicense);
					server->CurrentAssignedBridgeLicense = Count(s->Cedar->AssignedBridgeLicense);
				}
			}

			if (StrLen(sessionname) != 0)
			{
				// Specify the session name
				Free(s->Name);
				s->Name = CopyStr(sessionname);
			}

			{
				char ip[128];
				IPToStr(ip, sizeof(ip), &c->FirstSock->RemoteIP);
				HLog(hub, "LH_NEW_SESSION", c->Name, s->Name, ip, c->FirstSock->RemotePort,
					c->FirstSock->UnderlayProtocol,
					c->FirstSock->ProtocolDetails);
			}

			c->Session = s;
			s->AdministratorMode = admin_mode;
			StrCpy(s->UserNameReal, sizeof(s->UserNameReal), username_real);
			StrCpy(s->GroupName, sizeof(s->GroupName), groupname);

			// Get the session key
			Copy(session_key, s->SessionKey, SHA1_SIZE);

			// Set the parameters
			s->MaxConnection = max_connection;
			s->UseEncrypt = use_encrypt;
			if (s->UseEncrypt && use_fast_rc4)
			{
				s->UseFastRC4 = use_fast_rc4;
			}
			s->UseCompress = use_compress;
			s->HalfConnection = half_connection;
			s->Timeout = timeout;
			s->QoS = qos;
			s->NoReconnectToSession = no_reconnect_to_session;

			s->VLanId = policy->VLanId;

			// User name
			s->Username = CopyStr(username);

			HLog(hub, "LH_SET_SESSION", s->Name, s->MaxConnection,
				s->UseEncrypt ? _UU("L_YES") : _UU("L_NO"),
				s->UseCompress ? _UU("L_YES") : _UU("L_NO"),
				s->HalfConnection ? _UU("L_YES") : _UU("L_NO"),
				s->Timeout / 1000);

			msg = GetHubMsg(hub);

			// Suppress client update notification flag
			if (hub->Option != NULL)
			{
				suppress_client_update_notification = hub->Option->SuppressClientUpdateNotification;
			}
		}
		Unlock(hub->lock);

		// Send a Welcome packet to the client
		p = PackWelcome(s);

		PackAddBool(p, "suppress_client_update_notification", suppress_client_update_notification);

		if (s->InProcMode)
		{
			if (IsZero(mschap_v2_server_response_20, sizeof(mschap_v2_server_response_20)) == false)
			{
				// MS-CHAPv2 Response
				PackAddData(p, "IpcMsChapV2ServerResponse", mschap_v2_server_response_20, sizeof(mschap_v2_server_response_20));
			}
		}

		if (true)
		{
			// A message to be displayed in the VPN Client (Will not be displayed if the VPN Gate Virtual HUB)
			char *utf;
			wchar_t winver_msg_client[3800];
			wchar_t winver_msg_server[3800];
			UINT tmpsize;
			wchar_t *tmp;
			RPC_WINVER server_winver;

			GetWinVer(&server_winver);

			Zero(winver_msg_client, sizeof(winver_msg_client));
			Zero(winver_msg_server, sizeof(winver_msg_server));

			if (IsSupportedWinVer(&winver) == false)
			{
				SYSTEMTIME st;

				LocalTime(&st);

				UniFormat(winver_msg_client, sizeof(winver_msg_client), _UU("WINVER_ERROR_FORMAT"),
					_UU("WINVER_ERROR_PC_LOCAL"),
					winver.Title,
					_UU("WINVER_ERROR_VPNSERVER"),
					SUPPORTED_WINDOWS_LIST,
					_UU("WINVER_ERROR_PC_LOCAL"),
					_UU("WINVER_ERROR_VPNSERVER"),
					_UU("WINVER_ERROR_VPNSERVER"),
					_UU("WINVER_ERROR_VPNSERVER"),
					st.wYear, st.wMonth);
			}

			if (IsSupportedWinVer(&server_winver) == false)
			{
				SYSTEMTIME st;

				LocalTime(&st);

				UniFormat(winver_msg_server, sizeof(winver_msg_server), _UU("WINVER_ERROR_FORMAT"),
					_UU("WINVER_ERROR_PC_REMOTE"),
					server_winver.Title,
					_UU("WINVER_ERROR_VPNSERVER"),
					SUPPORTED_WINDOWS_LIST,
					_UU("WINVER_ERROR_PC_REMOTE"),
					_UU("WINVER_ERROR_VPNSERVER"),
					_UU("WINVER_ERROR_VPNSERVER"),
					_UU("WINVER_ERROR_VPNSERVER"),
					st.wYear, st.wMonth);
			}

			tmpsize = UniStrSize(winver_msg_client) + UniStrSize(winver_msg_server) + UniStrSize(msg) + (16000 + 3000) * sizeof(wchar_t);

			tmp = ZeroMalloc(tmpsize);

			if (IsURLMsg(msg, NULL, 0) == false)
			{

				if (s != NULL && s->IsRUDPSession && c != NULL && StrCmpi(hub->Name, VG_HUBNAME) != 0)
				{
					// Show the warning message if the connection is made by NAT-T
					wchar_t *tmp2;
					UINT tmp2_size = 2400 * sizeof(wchar_t);
					char local_name[128];
					wchar_t local_name_2[128];
					char local_name_3[128];

					Zero(local_name, sizeof(local_name));
					Zero(local_name_2, sizeof(local_name_2));
					Zero(local_name_3, sizeof(local_name_3));

					GetMachineName(local_name, sizeof(local_name));

#ifdef	OS_WIN32
					MsGetComputerNameFullEx(local_name_2, sizeof(local_name_2), true);

					UniToStr(local_name_3, sizeof(local_name_3), local_name_2);

					if (IsEmptyStr(local_name_3) == false)
					{
						StrCpy(local_name, sizeof(local_name), local_name_3);
					}
#endif	// OS_WIN32

					tmp2 = ZeroMalloc(tmp2_size);
					UniFormat(tmp2, tmp2_size, _UU(c->ClientBuild >= 9428 ? "NATT_MSG" : "NATT_MSG2"), local_name);

					UniStrCat(tmp, tmpsize, tmp2);

					Free(tmp2);
				}

				{
					if (GetGlobalServerFlag(GSF_SHOW_OSS_MSG) != 0)
					{
						UniStrCat(tmp, tmpsize, _UU("OSS_MSG"));
					}
				}

				{
					UniStrCat(tmp, tmpsize, winver_msg_client);
					UniStrCat(tmp, tmpsize, winver_msg_server);
				}
			}
			UniStrCat(tmp, tmpsize, msg);
			
			utf = CopyUniToUtf(tmp);

			PackAddData(p, "Msg", utf, StrLen(utf));

			Free(tmp);
			Free(utf);
		}

		Free(msg);


		if (s->UseFastRC4)
		{
			// Generate a RC4 key pair
			GenerateRC4KeyPair(&key_pair);

			// Add to Welcome packet
			PackAddData(p, "rc4_key_client_to_server", key_pair.ClientToServerKey, sizeof(key_pair.ClientToServerKey));
			PackAddData(p, "rc4_key_server_to_client", key_pair.ServerToClientKey, sizeof(key_pair.ServerToClientKey));
			{
				char key1[64], key2[64];
				BinToStr(key1, sizeof(key1), key_pair.ClientToServerKey, 16);
				BinToStr(key2, sizeof(key2), key_pair.ServerToClientKey, 16);
				Debug(
					"Client to Server Key: %s\n"
					"Server to Client Key: %s\n",
					key1, key2);
			}
		}

		// Brand string for the connection limit
		{
			char *branded_cfroms = _SS("BRANDED_C_FROM_S");
			if(StrLen(branded_cfroms) > 0)
			{
				PackAddStr(p, "branded_cfroms", branded_cfroms);
			}
		}

		HttpServerSend(c->FirstSock, p);
		FreePack(p);

		// Receive a signature
		Copy(&c->Session->NodeInfo, &node, sizeof(NODE_INFO));


		{
			wchar_t tmp[MAX_SIZE * 2];
			NodeInfoToStr(tmp, sizeof(tmp), &s->NodeInfo);

			HLog(hub, "LH_NODE_INFO", s->Name, tmp);

			if (s->VLanId != 0)
			{
				HLog(hub, "LH_VLAN_ID", s->Name, s->VLanId);
			}
		}

		// Shift the connection to the tunneling mode
		StartTunnelingMode(c);

		// Processing of half-connection mode
		if (s->HalfConnection)
		{
			// The direction of the first socket is client to server
			TCPSOCK *ts = (TCPSOCK *)LIST_DATA(c->Tcp->TcpSockList, 0);
			ts->Direction = TCP_CLIENT_TO_SERVER;
		}

		if (s->UseFastRC4)
		{
			// Set the RC4 key information to the first TCP connection
			TCPSOCK *ts = (TCPSOCK *)LIST_DATA(c->Tcp->TcpSockList, 0);
			Copy(&ts->Rc4KeyPair, &key_pair, sizeof(RC4_KEY_PAIR));

			InitTcpSockRc4Key(ts, true);
		}

		if (s->UseEncrypt && s->UseFastRC4 == false)
		{
			s->UseSSLDataEncryption = true;
		}
		else
		{
			s->UseSSLDataEncryption = false;
		}

		if (s->Hub->Type == HUB_TYPE_FARM_DYNAMIC && s->Cedar->Server != NULL && s->Cedar->Server->ServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			if (s->Hub->BeingOffline == false)
			{
				// Start the SecureNAT on the dynamic Virtual HUB
				EnableSecureNATEx(s->Hub, false, true);

				cluster_dynamic_secure_nat = true;
			}
		}

		if (s->LocalHostSession)
		{
			// Update the local MAC address list
			RefreshLocalMacAddressList();
		}

		// Discard the user list cache
		DeleteAllUserListCache(hub->UserList);


		// Main routine of the session
		Debug("SessionMain()\n");
		s->NumLoginIncrementUserObject = loggedin_user_object;
		s->NumLoginIncrementHubObject = s->Hub;
		s->NumLoginIncrementTick = Tick64() + (UINT64)NUM_LOGIN_INCREMENT_INTERVAL;
		SessionMain(s);


		// Discard the user list cache
		DeleteAllUserListCache(hub->UserList);

		// Decrement the current number of connections
		Lock(s->Hub->lock);
		{
			if (use_bridge_license)
			{
				Dec(hub->NumSessionsBridge);
			}

			if (use_client_license)
			{
				Dec(hub->NumSessionsClient);
			}

			Dec(s->Hub->NumSessions);
			Dec(s->Hub->Cedar->CurrentSessions);

			// Decrement the number of licenses
			if (use_bridge_license)
			{
				Dec(s->Cedar->AssignedBridgeLicense);
			}

			if (use_client_license)
			{
				Dec(s->Cedar->AssignedClientLicense);
			}

			if (server != NULL)
			{
				// Update the total allocation of the number of licenses for Server structure
				if (server->ServerType == SERVER_TYPE_STANDALONE)
				{
					// Update only stand-alone mode
					// (Periodically polled in the cluster controller mode)
					server->CurrentAssignedClientLicense = Count(s->Cedar->AssignedClientLicense);
					server->CurrentAssignedBridgeLicense = Count(s->Cedar->AssignedBridgeLicense);
				}
			}
		}
		Unlock(s->Hub->lock);

		PrintSessionTotalDataSize(s);

		HLog(s->Hub, "LH_END_SESSION", s->Name, s->TotalSendSizeReal, s->TotalRecvSizeReal);

		if (cluster_dynamic_secure_nat && s->Hub->BeingOffline == false)
		{
			// Stop the SecureNAT on the dynamic Virtual HUB
			EnableSecureNATEx(s->Hub, false, true);
		}

		if (s->UdpAccel != NULL)
		{
			// Release the UDP acceleration
			FreeUdpAccel(s->UdpAccel);
			s->UdpAccel = NULL;
		}

		ReleaseSession(s);

		ret = true;
		c->Err = ERR_SESSION_REMOVED;

		ReleaseHub(hub);

		goto CLEANUP;
	}
	else if (StrCmpi(method, "additional_connect") == 0)
	{
		SOCK *sock;
		TCPSOCK *ts;
		UINT dummy;

		c->Type = CONNECTION_TYPE_ADDITIONAL;

		// Additional connection
		// Read the session key
		if (GetSessionKeyFromPack(p, session_key, &dummy) == false)
		{
			FreePack(p);
			c->Err = ERR_PROTOCOL_ERROR;
			goto CLEANUP;
		}

		FreePack(p);

		// Get the session from the session key
		s = GetSessionFromKey(c->Cedar, session_key);
		if (s == NULL || s->Halt || s->NoReconnectToSession)
		{
			// Session can not be found, or re-connection is prohibited
			Debug("Session Not Found.\n");
			c->Err = ERR_SESSION_TIMEOUT;
			goto CLEANUP;
		}

		// Session is found
		Debug("Session Found: %s\n", s->Name);
		// Check the protocol of session
		c->Err = 0;
		Lock(s->lock);
		{
			if (s->Connection->Protocol != CONNECTION_TCP)
			{
				c->Err = ERR_INVALID_PROTOCOL;
			}
		}
		Unlock(s->lock);
		// Check the current number of connections of the session
		Lock(s->Connection->lock);
		if (c->Err == 0)
		{
			if (Count(s->Connection->CurrentNumConnection) > s->MaxConnection)
			{
				c->Err = ERR_TOO_MANY_CONNECTION;
			}
		}
		if (c->Err != 0)
		{
			Unlock(s->Connection->lock);
			if (c->Err == ERR_TOO_MANY_CONNECTION)
			{
				Debug("Session TOO MANY CONNECTIONS !!: %u\n",
					Count(s->Connection->CurrentNumConnection));
			}
			else
			{
				Debug("Session Invalid Protocol.\n");
			}
			ReleaseSession(s);
			goto CLEANUP;
		}

		// Generate a high-speed RC4 encryption key
		if (s->UseFastRC4)
		{
			GenerateRC4KeyPair(&key_pair);
		}

		// Add the socket of this connection to the connection list of the session (TCP)
		sock = c->FirstSock;

		if (sock->IsRUDPSocket && sock->BulkRecvKey != NULL && sock->BulkSendKey != NULL)
		{
			if (s->BulkRecvKeySize != 0 && s->BulkSendKeySize != 0)
			{
				// Restore R-UDP bulk send/recv keys for additional connections
				Copy(sock->BulkRecvKey->Data, s->BulkRecvKey, s->BulkRecvKeySize);
				sock->BulkRecvKey->Size = s->BulkRecvKeySize;
				Copy(sock->BulkSendKey->Data, s->BulkSendKey, s->BulkSendKeySize);
				sock->BulkSendKey->Size = s->BulkSendKeySize;

				if (false)
				{
					char tmp1[128];
					char tmp2[128];
					BinToStr(tmp1, sizeof(tmp1), s->BulkRecvKey, s->BulkRecvKeySize);
					BinToStr(tmp2, sizeof(tmp2), s->BulkSendKey, s->BulkSendKeySize);
					Debug("Restore: s->BulkRecvKey->Size = %u, s->BulkSendKey->Size = %u\n",
						s->BulkRecvKeySize, s->BulkSendKeySize);
					Debug("Restore:\n%s\n%s\n\n", tmp1, tmp2);
				}			
			}
		}

		ts = NewTcpSock(sock);
		SetTimeout(sock, CONNECTING_TIMEOUT);
		direction = TCP_BOTH;
		LockList(s->Connection->Tcp->TcpSockList);
		{
			if (s->HalfConnection)
			{
				// In half-connection, directions of the TCP connections are automatically
				// adjusted by examining all current direction of the TCP connections
				UINT i, c2s, s2c;
				c2s = s2c = 0;
				for (i = 0;i < LIST_NUM(s->Connection->Tcp->TcpSockList);i++)
				{
					TCPSOCK *ts = (TCPSOCK *)LIST_DATA(s->Connection->Tcp->TcpSockList, i);
					if (ts->Direction == TCP_SERVER_TO_CLIENT)
					{
						s2c++;
					}
					else
					{
						c2s++;
					}
				}
				if (s2c > c2s)
				{
					direction = TCP_CLIENT_TO_SERVER;
				}
				else
				{
					direction = TCP_SERVER_TO_CLIENT;
				}
				Debug("%u/%u\n", s2c, c2s);
				ts->Direction = direction;
			}
		}
		UnlockList(s->Connection->Tcp->TcpSockList);

		if (s->UseFastRC4)
		{
			// Set the RC4 key information
			Copy(&ts->Rc4KeyPair, &key_pair, sizeof(RC4_KEY_PAIR));

			InitTcpSockRc4Key(ts, true);
		}

		// Return a success result
		p = PackError(ERR_NO_ERROR);
		PackAddInt(p, "direction", direction);

		if (s->UseFastRC4)
		{
			// Add a RC4 key information
			PackAddData(p, "rc4_key_client_to_server", key_pair.ClientToServerKey, sizeof(key_pair.ClientToServerKey));
			PackAddData(p, "rc4_key_server_to_client", key_pair.ServerToClientKey, sizeof(key_pair.ServerToClientKey));
			{
				char key1[64], key2[64];
				BinToStr(key1, sizeof(key1), key_pair.ClientToServerKey, 16);
				BinToStr(key2, sizeof(key2), key_pair.ServerToClientKey, 16);
				Debug(
					"Client to Server Key: %s\n"
					"Server to Client Key: %s\n",
					key1, key2);
			}
		}

		HttpServerSend(c->FirstSock, p);
		FreePack(p);

		SetTimeout(sock, INFINITE);

		LockList(s->Connection->Tcp->TcpSockList);
		{
			Add(s->Connection->Tcp->TcpSockList, ts);
		}
		UnlockList(s->Connection->Tcp->TcpSockList);

		// Increment the number of connections
		Inc(s->Connection->CurrentNumConnection);
		Debug("TCP Connection Incremented: %u\n", Count(s->Connection->CurrentNumConnection));

		// Issue the Cancel of session
		Cancel(s->Cancel1);

		Unlock(s->Connection->lock);

		c->flag1 = true;

		ReleaseSession(s);

		return true;
	}
	else if (StrCmpi(method, "enum_hub") == 0)
	{
		// Enumerate the Virtual HUB
		UINT i, num;
		LIST *o;
		o = NewListFast(NULL);

		c->Type = CONNECTION_TYPE_ENUM_HUB;

		FreePack(p);
		p = NewPack();
		LockList(c->Cedar->HubList);
		{
			num = LIST_NUM(c->Cedar->HubList);
			for (i = 0;i < num;i++)
			{
				HUB *h = LIST_DATA(c->Cedar->HubList, i);
				if (h->Option != NULL && h->Option->NoEnum == false)
				{
					Insert(o, CopyStr(h->Name));
				}
			}
		}
		UnlockList(c->Cedar->HubList);

		num = LIST_NUM(o);
		for (i = 0;i < num;i++)
		{
			char *name = LIST_DATA(o, i);
			PackAddStrEx(p, "HubName", name, i, num);
			Free(name);
		}
		ReleaseList(o);
		PackAddInt(p, "NumHub", num);

		HttpServerSend(c->FirstSock, p);
		FreePack(p);
		FreePack(HttpServerRecv(c->FirstSock));
		c->Err = 0;

		SLog(c->Cedar, "LS_ENUM_HUB", c->Name, num);

		error_detail = "enum_hub";

		goto CLEANUP;
	}
	else if (StrCmpi(method, "farm_connect") == 0)
	{
		// Server farm connection request
		CEDAR *cedar = c->Cedar;
		c->Type = CONNECTION_TYPE_FARM_RPC;
		c->Err = 0;
		if (c->Cedar->Server == NULL)
		{
			// Unsupported
			c->Err = ERR_NOT_FARM_CONTROLLER;
		}
		else
		{
			SERVER *s = c->Cedar->Server;
			if (s->ServerType != SERVER_TYPE_FARM_CONTROLLER || s->FarmControllerInited == false)
			{
				// Not a farm controller
				SLog(c->Cedar, "LS_FARM_ACCEPT_1", c->Name);
				c->Err = ERR_NOT_FARM_CONTROLLER;
			}
			else
			{
				UCHAR check_secure_password[SHA1_SIZE];
				UCHAR secure_password[SHA1_SIZE];
				// User authentication
				SecurePassword(check_secure_password, s->HashedPassword, c->Random);
				if (PackGetDataSize(p, "SecurePassword") == sizeof(secure_password))
				{
					PackGetData(p, "SecurePassword", secure_password);
				}
				else
				{
					Zero(secure_password, sizeof(secure_password));
				}

				if (Cmp(secure_password, check_secure_password, SHA1_SIZE) != 0)
				{
					// Password is different
					SLog(c->Cedar, "LS_FARM_ACCEPT_2", c->Name);
					c->Err = ERR_ACCESS_DENIED;
				}
				else
				{
					// Get the certificate
					BUF *b;
					X *server_x;

					SLog(c->Cedar, "LS_FARM_ACCEPT_3", c->Name);
					b = PackGetBuf(p, "ServerCert");
					if (b == NULL)
					{
						c->Err = ERR_PROTOCOL_ERROR;
					}
					else
					{
						server_x = BufToX(b, false);
						FreeBuf(b);
						if (server_x == NULL)
						{
							c->Err = ERR_PROTOCOL_ERROR;
						}
						else
						{
							UINT ip;
							UINT point;
							char hostname[MAX_SIZE];

#ifdef	OS_WIN32
							MsSetThreadPriorityRealtime();
#endif	// OS_WIN32

							SetTimeout(c->FirstSock, SERVER_CONTROL_TCP_TIMEOUT);

							ip = PackGetIp32(p, "PublicIp");
							point = PackGetInt(p, "Point");
							if (PackGetStr(p, "HostName", hostname, sizeof(hostname)))
							{
								UINT num_port = PackGetIndexCount(p, "PublicPort");
								if (num_port >= 1 && num_port <= MAX_PUBLIC_PORT_NUM)
								{
									UINT *ports = ZeroMalloc(sizeof(UINT) * num_port);
									UINT i;

									for (i = 0;i < num_port;i++)
									{
										ports[i] = PackGetIntEx(p, "PublicPort", i);
									}

									SiFarmServ(s, c->FirstSock, server_x, ip, num_port, ports, hostname, point,
										PackGetInt(p, "Weight"), PackGetInt(p, "MaxSessions"));

									Free(ports);
								}
							}

							FreeX(server_x);
						}
					}
				}
			}
		}
		FreePack(p);
		goto CLEANUP;
	}
	else if (StrCmpi(method, "admin") == 0 && c->Cedar->Server != NULL)
	{
		UINT err;
		// Administrative RPC connection request
		c->Type = CONNECTION_TYPE_ADMIN_RPC;
		err = AdminAccept(c, p);
		FreePack(p);
		if (err != ERR_NO_ERROR)
		{
			PACK *p = PackError(err);
			HttpServerSend(c->FirstSock, p);
			FreePack(p);
		}

		error_detail = "admin_rpc";

		goto CLEANUP;
	}
	else if (StrCmpi(method, "password") == 0)
	{
		UINT err;
		// Password change request
		c->Type = CONNECTION_TYPE_PASSWORD;
		err = ChangePasswordAccept(c, p);
		FreePack(p);

		p = PackError(err);
		HttpServerSend(c->FirstSock, p);
		FreePack(p);

		error_detail = "change_password";

		goto CLEANUP;
	}
	else
	{
		// Unknown method
		FreePack(p);
		c->Err = ERR_PROTOCOL_ERROR;

		error_detail = "unknown_method";

		goto CLEANUP;
	}

CLEANUP:
	// Release the user object
	if (loggedin_user_object != NULL)
	{
		ReleaseUser(loggedin_user_object);
	}


	// Error packet transmission
	if (supress_return_pack_error == false)
	{
		p = PackError(c->Err);
		PackAddBool(p, "no_save_password", no_save_password);
		HttpServerSend(c->FirstSock, p);
		FreePack(p);
	}

	FreePack(HttpServerRecv(c->FirstSock));

	SleepThread(25);

	SLog(c->Cedar, "LS_CONNECTION_ERROR", c->Name, GetUniErrorStr(c->Err), c->Err);

	if (release_me_eap_client != NULL)
	{
		ReleaseEapClient(release_me_eap_client);
	}

	return ret;
}


// Create a Node information
void CreateNodeInfo(NODE_INFO *info, CONNECTION *c)
{
	SESSION *s;
	OS_INFO *os;
	char *product_id;
	IP ip;
	bool is_vgc = false;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	s = c->Session;
	os = GetOsInfo();



	Zero(info, sizeof(NODE_INFO));

	// Client product name
	StrCpy(info->ClientProductName, sizeof(info->ClientProductName), c->ClientStr);
	// Client version
	info->ClientProductVer = Endian32(c->ClientVer);
	// Client build number
	info->ClientProductBuild = Endian32(c->ClientBuild);

	// Server product name
	StrCpy(info->ServerProductName, sizeof(info->ServerProductName), c->ServerStr);
	// Server version
	info->ServerProductVer = Endian32(c->ServerVer);
	// Server build number
	info->ServerProductBuild = Endian32(c->ServerBuild);

	// Client OS name
	StrCpy(info->ClientOsName, sizeof(info->ClientOsName), os->OsProductName);
	// Client OS version
	StrCpy(info->ClientOsVer, sizeof(info->ClientOsVer), os->OsVersion);
	// Client OS Product ID
	product_id = OSGetProductId();
	StrCpy(info->ClientOsProductId, sizeof(info->ClientOsProductId), product_id);
	Free(product_id);

	// Client host name
#ifndef	OS_WIN32
	GetMachineName(info->ClientHostname, sizeof(info->ClientHostname));
#else	// OS_WIN32
	if (true)
	{
		wchar_t namew[256];
		char namea[256];

		Zero(namew, sizeof(namew));
		MsGetComputerNameFullEx(namew, sizeof(namew), true);

		Zero(namea, sizeof(namea));
		UniToStr(namea, sizeof(namea), namew);

		if (IsEmptyStr(namea))
		{
			GetMachineName(namea, sizeof(namea));
		}

		StrCpy(info->ClientHostname, sizeof(info->ClientHostname), namea);

	}
#endif	// OS_WIN32
	// Client IP address
	if (IsIP6(&c->FirstSock->LocalIP) == false)
	{
		info->ClientIpAddress = IPToUINT(&c->FirstSock->LocalIP);
	}
	else
	{
		Copy(info->ClientIpAddress6, c->FirstSock->LocalIP.ipv6_addr, sizeof(info->ClientIpAddress6));
	}
	// Client port number
	info->ClientPort = Endian32(c->FirstSock->LocalPort);

	// Server host name
	StrCpy(info->ServerHostname, sizeof(info->ServerHostname), c->ServerName);
	// Server IP address
	if (GetIP(&ip, info->ServerHostname))
	{
		if (IsIP6(&ip) == false)
		{
			info->ServerIpAddress = IPToUINT(&ip);
		}
		else
		{
			Copy(info->ServerIpAddress6, ip.ipv6_addr, sizeof(info->ServerIpAddress6));
		}
	}
	// Server port number
	info->ServerPort = Endian32(c->ServerPort);

	if (s->ClientOption->ProxyType == PROXY_SOCKS || s->ClientOption->ProxyType == PROXY_HTTP)
	{
		// Proxy host name
		StrCpy(info->ProxyHostname, sizeof(info->ProxyHostname), s->ClientOption->ProxyName);

		// Proxy Server IP Address
		if (IsIP6(&c->FirstSock->RemoteIP) == false)
		{
			info->ProxyIpAddress = IPToUINT(&c->FirstSock->RemoteIP);
		}
		else
		{
			Copy(&info->ProxyIpAddress6, c->FirstSock->RemoteIP.ipv6_addr, sizeof(info->ProxyIpAddress6));
		}

		info->ProxyPort = Endian32(c->FirstSock->RemotePort);
	}

	// HUB name
	StrCpy(info->HubName, sizeof(info->HubName), s->ClientOption->HubName);

	// Unique ID
	Copy(info->UniqueId, c->Cedar->UniqueId, sizeof(info->UniqueId));
}

// Connect a socket additionally
SOCK *ClientAdditionalConnectToServer(CONNECTION *c)
{
	SOCK *s;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	// Socket connection
	s = ClientConnectGetSocket(c, true, (c->DontUseTls1 ? false : true));
	if (s == NULL)
	{
		// Connection failure
		return NULL;
	}

	// Add the socket to the list
	LockList(c->ConnectingSocks);
	{
		Add(c->ConnectingSocks, s);
		AddRef(s->ref);
	}
	UnlockList(c->ConnectingSocks);

	if (c->Session->Halt)
	{
		// Stop
		Disconnect(s);
		LockList(c->ConnectingSocks);
		{
			if (Delete(c->ConnectingSocks, s))
			{
				ReleaseSock(s);
			}
		}
		UnlockList(c->ConnectingSocks);
		ReleaseSock(s);
		return NULL;
	}

	// Time-out
	SetTimeout(s, CONNECTING_TIMEOUT);

	// Start the SSL communication
	if (StartSSLEx(s, NULL, NULL, (c->DontUseTls1 ? false : true), 0, c->ServerName) == false)
	{
		// SSL communication failure
		Disconnect(s);
		LockList(c->ConnectingSocks);
		{
			if (Delete(c->ConnectingSocks, s))
			{
				ReleaseSock(s);
			}
		}
		UnlockList(c->ConnectingSocks);
		ReleaseSock(s);
		return NULL;
	}

	// Check the certificate
	if (CompareX(s->RemoteX, c->ServerX) == false)
	{
		// The certificate is invalid
		Disconnect(s);
		c->Session->SessionTimeOuted = true;
	}

	return s;
}

// Remove the key and certificate in the secure device
UINT SecureDelete(UINT device_id, char *pin, char *cert_name, char *key_name)
{
	SECURE *sec;
	// Validate arguments
	if (pin == NULL || device_id == 0)
	{
		return ERR_INTERNAL_ERROR;
	}

	// Open the device
	sec = OpenSec(device_id);
	if (sec == NULL)
	{
		return ERR_SECURE_DEVICE_OPEN_FAILED;
	}

	// Open the session
	if (OpenSecSession(sec, 0) == false)
	{
		CloseSec(sec);
		return ERR_SECURE_DEVICE_OPEN_FAILED;
	}

	// Login
	if (LoginSec(sec, pin) == false)
	{
		CloseSecSession(sec);
		CloseSec(sec);
		return ERR_SECURE_PIN_LOGIN_FAILED;
	}

	// Delete the certificate
	if (cert_name != NULL)
	{
		DeleteSecCert(sec, cert_name);
	}

	// Delete the Private key
	if (key_name != NULL)
	{
		DeleteSecKey(sec, key_name);
	}

	// Log out
	LogoutSec(sec);

	// Close the session
	CloseSecSession(sec);

	// Close the device
	CloseSec(sec);

	return ERR_NO_ERROR;
}

// Enumerate certificates and keys in the secure device
UINT SecureEnum(UINT device_id, char *pin, TOKEN_LIST **cert_list, TOKEN_LIST **key_list)
{
	SECURE *sec;
	LIST *o;
	LIST *cert_name_list, *key_name_list;
	// Validate arguments
	if (pin == NULL || device_id == 0 || cert_list == NULL || key_list == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	// Open the device
	sec = OpenSec(device_id);
	if (sec == NULL)
	{
		return ERR_SECURE_DEVICE_OPEN_FAILED;
	}

	// Open the session
	if (OpenSecSession(sec, 0) == false)
	{
		CloseSec(sec);
		return ERR_SECURE_DEVICE_OPEN_FAILED;
	}

	// Login
	if (LoginSec(sec, pin) == false)
	{
		CloseSecSession(sec);
		CloseSec(sec);
		return ERR_SECURE_PIN_LOGIN_FAILED;
	}

	// Enumerate objects
	if ((o = EnumSecObject(sec)) != NULL)
	{
		UINT i;

		cert_name_list = NewList(CompareStr);
		key_name_list = NewList(CompareStr);

		for (i = 0;i < LIST_NUM(o);i++)
		{
			SEC_OBJ *obj = LIST_DATA(o, i);

			if (obj->Type == SEC_X)
			{
				Add(cert_name_list, CopyStr(obj->Name));
			}
			else if (obj->Type == SEC_K)
			{
				Add(key_name_list, CopyStr(obj->Name));
			}
		}

		Sort(cert_name_list);
		Sort(key_name_list);

		*cert_list = ListToTokenList(cert_name_list);
		*key_list = ListToTokenList(key_name_list);

		// Release the memory
		FreeStrList(cert_name_list);
		FreeStrList(key_name_list);
		FreeEnumSecObject(o);
	}
	else
	{
		*cert_list = NullToken();
		*key_list = NullToken();
	}

	// Log out
	LogoutSec(sec);

	// Close the session
	CloseSecSession(sec);

	// Close the device
	CloseSec(sec);

	return ERR_NO_ERROR;
}

// Record the certificate and key to secure device
UINT SecureWrite(UINT device_id, char *cert_name, X *x, char *key_name, K *k, char *pin)
{
	SECURE *sec;
	bool failed;
	// Validate arguments
	if (pin == NULL || device_id == 0 || cert_name == NULL || x == NULL || key_name == NULL || k == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	// Open the device
	sec = OpenSec(device_id);
	if (sec == NULL)
	{
		return ERR_SECURE_DEVICE_OPEN_FAILED;
	}

	// Open the session
	if (OpenSecSession(sec, 0) == false)
	{
		CloseSec(sec);
		return ERR_SECURE_DEVICE_OPEN_FAILED;
	}

	// Login
	if (LoginSec(sec, pin) == false)
	{
		CloseSecSession(sec);
		CloseSec(sec);
		return ERR_SECURE_PIN_LOGIN_FAILED;
	}

	// Registration
	failed = false;

	// Register the certificate
	if (WriteSecCert(sec, true, cert_name, x) == false)
	{
		failed = true;
	}

	// Register the private key
	if (WriteSecKey(sec, true, key_name, k) == false)
	{
		failed = true;
	}

	// Log out
	LogoutSec(sec);

	// Close the session
	CloseSecSession(sec);

	// Close the device
	CloseSec(sec);

	if (failed == false)
	{
		// Success
		return ERR_NO_ERROR;
	}
	else
	{
		// Failure
		return ERR_SECURE_CANT_WRITE;
	}
}

// Attempt to sign by the secure device
UINT SecureSign(SECURE_SIGN *sign, UINT device_id, char *pin)
{
	SECURE *sec;
	X *x;
	// Validate arguments
	if (sign == false || pin == NULL || device_id == 0)
	{
		return ERR_INTERNAL_ERROR;
	}

	// Open the device
	sec = OpenSec(device_id);
	if (sec == NULL)
	{
		return ERR_SECURE_DEVICE_OPEN_FAILED;
	}

	// Open the session
	if (OpenSecSession(sec, 0) == false)
	{
		CloseSec(sec);
		return ERR_SECURE_DEVICE_OPEN_FAILED;
	}

	// Login
	if (LoginSec(sec, pin) == false)
	{
		CloseSecSession(sec);
		CloseSec(sec);
		return ERR_SECURE_PIN_LOGIN_FAILED;
	}

	// Read the certificate
	x = ReadSecCert(sec, sign->SecurePublicCertName);
	if (x == NULL)
	{
		LogoutSec(sec);
		CloseSecSession(sec);
		CloseSec(sec);
		return ERR_SECURE_NO_CERT;
	}

	// Sign by the private key
	if (SignSec(sec, sign->SecurePrivateKeyName, sign->Signature, sign->Random, SHA1_SIZE) == false)
	{
		// Signing failure
		FreeX(x);
		LogoutSec(sec);
		CloseSecSession(sec);
		CloseSec(sec);
		return ERR_SECURE_NO_PRIVATE_KEY;
	}

	// Convert the certificate to buffer
	sign->ClientCert = x;

	// Log out
	LogoutSec(sec);

	// Close the session
	CloseSecSession(sec);

	// Close the device
	CloseSec(sec);

	// Success
	return ERR_NO_ERROR;
}

// Client connects to the server additionally
bool ClientAdditionalConnect(CONNECTION *c, THREAD *t)
{
	SOCK *s;
	PACK *p;
	TCPSOCK *ts;
	UINT err;
	UINT direction;
	RC4_KEY_PAIR key_pair;
	// Validate arguments
	if (c == NULL)
	{
		return false;
	}

	// Socket connection to the server
	s = ClientAdditionalConnectToServer(c);
	if (s == NULL)
	{
		// Failed to connect socket
		return false;
	}

	if (c->Halt)
	{
		goto CLEANUP;
	}

	// Send a signature
	Debug("Uploading Signature...\n");
	if (ClientUploadSignature(s) == false)
	{
		goto CLEANUP;
	}

	if (c->Halt)
	{
		// Stop
		goto CLEANUP;
	}

	// Receive a Hello packet
	Debug("Downloading Hello...\n");
	if (ClientDownloadHello(c, s) == false)
	{
		goto CLEANUP;
	}

	if (c->Halt)
	{
		// Stop
		goto CLEANUP;
	}

	// Send a authentication data for the additional connection
	if (ClientUploadAuth2(c, s) == false)
	{
		// Disconnected
		goto CLEANUP;
	}

	// Receive a response
	p = HttpClientRecv(s);
	if (p == NULL)
	{
		// Disconnected
		goto CLEANUP;
	}

	err = GetErrorFromPack(p);
	direction = PackGetInt(p, "direction");

	if (c->Session->UseFastRC4)
	{
		// Get the RC4 key information
		if (PackGetDataSize(p, "rc4_key_client_to_server") == 16)
		{
			PackGetData(p, "rc4_key_client_to_server", key_pair.ClientToServerKey);
		}
		if (PackGetDataSize(p, "rc4_key_server_to_client") == 16)
		{
			PackGetData(p, "rc4_key_server_to_client", key_pair.ServerToClientKey);
		}
		{
			char key1[64], key2[64];
			BinToStr(key1, sizeof(key1), key_pair.ClientToServerKey, 16);
			BinToStr(key2, sizeof(key2), key_pair.ServerToClientKey, 16);
			Debug(
				"Client to Server Key: %s\n"
				"Server to Client Key: %s\n",
				key1, key2);
		}
	}

	FreePack(p);
	p = NULL;

	if (err != 0)
	{
		// Error has occurred
		Debug("Additional Connect Error: %u\n", err);
		if (err == ERR_SESSION_TIMEOUT || err == ERR_INVALID_PROTOCOL)
		{
			// We shall re-connection because it is a fatal error
			c->Session->SessionTimeOuted = true;
		}
		goto CLEANUP;
	}

	Debug("Additional Connect Succeed!\n");

	if (s->IsRUDPSocket && s->BulkRecvKey != NULL && s->BulkSendKey != NULL)
	{
		// Restore R-UDP bulk send/recv keys for additional connections
		if (c->Session->BulkRecvKeySize != 0 && c->Session->BulkSendKeySize != 0)
		{
			Copy(s->BulkRecvKey->Data, c->Session->BulkRecvKey, c->Session->BulkRecvKeySize);
			s->BulkRecvKey->Size = c->Session->BulkRecvKeySize;

			Copy(s->BulkSendKey->Data, c->Session->BulkSendKey, c->Session->BulkSendKeySize);
			s->BulkSendKey->Size = c->Session->BulkSendKeySize;

			if (false)
			{
				char tmp1[128];
				char tmp2[128];
				BinToStr(tmp1, sizeof(tmp1), s->BulkRecvKey->Data, s->BulkRecvKey->Size);
				BinToStr(tmp2, sizeof(tmp2), s->BulkSendKey->Data, s->BulkSendKey->Size);
				Debug("Restore: s->BulkRecvKey->Size = %u, s->BulkSendKey->Size = %u\n",
					s->BulkRecvKey->Size, s->BulkSendKey->Size);
				Debug("Restore:\n%s\n%s\n\n", tmp1, tmp2);
			}			
		}
	}

	// Success the additional connection
	// Add to the TcpSockList of the connection
	ts = NewTcpSock(s);

	if (c->ServerMode == false)
	{
		if (c->Session->ClientOption->ConnectionDisconnectSpan != 0)
		{
			ts->DisconnectTick = Tick64() + c->Session->ClientOption->ConnectionDisconnectSpan * (UINT64)1000;
		}
	}

	LockList(c->Tcp->TcpSockList);
	{
		ts->Direction = direction;
		Add(c->Tcp->TcpSockList, ts);
	}
	UnlockList(c->Tcp->TcpSockList);
	Debug("TCP Connection Incremented: %u\n", Count(c->CurrentNumConnection));

	if (c->Session->HalfConnection)
	{
		Debug("New Half Connection: %s\n",
			direction == TCP_SERVER_TO_CLIENT ? "TCP_SERVER_TO_CLIENT" : "TCP_CLIENT_TO_SERVER"
			);
	}

	if (c->Session->UseFastRC4)
	{
		// Set the RC4 encryption key
		Copy(&ts->Rc4KeyPair, &key_pair, sizeof(RC4_KEY_PAIR));

		InitTcpSockRc4Key(ts, false);
	}

	// Issue the Cancel to the session
	Cancel(c->Session->Cancel1);

	// Remove the socket from the socket list of connected
	LockList(c->ConnectingSocks);
	{
		if (Delete(c->ConnectingSocks, s))
		{
			ReleaseSock(s);
		}
	}
	UnlockList(c->ConnectingSocks);
	ReleaseSock(s);
	return true;

CLEANUP:
	// Disconnection process
	Disconnect(s);
	LockList(c->ConnectingSocks);
	{
		if (Delete(c->ConnectingSocks, s))
		{
			ReleaseSock(s);

		}
	}
	UnlockList(c->ConnectingSocks);
	ReleaseSock(s);
	return false;
}

// Secure device signing thread
void ClientSecureSignThread(THREAD *thread, void *param)
{
	SECURE_SIGN_THREAD_PROC *p = (SECURE_SIGN_THREAD_PROC *)param;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	NoticeThreadInit(thread);

	p->Ok = p->SecureSignProc(p->Connection->Session, p->Connection, p->SecureSign);
	p->UserFinished = true;
}

// Signing with the secure device
bool ClientSecureSign(CONNECTION *c, UCHAR *sign, UCHAR *random, X **x)
{
	SECURE_SIGN_THREAD_PROC *p;
	SECURE_SIGN *ss;
	SESSION *s;
	CLIENT_OPTION *o;
	CLIENT_AUTH *a;
	THREAD *thread;
	UINT64 start;
	bool ret;
	// Validate arguments
	if (c == NULL || sign == NULL || random == NULL || x == NULL)
	{
		return false;
	}

	s = c->Session;
	o = s->ClientOption;
	a = s->ClientAuth;

	p = ZeroMalloc(sizeof(SECURE_SIGN_THREAD_PROC));
	p->Connection = c;
	ss = p->SecureSign = ZeroMallocEx(sizeof(SECURE_SIGN), true);
	StrCpy(ss->SecurePrivateKeyName, sizeof(ss->SecurePrivateKeyName),
		a->SecurePrivateKeyName);
	StrCpy(ss->SecurePublicCertName, sizeof(ss->SecurePublicCertName),
		a->SecurePublicCertName);
	ss->UseSecureDeviceId = c->Cedar->Client->UseSecureDeviceId;
	Copy(ss->Random, random, SHA1_SIZE);

#ifdef	OS_WIN32
	ss->BitmapId = CmGetSecureBitmapId(c->ServerName);
#endif	// OS_WIN32

	p->SecureSignProc = a->SecureSignProc;

	// Create a thread
	thread = NewThread(ClientSecureSignThread, p);
	WaitThreadInit(thread);

	// Poll every 0.5 seconds until signing is completed or canceled
	start = Tick64();
	while (true)
	{
		if ((Tick64() - start) > CONNECTING_POOLING_SPAN)
		{
			// Send a NOOP periodically for disconnection prevention
			start = Tick64();
			ClientUploadNoop(c);
		}
		if (p->UserFinished)
		{
			// User selected
			break;
		}
		WaitThread(thread, 500);
	}
	ReleaseThread(thread);

	ret = p->Ok;

	if (ret)
	{
		Copy(sign, ss->Signature, sizeof(ss->Signature));
		*x = ss->ClientCert;
	}

	Free(p->SecureSign);
	Free(p);

	return ret;
}

// Server certificate confirmation thread
void ClientCheckServerCertThread(THREAD *thread, void *param)
{
	CHECK_CERT_THREAD_PROC *p = (CHECK_CERT_THREAD_PROC *)param;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	// Notify the completion of initialization
	NoticeThreadInit(thread);

	// Query for the selection to the user
	p->Ok = p->CheckCertProc(p->Connection->Session, p->Connection, p->ServerX, &p->Exipred);
	p->UserSelected = true;
}

// Client verify the certificate of the server
bool ClientCheckServerCert(CONNECTION *c, bool *expired)
{
	CLIENT_AUTH *auth;
	X *x;
	CHECK_CERT_THREAD_PROC *p;
	THREAD *thread;
	CEDAR *cedar;
	bool ret;
	UINT64 start;
	// Validate arguments
	if (c == NULL)
	{
		return false;
	}

	if (expired != NULL)
	{
		*expired = false;
	}

	auth = c->Session->ClientAuth;
	cedar = c->Cedar;

	if (auth->CheckCertProc == NULL && c->Session->LinkModeClient == false)
	{
		// No checking function
		return true;
	}

	if (c->Session->LinkModeClient && c->Session->Link->CheckServerCert == false)
	{
		// It's in cascade connection mode, but do not check the server certificate
		return true;
	}

	if (c->UseTicket)
	{
		// Check the certificate of the redirected VPN server
		if (CompareX(c->FirstSock->RemoteX, c->ServerX) == false)
		{
			return false;
		}
		else
		{
			return true;
		}
	}

	x = CloneX(c->FirstSock->RemoteX);
	if (x == NULL)
	{
		// Strange error occurs
		return false;
	}

	if (CheckXDateNow(x))
	{
		// Check whether it is signed by the root certificate to trust
		if (c->Session->LinkModeClient == false)
		{
			// Normal VPN Client mode
			if (CheckSignatureByCa(cedar, x))
			{
				// This certificate can be trusted because it is signed
				FreeX(x);
				return true;
			}
		}
		else
		{
			// Cascade connection mode
			if (CheckSignatureByCaLinkMode(c->Session, x))
			{
				// This certificate can be trusted because it is signed
				FreeX(x);
				return true;
			}
		}
	}

	if (c->Session->LinkModeClient)
	{
		if (CheckXDateNow(x))
		{
			Lock(c->Session->Link->lock);
			{
				if (c->Session->Link->ServerCert != NULL)
				{
					if (CompareX(c->Session->Link->ServerCert, x))
					{
						Unlock(c->Session->Link->lock);
						// Exactly match the certificate that is registered in the cascade configuration
						FreeX(x);
						return true;
					}
				}
			}
			Unlock(c->Session->Link->lock);
		}
		else
		{
			if (expired != NULL)
			{
				*expired = true;
			}
		}

		// Verification failure at this point in the case of cascade connection mode
		FreeX(x);
		return false;
	}

	p = ZeroMalloc(sizeof(CHECK_CERT_THREAD_PROC));
	p->ServerX = x;
	p->CheckCertProc = auth->CheckCertProc;
	p->Connection = c;

	// Create a thread
	thread = NewThread(ClientCheckServerCertThread, p);
	WaitThreadInit(thread);

	// Poll at 0.5-second intervals until the user selects whether the connection
	start = Tick64();
	while (true)
	{
		if ((Tick64() - start) > CONNECTING_POOLING_SPAN)
		{
			// Send a NOOP periodically for disconnection prevention
			start = Tick64();
			ClientUploadNoop(c);
		}
		if (p->UserSelected)
		{
			// User-selected
			break;
		}
		WaitThread(thread, 500);
	}

	if (expired != NULL)
	{
		*expired = p->Exipred;
	}

	ret = p->Ok;
	FreeX(p->ServerX);
	Free(p);
	ReleaseThread(thread);

	return ret;
}

// Client connects to the server
bool ClientConnect(CONNECTION *c)
{
	bool ret = false;
	bool ok = false;
	UINT err;
	SOCK *s;
	PACK *p = NULL;
	UINT session_key_32;
	SESSION *sess;
	char session_name[MAX_SESSION_NAME_LEN + 1];
	char connection_name[MAX_CONNECTION_NAME_LEN + 1];
	UCHAR session_key[SHA1_SIZE];
	RC4_KEY_PAIR key_pair;
	POLICY *policy;
	bool expired = false;
	IP server_ip;
	// Validate arguments
	if (c == NULL)
	{
		return false;
	}

	sess = c->Session;

	PrintStatus(sess, L"init");
	PrintStatus(sess, _UU("STATUS_1"));

REDIRECTED:

	// [Connecting]
	c->Status = CONNECTION_STATUS_CONNECTING;
	c->Session->ClientStatus = CLIENT_STATUS_CONNECTING;

	s = ClientConnectToServer(c);
	if (s == NULL)
	{
		PrintStatus(sess, L"free");
		return false;
	}

	Copy(&server_ip, &s->RemoteIP, sizeof(IP));

	if (c->Halt)
	{
		// Stop
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	// [Negotiating]
	c->Session->ClientStatus = CLIENT_STATUS_NEGOTIATION;

	// Initialize the UDP acceleration function
	if (sess->ClientOption != NULL && sess->ClientOption->NoUdpAcceleration == false)
	{
		if (sess->ClientOption->ProxyType == PROXY_DIRECT)
		{
			if (s->Type == SOCK_TCP)
			{
				if (sess->UdpAccel == NULL)
				{
					bool no_nat_t = false;

					if (sess->ClientOption->PortUDP != 0)
					{
						// There is no need for NAT-T treatment on my part if the UDP port on the other end is known beforehand
						no_nat_t = true;
					}


					sess->UdpAccel = NewUdpAccel(c->Cedar, &s->LocalIP, true, true, no_nat_t);
				}
			}
		}
	}

	// Send a signature
	Debug("Uploading Signature...\n");
	if (ClientUploadSignature(s) == false)
	{
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	if (c->Halt)
	{
		// Stop
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	PrintStatus(sess, _UU("STATUS_5"));

	// Receive a Hello packet
	Debug("Downloading Hello...\n");
	if (ClientDownloadHello(c, s) == false)
	{
		goto CLEANUP;
	}

	if (c->Session->ClientOption != NULL && c->Session->ClientOption->FromAdminPack)
	{
		if (IsAdminPackSupportedServerProduct(c->ServerStr) == false)
		{
			c->Err = ERR_NOT_ADMINPACK_SERVER;
			goto CLEANUP;
		}
	}

	if (c->Halt)
	{
		// Stop
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	Debug("Server Version : %u\n"
		"Server String  : %s\n"
		"Server Build   : %u\n"
		"Client Version : %u\n"
		"Client String  : %s\n"
		"Client Build   : %u\n",
		c->ServerVer, c->ServerStr, c->ServerBuild,
		c->ClientVer, c->ClientStr, c->ClientBuild);

	// During user authentication
	c->Session->ClientStatus = CLIENT_STATUS_AUTH;

	// Verify the server certificate by the client
	if (ClientCheckServerCert(c, &expired) == false)
	{
		if (expired == false)
		{
			c->Err = ERR_CERT_NOT_TRUSTED;
		}
		else
		{
			c->Err = ERR_SERVER_CERT_EXPIRES;
		}

		if (c->Session->LinkModeClient == false && c->Err == ERR_CERT_NOT_TRUSTED)
		{
			c->Session->ForceStopFlag = true;
		}

		goto CLEANUP;
	}

	PrintStatus(sess, _UU("STATUS_6"));

	// Send the authentication data
	if (ClientUploadAuth(c) == false)
	{
		goto CLEANUP;
	}

	if (c->Halt)
	{
		// Stop
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	// Receive a Welcome packet
	p = HttpClientRecv(s);
	if (p == NULL)
	{
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	// Error checking
	err = GetErrorFromPack(p);
	if (err != 0)
	{
		// An error has occured
		c->Err = err;
		c->ClientConnectError_NoSavePassword = PackGetBool(p, "no_save_password");
		goto CLEANUP;
	}

	// Branding string check for the connection limit
	{
		char tmp[20];
		char *branded_cfroms = _SS("BRANDED_C_FROM_S");
		PackGetStr(p, "branded_cfroms", tmp, sizeof(tmp));

		if(StrLen(branded_cfroms) > 0 && StrCmpi(branded_cfroms, tmp) != 0)
		{
			c->Err = ERR_BRANDED_C_FROM_S;
			goto CLEANUP;
		}
	}

	if (c->Cedar->Server == NULL)
	{
		// Suppress client notification flag
		if (PackIsValueExists(p, "suppress_client_update_notification"))
		{
			bool suppress_client_update_notification = PackGetBool(p, "suppress_client_update_notification");

#ifdef	OS_WIN32
			MsRegWriteIntEx2(REG_LOCAL_MACHINE, PROTO_SUPPRESS_CLIENT_UPDATE_NOTIFICATION_REGKEY, PROTO_SUPPRESS_CLIENT_UPDATE_NOTIFICATION_REGVALUE,
				(suppress_client_update_notification ? 1 : 0), false, true);
#endif	// OS_WIN32
		}
	}

	if (true)
	{
		// Message retrieval
		UINT utf_size;
		char *utf;
		wchar_t *msg;

		utf_size = PackGetDataSize(p, "Msg");
		utf = ZeroMalloc(utf_size + 8);
		PackGetData(p, "Msg", utf);

		msg = CopyUtfToUni(utf);

		if (IsEmptyUniStr(msg) == false)
		{
			if (c->Session->Client_Message != NULL)
			{
				Free(c->Session->Client_Message);
			}

			c->Session->Client_Message = msg;
		}
		else
		{
			Free(msg);
		}

		Free(utf);
	}

	if (PackGetInt(p, "Redirect") != 0)
	{
		UINT i;
		UINT ip;
		UINT num_port;
		UINT *ports;
		UINT use_port = 0;
		UINT current_port = c->ServerPort;
		UCHAR ticket[SHA1_SIZE];
		X *server_cert;
		BUF *b;

		// Redirect mode
		PrintStatus(sess, _UU("STATUS_8"));

		ip = PackGetIp32(p, "Ip");
		num_port = MAX(MIN(PackGetIndexCount(p, "Port"), MAX_PUBLIC_PORT_NUM), 1);
		ports = ZeroMalloc(sizeof(UINT) * num_port);
		for (i = 0;i < num_port;i++)
		{
			ports[i] = PackGetIntEx(p, "Port", i);
		}

		// Select a port number
		for (i = 0;i < num_port;i++)
		{
			if (ports[i] == current_port)
			{
				use_port = current_port;
			}
		}
		if (use_port == 0)
		{
			use_port = ports[0];
		}

		Free(ports);

		if (PackGetDataSize(p, "Ticket") == SHA1_SIZE)
		{
			PackGetData(p, "Ticket", ticket);
		}

		b = PackGetBuf(p, "Cert");
		if (b != NULL)
		{
			server_cert = BufToX(b, false);
			FreeBuf(b);
		}

		if (c->ServerX != NULL)
		{
			FreeX(c->ServerX);
		}
		c->ServerX = server_cert;

		IPToStr32(c->ServerName, sizeof(c->ServerName), ip);
		c->ServerPort = use_port;

		c->UseTicket = true;
		Copy(c->Ticket, ticket, SHA1_SIZE);

		FreePack(p);

		p = NewPack();
		HttpClientSend(s, p);
		FreePack(p);

		p = NULL;

		c->FirstSock = NULL;
		Disconnect(s);
		ReleaseSock(s);
		s = NULL;

		goto REDIRECTED;
	}

	PrintStatus(sess, _UU("STATUS_7"));

	// Parse the Welcome packet
	if (ParseWelcomeFromPack(p, session_name, sizeof(session_name),
		connection_name, sizeof(connection_name), &policy) == false)
	{
		// Parsing failure
		c->Err = ERR_PROTOCOL_ERROR;
		goto CLEANUP;
	}

	// Get the session key
	if (GetSessionKeyFromPack(p, session_key, &session_key_32) == false)
	{
		// Acquisition failure
		Free(policy);
		policy = NULL;
		c->Err = ERR_PROTOCOL_ERROR;
		goto CLEANUP;
	}

	Copy(c->Session->SessionKey, session_key, SHA1_SIZE);
	c->Session->SessionKey32 = session_key_32;

	// Save the contents of the Welcome packet
	Debug("session_name: %s, connection_name: %s\n",
		session_name, connection_name);

	Lock(c->Session->lock);
	{
		// Deploy and update connection parameters
		sess->EnableUdpRecovery = PackGetBool(p, "enable_udp_recovery");
		c->Session->MaxConnection = PackGetInt(p, "max_connection");

		if (sess->EnableUdpRecovery == false)
		{
			c->Session->MaxConnection = MIN(c->Session->MaxConnection, c->Session->ClientOption->MaxConnection);
		}

		c->Session->MaxConnection = MIN(c->Session->MaxConnection, MAX_TCP_CONNECTION);
		c->Session->MaxConnection = MAX(c->Session->MaxConnection, 1);
		c->Session->UseCompress = PackGetInt(p, "use_compress") == 0 ? false : true;
		c->Session->UseEncrypt = PackGetInt(p, "use_encrypt") == 0 ? false : true;
		c->Session->NoSendSignature = PackGetBool(p, "no_send_signature");
		if (c->Session->UseEncrypt)
		{
			c->Session->UseFastRC4 = PackGetInt(p, "use_fast_rc4") == 0 ? false : true;
		}
		c->Session->HalfConnection = PackGetInt(p, "half_connection") == 0 ? false : true;
		c->Session->IsAzureSession = PackGetInt(p, "is_azure_session") == 0 ? false : true;
		c->Session->Timeout = PackGetInt(p, "timeout");
		c->Session->QoS = PackGetInt(p, "qos") == 0 ? false : true;
		if (c->Session->QoS)
		{
			c->Session->MaxConnection = MAX(c->Session->MaxConnection, (UINT)(c->Session->HalfConnection ? 4 : 2));
		}
		c->Session->VLanId = PackGetInt(p, "vlan_id");

		// R-UDP Session ?
		c->Session->IsRUDPSession = s->IsRUDPSocket;

		ZeroIP4(&c->Session->AzureRealServerGlobalIp);

		if (c->Session->IsAzureSession)
		{
			// Disable the life parameter of the connection in the case of VPN Azure relayed session
			c->Session->ClientOption->ConnectionDisconnectSpan = 0;

			// Get the AzureRealServerGlobalIp the case of VPN Azure relayed
			PackGetIp(p, "azure_real_server_global_ip", &c->Session->AzureRealServerGlobalIp);
		}

		if (c->Session->IsRUDPSession)
		{
			// Disable the life parameter of the connection in the case of R-UDP session
			c->Session->ClientOption->ConnectionDisconnectSpan = 0;

			// Disable QoS, etc. in the case of R-UDP session
			c->Session->QoS = false;
			c->Session->HalfConnection = false;

			if (c->Session->EnableUdpRecovery == false)
			{
				// Set the number of connection to 1 if UDP recovery is not supported
				c->Session->MaxConnection = 1;
			}
		}

		// Physical communication protocol
		StrCpy(c->Session->UnderlayProtocol, sizeof(c->Session->UnderlayProtocol), s->UnderlayProtocol);

		AddProtocolDetailsStr(c->Session->ProtocolDetails, sizeof(c->Session->ProtocolDetails), s->ProtocolDetails);

		if (c->Session->IsAzureSession)
		{
			StrCpy(c->Session->UnderlayProtocol, sizeof(c->Session->UnderlayProtocol), SOCK_UNDERLAY_AZURE);

			AddProtocolDetailsStr(c->Session->ProtocolDetails, sizeof(c->Session->ProtocolDetails),
				"VPNAzure");
		}

		if (c->Protocol == CONNECTION_UDP)
		{
			// In the case of UDP protocol, receive the key from the server
			if (PackGetDataSize(p, "udp_send_key") == sizeof(c->Session->UdpSendKey))
			{
				PackGetData(p, "udp_send_key", c->Session->UdpSendKey);
			}

			if (PackGetDataSize(p, "udp_recv_key") == sizeof(c->Session->UdpRecvKey))
			{
				PackGetData(p, "udp_recv_key", c->Session->UdpRecvKey);
			}
		}

		if (c->Session->UseFastRC4)
		{
			// Get the RC4 key information
			if (PackGetDataSize(p, "rc4_key_client_to_server") == 16)
			{
				PackGetData(p, "rc4_key_client_to_server", key_pair.ClientToServerKey);
			}
			if (PackGetDataSize(p, "rc4_key_server_to_client") == 16)
			{
				PackGetData(p, "rc4_key_server_to_client", key_pair.ServerToClientKey);
			}
			{
				char key1[64], key2[64];
				BinToStr(key1, sizeof(key1), key_pair.ClientToServerKey, 16);
				BinToStr(key2, sizeof(key2), key_pair.ServerToClientKey, 16);
				Debug(
					"Client to Server Key: %s\n"
					"Server to Client Key: %s\n",
					key1, key2);
			}
		}

		sess->EnableBulkOnRUDP = false;
		sess->EnableHMacOnBulkOfRUDP = false;
		if (s != NULL && s->IsRUDPSocket && s->BulkRecvKey != NULL && s->BulkSendKey != NULL)
		{
			// Bulk transfer on R-UDP
			sess->EnableHMacOnBulkOfRUDP = PackGetBool(p, "enable_hmac_on_bulk_of_rudp");
			sess->BulkOnRUDPVersion = PackGetInt(p, "rudp_bulk_version");

			if (PackGetBool(p, "enable_bulk_on_rudp"))
			{
				// Receive the key
				UCHAR key_send[RUDP_BULK_KEY_SIZE_MAX];
				UCHAR key_recv[RUDP_BULK_KEY_SIZE_MAX];

				UINT key_size = SHA1_SIZE;

				if (sess->BulkOnRUDPVersion == 2)
				{
					key_size = RUDP_BULK_KEY_SIZE_V2;
				}

				if (PackGetData2(p, "bulk_on_rudp_send_key", key_send, key_size) &&
					PackGetData2(p, "bulk_on_rudp_recv_key", key_recv, key_size))
				{
					sess->EnableBulkOnRUDP = true;

					Copy(s->BulkSendKey->Data, key_send, key_size);
					Copy(s->BulkRecvKey->Data, key_recv, key_size);

					s->BulkSendKey->Size = key_size;
					s->BulkRecvKey->Size = key_size;

					// Backup R-UDP bulk send/recv keys for additional connections
					Copy(sess->BulkSendKey, s->BulkSendKey->Data, s->BulkSendKey->Size);
					sess->BulkSendKeySize = s->BulkSendKey->Size;

					Copy(sess->BulkRecvKey, s->BulkRecvKey->Data, s->BulkRecvKey->Size);
					sess->BulkRecvKeySize = s->BulkRecvKey->Size;

					if (false)
					{
						char tmp1[128];
						char tmp2[128];
						BinToStr(tmp1, sizeof(tmp1), sess->BulkRecvKey, sess->BulkSendKeySize);
						BinToStr(tmp2, sizeof(tmp2), sess->BulkSendKey, sess->BulkRecvKeySize);
						Debug("Backup: sess->BulkRecvKeySize = %u, sess->BulkSendKeySize = %u\n",
							sess->BulkRecvKeySize, sess->BulkSendKeySize);
						Debug("Backup:\n%s\n%s\n\n", tmp1, tmp2);
					}			

					AddProtocolDetailsKeyValueInt(sess->ProtocolDetails, sizeof(sess->ProtocolDetails),
						"RUDP_Bulk_Ver",
						sess->BulkOnRUDPVersion);
				}
			}
		}

		Debug("EnableBulkOnRUDP = %u\n", sess->EnableBulkOnRUDP);
		Debug("EnableHMacOnBulkOfRUDP = %u\n", sess->EnableHMacOnBulkOfRUDP);
		Debug("EnableUdpRecovery = %u\n", sess->EnableUdpRecovery);
		Debug("BulkOnRUDPVersion = %u\n", sess->BulkOnRUDPVersion);

		sess->UseUdpAcceleration = false;
		sess->IsUsingUdpAcceleration = false;
		sess->UseHMacOnUdpAcceleration = false;

		if (sess->UdpAccel != NULL)
		{
			sess->UdpAccel->UseHMac = false;

			sess->UdpAccelFastDisconnectDetect = false;

			if (PackGetBool(p, "use_udp_acceleration"))
			{
				UINT udp_acceleration_version = PackGetInt(p, "udp_acceleration_version");
				IP udp_acceleration_server_ip;

				if (udp_acceleration_version == 0)
				{
					udp_acceleration_version = 1;
				}

				sess->UdpAccelFastDisconnectDetect = PackGetBool(p, "udp_accel_fast_disconnect_detect");

				if (PackGetIp(p, "udp_acceleration_server_ip", &udp_acceleration_server_ip))
				{
					UINT udp_acceleration_server_port = PackGetInt(p, "udp_acceleration_server_port");

					if (IsZeroIp(&udp_acceleration_server_ip))
					{
						Copy(&udp_acceleration_server_ip, &s->RemoteIP, sizeof(IP));
					}

					if (udp_acceleration_server_port != 0)
					{
						UCHAR udp_acceleration_server_key[UDP_ACCELERATION_COMMON_KEY_SIZE_V1];
						UCHAR udp_acceleration_server_key_v2[UDP_ACCELERATION_COMMON_KEY_SIZE_V2];
						UINT server_cookie = PackGetInt(p, "udp_acceleration_server_cookie");
						UINT client_cookie = PackGetInt(p, "udp_acceleration_client_cookie");
						bool encryption = PackGetBool(p, "udp_acceleration_use_encryption");

						Zero(udp_acceleration_server_key, sizeof(udp_acceleration_server_key));
						Zero(udp_acceleration_server_key_v2, sizeof(udp_acceleration_server_key_v2));

						PackGetData2(p, "udp_acceleration_server_key", udp_acceleration_server_key, UDP_ACCELERATION_COMMON_KEY_SIZE_V1);
						PackGetData2(p, "udp_acceleration_server_key_v2", udp_acceleration_server_key_v2, UDP_ACCELERATION_COMMON_KEY_SIZE_V2);

						if (server_cookie != 0 && client_cookie != 0)
						{
							IP remote_ip;

							Copy(&remote_ip, &s->RemoteIP, sizeof(IP));

							if (IsZeroIp(&c->Session->AzureRealServerGlobalIp) == false)
							{
								Copy(&remote_ip, &c->Session->AzureRealServerGlobalIp, sizeof(IP));
							}

							sess->UdpAccel->Version = 1;
							if (udp_acceleration_version == 2)
							{
								sess->UdpAccel->Version = 2;
							}

							if (UdpAccelInitClient(sess->UdpAccel,
								sess->UdpAccel->Version == 2 ? udp_acceleration_server_key_v2 : udp_acceleration_server_key,
								&udp_acceleration_server_ip, udp_acceleration_server_port,
								server_cookie, client_cookie, &remote_ip) == false)
							{
								Debug("UdpAccelInitClient failed.\n");
							}
							else
							{
								sess->UseUdpAcceleration = true;

								sess->UdpAccel->FastDetect = sess->UdpAccelFastDisconnectDetect;

								sess->UdpAccel->PlainTextMode = !encryption;

								sess->UseHMacOnUdpAcceleration = PackGetBool(p, "use_hmac_on_udp_acceleration");

								if (sess->UseHMacOnUdpAcceleration)
								{
									sess->UdpAccel->UseHMac = true;
								}

								AddProtocolDetailsKeyValueInt(sess->ProtocolDetails, sizeof(sess->ProtocolDetails),
									"UDPAccel_Ver",
									sess->UdpAccel->Version);

								if (sess->UdpAccel->Version >= 2)
								{
									AddProtocolDetailsStr(sess->ProtocolDetails, sizeof(sess->ProtocolDetails),
										Aead_ChaCha20Poly1305_Ietf_IsOpenSSL() ? 
										"ChachaPoly_OpenSSL" : "ChachaPoly_Self");
								}

								AddProtocolDetailsKeyValueInt(sess->ProtocolDetails, sizeof(sess->ProtocolDetails),
									"UDPAccel_MSS",
									UdpAccelCalcMss(sess->UdpAccel));
							}
						}
					}
				}
			}
		}
	}
	Unlock(c->Session->lock);

	Debug("UseUdpAcceleration = %u\n", sess->UseUdpAcceleration);

	if (sess->UseUdpAcceleration == false)
	{
		if (sess->UdpAccel != NULL)
		{
			FreeUdpAccel(sess->UdpAccel);
			sess->UdpAccel = NULL;
		}
	}

	Lock(c->lock);
	{
		if (c->Name != NULL)
		{
			Free(c->Name);
		}
		c->Name = CopyStr(connection_name);

		// Save the name of a cryptographic algorithm
		if (c->CipherName != NULL)
		{
			Free(c->CipherName);
		}

		c->CipherName = CopyStr(c->FirstSock->CipherName);
	}
	Unlock(c->lock);

	Lock(c->Session->lock);
	{
		if (c->Session->Name != NULL)
		{
			Free(c->Session->Name);
		}
		c->Session->Name = CopyStr(session_name);

		c->Session->Policy = policy;
	}
	Unlock(c->Session->lock);

	// Discard the Welcome packet
	FreePack(p);
	p = NULL;


	// Connection establishment
	c->Session->ClientStatus = CLIENT_STATUS_ESTABLISHED;

	// Save the server certificate
	if (c->ServerX == NULL)
	{
		c->ServerX = CloneX(c->FirstSock->RemoteX);
	}

	PrintStatus(sess, _UU("STATUS_9"));

	// Shift the connection to the tunneling mode
	StartTunnelingMode(c);
	s = NULL;

	if (c->Session->HalfConnection)
	{
		// Processing in the case of half-connection
		TCPSOCK *ts = (TCPSOCK *)LIST_DATA(c->Tcp->TcpSockList, 0);
		ts->Direction = TCP_CLIENT_TO_SERVER;
	}

	if (c->Session->UseFastRC4)
	{
		// Set the high-speed RC4 encryption key
		TCPSOCK *ts = (TCPSOCK *)LIST_DATA(c->Tcp->TcpSockList, 0);
		Copy(&ts->Rc4KeyPair, &key_pair, sizeof(key_pair));

		InitTcpSockRc4Key(ts, false);
	}

	// SSL encryption flag
	if (c->Session->UseEncrypt && c->Session->UseFastRC4 == false)
	{
		c->Session->UseSSLDataEncryption = true;
	}
	else
	{
		c->Session->UseSSLDataEncryption = false;
	}

	PrintStatus(sess, L"free");

	CLog(c->Cedar->Client, "LC_CONNECT_2", c->Session->ClientOption->AccountName,
		session_name);

	if (c->Session->LinkModeClient && c->Session->Link != NULL)
	{
		HLog(c->Session->Link->Hub, "LH_CONNECT_2", c->Session->ClientOption->AccountName, session_name);
	}

	// Main routine of the session
	SessionMain(c->Session);

	ok = true;

	if (c->Err == ERR_USER_CANCEL)
	{
		ret = true;
	}

CLEANUP:
	c->FirstSock = NULL;

	if (sess->UdpAccel != NULL)
	{
		FreeUdpAccel(sess->UdpAccel);
		sess->UdpAccel = NULL;
	}

	if (p != NULL)
	{
		FreePack(p);
	}

	Disconnect(s);
	ReleaseSock(s);

	Debug("Error: %u\n", c->Err);

	if (ok == false)
	{
		PrintStatus(sess, L"free");
	}

	return ret;
}

// Parse the Welcome packet
bool ParseWelcomeFromPack(PACK *p, char *session_name, UINT session_name_size,
						  char *connection_name, UINT connection_name_size,
						  POLICY **policy)
{
	// Validate arguments
	if (p == NULL || session_name == NULL || connection_name == NULL || policy == NULL)
	{
		return false;
	}

	// Session name
	if (PackGetStr(p, "session_name", session_name, session_name_size) == false)
	{
		return false;
	}

	// Connection name
	if (PackGetStr(p, "connection_name", connection_name, connection_name_size) == false)
	{
		return false;
	}

	// Policy
	*policy = PackGetPolicy(p);
	if (*policy == NULL)
	{
		return false;
	}

	return true;
}

// Generate the Welcome packet
PACK *PackWelcome(SESSION *s)
{
	PACK *p;
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}

	p = NewPack();

	// Session name
	PackAddStr(p, "session_name", s->Name);

	// Connection name
	PackAddStr(p, "connection_name", s->Connection->Name);

	// Parameters
	PackAddInt(p, "max_connection", s->MaxConnection);
	PackAddInt(p, "use_encrypt", s->UseEncrypt == false ? 0 : 1);
	PackAddInt(p, "use_fast_rc4", s->UseFastRC4 == false ? 0 : 1);
	PackAddInt(p, "use_compress", s->UseCompress == false ? 0 : 1);
	PackAddInt(p, "half_connection", s->HalfConnection == false ? 0 : 1);
	PackAddInt(p, "timeout", s->Timeout);
	PackAddInt(p, "qos", s->QoS ? 1 : 0);
	PackAddInt(p, "is_azure_session", s->IsAzureSession);

	// Session key
	PackAddData(p, "session_key", s->SessionKey, SHA1_SIZE);
	PackAddInt(p, "session_key_32", s->SessionKey32);

	// Policy
	PackAddPolicy(p, s->Policy);

	// VLAN ID
	PackAddInt(p, "vlan_id", s->VLanId);

	if (s->Connection->Protocol == CONNECTION_UDP)
	{
		// In the case of UDP protocol, generate 2 pairs of key
		Rand(s->UdpSendKey, sizeof(s->UdpSendKey));
		Rand(s->UdpRecvKey, sizeof(s->UdpRecvKey));

		// Send to client by exchanging 2 keys
		PackAddData(p, "udp_send_key", s->UdpRecvKey, sizeof(s->UdpRecvKey));
		PackAddData(p, "udp_recv_key", s->UdpSendKey, sizeof(s->UdpSendKey));
	}

	// no_send_signature
	if (s->NoSendSignature)
	{
		PackAddBool(p, "no_send_signature", true);
	}

	if (s->InProcMode)
	{
		// MAC address for IPC
		PackAddData(p, "IpcMacAddress", s->IpcMacAddress, 6);

		// Virtual HUB name
		PackAddStr(p, "IpcHubName", s->Hub->Name);

		// Shared Buffer
		s->IpcSessionSharedBuffer = NewSharedBuffer(NULL, sizeof(IPC_SESSION_SHARED_BUFFER_DATA));
		AddRef(s->IpcSessionSharedBuffer->Ref);

		s->IpcSessionShared = s->IpcSessionSharedBuffer->Data;

		PackAddInt64(p, "IpcSessionSharedBuffer", (UINT64)s->IpcSessionSharedBuffer);
	}

	if (s->UdpAccel != NULL)
	{
		// UDP acceleration function
		PackAddBool(p, "use_udp_acceleration", true);
		PackAddInt(p, "udp_acceleration_version", s->UdpAccel->Version);
		PackAddIp(p, "udp_acceleration_server_ip", &s->UdpAccel->MyIp);
		PackAddInt(p, "udp_acceleration_server_port", s->UdpAccel->MyPort);
		PackAddData(p, "udp_acceleration_server_key", s->UdpAccel->MyKey, UDP_ACCELERATION_COMMON_KEY_SIZE_V1);
		PackAddData(p, "udp_acceleration_server_key_v2", s->UdpAccel->MyKey_V2, UDP_ACCELERATION_COMMON_KEY_SIZE_V2);
		PackAddInt(p, "udp_acceleration_server_cookie", s->UdpAccel->MyCookie);
		PackAddInt(p, "udp_acceleration_client_cookie", s->UdpAccel->YourCookie);
		PackAddBool(p, "udp_acceleration_use_encryption", !s->UdpAccel->PlainTextMode);
		PackAddBool(p, "use_hmac_on_udp_acceleration", s->UdpAccel->UseHMac);
		PackAddBool(p, "udp_accel_fast_disconnect_detect", s->UdpAccelFastDisconnectDetect);
	}

	if (s->EnableBulkOnRUDP)
	{
		// Allow bulk transfer on R-UDP
		PackAddBool(p, "enable_bulk_on_rudp", true);
		PackAddBool(p, "enable_hmac_on_bulk_of_rudp", s->EnableHMacOnBulkOfRUDP);
		PackAddInt(p, "rudp_bulk_version", s->BulkOnRUDPVersion);

		if (s->BulkOnRUDPVersion == 2)
		{
			PackAddData(p, "bulk_on_rudp_send_key", s->Connection->FirstSock->BulkRecvKey->Data, RUDP_BULK_KEY_SIZE_V2);
			s->Connection->FirstSock->BulkRecvKey->Size = RUDP_BULK_KEY_SIZE_V2;

			PackAddData(p, "bulk_on_rudp_recv_key", s->Connection->FirstSock->BulkSendKey->Data, RUDP_BULK_KEY_SIZE_V2);
			s->Connection->FirstSock->BulkSendKey->Size = RUDP_BULK_KEY_SIZE_V2;
		}
		else
		{
			PackAddData(p, "bulk_on_rudp_send_key", s->Connection->FirstSock->BulkRecvKey->Data, SHA1_SIZE);
			s->Connection->FirstSock->BulkRecvKey->Size = SHA1_SIZE;

			PackAddData(p, "bulk_on_rudp_recv_key", s->Connection->FirstSock->BulkSendKey->Data, SHA1_SIZE);
			s->Connection->FirstSock->BulkSendKey->Size = SHA1_SIZE;
		}

		// Backup R-UDP bulk send/recv keys for additional connections
		Copy(s->BulkSendKey, s->Connection->FirstSock->BulkSendKey->Data,
			s->Connection->FirstSock->BulkSendKey->Size);

		s->BulkSendKeySize = s->Connection->FirstSock->BulkSendKey->Size;

		Copy(s->BulkRecvKey, s->Connection->FirstSock->BulkRecvKey->Data,
			s->Connection->FirstSock->BulkRecvKey->Size);

		s->BulkRecvKeySize = s->Connection->FirstSock->BulkRecvKey->Size;

		if (false)
		{
			char tmp1[128];
			char tmp2[128];
			BinToStr(tmp1, sizeof(tmp1), s->BulkRecvKey, s->BulkSendKeySize);
			BinToStr(tmp2, sizeof(tmp2), s->BulkSendKey, s->BulkRecvKeySize);
			Debug("Backup: s->BulkRecvKeySize = %u, s->BulkSendKeySize = %u\n",
				s->BulkRecvKeySize, s->BulkSendKeySize);
			Debug("Backup:\n%s\n%s\n\n", tmp1, tmp2);
		}			
	}

	if (s->IsAzureSession)
	{
		if (s->Connection != NULL && s->Connection->FirstSock != NULL)
		{
			SOCK *sock = s->Connection->FirstSock;

			PackAddIp(p, "azure_real_server_global_ip", &sock->Reverse_MyServerGlobalIp);
		}
	}

	PackAddBool(p, "enable_udp_recovery", s->EnableUdpRecovery);

	return p;
}

#define	PACK_ADD_POLICY_BOOL(name, value)	\
	PackAddBool(p, "policy:" name, y->value == false ? 0 : 1)
#define	PACK_ADD_POLICY_UINT(name, value)	\
	PackAddInt(p, "policy:" name, y->value)
#define	PACK_GET_POLICY_BOOL(name, value)	\
	y->value = (PackGetBool(p, "policy:" name))
#define	PACK_GET_POLICY_UINT(name, value)	\
	y->value = PackGetInt(p, "policy:" name)

// Get a PACK from the session key
bool GetSessionKeyFromPack(PACK *p, UCHAR *session_key, UINT *session_key_32)
{
	// Validate arguments
	if (p == NULL || session_key == NULL || session_key_32 == NULL)
	{
		return false;
	}

	if (PackGetDataSize(p, "session_key") != SHA1_SIZE)
	{
		return false;
	}
	if (PackGetData(p, "session_key", session_key) == false)
	{
		return false;
	}
	*session_key_32 = PackGetInt(p, "session_key_32");

	return true;
}

// Get the policy from the PACK
POLICY *PackGetPolicy(PACK *p)
{
	POLICY *y;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	y = ZeroMalloc(sizeof(POLICY));

	// Bool value
	// Ver 2
	PACK_GET_POLICY_BOOL("Access", Access);
	PACK_GET_POLICY_BOOL("DHCPFilter", DHCPFilter);
	PACK_GET_POLICY_BOOL("DHCPNoServer", DHCPNoServer);
	PACK_GET_POLICY_BOOL("DHCPForce", DHCPForce);
	PACK_GET_POLICY_BOOL("NoBridge", NoBridge);
	PACK_GET_POLICY_BOOL("NoRouting", NoRouting);
	PACK_GET_POLICY_BOOL("PrivacyFilter", PrivacyFilter);
	PACK_GET_POLICY_BOOL("NoServer", NoServer);
	PACK_GET_POLICY_BOOL("CheckMac", CheckMac);
	PACK_GET_POLICY_BOOL("CheckIP", CheckIP);
	PACK_GET_POLICY_BOOL("ArpDhcpOnly", ArpDhcpOnly);
	PACK_GET_POLICY_BOOL("MonitorPort", MonitorPort);
	PACK_GET_POLICY_BOOL("NoBroadcastLimiter", NoBroadcastLimiter);
	PACK_GET_POLICY_BOOL("FixPassword", FixPassword);
	PACK_GET_POLICY_BOOL("NoQoS", NoQoS);
	// Ver 3
	PACK_GET_POLICY_BOOL("RSandRAFilter", RSandRAFilter);
	PACK_GET_POLICY_BOOL("RAFilter", RAFilter);
	PACK_GET_POLICY_BOOL("DHCPv6Filter", DHCPv6Filter);
	PACK_GET_POLICY_BOOL("DHCPv6NoServer", DHCPv6NoServer);
	PACK_GET_POLICY_BOOL("NoRoutingV6", NoRoutingV6);
	PACK_GET_POLICY_BOOL("CheckIPv6", CheckIPv6);
	PACK_GET_POLICY_BOOL("NoServerV6", NoServerV6);
	PACK_GET_POLICY_BOOL("NoSavePassword", NoSavePassword);
	PACK_GET_POLICY_BOOL("FilterIPv4", FilterIPv4);
	PACK_GET_POLICY_BOOL("FilterIPv6", FilterIPv6);
	PACK_GET_POLICY_BOOL("FilterNonIP", FilterNonIP);
	PACK_GET_POLICY_BOOL("NoIPv6DefaultRouterInRA", NoIPv6DefaultRouterInRA);
	PACK_GET_POLICY_BOOL("NoIPv6DefaultRouterInRAWhenIPv6", NoIPv6DefaultRouterInRAWhenIPv6);

	// UINT value
	// Ver 2
	PACK_GET_POLICY_UINT("MaxConnection", MaxConnection);
	PACK_GET_POLICY_UINT("TimeOut", TimeOut);
	PACK_GET_POLICY_UINT("MaxMac", MaxMac);
	PACK_GET_POLICY_UINT("MaxIP", MaxIP);
	PACK_GET_POLICY_UINT("MaxUpload", MaxUpload);
	PACK_GET_POLICY_UINT("MaxDownload", MaxDownload);
	PACK_GET_POLICY_UINT("MultiLogins", MultiLogins);
	// Ver 3
	PACK_GET_POLICY_UINT("MaxIPv6", MaxIPv6);
	PACK_GET_POLICY_UINT("AutoDisconnect", AutoDisconnect);
	PACK_GET_POLICY_UINT("VLanId", VLanId);

	// Ver 3 flag
	PACK_GET_POLICY_BOOL("Ver3", Ver3);

	return y;
}

// Insert the policy into the PACK
void PackAddPolicy(PACK *p, POLICY *y)
{
	// Validate arguments
	if (p == NULL || y == NULL)
	{
		return;
	}

	// Bool value
	// Ver 2
	PACK_ADD_POLICY_BOOL("Access", Access);
	PACK_ADD_POLICY_BOOL("DHCPFilter", DHCPFilter);
	PACK_ADD_POLICY_BOOL("DHCPNoServer", DHCPNoServer);
	PACK_ADD_POLICY_BOOL("DHCPForce", DHCPForce);
	PACK_ADD_POLICY_BOOL("NoBridge", NoBridge);
	PACK_ADD_POLICY_BOOL("NoRouting", NoRouting);
	PACK_ADD_POLICY_BOOL("PrivacyFilter", PrivacyFilter);
	PACK_ADD_POLICY_BOOL("NoServer", NoServer);
	PACK_ADD_POLICY_BOOL("CheckMac", CheckMac);
	PACK_ADD_POLICY_BOOL("CheckIP", CheckIP);
	PACK_ADD_POLICY_BOOL("ArpDhcpOnly", ArpDhcpOnly);
	PACK_ADD_POLICY_BOOL("MonitorPort", MonitorPort);
	PACK_ADD_POLICY_BOOL("NoBroadcastLimiter", NoBroadcastLimiter);
	PACK_ADD_POLICY_BOOL("FixPassword", FixPassword);
	PACK_ADD_POLICY_BOOL("NoQoS", NoQoS);
	// Ver 3
	PACK_ADD_POLICY_BOOL("RSandRAFilter", RSandRAFilter);
	PACK_ADD_POLICY_BOOL("RAFilter", RAFilter);
	PACK_ADD_POLICY_BOOL("DHCPv6Filter", DHCPv6Filter);
	PACK_ADD_POLICY_BOOL("DHCPv6NoServer", DHCPv6NoServer);
	PACK_ADD_POLICY_BOOL("NoRoutingV6", NoRoutingV6);
	PACK_ADD_POLICY_BOOL("CheckIPv6", CheckIPv6);
	PACK_ADD_POLICY_BOOL("NoServerV6", NoServerV6);
	PACK_ADD_POLICY_BOOL("NoSavePassword", NoSavePassword);
	PACK_ADD_POLICY_BOOL("FilterIPv4", FilterIPv4);
	PACK_ADD_POLICY_BOOL("FilterIPv6", FilterIPv6);
	PACK_ADD_POLICY_BOOL("FilterNonIP", FilterNonIP);
	PACK_ADD_POLICY_BOOL("NoIPv6DefaultRouterInRA", NoIPv6DefaultRouterInRA);
	PACK_ADD_POLICY_BOOL("NoIPv6DefaultRouterInRAWhenIPv6", NoIPv6DefaultRouterInRAWhenIPv6);

	// UINT value
	// Ver 2
	PACK_ADD_POLICY_UINT("MaxConnection", MaxConnection);
	PACK_ADD_POLICY_UINT("TimeOut", TimeOut);
	PACK_ADD_POLICY_UINT("MaxMac", MaxMac);
	PACK_ADD_POLICY_UINT("MaxIP", MaxIP);
	PACK_ADD_POLICY_UINT("MaxUpload", MaxUpload);
	PACK_ADD_POLICY_UINT("MaxDownload", MaxDownload);
	PACK_ADD_POLICY_UINT("MultiLogins", MultiLogins);
	// Ver 3
	PACK_ADD_POLICY_UINT("MaxIPv6", MaxIPv6);
	PACK_ADD_POLICY_UINT("AutoDisconnect", AutoDisconnect);
	PACK_ADD_POLICY_UINT("VLanId", VLanId);

	// Ver 3 flag
	PackAddBool(p, "policy:Ver3", true);
}

// Upload the authentication data for the additional connection
bool ClientUploadAuth2(CONNECTION *c, SOCK *s)
{
	PACK *p = NULL;
	// Validate arguments
	if (c == NULL)
	{
		return false;
	}

	p = PackAdditionalConnect(c->Session->SessionKey);

	PackAddClientVersion(p, c);

	if (HttpClientSend(s, p) == false)
	{
		FreePack(p);
		return false;
	}
	FreePack(p);

	return true;
}

// Send a NOOP
void ClientUploadNoop(CONNECTION *c)
{
	PACK *p;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	p = PackError(0);
	PackAddInt(p, "noop", 1);
	HttpClientSend(c->FirstSock, p);
	FreePack(p);

	p = HttpClientRecv(c->FirstSock);
	if (p != NULL)
	{
		FreePack(p);
	}
}

// Add client version information to the PACK
void PackAddClientVersion(PACK *p, CONNECTION *c)
{
	// Validate arguments
	if (p == NULL || c == NULL)
	{
		return;
	}

	PackAddStr(p, "client_str", c->ClientStr);
	PackAddInt(p, "client_ver", c->ClientVer);
	PackAddInt(p, "client_build", c->ClientBuild);
}

// Upload the certificate data for the new connection
bool ClientUploadAuth(CONNECTION *c)
{
	PACK *p = NULL;
	CLIENT_AUTH *a;
	CLIENT_OPTION *o;
	X *x;
	bool ret;
	NODE_INFO info;
	UCHAR secure_password[SHA1_SIZE];
	UCHAR sign[4096 / 8];
	UCHAR unique[SHA1_SIZE];
	RPC_WINVER v;
	// Validate arguments
	if (c == NULL)
	{
		return false;
	}

	Zero(sign, sizeof(sign));

	a = c->Session->ClientAuth;
	o = c->Session->ClientOption;

	if (c->UseTicket == false)
	{
		switch (a->AuthType)
		{
		case CLIENT_AUTHTYPE_ANONYMOUS:
			// Anonymous authentication
			p = PackLoginWithAnonymous(o->HubName, a->Username);
			break;

		case CLIENT_AUTHTYPE_PASSWORD:
			// Password authentication
			SecurePassword(secure_password, a->HashedPassword, c->Random);
			p = PackLoginWithPassword(o->HubName, a->Username, secure_password);
			break;

		case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
			// Plaintext password authentication
			p = PackLoginWithPlainPassword(o->HubName, a->Username, a->PlainPassword);
			break;

		case CLIENT_AUTHTYPE_CERT:
			// Certificate authentication
			if (a->ClientX != NULL && a->ClientX->is_compatible_bit &&
				a->ClientX->bits != 0 && (a->ClientX->bits / 8) <= sizeof(sign))
			{
				if (RsaSignEx(sign, c->Random, SHA1_SIZE, a->ClientK, a->ClientX->bits))
				{
					p = PackLoginWithCert(o->HubName, a->Username, a->ClientX, sign, a->ClientX->bits / 8);
					c->ClientX = CloneX(a->ClientX);
				}
			}
			break;

		case CLIENT_AUTHTYPE_SECURE:
			// Authentication by secure device
			if (ClientSecureSign(c, sign, c->Random, &x))
			{
				p = PackLoginWithCert(o->HubName, a->Username, x, sign, x->bits / 8);
				c->ClientX = CloneX(x);
				FreeX(x);
			}
			else
			{
				c->Err = ERR_SECURE_DEVICE_OPEN_FAILED;
				c->Session->ForceStopFlag = true;
			}
			break;
		}
	}
	else
	{
		// Ticket
		p = NewPack();
		PackAddStr(p, "method", "login");
		PackAddStr(p, "hubname", o->HubName);
		PackAddStr(p, "username", a->Username);
		PackAddInt(p, "authtype", AUTHTYPE_TICKET);
		PackAddData(p, "ticket", c->Ticket, SHA1_SIZE);
	}

	if (p == NULL)
	{
		// Error
		if (c->Err != ERR_SECURE_DEVICE_OPEN_FAILED)
		{
			c->Err = ERR_PROTOCOL_ERROR;
		}
		return false;
	}

	PackAddClientVersion(p, c);

	// Protocol
	PackAddInt(p, "protocol", c->Protocol);

	// Version, etc.
	PackAddStr(p, "hello", c->ClientStr);
	PackAddInt(p, "version", c->ClientVer);
	PackAddInt(p, "build", c->ClientBuild);
	PackAddInt(p, "client_id", c->Cedar->ClientId);

	// The maximum number of connections
	PackAddInt(p, "max_connection", o->MaxConnection);
	// Flag to use of cryptography
	PackAddInt(p, "use_encrypt", o->UseEncrypt == false ? 0 : 1);
	// Fast encryption using flag
	//	PackAddInt(p, "use_fast_rc4", o->UseFastRC4 == false ? 0 : 1);
	// Data compression flag
	PackAddInt(p, "use_compress", o->UseCompress == false ? 0 : 1);
	// Half connection flag
	PackAddInt(p, "half_connection", o->HalfConnection == false ? 0 : 1);

	// Bridge / routing mode flag
	PackAddBool(p, "require_bridge_routing_mode", o->RequireBridgeRoutingMode);

	// Monitor mode flag
	PackAddBool(p, "require_monitor_mode", o->RequireMonitorMode);

	// VoIP / QoS flag
	PackAddBool(p, "qos", o->DisableQoS ? false : true);

	// Bulk transfer support
	PackAddBool(p, "support_bulk_on_rudp", true);
	PackAddBool(p, "support_hmac_on_bulk_of_rudp", true);

	// UDP recovery support
	PackAddBool(p, "support_udp_recovery", true);

	// Unique ID
	GenerateMachineUniqueHash(unique);
	PackAddData(p, "unique_id", unique, SHA1_SIZE);

	// UDP acceleration function using flag
	if (o->NoUdpAcceleration == false && c->Session->UdpAccel != NULL)
	{
		IP my_ip;

		Zero(&my_ip, sizeof(my_ip));

		PackAddBool(p, "use_udp_acceleration", true);

		PackAddInt(p, "udp_acceleration_version", c->Session->UdpAccel->Version);

		Copy(&my_ip, &c->Session->UdpAccel->MyIp, sizeof(IP));
		if (IsLocalHostIP(&my_ip))
		{
			if (IsIP4(&my_ip))
			{
				ZeroIP4(&my_ip);
			}
			else
			{
				ZeroIP6(&my_ip);
			}
		}

		PackAddIp(p, "udp_acceleration_client_ip", &my_ip);
		PackAddInt(p, "udp_acceleration_client_port", c->Session->UdpAccel->MyPort);
		PackAddData(p, "udp_acceleration_client_key", c->Session->UdpAccel->MyKey, UDP_ACCELERATION_COMMON_KEY_SIZE_V1);
		PackAddData(p, "udp_acceleration_client_key_v2", c->Session->UdpAccel->MyKey_V2, UDP_ACCELERATION_COMMON_KEY_SIZE_V2);
		PackAddBool(p, "support_hmac_on_udp_acceleration", true);
		PackAddBool(p, "support_udp_accel_fast_disconnect_detect", true);
		PackAddInt(p, "udp_acceleration_max_version", 2);
	}

	PackAddInt(p, "rudp_bulk_max_version", 2);

	// Brand string for the connection limit
	{
		char *branded_ctos = _SS("BRANDED_C_TO_S");
		if(StrLen(branded_ctos) > 0)
		{
			PackAddStr(p, "branded_ctos", branded_ctos);
		}
	}

	// Node information
	CreateNodeInfo(&info, c);
	OutRpcNodeInfo(p, &info);

	// OS information
	GetWinVer(&v);
	OutRpcWinVer(p, &v);

	ret = HttpClientSend(c->FirstSock, p);
	if (ret == false)
	{
		c->Err = ERR_DISCONNECTED;
	}

	FreePack(p);

	return ret;
}

// Upload the Hello packet
bool ServerUploadHello(CONNECTION *c)
{
	PACK *p;
	// Validate arguments
	if (c == NULL)
	{
		return false;
	}

	// Random number generation
	Rand(c->Random, SHA1_SIZE);

	p = PackHello(c->Random, c->ServerVer, c->ServerBuild, c->ServerStr);
	if (HttpServerSend(c->FirstSock, p) == false)
	{
		FreePack(p);
		c->Err = ERR_DISCONNECTED;
		return false;
	}

	FreePack(p);

	return true;
}

// Download the Hello packet
bool ClientDownloadHello(CONNECTION *c, SOCK *s)
{
	PACK *p;
	UINT err;
	UCHAR random[SHA1_SIZE];
	// Validate arguments
	if (c == NULL)
	{
		return false;
	}

	// Data reception
	p = HttpClientRecv(s);
	if (p == NULL)
	{
		c->Err = ERR_SERVER_IS_NOT_VPN;
		return false;
	}

	if (err = GetErrorFromPack(p))
	{
		// An error has occured
		c->Err = err;
		FreePack(p);
		return false;
	}

	// Packet interpretation
	if (GetHello(p, random, &c->ServerVer, &c->ServerBuild, c->ServerStr, sizeof(c->ServerStr)) == false)
	{
		c->Err = ERR_SERVER_IS_NOT_VPN;
		FreePack(p);
		return false;
	}

	if (c->FirstSock == s)
	{
		Copy(c->Random, random, SHA1_SIZE);
	}

	FreePack(p);

	return true;
}

// Download the signature
bool ServerDownloadSignature(CONNECTION *c, char **error_detail_str)
{
	HTTP_HEADER *h;
	UCHAR *data;
	UINT data_size;
	SOCK *s;
	UINT num = 0, max = 19;
	SERVER *server;
	char *vpn_http_target = HTTP_VPN_TARGET2;
	bool check_hostname = false;
	bool disable_json_api = false;
	// Validate arguments
	if (c == NULL)
	{
		return false;
	}

	server = c->Cedar->Server;

	disable_json_api = server->DisableJsonRpcWebApi;





	s = c->FirstSock;

	while (true)
	{
		bool not_found_error = false;

		num++;
		if (num > max)
		{
			// Disconnect
			Disconnect(s);
			c->Err = ERR_CLIENT_IS_NOT_VPN;

			*error_detail_str = "HTTP_TOO_MANY_REQUEST";
			return false;
		}
		// Receive a header
		h = RecvHttpHeader(s);
		if (h == NULL)
		{
			c->Err = ERR_CLIENT_IS_NOT_VPN;
			if (c->IsJsonRpc)
			{
				c->Err = ERR_DISCONNECTED;
			}
			return false;
		}

		if (check_hostname && (StrCmpi(h->Version, "HTTP/1.1") == 0 || StrCmpi(h->Version, "HTTP/1.2") == 0))
		{
			HTTP_VALUE *v;
			char hostname[64];

			Zero(hostname, sizeof(hostname));

			v = GetHttpValue(h, "Host");
			if (v != NULL)
			{
				StrCpy(hostname, sizeof(hostname), v->Data);
			}

			if (IsEmptyStr(hostname))
			{
				// Invalid hostname
				HttpSendInvalidHostname(s, h->Target);
				FreeHttpHeader(h);
				c->Err = ERR_CLIENT_IS_NOT_VPN;
				*error_detail_str = "Invalid_hostname";
				return false;
			}
		}




		// Interpret
		if (StrCmpi(h->Method, "POST") == 0)
		{
			// Receive the data since it's POST
			data_size = GetContentLength(h);

			if (disable_json_api == false)
			{
				if (StrCmpi(h->Target, "/api") == 0 || StrCmpi(h->Target, "/api/") == 0)
				{
					c->IsJsonRpc = true;
					c->Type = CONNECTION_TYPE_ADMIN_RPC;

					JsonRpcProcPost(c, s, h, data_size);

					FreeHttpHeader(h);

					if (c->JsonRpcAuthed)
					{
						num = 0;
					}

					continue;
				}
				else if (StartWith(h->Target, "/admin"))
				{
					c->IsJsonRpc = true;
					c->Type = CONNECTION_TYPE_ADMIN_RPC;

					AdminWebProcPost(c, s, h, data_size, h->Target);

					FreeHttpHeader(h);

					if (c->JsonRpcAuthed)
					{
						num = 0;
					}

					continue;
				}
			}

			if ((data_size > MAX_WATERMARK_SIZE || data_size < SizeOfWaterMark()) && (data_size != StrLen(HTTP_VPN_TARGET_POSTDATA)))
			{
				// Data is too large
				HttpSendForbidden(s, h->Target, NULL);
				FreeHttpHeader(h);
				c->Err = ERR_CLIENT_IS_NOT_VPN;
				*error_detail_str = "POST_Recv_TooLong";
				return false;
			}
			data = Malloc(data_size);
			if (RecvAll(s, data, data_size, s->SecureMode) == false)
			{
				// Data reception failure
				Free(data);
				FreeHttpHeader(h);
				c->Err = ERR_DISCONNECTED;
				*error_detail_str = "POST_Recv_Failed";
				return false;
			}
			// Check the Target
			if ((StrCmpi(h->Target, vpn_http_target) != 0) || not_found_error)
			{
				// Target is invalid
				HttpSendNotFound(s, h->Target);
				Free(data);
				FreeHttpHeader(h);
				*error_detail_str = "POST_Target_Wrong";
			}
			else
			{
				// Compare posted data with the WaterMark
				if ((data_size == StrLen(HTTP_VPN_TARGET_POSTDATA) && (Cmp(data, HTTP_VPN_TARGET_POSTDATA, data_size) == 0))
					|| ((data_size >= SizeOfWaterMark()) && Cmp(data, WaterMark, SizeOfWaterMark()) == 0))
				{
					// Check the WaterMark
					Free(data);
					FreeHttpHeader(h);
					return true;
				}
				else
				{
					// WaterMark is incorrect
					HttpSendForbidden(s, h->Target, NULL);
					FreeHttpHeader(h);
					*error_detail_str = "POST_WaterMark_Error";
				}
			}
		}
		else if (StrCmpi(h->Method, "OPTIONS") == 0)
		{
			if (disable_json_api == false)
			{
				if (StrCmpi(h->Target, "/api") == 0 || StrCmpi(h->Target, "/api/") == 0 || StartWith(h->Target, "/admin"))
				{
					c->IsJsonRpc = true;
					c->Type = CONNECTION_TYPE_ADMIN_RPC;

					JsonRpcProcOptions(c, s, h, h->Target);

					FreeHttpHeader(h);

					num = 0;

					continue;
				}
			}
		}
		else if (StrCmpi(h->Method, "SSTP_DUPLEX_POST") == 0 && (server->DisableSSTPServer == false || s->IsReverseAcceptedSocket
			) &&
			GetServerCapsBool(server, "b_support_sstp") && GetNoSstp() == false)
		{
			// SSTP client is connected
			c->WasSstp = true;

			if (StrCmpi(h->Target, SSTP_URI) == 0)
			{
				bool sstp_ret;
				// Accept the SSTP connection
				c->Type = CONNECTION_TYPE_SSTP;

				sstp_ret = AcceptSstp(c);

				c->Err = ERR_DISCONNECTED;
				FreeHttpHeader(h);

				if (sstp_ret)
				{
					*error_detail_str = "";
				}
				else
				{
					*error_detail_str = "SSTP_ABORT";
				}

				return false;
			}
			else
			{
				// URI is invalid
				HttpSendNotFound(s, h->Target);
				*error_detail_str = "SSTP_URL_WRONG";
			}

			FreeHttpHeader(h);
		}
		else
		{
			// This should not be a VPN client, but interpret a bit more
			if (StrCmpi(h->Method, "GET") != 0 && StrCmpi(h->Method, "HEAD") != 0
				 && StrCmpi(h->Method, "POST") != 0)
			{
				// Unsupported method calls
				HttpSendNotImplemented(s, h->Method, h->Target, h->Version);
				*error_detail_str = "HTTP_BAD_METHOD";
			}
			else
			{

				if (StrCmpi(h->Target, "/") == 0)
				{
					// Root directory
					SERVER *s = c->Cedar->Server;

					*error_detail_str = "HTTP_ROOT";

					{
						BUF *b = NULL;
						
						if (disable_json_api == false)
						{
							b = ReadDump("|wwwroot\\index.html");
						}

						if (b != NULL)
						{
							FreeHttpHeader(h);
							h = NewHttpHeader("HTTP/1.1", "202", "OK");
							AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE4));
							AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
							AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));

							PostHttp(c->FirstSock, h, b->Buf, b->Size);

							FreeBuf(b);
						}
						else
						{
							HttpSendForbidden(c->FirstSock, h->Target, "");
						}
					}
				}
				else
				{
					bool b = false;

					// Show the WebUI if the configuration allow to use the WebUI
					if (c->Cedar->Server != NULL && c->Cedar->Server->UseWebUI)
					{
						WU_WEBPAGE *page;

						// Show the WebUI
						page = WuGetPage(h->Target, c->Cedar->WebUI);

						if (page != NULL)
						{
							PostHttp(s, page->header, page->data, page->size);
							b = true;
							WuFreeWebPage(page);
						}

					}

					if (c->FirstSock->RemoteIP.addr[0] == 127)
					{
						if (StrCmpi(h->Target, HTTP_SAITAMA) == 0)
						{
							// Saitama (joke)
							FreeHttpHeader(h);
							h = NewHttpHeader("HTTP/1.1", "202", "OK");
							AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE3));
							AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
							AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
							PostHttp(s, h, Saitama, SizeOfSaitama());
							b = true;
						}
						else if (StartWith(h->Target, HTTP_PICTURES))
						{
							BUF *buf;

							// Lots of photos
							buf = ReadDump("|Pictures.mht");

							if (buf != NULL)
							{
								FreeHttpHeader(h);
								h = NewHttpHeader("HTTP/1.1", "202", "OK");
								AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE5));
								AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
								AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
								PostHttp(s, h, buf->Buf, buf->Size);
								b = true;

								FreeBuf(buf);
							}
						}
					}

					if (b == false)
					{
						if (disable_json_api == false)
						{
							if (StartWith(h->Target, "/api?") || StartWith(h->Target, "/api/") || StrCmpi(h->Target, "/api") == 0)
							{
								c->IsJsonRpc = true;
								c->Type = CONNECTION_TYPE_ADMIN_RPC;

								JsonRpcProcGet(c, s, h, h->Target);

								if (c->JsonRpcAuthed)
								{
									num = 0;
								}

								FreeHttpHeader(h);

								continue;
							}
							else if (StartWith(h->Target, "/admin"))
							{
								c->IsJsonRpc = true;
								c->Type = CONNECTION_TYPE_ADMIN_RPC;

								AdminWebProcGet(c, s, h, h->Target);

								if (c->JsonRpcAuthed)
								{
									num = 0;
								}

								FreeHttpHeader(h);

								continue;
							}
						}

						if (false) // TODO
						{
							if (StrCmpi(h->Target, "/mvpn") == 0 || StrCmpi(h->Target, "/mvpn/") == 0)
							{
								MvpnProcGet(c, s, h, h->Target);

								FreeHttpHeader(h);
								continue;
							}
						}
					}

					if (b == false)
					{
						// Not Found
						HttpSendNotFound(s, h->Target);

						*error_detail_str = "HTTP_NOT_FOUND";
					}
				}
			}
			FreeHttpHeader(h);
		}
	}
}

// Upload a signature
bool ClientUploadSignature(SOCK *s)
{
	HTTP_HEADER *h;
	UINT water_size, rand_size;
	UCHAR *water;
	char ip_str[128];
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	IPToStr(ip_str, sizeof(ip_str), &s->RemoteIP);

	h = NewHttpHeader("POST", HTTP_VPN_TARGET2, "HTTP/1.1");
	AddHttpValue(h, NewHttpValue("Host", ip_str));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE3));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));



	// Generate a watermark
	rand_size = Rand32() % (HTTP_PACK_RAND_SIZE_MAX * 2);
	water_size = SizeOfWaterMark() + rand_size;
	water = Malloc(water_size);
	Copy(water, WaterMark, SizeOfWaterMark());
	Rand(&water[SizeOfWaterMark()], rand_size);

	// Upload the watermark data
	if (PostHttp(s, h, water, water_size) == false)
	{
		Free(water);
		FreeHttpHeader(h);
		return false;
	}

	Free(water);
	FreeHttpHeader(h);

	return true;
}

// Establish a connection to the server
SOCK *ClientConnectToServer(CONNECTION *c)
{
	SOCK *s = NULL;
	X *x = NULL;
	K *k = NULL;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		return NULL;
	}

	// Get the socket by connecting
	s = ClientConnectGetSocket(c, false, (c->DontUseTls1 ? false : true));
	if (s == NULL)
	{
		// Connection failure
		return NULL;
	}

	c->FirstSock = s;

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		ReleaseSock(s);
		c->FirstSock = NULL;
		return NULL;
	}

	// Time-out
	SetTimeout(s, CONNECTING_TIMEOUT);

	// Start the SSL communication
	if (StartSSLEx(s, x, k, (c->DontUseTls1 ? false : true), 0, c->ServerName) == false)
	{
		// SSL communication start failure
		Disconnect(s);
		ReleaseSock(s);
		c->FirstSock = NULL;
		c->Err = ERR_SERVER_IS_NOT_VPN;
		return NULL;
	}

	if (s->RemoteX == NULL)
	{
		// SSL communication start failure
		Disconnect(s);
		ReleaseSock(s);
		c->FirstSock = NULL;
		c->Err = ERR_SERVER_IS_NOT_VPN;
		return NULL;
	}

	return s;
}

// Return a socket by connecting to the server
SOCK *ClientConnectGetSocket(CONNECTION *c, bool additional_connect, bool no_tls)
{
	SOCK *s = NULL;
	CLIENT_OPTION *o;
	char *host_for_direct_connection;
	UINT port_for_direct_connection;
	wchar_t tmp[MAX_SIZE];
	SESSION *sess;
	volatile bool *cancel_flag = NULL;
	void *hWnd;
	UINT nat_t_err = 0;
	bool is_additonal_rudp_session = false;
	UCHAR uc = 0;
	IP ret_ip;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	Zero(&ret_ip, sizeof(IP));

	sess = c->Session;

	if (sess != NULL)
	{
		cancel_flag = &sess->CancelConnect;
		is_additonal_rudp_session = sess->IsRUDPSession;
	}

	hWnd = c->hWndForUI;

	o = c->Session->ClientOption;

	if (additional_connect)
	{
		if (sess != NULL)
		{
			Copy(&ret_ip, &sess->ServerIP_CacheForNextConnect, sizeof(IP));
		}
	}

	if (c->RestoreServerNameAndPort && additional_connect)
	{
		// Restore to the original server name and port number
		c->RestoreServerNameAndPort = false;

		if (StrCmpi(c->ServerName, o->Hostname) != 0)
		{
			StrCpy(c->ServerName, sizeof(c->ServerName), o->Hostname);
			Zero(&ret_ip, sizeof(IP));
		}

		c->ServerPort = o->Port;
	}

	host_for_direct_connection = c->ServerName;
	port_for_direct_connection = c->ServerPort;

	switch (o->ProxyType)
	{
	case PROXY_DIRECT:	// TCP/IP
		UniFormat(tmp, sizeof(tmp), _UU("STATUS_4"), c->ServerName);
		PrintStatus(sess, tmp);
		// Production job
		if (o->PortUDP == 0)
		{
			{
				// If additional_connect == false, enable trying to NAT-T connection
				// If additional_connect == true, follow the IsRUDPSession setting in this session
				s = TcpIpConnectEx(host_for_direct_connection, port_for_direct_connection,
					(bool *)cancel_flag, hWnd, &nat_t_err, (additional_connect ? (!is_additonal_rudp_session) : false),
					true, no_tls, &ret_ip);
			}
		}
		else
		{
			// Mode to connect with R-UDP directly without using NAT-T server when using UDP
			IP ip;

			Zero(&ip, sizeof(ip));

			StrToIP(&ip, o->Hostname);


			s = NewRUDPClientDirect(VPN_RUDP_SVC_NAME, &ip, o->PortUDP, &nat_t_err,
				TIMEOUT_TCP_PORT_CHECK, (bool *)cancel_flag, NULL, NULL, 0, false);

			if (s != NULL)
			{
				StrCpy(s->UnderlayProtocol, sizeof(s->UnderlayProtocol), SOCK_UNDERLAY_NAT_T);
				AddProtocolDetailsStr(s->UnderlayProtocol, sizeof(s->UnderlayProtocol), "NAT-T");
			}
		}
		if (s == NULL)
		{
			// Connection failure
			if (nat_t_err != RUDP_ERROR_NAT_T_TWO_OR_MORE)
			{
				c->Err = ERR_CONNECT_FAILED;
			}
			else
			{
				c->Err = ERR_NAT_T_TWO_OR_MORE;
			}
			return NULL;
		}
		break;

	case PROXY_HTTP:	// HTTP Proxy
		host_for_direct_connection = o->ProxyName;
		port_for_direct_connection = o->ProxyPort;

		UniFormat(tmp, sizeof(tmp), _UU("STATUS_2"), c->ServerName, o->ProxyName);
		PrintStatus(sess, tmp);


		// Proxy connection
		s = ProxyConnectEx(c, host_for_direct_connection, port_for_direct_connection,
			c->ServerName, c->ServerPort, o->ProxyUsername, o->ProxyPassword,
			additional_connect, (bool *)cancel_flag, hWnd);
		if (s == NULL)
		{
			// Connection failure
			return NULL;
		}
		break;

	case PROXY_SOCKS:	// SOCKS Proxy
		host_for_direct_connection = o->ProxyName;

		port_for_direct_connection = o->ProxyPort;

		UniFormat(tmp, sizeof(tmp), _UU("STATUS_2"), c->ServerName, o->ProxyName);
		PrintStatus(sess, tmp);


		// SOCKS connection
		s = SocksConnectEx2(c, host_for_direct_connection, port_for_direct_connection,
			c->ServerName, c->ServerPort, o->ProxyUsername,
			additional_connect, (bool *)cancel_flag, hWnd, 0, &ret_ip);
		if (s == NULL)
		{
			// Connection failure
			return NULL;
		}
		break;
	}

	if (s == NULL)
	{
		// Connection failure
		c->Err = ERR_CONNECT_FAILED;
	}
	else
	{
		// Success to connect
		// Keep a note of the IP address
		if (additional_connect == false || IsZeroIP(&s->RemoteIP))
		{
			if (((s->IsRUDPSocket || s->IPv6) && IsZeroIP(&s->RemoteIP) == false && o->ProxyType == PROXY_DIRECT) || GetIP(&c->Session->ServerIP, host_for_direct_connection) == false)
			{
				Copy(&c->Session->ServerIP, &s->RemoteIP, sizeof(IP));
			}
		}

		if (IsZeroIP(&ret_ip) == false)
		{
			if (c->Session != NULL)
			{
				if (additional_connect == false)
				{
					Copy(&c->Session->ServerIP_CacheForNextConnect, &ret_ip, sizeof(IP));

					Debug("Saved ServerIP_CacheForNextConnect: %s = %r\n", c->ServerName, &ret_ip);
				}
			}
		}
	}

	return s;
}

// Connect via SOCKS
SOCK *SocksConnect(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
				   char *server_host_name, UINT server_port,
				   char *username, bool additional_connect)
{
	return SocksConnectEx(c, proxy_host_name, proxy_port,
		server_host_name, server_port, username, additional_connect, NULL, NULL);
}
SOCK *SocksConnectEx(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
				   char *server_host_name, UINT server_port,
				   char *username, bool additional_connect,
				   bool *cancel_flag, void *hWnd)
{
	return SocksConnectEx2(c, proxy_host_name, proxy_port,
		server_host_name, server_port, username, additional_connect, cancel_flag,
		hWnd, 0, NULL);
}
SOCK *SocksConnectEx2(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
				   char *server_host_name, UINT server_port,
				   char *username, bool additional_connect,
				   bool *cancel_flag, void *hWnd, UINT timeout, IP *ret_ip)
{
	SOCK *s = NULL;
	IP ip;
	// Validate arguments
	if (c == NULL || proxy_host_name == NULL || proxy_port == 0 || server_host_name == NULL
		|| server_port == 0)
	{
		if (c != NULL)
		{
			c->Err = ERR_PROXY_CONNECT_FAILED;
		}
		return NULL;
	}

	// Get the IP address of the destination server
	if (GetIP(&ip, server_host_name) == false)
	{
		// Failure
		c->Err = ERR_CONNECT_FAILED;
		return NULL;
	}

	if (c->Halt)
	{
		// Stop
		c->Err = ERR_USER_CANCEL;
		return NULL;
	}

	// Connection
	s = TcpConnectEx3(proxy_host_name, proxy_port, timeout, cancel_flag, hWnd, true, NULL, false, false, ret_ip);
	if (s == NULL)
	{
		// Failure
		c->Err = ERR_PROXY_CONNECT_FAILED;
		return NULL;
	}

	// Timeout setting
	SetTimeout(s, MIN(CONNECTING_TIMEOUT_PROXY, (timeout == 0 ? INFINITE : timeout)));

	if (additional_connect == false)
	{
		c->FirstSock = s;
	}

	// Request packet transmission
	if (SocksSendRequestPacket(c, s, server_port, &ip, username) == false)
	{
		// Failure
		if (additional_connect == false)
		{
			c->FirstSock = NULL;
		}
		Disconnect(s);
		ReleaseSock(s);
		return NULL;
	}

	// Receive a response packet
	if (SocksRecvResponsePacket(c, s) == false)
	{
		// Failure
		if (additional_connect == false)
		{
			c->FirstSock = NULL;
		}
		Disconnect(s);
		ReleaseSock(s);
		return NULL;
	}

	SetTimeout(s, INFINITE);

	return s;
}

// Receive a SOCKS response packet
bool SocksRecvResponsePacket(CONNECTION *c, SOCK *s)
{
	BUF *b;
	UINT size = 8;
	UCHAR tmp[8];
	UCHAR vn, cd;
	// Validate arguments
	if (c == NULL || s == NULL)
	{
		return false;
	}

	if (RecvAll(s, tmp, sizeof(tmp), false) == false)
	{
		c->Err = ERR_DISCONNECTED;
		return false;
	}

	b = NewBuf();
	WriteBuf(b, tmp, sizeof(tmp));
	SeekBuf(b, 0, 0);

	ReadBuf(b, &vn, 1);
	ReadBuf(b, &cd, 1);

	FreeBuf(b);

	if (vn != 0)
	{
		c->Err = ERR_PROXY_ERROR;
		return false;
	}

	switch (cd)
	{
	case 90:
		// Success
		return true;

	case 93:
		// Authentication failure
		c->Err = ERR_PROXY_AUTH_FAILED;
		return false;

	default:
		// Connection to the server failure
		c->Err = ERR_CONNECT_FAILED;
		return false;
	}
}

// Send a SOCKS request packet
bool SocksSendRequestPacket(CONNECTION *c, SOCK *s, UINT dest_port, IP *dest_ip, char *userid)
{
	BUF *b;
	UCHAR vn, cd;
	USHORT port;
	UINT ip;
	bool ret;
	// Validate arguments
	if (s == NULL || dest_port == 0 || dest_ip == NULL || c == NULL)
	{
		return false;
	}
	if (userid == NULL)
	{
		userid = "";
	}

	b = NewBuf();
	vn = 4;
	cd = 1;
	WriteBuf(b, &vn, 1);
	WriteBuf(b, &cd, 1);
	port = Endian16((USHORT)dest_port);
	ip = IPToUINT(dest_ip);
	WriteBuf(b, &port, 2);
	WriteBuf(b, &ip, 4);
	WriteBuf(b, userid, StrLen(userid) + 1);

	ret = SendAll(s, b->Buf, b->Size, false);
	if (ret == false)
	{
		c->Err = ERR_DISCONNECTED;
	}

	FreeBuf(b);

	return ret;
}

// Connect through a proxy
SOCK *ProxyConnect(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
				   char *server_host_name, UINT server_port,
				   char *username, char *password, bool additional_connect)
{
	return ProxyConnectEx(c, proxy_host_name, proxy_port,
		server_host_name, server_port, username, password, additional_connect, NULL, NULL);
}
SOCK *ProxyConnectEx(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
				   char *server_host_name, UINT server_port,
				   char *username, char *password, bool additional_connect,
				   bool *cancel_flag, void *hWnd)
{
	return ProxyConnectEx2(c, proxy_host_name, proxy_port,
		server_host_name, server_port, username, password, additional_connect,
		cancel_flag, hWnd, 0);
}
SOCK *ProxyConnectEx2(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
				   char *server_host_name, UINT server_port,
				   char *username, char *password, bool additional_connect,
				   bool *cancel_flag, void *hWnd, UINT timeout)
{
	SOCK *s = NULL;
	bool use_auth = false;
	char tmp[MAX_SIZE];
	char auth_tmp_str[MAX_SIZE], auth_b64_str[MAX_SIZE * 2];
	char basic_str[MAX_SIZE * 2];
	UINT http_error_code;
	HTTP_HEADER *h;
	char server_host_name_tmp[256];
	UINT i, len;
	// Validate arguments
	if (c == NULL || proxy_host_name == NULL || proxy_port == 0 || server_host_name == NULL ||
		server_port == 0)
	{
		if (c != NULL)
		{
			c->Err = ERR_PROXY_CONNECT_FAILED;
		}
		return NULL;
	}
	if (username != NULL && password != NULL &&
		(StrLen(username) != 0 || StrLen(password) != 0))
	{
		use_auth = true;
	}

	if (c->Halt)
	{
		// Stop
		c->Err = ERR_USER_CANCEL;
		return NULL;
	}

	Zero(server_host_name_tmp, sizeof(server_host_name_tmp));
	StrCpy(server_host_name_tmp, sizeof(server_host_name_tmp), server_host_name);

	len = StrLen(server_host_name_tmp);

	for (i = 0;i < len;i++)
	{
		if (server_host_name_tmp[i] == '/')
		{
			server_host_name_tmp[i] = 0;
		}
	}

	// Connection
	s = TcpConnectEx3(proxy_host_name, proxy_port, timeout, cancel_flag, hWnd, true, NULL, false, false, NULL);
	if (s == NULL)
	{
		// Failure
		c->Err = ERR_PROXY_CONNECT_FAILED;
		return NULL;
	}

	// Timeout setting
	SetTimeout(s, MIN(CONNECTING_TIMEOUT_PROXY, (timeout == 0 ? INFINITE : timeout)));

	if (additional_connect == false)
	{
		c->FirstSock = s;
	}

	// HTTP header generation
	if (IsStrIPv6Address(server_host_name_tmp))
	{
		IP ip;
		char iptmp[MAX_PATH];

		StrToIP(&ip, server_host_name_tmp);
		IPToStr(iptmp, sizeof(iptmp), &ip);

		Format(tmp, sizeof(tmp), "[%s]:%u", iptmp, server_port);
	}
	else
	{
		Format(tmp, sizeof(tmp), "%s:%u", server_host_name_tmp, server_port);
	}

	h = NewHttpHeader("CONNECT", tmp, "HTTP/1.0");
	AddHttpValue(h, NewHttpValue("User-Agent", (c->Cedar == NULL ? DEFAULT_USER_AGENT : c->Cedar->HttpUserAgent)));
	AddHttpValue(h, NewHttpValue("Host", server_host_name_tmp));
	AddHttpValue(h, NewHttpValue("Content-Length", "0"));
	AddHttpValue(h, NewHttpValue("Proxy-Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Pragma", "no-cache"));

	if (use_auth)
	{
		wchar_t tmp[MAX_SIZE];
		UniFormat(tmp, sizeof(tmp), _UU("STATUS_3"), server_host_name_tmp);
		// Generate the authentication string
		Format(auth_tmp_str, sizeof(auth_tmp_str), "%s:%s",
			username, password);

		// Base64 encode
		Zero(auth_b64_str, sizeof(auth_b64_str));
		Encode64(auth_b64_str, auth_tmp_str);
		Format(basic_str, sizeof(basic_str), "Basic %s", auth_b64_str);

		AddHttpValue(h, NewHttpValue("Proxy-Authorization", basic_str));
	}

	// Transmission
	if (SendHttpHeader(s, h) == false)
	{
		// Failure
		if (additional_connect == false)
		{
			c->FirstSock = NULL;
		}
		FreeHttpHeader(h);
		Disconnect(s);
		ReleaseSock(s);
		c->Err = ERR_PROXY_ERROR;
		return NULL;
	}

	FreeHttpHeader(h);

	if (c->Halt)
	{
		// Stop
		if (additional_connect == false)
		{
			c->FirstSock = NULL;
		}
		Disconnect(s);
		ReleaseSock(s);
		c->Err = ERR_USER_CANCEL;
		return NULL;
	}

	// Receive the results
	h = RecvHttpHeader(s);
	if (h == NULL)
	{
		// Failure
		if (additional_connect == false)
		{
			c->FirstSock = NULL;
		}
		FreeHttpHeader(h);
		Disconnect(s);
		ReleaseSock(s);
		c->Err = ERR_PROXY_ERROR;
		return NULL;
	}

	http_error_code = 0;
	if (StrLen(h->Method) == 8)
	{
		if (Cmp(h->Method, "HTTP/1.", 7) == 0)
		{
			http_error_code = ToInt(h->Target);
		}
	}
	FreeHttpHeader(h);

	// Check the code
	switch (http_error_code)
	{
	case 401:
	case 403:
	case 407:
		// Authentication failure
		if (additional_connect == false)
		{
			c->FirstSock = NULL;
		}
		Disconnect(s);
		ReleaseSock(s);
		c->Err = ERR_PROXY_AUTH_FAILED;
		return NULL;

	default:
		if ((http_error_code / 100) == 2)
		{
			// Success
			SetTimeout(s, INFINITE);
			return s;
		}
		else
		{
			// Receive an unknown result
			if (additional_connect == false)
			{
				c->FirstSock = NULL;
			}
			Disconnect(s);
			ReleaseSock(s);
			c->Err = ERR_PROXY_ERROR;
			return NULL;
		}
	}
}

// TCP connection function
SOCK *TcpConnectEx2(char *hostname, UINT port, UINT timeout, bool *cancel_flag, void *hWnd, bool try_start_ssl, bool ssl_no_tls)
{
	return TcpConnectEx3(hostname, port, timeout, cancel_flag, hWnd, false, NULL, try_start_ssl, ssl_no_tls, NULL);
}
SOCK *TcpConnectEx3(char *hostname, UINT port, UINT timeout, bool *cancel_flag, void *hWnd, bool no_nat_t, UINT *nat_t_error_code, bool try_start_ssl, bool ssl_no_tls, IP *ret_ip)
{
#ifdef	OS_WIN32
	if (hWnd == NULL)
	{
#endif	// OS_WIN32
		return ConnectEx4(hostname, port, timeout, cancel_flag, (no_nat_t ? NULL : VPN_RUDP_SVC_NAME), nat_t_error_code, try_start_ssl, ssl_no_tls, true, ret_ip);
#ifdef	OS_WIN32
	}
	else
	{
		return WinConnectEx3((HWND)hWnd, hostname, port, timeout, 0, NULL, NULL, nat_t_error_code, (no_nat_t ? NULL : VPN_RUDP_SVC_NAME), try_start_ssl, ssl_no_tls);
	}
#endif	// OS_WIN32
}

// Connect with TCP/IP
SOCK *TcpIpConnect(char *hostname, UINT port, bool try_start_ssl, bool ssl_no_tls)
{
	return TcpIpConnectEx(hostname, port, NULL, NULL, NULL, false, try_start_ssl, ssl_no_tls, NULL);
}
SOCK *TcpIpConnectEx(char *hostname, UINT port, bool *cancel_flag, void *hWnd, UINT *nat_t_error_code, bool no_nat_t, bool try_start_ssl, bool ssl_no_tls, IP *ret_ip)
{
	SOCK *s = NULL;
	UINT dummy_int = 0;
	// Validate arguments
	if (nat_t_error_code == NULL)
	{
		nat_t_error_code = &dummy_int;
	}
	*nat_t_error_code = 0;
	if (hostname == NULL || port == 0)
	{
		return NULL;
	}

	s = TcpConnectEx3(hostname, port, 0, cancel_flag, hWnd, no_nat_t, nat_t_error_code, try_start_ssl, ssl_no_tls, ret_ip);
	if (s == NULL)
	{
		return NULL;
	}

	return s;
}

// Protocol routine initialization
void InitProtocol()
{
}

// Release the protocol routine
void FreeProtocol()
{
}

// Create a Hello packet
PACK *PackHello(void *random, UINT ver, UINT build, char *server_str)
{
	PACK *p;
	// Validate arguments
	if (random == NULL || server_str == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "hello", server_str);
	PackAddInt(p, "version", ver);
	PackAddInt(p, "build", build);
	PackAddData(p, "random", random, SHA1_SIZE);

	return p;
}

// Interpret the Hello packet
bool GetHello(PACK *p, void *random, UINT *ver, UINT *build, char *server_str, UINT server_str_size)
{
	// Validate arguments
	if (p == NULL || random == NULL || ver == NULL || server_str == NULL)
	{
		return false;
	}

	if (PackGetStr(p, "hello", server_str, server_str_size) == false)
	{
		return false;
	}
	*ver = PackGetInt(p, "version");
	*build = PackGetInt(p, "build");
	if (PackGetDataSize(p, "random") != SHA1_SIZE)
	{
		return false;
	}
	if (PackGetData(p, "random", random) == false)
	{
		return false;
	}

	return true;
}

// Get the authentication method from PACK
UINT GetAuthTypeFromPack(PACK *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return 0;
	}

	return PackGetInt(p, "authtype");
}

// Get the HUB name and the user name from the PACK
bool GetHubnameAndUsernameFromPack(PACK *p, char *username, UINT username_size,
								   char *hubname, UINT hubname_size)
{
	// Validate arguments
	if (p == NULL || username == NULL || hubname == NULL)
	{
		return false;
	}

	if (PackGetStr(p, "username", username, username_size) == false)
	{
		return false;
	}
	if (PackGetStr(p, "hubname", hubname, hubname_size) == false)
	{
		return false;
	}
	return true;
}

// Get the protocol from PACK
UINT GetProtocolFromPack(PACK *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return 0;
	}

#if	0
	return PackGetInt(p, "protocol");
#else
	// Limit to the TCP protocol in the current version
	return CONNECTION_TCP;
#endif
}

// Get the method from the PACK
bool GetMethodFromPack(PACK *p, char *method, UINT size)
{
	// Validate arguments
	if (p == NULL || method == NULL || size == 0)
	{
		return false;
	}

	return PackGetStr(p, "method", method, size);
}

// Generate a packet of certificate authentication login
PACK *PackLoginWithCert(char *hubname, char *username, X *x, void *sign, UINT sign_size)
{
	PACK *p;
	BUF *b;
	// Validate arguments
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_CERT);

	// Certificate
	b = XToBuf(x, false);
	PackAddData(p, "cert", b->Buf, b->Size);
	FreeBuf(b);

	// Signature data
	PackAddData(p, "sign", sign, sign_size);

	return p;
}

// Generate a packet of plain text password authentication login
PACK *PackLoginWithPlainPassword(char *hubname, char *username, void *plain_password)
{
	PACK *p;
	// Validate arguments
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_PLAIN_PASSWORD);
	PackAddStr(p, "plain_password", plain_password);

	return p;
}

// Generate a packet of OpenVPN certificate login
PACK *PackLoginWithOpenVPNCertificate(char *hubname, char *username, X *x)
{
	PACK *p;
	char cn_username[128];
	BUF *cert_buf = NULL;
	// Validate arguments
	if (hubname == NULL || username == NULL || x == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);

	if (IsEmptyStr(username))
	{
		if (x->subject_name == NULL)
		{
			return NULL;
		}
		UniToStr(cn_username, sizeof(cn_username), x->subject_name->CommonName);
		PackAddStr(p, "username", cn_username);
	}
	else
	{
		PackAddStr(p, "username", username);
	}

	PackAddInt(p, "authtype", AUTHTYPE_OPENVPN_CERT);

	cert_buf = XToBuf(x, false);
	PackAddBuf(p, "cert", cert_buf);
	FreeBuf(cert_buf);

	return p;
}

// Create a packet of password authentication login
PACK *PackLoginWithPassword(char *hubname, char *username, void *secure_password)
{
	PACK *p;
	// Validate arguments
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_PASSWORD);
	PackAddData(p, "secure_password", secure_password, SHA1_SIZE);

	return p;
}

// Create a packet for anonymous login
PACK *PackLoginWithAnonymous(char *hubname, char *username)
{
	PACK *p;
	// Validate arguments
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_ANONYMOUS);

	return p;
}

// Create a packet for the additional connection
PACK *PackAdditionalConnect(UCHAR *session_key)
{
	PACK *p;
	// Validate arguments
	if (session_key == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "additional_connect");
	PackAddData(p, "session_key", session_key, SHA1_SIZE);

	return p;
}


// Generate a RC4 key pair
void GenerateRC4KeyPair(RC4_KEY_PAIR *k)
{
	// Validate arguments
	if (k == NULL)
	{
		return;
	}

	Rand(k->ClientToServerKey, sizeof(k->ClientToServerKey));
	Rand(k->ServerToClientKey, sizeof(k->ServerToClientKey));
}

// MVPN GET Procedure (WebSocket)
void MvpnProcGet(CONNECTION *c, SOCK *s, HTTP_HEADER *h, char *url_target)
{
	HTTP_VALUE *req_upgrade;
	HTTP_VALUE *req_version;
	HTTP_VALUE *req_key;
	char response_key[64];
	UINT client_ws_version = 0;
	char *bad_request_body = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"\"http://www.w3.org/TR/html4/strict.dtd\">\r\n<HTML><HEAD><TITLE>Bad Request</TITLE>\r\n<META HTTP-EQUIV=\"Content-Type\" Content=\"text/html; charset=us-ascii\"></HEAD>\r\n<BODY><h2>Bad Request</h2>\r\n<hr><p>HTTP Error 400. The request is badly formed.</p>\r\n</BODY></HTML>";
	if (c == NULL || s == NULL || h == NULL || url_target == NULL)
	{
		return;
	}

	req_upgrade = GetHttpValue(h, "Upgrade");
	if (req_upgrade == NULL || StrCmpi(req_upgrade->Data, "websocket") != 0)
	{
		MvpnSendReply(s, 400, "Bad Request", bad_request_body, StrLen(bad_request_body),
			NULL, NULL, NULL, h);
		return;
	}

	req_version = GetHttpValue(h, "Sec-WebSocket-Version");
	if (req_version != NULL) client_ws_version = ToInt(req_version->Data);
	if (client_ws_version != 13)
	{
		MvpnSendReply(s, 400, "Bad Request", NULL, 0,
			NULL, "Sec-WebSocket-Version", "13", h);
		return;
	}

	Zero(response_key, sizeof(response_key));
	req_key = GetHttpValue(h, "Sec-WebSocket-Key");
	if (req_key != NULL)
	{
		char tmp[MAX_SIZE];
		UCHAR hash[SHA1_SIZE];
		StrCpy(tmp, sizeof(tmp), req_key->Data);
		StrCat(tmp, sizeof(tmp), "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
		HashSha1(hash, tmp, StrLen(tmp));
		B64_Encode(response_key, hash, SHA1_SIZE);
	}
	else
	{
		MvpnSendReply(s, 400, "Bad Request", NULL, 0,
			NULL, "Sec-WebSocket-Version", "13", h);
		return;
	}

	MvpnSendReply(s, 101, "Switching Protocols", NULL, 0, NULL,
		"Sec-WebSocket-Accept", response_key, h);

	MvpnAccept(c, s);
}

// MVPN Send Reply
bool MvpnSendReply(SOCK *s, UINT status_code, char *status_string, UCHAR *data, UINT data_size, char *content_type,
				   char *add_header_name, char *add_header_value, HTTP_HEADER *request_headers)
{
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char error_code_str[16];
	bool ret = false;
	HTTP_VALUE *origin;
	HTTP_VALUE *upgrade;
	HTTP_VALUE *req_connection;
	if (s == NULL || status_string == NULL || (data_size != 0 && data == NULL) || request_headers == NULL)
	{
		return false;
	}
	if (content_type == NULL)
	{
		content_type = "text/html; charset=utf-8";
	}

	req_connection = GetHttpValue(request_headers, "Connection");

	ToStr(error_code_str, status_code);
	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	h = NewHttpHeader("HTTP/1.1", error_code_str, status_string);

	AddHttpValue(h, NewHttpValue("Cache-Control", "no-cache"));
	if (data_size != 0)
	{
		AddHttpValue(h, NewHttpValue("Content-Type", content_type));
	}
	AddHttpValue(h, NewHttpValue("Date", date_str));
	if (req_connection != NULL)
	{
		AddHttpValue(h, NewHttpValue("Connection", req_connection->Data));
	}
	else
	{
		AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	}
	AddHttpValue(h, NewHttpValue("Access-Control-Allow-Headers", "content-type"));
	AddHttpValue(h, NewHttpValue("Access-Control-Allow-Headers", "authorization"));
	AddHttpValue(h, NewHttpValue("Access-Control-Allow-Headers", "x-websocket-extensions"));
	AddHttpValue(h, NewHttpValue("Access-Control-Allow-Headers", "x-websocket-version"));
	AddHttpValue(h, NewHttpValue("Access-Control-Allow-Headers", "x-websocket-protocol"));
	AddHttpValue(h, NewHttpValue("Access-Control-Allow-Credentials", "true"));

	origin = GetHttpValue(request_headers, "Origin");
	if (origin != NULL)
	{
		AddHttpValue(h, NewHttpValue("Access-Control-Allow-Origin", origin->Data));
	}

	upgrade = GetHttpValue(request_headers, "Upgrade");
	if (upgrade != NULL)
	{
		AddHttpValue(h, NewHttpValue("Upgrade", upgrade->Data));
	}

	if (add_header_name != NULL && add_header_value != NULL)
	{
		AddHttpValue(h, NewHttpValue(add_header_name, add_header_value));
	}

	ret = PostHttp(s, h, data, data_size);

	FreeHttpHeader(h);

	return ret;
}

// MVPN Accept
void MvpnAccept(CONNECTION *c, SOCK *s)
{
	WS *w;
	UINT err;
	if (c == NULL || s == NULL)
	{
		return;
	}

	w = NewWs(s);

	err = MvpnDoAccept(c, w);

	//while (true)
	//{
	//	UINT r;
	//	Zero(data, sizeof(data));
	//	r = WsRecvSyncAll(w, data, 7);
	//	if (!r)
	//	{
	//		break;
	//	}
	//	Print("WS_Recv: %s\n", data);
	//	r = WsSendSync(w, data, 7);
	//	if (!r)
	//	{
	//		break;
	//	}
	//	Print("WS_Send: %s\n", data);
	//}

	ReleaseWs(w);
}

// New WebSocket
WS *NewWs(SOCK *s)
{
	WS *w;
	if (s == NULL)
	{
		return NULL;
	}

	w = ZeroMalloc(sizeof(WS));

	w->Ref = NewRef();

	w->MaxBufferSize = MAX_BUFFERING_PACKET_SIZE;
	w->Sock = s;
	AddRef(w->Sock->ref);

	w->Wsp = NewWsp();

	return w;
}

// Release WebSocket
void ReleaseWs(WS *w)
{
	if (w == NULL)
	{
		return;
	}

	if (Release(w->Ref) == 0)
	{
		CleanupWs(w);
	}
}

void CleanupWs(WS *w)
{
	if (w == NULL)
	{
		return;
	}

	if (w->Sock != NULL)
	{
		Disconnect(w->Sock);
		ReleaseSock(w->Sock);
	}

	FreeWsp(w->Wsp);

	Free(w);
}

// WebSocket: Send a frame in sync mode
bool WsSendSync(WS *w, void *data, UINT size)
{
	UCHAR *send_buf;
	UINT send_buf_size;
	if (size == 0)
	{
		return !w->Disconnected;
	}
	if (w == NULL || data == NULL)
	{
		return false;
	}
	if (w->Disconnected || w->Wsp->HasError)
	{
		Disconnect(w->Sock);
		return false;
	}

	WriteFifo(w->Wsp->AppSendFifo, data, size);
	WspTry(w->Wsp);
	if (w->Wsp->HasError == false)
	{
		send_buf = FifoPtr(w->Wsp->PhysicalSendFifo);
		send_buf_size = FifoSize(w->Wsp->PhysicalSendFifo);
		if (SendAll(w->Sock, send_buf, send_buf_size, w->Sock->SecureMode))
		{
			ReadFifo(w->Wsp->PhysicalSendFifo, NULL, send_buf_size);
			return true;
		}
	}

	w->Disconnected = true;
	Disconnect(w->Sock);

	return false;
}

// WebSocket: Send a frame in async mode
UINT WsSendAsync(WS *w, void *data, UINT size)
{
	bool disconnected = false;
	UINT ret = 0;
	if (size == 0)
	{
		return !w->Disconnected;
	}
	if (w == NULL || data == NULL)
	{
		return 0;
	}
	if (w->Disconnected || w->Wsp->HasError)
	{
		Disconnect(w->Sock);
		return 0;
	}

	if (FifoSize(w->Wsp->PhysicalSendFifo) > w->Wsp->MaxBufferSize)
	{
		return INFINITE;
	}

	WriteFifo(w->Wsp->AppSendFifo, data, size);

	if (WsTrySendAsync(w) == false)
	{
		ret = 0;
	}
	else
	{
		ret = size;
	}

	if (ret == 0)
	{
		w->Disconnected = true;
		Disconnect(w->Sock);
	}

	return ret;
}

// WebSocket: Send buffered streams in async mode
bool WsTrySendAsync(WS *w)
{
	bool ret = false;
	if (w == NULL)
	{
		return false;
	}
	if (w->Disconnected || w->Wsp->HasError)
	{
		Disconnect(w->Sock);
		return false;
	}

	WspTry(w->Wsp);

	if (w->Wsp->HasError == false)
	{
		while (true)
		{
			UINT send_size = FifoSize(w->Wsp->PhysicalSendFifo);
			UINT r;
			if (send_size == 0)
			{
				ret = true;
				break;
			}

			r = Send(w->Sock, FifoPtr(w->Wsp->PhysicalSendFifo), send_size, w->Sock->SecureMode);

			if (r == INFINITE)
			{
				ret = true;
				break;
			}
			else if (r == 0)
			{
				ret = false;
				break;
			}
			else
			{
				ReadFifo(w->Wsp->PhysicalSendFifo, NULL, r);
			}
		}
	}
	else
	{
		ret = false;
	}

	if (ret == 0)
	{
		w->Disconnected = true;
		Disconnect(w->Sock);
	}

	return ret;
}

// WebSocket: Receive a frame in async mode
UINT WsRecvAsync(WS *w, void *data, UINT size)
{
	bool disconnected = false;
	UINT ret = 0;
	if (w == NULL || data == NULL || size == 0)
	{
		return 0;
	}
	if (w->Disconnected || w->Wsp->HasError)
	{
		Disconnect(w->Sock);
		return 0;
	}

	// Receive all arrived data from the socket
	while (FifoSize(w->Wsp->PhysicalRecvFifo) < w->MaxBufferSize)
	{
		UINT r;

		r = Recv(w->Sock, w->TmpBuf, sizeof(w->TmpBuf), w->Sock->SecureMode);
		if (r == 0)
		{
			// Disconnected
			disconnected = true;
			break;
		}
		else if (r == INFINITE)
		{
			// Pending
			break;
		}
		else
		{
			// Received some data
			WriteFifo(w->Wsp->PhysicalRecvFifo, w->TmpBuf, r);
		}
	}

	if (disconnected == false)
	{
		UINT sz;
		WspTry(w->Wsp);
		if (w->Wsp->HasError)
		{
			disconnected = true;
		}
		else
		{
			sz = FifoSize(w->Wsp->AppRecvFifo);
			if (sz >= 1)
			{
				if (sz > size)
				{
					sz = size;
				}
				ReadFifo(w->Wsp->AppRecvFifo, data, sz);
				ret = sz;
			}
			else
			{
				ret = INFINITE;
			}
		}
	}

	if (disconnected)
	{
		w->Disconnected = true;
		Disconnect(w->Sock);
		ret = 0;
	}

	return ret;
}

// WebSocket: Receive a frame in sync mode until fulfill the buffer
bool WsRecvSyncAll(WS *w, void *data, UINT size)
{
	UINT recv_size;
	if (w == NULL || data == NULL || size == 0)
	{
		return false;
	}

	recv_size = 0;

	while (true)
	{
		UINT sz, ret;

		sz = size - recv_size;
		ret = WsRecvSync(w, (UCHAR *)data + recv_size, sz);
		if (ret == 0)
		{
			return false;
		}
		recv_size += ret;
		if (recv_size >= size)
		{
			return true;
		}
	}
}

// WebSocket: Receive a frame in sync mode
UINT WsRecvSync(WS *w, void *data, UINT size)
{
	if (w == NULL || data == NULL || size == 0)
	{
		return 0;
	}
	if (w->Disconnected || w->Wsp->HasError)
	{
		Disconnect(w->Sock);
		return 0;
	}

	while (w->Disconnected == false || w->Wsp->HasError == false)
	{
		UINT r;
		UINT sz;
		WspTry(w->Wsp);
		if (w->Wsp->HasError)
		{
			break;
		}
		sz = FifoSize(w->Wsp->AppRecvFifo);
		if (sz >= 1)
		{
			if (sz > size)
			{
				sz = size;
			}
			ReadFifo(w->Wsp->AppRecvFifo, data, sz);
			return sz;
		}
		r = Recv(w->Sock, w->TmpBuf, sizeof(w->TmpBuf), w->Sock->SecureMode);
		if (r == 0 || r == SOCK_LATER)
		{
			break;
		}
		WriteFifo(w->Wsp->PhysicalRecvFifo, w->TmpBuf, r);
	}

	w->Disconnected = true;
	Disconnect(w->Sock);

	return 0;
}

// New WebSocket protocol
WSP *NewWsp()
{
	WSP *p = ZeroMalloc(sizeof(WSP));

	p->AppRecvFifo = NewFifo();
	p->AppSendFifo = NewFifo();
	p->PhysicalRecvFifo = NewFifo();
	p->PhysicalSendFifo = NewFifo();

	p->MaxBufferSize = MAX_BUFFERING_PACKET_SIZE;

	return p;
}

// Free WebSocket protocol
void FreeWsp(WSP *p)
{
	if (p == NULL)
	{
		return;
	}

	ReleaseFifo(p->AppRecvFifo);
	ReleaseFifo(p->AppSendFifo);
	ReleaseFifo(p->PhysicalRecvFifo);
	ReleaseFifo(p->PhysicalSendFifo);

	Free(p);
}

// WebSocket protocol: Try to interpret send/recv buffers
void WspTry(WSP *p)
{
	if (p == NULL)
	{
		return;
	}

	// Physical -> App
	while (p->HasError == false)
	{
		UINT read_buffer_size;
		BLOCK *b = WspTryRecvNextFrame(p, &read_buffer_size);
		if (b == NULL)
		{
			// No more frames
			break;
		}

		if (b->Param1 == WS_OPCODE_CONTINUE || b->Param1 == WS_OPCODE_TEXT || b->Param1 == WS_OPCODE_BIN)
		{
			WriteFifo(p->AppRecvFifo, b->Buf, b->Size);
		}
		else if (b->Param1 == WS_OPCODE_PING)
		{
			if (FifoSize(p->PhysicalSendFifo) <= p->MaxBufferSize)
			{
				WspTrySendFrame(p, WS_OPCODE_PONG, b->Buf, b->Size);
			}
		}
		else if (b->Param1 == WS_OPCODE_PONG)
		{
		}
		else
		{
			// Error: disconnect
			p->HasError = true;
		}

		ReadFifo(p->PhysicalRecvFifo, NULL, read_buffer_size);

		FreeBlock(b);
	}

	// App -> Physical
	while (p->HasError == false)
	{
		UINT size;
		UCHAR *data;

		size = FifoSize(p->AppSendFifo);
		if (size == 0)
		{
			// No more data
			break;
		}

		if (size > WS_SEND_SINGLE_FRAGMENT_SIZE)
		{
			size = WS_SEND_SINGLE_FRAGMENT_SIZE;
		}
		data = FifoPtr(p->AppSendFifo);

		WspTrySendFrame(p, WS_OPCODE_BIN, data, size);

		ReadFifo(p->AppSendFifo, NULL, size);
	}
}

// WebSocket protocol: Try to send a single frame
void WspTrySendFrame(WSP *p, UCHAR opcode, void *data, UINT size)
{
	BUF *b;
	UCHAR flag_and_opcode;
	if (p == NULL || (size != 0 && data == NULL))
	{
		return;
	}
	if (p->HasError)
	{
		return;
	}

	b = NewBuf();

	flag_and_opcode = 0x80 | (opcode & 0x0F);
	WriteBufChar(b, flag_and_opcode);

	if (size <= 125)
	{
		WriteBufChar(b, size);
	}
	else if (size <= 65536)
	{
		WriteBufChar(b, 126);
		WriteBufShort(b, size);
	}
	else
	{
		WriteBufChar(b, 127);
		WriteBufInt64(b, size);
	}

	WriteBuf(b, data, size);

	WriteFifo(p->PhysicalSendFifo, b->Buf, b->Size);

	FreeBuf(b);
}

// WebSocket protocol: Try to receive a single frame
BLOCK *WspTryRecvNextFrame(WSP *p, UINT *read_buffer_size)
{
	BLOCK *b;
	UCHAR *buf;
	UCHAR *buf_pos0;
	UINT sz;
	UCHAR flag_and_opcode;
	UCHAR mask_and_payload_len;
	UCHAR mask_flag;
	UINT payload_len;
	UCHAR mask_key[4];
	UCHAR *ret_data;
	if (p == NULL || read_buffer_size == NULL)
	{
		return NULL;
	}
	if (p->HasError)
	{
		return NULL;
	}

	buf = buf_pos0 = FifoPtr(p->PhysicalRecvFifo);
	sz = FifoSize(p->PhysicalRecvFifo);

	if (sz < 1)
	{
		return NULL;
	}
	flag_and_opcode = *buf;
	buf += 1;
	sz -= 1;

	if (sz < 1)
	{
		return NULL;
	}
	mask_and_payload_len = *buf;
	buf += 1;
	sz -= 1;

	mask_flag = mask_and_payload_len & 0x80;
	payload_len = mask_and_payload_len & 0x7F;
	if (payload_len == 126)
	{
		if (sz < sizeof(USHORT))
		{
			return NULL;
		}
		payload_len = READ_USHORT(buf);
		buf += sizeof(USHORT);
		sz -= sizeof(USHORT);
	}
	else if (payload_len == 127)
	{
		UINT64 u64;
		if (sz < sizeof(UINT64))
		{
			return NULL;
		}
		u64 = READ_UINT64(buf);
		buf += sizeof(UINT64);
		sz -= sizeof(UINT64);
		if (u64 > 0x7FFFFFFF)
		{
			p->HasError = true;
			return NULL;
		}
		payload_len = (UINT)u64;
	}

	if (payload_len > WS_MAX_PAYLOAD_LEN_PER_FRAME)
	{
		p->HasError = true;
		return NULL;
	}

	if (mask_flag)
	{
		if (sz < 4)
		{
			return NULL;
		}
		Copy(mask_key, buf, 4);
		buf += 4;
		sz -= 4;
	}

	if (payload_len >= 1 && sz < payload_len)
	{
		return NULL;
	}

	ret_data = Clone(buf, payload_len);
	sz -= payload_len;
	buf += payload_len;

	if (mask_flag)
	{
		UINT i;
		for (i = 0;i < payload_len;i++)
		{
			ret_data[i] ^= mask_key[i % 4];
		}
	}

	b = NewBlock(ret_data, payload_len, 0);
	b->Param1 = (flag_and_opcode & 0xF);

	*read_buffer_size = (UINT)(buf - buf_pos0);

	return b;
}

// WebSocket: Receive a PACK serialized with JSON
PACK *WsRecvPack(WS *w)
{
	USHORT us;
	UINT size;
	UCHAR *buf;
	PACK *p = NULL;
	if (w == NULL)
	{
		return NULL;
	}

	if (WsRecvSyncAll(w, &us, sizeof(us)))
	{
		size = Endian16(us);

		buf = ZeroMalloc(size + 1);

		if (WsRecvSyncAll(w, buf, size))
		{
			p = JsonStrToPack(buf);
		}

		Free(buf);
	}

	return p;
}

// WebSocket: Send a PACK serialized with JSON
bool WsSendPack(WS *w, PACK *p)
{
	BUF *b;
	char *json_str;
	bool ret = false;
	if (w == NULL || p == NULL)
	{
		return false;
	}

	json_str = PackToJsonStr(p);
	if (json_str == NULL)
	{
		return false;
	}

	b = NewBuf();

	WriteBufShort(b, StrLen(json_str));
	WriteBuf(b, json_str, StrLen(json_str));

	ret = WsSendSync(w, b->Buf, b->Size);

	FreeBuf(b);

	Free(json_str);

	return ret;
}

// WebSocket: new error pack
PACK *WsNewErrorPack(UINT err)
{
	PACK *p = NewPack();
	char *error_code_str = WsErrorCodeToString(err);
	wchar_t *error_message = _E(err);

	PackAddStr(p, "Error", error_code_str);
	PackAddUniStr(p, "ErrorMessage", error_message);

	return p;
}

// MVPN: convert error code to string
char *WsErrorCodeToString(UINT err)
{
	char *ret = "e_unknown";
	switch (err)
	{
	case ERR_NO_ERROR:
		ret = "ok";
		break;
	case ERR_PROTOCOL_ERROR:
		ret = "e_protocol";
		break;
	case ERR_INTERNAL_ERROR:
		ret = "e_internal";
		break;
	case ERR_DISCONNECTED:
	case ERR_AUTO_DISCONNECTED:
		ret = "e_disconnected";
		break;
	case ERR_ACCESS_DENIED:
		ret = "e_access_denied";
		break;
	case ERR_HUB_NOT_FOUND:
		ret = "e_network_not_found";
		break;
	case ERR_HUB_STOPPING:
		ret = "e_network_disabled";
		break;
	case ERR_AUTH_FAILED:
		ret = "e_auth_failed";
		break;
	case ERR_SESSION_TIMEOUT:
		ret = "e_timeout";
		break;
	case ERR_USER_CANCEL:
		ret = "e_user_cancel";
		break;
	case ERR_AUTHTYPE_NOT_SUPPORTED:
		ret = "e_auth_method_not_supported";
		break;
	case ERR_TOO_MANY_CONNECTION:
		ret = "e_too_many_connection";
		break;
	case ERR_HUB_IS_BUSY:
		ret = "e_too_many_session";
		break;
	case ERR_TOO_MANY_USER_SESSION:
		ret = "e_too_many_user_session";
		break;
	case ERR_OBJECT_NOT_FOUND:
		ret = "e_object_not_found";
		break;
	case ERR_NOT_SUPPORTED:
	case ERR_NOT_SUPPORTED_AUTH_ON_OPENSOURCE:
		ret = "e_not_supported";
		break;
	case ERR_INVALID_PARAMETER:
		ret = "e_invalid_parameter";
		break;
	case ERR_NULL_PASSWORD_LOCAL_ONLY:
		ret = "e_empty_password_local_only";
		break;
	case ERR_MONITOR_MODE_DENIED:
		ret = "e_mirror_mode_denied";
		break;
	case ERR_BRIDGE_MODE_DENIED:
		ret = "e_bridge_mode_denied";
		break;
	case ERR_IP_ADDRESS_DENIED:
		ret = "e_client_ip_address_denied";
		break;
	case ERR_MSCHAP2_PASSWORD_NEED_RESET:
		ret = "e_user_password_must_reset";
		break;

	case ERR_DHCP_SERVER_NOT_RUNNING:
		ret = "e_dhcp_server_not_running";
		break;
	}
	return ret;
}

// MVPN processing a client
UINT MvpnDoAccept(CONNECTION *c, WS *w)
{
	UINT ret = ERR_INTERNAL_ERROR;
	PACK *client_hello = NULL;
	UINT client_ver = 0;
	char client_impl[256];
	UCHAR client_nonce[128];
	char client_hub_name[MAX_HUBNAME_LEN + 1];
	UINT server_ver = 0;
	char server_impl[256];
	UCHAR server_nonce[128];
	PACK *server_hello = NULL;
	UINT auth_ret = ERR_INTERNAL_ERROR;
	IPC *ipc = NULL;
	UINT i;
	UINT heartbeat_interval = 0;
	UINT disconnect_timeout = 0;
	bool use_udp_acceleration = false;
	IP client_udp_acceleration_ip = {0};
	UINT client_udp_acceleration_port = 0;
	UCHAR client_udp_acceleration_key[UDP_ACCELERATION_COMMON_KEY_SIZE_V2] = {0};
	UDP_ACCEL *udp_accel = NULL;
	bool l3_ipv4_enable = false;
	bool l3_ipv4_dynamic = false;
	IP l3_ipv4_ip = {0};
	IP l3_ipv4_mask = {0};
	IP l3_ipv4_gw = {0};
	IP l3_ipv4_dns1 = {0};
	IP l3_ipv4_dns2 = {0};
	IP l3_ipv4_wins1 = {0};
	IP l3_ipv4_wins2 = {0};
	IP l3_ipv4_dhcp_server = {0};
	char l3_ipv4_classless_routes[4096] = {0};
	bool l3_ipv4_dhcp_allocated = false;

	if (c == NULL || w == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	Rand(server_nonce, sizeof(server_nonce));

	// Phase 1: Receive a Client Hello packet
	client_hello = WsRecvPack(w);
	if (client_hello == NULL)
	{
		ret = ERR_PROTOCOL_ERROR;
		goto LABEL_CLEANUP;
	}
	client_ver = PackGetInt(client_hello, "MvpnProtocolVersion");
	if (client_ver < MVPN_VERSION_MIN)
	{
		ret = ERR_PROTOCOL_ERROR;
		goto LABEL_CLEANUP;
	}
	server_ver = MIN(MVPN_VERSION_CURRENT, client_ver);
	if (PackGetData2(client_hello, "Nonce", client_nonce, 128) == false)
	{
		ret = ERR_PROTOCOL_ERROR;
		goto LABEL_CLEANUP;
	}
	if (PackGetStr(client_hello, "Implementation", client_impl, sizeof(client_impl)) == false)
	{
		ret = ERR_PROTOCOL_ERROR;
		goto LABEL_CLEANUP;
	}
	heartbeat_interval = PackGetInt(client_hello, "HeartBeatInterval");

	if (heartbeat_interval == 0) heartbeat_interval = MVPN_HEARTBEAT_INTERVAL_DEFAULT;
	heartbeat_interval = MAKESURE(heartbeat_interval, MVPN_HEARTBEAT_INTERVAL_MIN, MVPN_HEARTBEAT_INTERVAL_MAX);

	disconnect_timeout = PackGetInt(client_hello, "DisconnectTimeout");
	if (disconnect_timeout == 0) disconnect_timeout = MVPN_DISCONNECT_TIMEOUT_DEFAULT;
	disconnect_timeout = MAKESURE(disconnect_timeout, MVPN_DISCONNECT_TIMEOUT_MIN, MVPN_DISCONNECT_TIMEOUT_MAX);

	heartbeat_interval = MIN(heartbeat_interval, disconnect_timeout / 2);

	use_udp_acceleration = PackGetBool(client_hello, "UseUdpAcceleration");
	if (use_udp_acceleration)
	{
		client_udp_acceleration_port = PackGetInt(client_hello, "UdpAccelerationClientPort");
		if (client_udp_acceleration_port == 0 ||
			PackGetIp(client_hello, "UdpAccelerationClientIp", &client_udp_acceleration_ip) == false ||
			PackGetData2(client_hello, "UdpAccelerationClientKey", client_udp_acceleration_key, sizeof(client_udp_acceleration_key)) == false)
		{
			use_udp_acceleration = false;
		}
	}


	Zero(client_hub_name, sizeof(client_hub_name));
	PackGetStr(client_hello, "NetworkName", client_hub_name, sizeof(client_hub_name));

	l3_ipv4_enable = PackGetBool(client_hello, "L3HelperIPv4Enable");
	if (l3_ipv4_enable)
	{
		char tmp[256];
		bool ok = false;

		PackGetStr(client_hello, "L3HelperIPv4AddressType", tmp, sizeof(tmp));

		if (StrCmpi(tmp, MVPN_ADDRESS_TYPE_STATIC) == 0)
		{
			// Static IP address
			l3_ipv4_dynamic = false;

			if (PackGetIp(client_hello, "L3HelperIPv4Address", &l3_ipv4_ip) &&
				PackGetIp(client_hello, "L3HelperIPv4SubnetMask", &l3_ipv4_mask) &&
				PackGetIp(client_hello, "L3HelperIPv4Gateway", &l3_ipv4_gw))
			{
				ok = true;
			}
		}
		else if (StrCmpi(tmp, MVPN_ADDRESS_TYPE_DYNAMIC) == 0)
		{
			// Dynamic IP address
			l3_ipv4_dynamic = true;
			ok = true;
		}

		if (ok == false)
		{
			ret = ERR_PROTOCOL_ERROR;
			goto LABEL_CLEANUP;
		}
	}

	// Phase 2: Send a Server Hello packet
	server_hello = WsNewErrorPack(ERR_NO_ERROR);
	StrCpy(server_impl, sizeof(server_impl), "Test Server");
	PackAddInt(server_hello, "MvpnProtocolVersion", server_ver);
	PackAddData(server_hello, "Nonce", server_nonce, 128);
	PackAddStr(server_hello, "Implementation", server_impl);
	PackAddStr(server_hello, "SupportedAuthMethod", MVPN_AUTHTYPE_ALL_SUPPORTED);
	if (WsSendPack(w, server_hello) == false)
	{
		ret = ERR_DISCONNECTED;
		goto LABEL_CLEANUP;
	}

	// Phase 3: Receive a Client Auth packet
	for (i = 0;i < MVPN_MAX_AUTH_RETRY;i++)
	{
		bool auth_finish = false;
		PACK *client_auth = NULL;
		char auth_method[64] = {0};
		char auth_username[MAX_USERNAME_LEN + 1];
		IPC *ipc_tmp = NULL;
		IPC_PARAM ipc_param;
		UINT ipc_error_code = 0;
		UINT mss = INFINITE;

		auth_ret = ERR_INTERNAL_ERROR;

		client_auth = WsRecvPack(w);
		if (client_auth == NULL)
		{
			auth_ret = ERR_PROTOCOL_ERROR;
			goto LABEL_EXIT_AUTH_RETRY;
		}

		PackGetStr(client_auth, "AuthMethod", auth_method, sizeof(auth_method));
		if (IsEmptyStr(auth_method))
		{
			auth_ret = ERR_PROTOCOL_ERROR;
			goto LABEL_EXIT_AUTH_RETRY;
		}

		PackGetStr(client_auth, "AuthUsername", auth_username, sizeof(auth_username));
		if (IsEmptyStr(auth_method))
		{
			auth_ret = ERR_PROTOCOL_ERROR;
			goto LABEL_EXIT_AUTH_RETRY;
		}

		Zero(&ipc_param, sizeof(ipc_param));
		StrCpy(ipc_param.ClientName, sizeof(ipc_param.ClientName), MVPN_CLIENT_NAME);

		if (IsEmptyStr(client_impl) == false)
		{
			StrCat(ipc_param.ClientName, sizeof(ipc_param.ClientName), " - ");
			StrCat(ipc_param.ClientName, sizeof(ipc_param.ClientName), client_impl);
		}

		StrCpy(ipc_param.Postfix, sizeof(ipc_param.Postfix), NVPN_POSTFIX);
		StrCpy(ipc_param.HubName, sizeof(ipc_param.HubName), client_hub_name);
		StrCpy(ipc_param.UserName, sizeof(ipc_param.UserName), auth_username);
		CopyIP(&ipc_param.ClientIp, &w->Sock->RemoteIP);
		ipc_param.ClientPort = w->Sock->RemotePort;
		CopyIP(&ipc_param.ServerIp, &w->Sock->LocalIP);
		ipc_param.ServerPort = w->Sock->LocalPort;
		StrCpy(ipc_param.ClientHostname, sizeof(ipc_param.ClientHostname), w->Sock->RemoteHostname);
		StrCpy(ipc_param.CryptName, sizeof(ipc_param.CryptName), w->Sock->CipherName);
		ipc_param.Layer = IPC_LAYER_3; // TODO
		ipc_param.BridgeMode = false; // TODO

		// MSS
		if (udp_accel != NULL) mss = MIN(mss, UdpAccelCalcMss(udp_accel));
		if (mss == INFINITE)
		{
			mss = 0;
		}
		ipc_param.Mss = mss;

		if (StrCmpi(auth_method, MVPN_AUTHTYPE_ANONYMOUS) == 0)
		{
			// Anonymous
		}
		else if (StrCmpi(auth_method, MVPN_AUTHTYPE_PASSWORD_PLAIN) == 0)
		{
			// Plaintext
			char pw[MAX_PASSWORD_LEN + 1];
			PackGetStr(client_auth, "AuthPlainPassword", pw, sizeof(pw));
			StrCpy(ipc_param.Password, sizeof(ipc_param.Password), pw);
		}
		else
		{
			// Unknown auth method
			auth_ret = ERR_AUTHTYPE_NOT_SUPPORTED;
			goto LABEL_EXIT_AUTH_RETRY;
		}

		ipc_tmp = NewIPCByParam(c->Cedar, &ipc_param, &ipc_error_code);

		if (ipc_tmp == NULL)
		{
			auth_ret = ipc_error_code;
			goto LABEL_EXIT_AUTH_RETRY;
		}
		else
		{
			ipc = ipc_tmp;
			auth_finish = true;
		}

		auth_ret = ERR_NO_ERROR;

LABEL_EXIT_AUTH_RETRY:
		if (auth_ret != ERR_NO_ERROR)
		{
			// Phase 4: Send a Server Auth Response
			PACK *error_pack = WsNewErrorPack(auth_ret);
			UINT remain_retry = MVPN_MAX_AUTH_RETRY - 1 - i;
			PackAddInt(error_pack, "RetryAllowedCount", remain_retry);
			WsSendPack(w, error_pack);
			FreePack(error_pack);
		}
		FreePack(client_auth);
		if (auth_finish)
		{
			break;
		}
	}

	if (ipc != NULL)
	{
		AddProtocolDetailsStr(ipc->IpcSessionShared->ProtocolDetails, sizeof(ipc->IpcSessionShared->ProtocolDetails),
			"ModernVPN");
		AddProtocolDetailsKeyValueStr(ipc->IpcSessionShared->ProtocolDetails, sizeof(ipc->IpcSessionShared->ProtocolDetails),
			"Transport", "TCP_WebSocket");
	}

	if (ipc != NULL && l3_ipv4_enable)
	{
		// L3 IPv4 helper is enabled
		if (l3_ipv4_dynamic == false)
		{
			// Static IP
			IPCSetIPv4Parameters(ipc, &l3_ipv4_ip, &l3_ipv4_mask,
				&l3_ipv4_gw, NULL);
		}
		else
		{
			// Dynamic IP
			DHCP_OPTION_LIST cao;

			Zero(&cao, sizeof(cao));

			if (IPCDhcpAllocateIP(ipc, &cao, NULL) == false)
			{
				// DHCP alloc failed
				ret = ERR_DHCP_SERVER_NOT_RUNNING;
				goto LABEL_CLEANUP;
			}

			l3_ipv4_dhcp_allocated = true;

			UINTToIP(&l3_ipv4_dhcp_server, cao.ServerAddress);

			UINTToIP(&l3_ipv4_ip, cao.ClientAddress);
			UINTToIP(&l3_ipv4_mask, cao.SubnetMask);
			UINTToIP(&l3_ipv4_gw, cao.Gateway);
			UINTToIP(&l3_ipv4_dns1, cao.DnsServer);
			UINTToIP(&l3_ipv4_dns2, cao.DnsServer2);
			UINTToIP(&l3_ipv4_wins1, cao.WinsServer);
			UINTToIP(&l3_ipv4_wins2, cao.WinsServer2);

			BuildClasslessRouteTableStr(l3_ipv4_classless_routes, sizeof(l3_ipv4_classless_routes),
				&cao.ClasslessRoute);

			IPCSetIPv4Parameters(ipc, &l3_ipv4_ip, &l3_ipv4_mask,
				&l3_ipv4_gw, &cao.ClasslessRoute);
		}
	}

	if (ipc != NULL && use_udp_acceleration)
	{
		udp_accel = NewUdpAccel(c->Cedar, (c->FirstSock->IsRUDPSocket ? NULL : &c->FirstSock->LocalIP),
			false, false, false);

		udp_accel->Version = 2;

		udp_accel->FastDetect = true;
		udp_accel->ReadRawFlagMode = true;

		if (UdpAccelInitServer(udp_accel, client_udp_acceleration_key,
			&client_udp_acceleration_ip, client_udp_acceleration_port, NULL) == false)
		{
			FreeUdpAccel(udp_accel);
			udp_accel = NULL;
		}
	}

	if (ipc != NULL)
	{
		// Phase 4: Send auth OK response
		PACK *ok_pack = WsNewErrorPack(ERR_NO_ERROR);
		PackAddInt(ok_pack, "HeartBeatInterval", heartbeat_interval);
		PackAddInt(ok_pack, "DisconnectTimeout", disconnect_timeout);
		PackAddStr(ok_pack, "NetworkName", ipc->HubName);

		if (udp_accel != NULL)
		{
			PackAddBool(ok_pack, "UseUdpAcceleration", true);
			PackAddIp(ok_pack, "UdpAccelerationServerIp", &udp_accel->MyIp);
			PackAddInt(ok_pack, "UdpAccelerationServerPort", udp_accel->MyPort);
			PackAddData(ok_pack, "UdpAccelerationServerKey", udp_accel->MyKey_V2, sizeof(udp_accel->MyKey_V2));
			PackAddInt(ok_pack, "UdpAccelerationServerCookie", udp_accel->MyCookie);
			PackAddInt(ok_pack, "UdpAccelerationClientCookie", udp_accel->YourCookie);
		}
		else
		{
			PackAddBool(ok_pack, "UseUdpAcceleration", false);
		}

		PackAddBool(ok_pack, "L3HelperIPv4Enable", l3_ipv4_enable);

		if (l3_ipv4_enable)
		{
			PackAddStr(ok_pack, "L3HelperIPv4AddressType",
				l3_ipv4_dynamic ? MVPN_ADDRESS_TYPE_DYNAMIC : MVPN_ADDRESS_TYPE_STATIC);
			PackAddIp(ok_pack, "L3HelperIPv4Address", &l3_ipv4_ip);
			PackAddIp(ok_pack, "L3HelperIPv4SubnetMask", &l3_ipv4_mask);
			PackAddIp(ok_pack, "L3HelperIPv4Gateway", &l3_ipv4_gw);
			PackAddIp(ok_pack, "L3HelperIPv4DnsServer1", &l3_ipv4_dns1);
			PackAddIp(ok_pack, "L3HelperIPv4DnsServer2", &l3_ipv4_dns2);
			PackAddIp(ok_pack, "L3HelperIPv4WinsServer1", &l3_ipv4_wins1);
			PackAddIp(ok_pack, "L3HelperIPv4WinsServer2", &l3_ipv4_wins2);
			PackAddStr(ok_pack, "L3HelperIPv4PushedStaticRoutes", l3_ipv4_classless_routes);
		}

		WsSendPack(w, ok_pack);
		FreePack(ok_pack);

		// Session main loop
		if (true)
		{
			SOCK *sock = w->Sock;
			SOCK_EVENT *sock_event = NewSockEvent();
			FIFO *send_fifo = NewFifo();
			FIFO *recv_fifo = NewFifo();
			bool has_error = false;
			UINT magic_number = Endian32(MVPN_PACKET_MAGIC_NUMBER);
			UINT64 last_sent_heartbeat = 0;
			UINT tmp_buf_size = 256000;
			UCHAR *tmp_buf = ZeroMalloc(tmp_buf_size);
			UINT64 last_comm_recv = Tick64();

			SetTimeout(sock, TIMEOUT_INFINITE);
			JoinSockToSockEvent(sock, sock_event);
			if (udp_accel != NULL)
			{
				JoinSockToSockEvent(udp_accel->UdpSock, sock_event);
			}
			IPCSetSockEventWhenRecvL2Packet(ipc, sock_event);

			while (true)
			{
				UINT next_interval = INFINITE;
				UINT send_ret = 0;
				UINT64 now = Tick64();
				UINT r;

				if (udp_accel != NULL)
				{
					UdpAccelSetTick(udp_accel, now);
					UdpAccelPoll(udp_accel);
					ipc->IpcSessionShared->EnableUdpAccel = true;
					ipc->IpcSessionShared->UsingUdpAccel = UdpAccelIsSendReady(udp_accel, true);
				}
				else
				{
					ipc->IpcSessionShared->EnableUdpAccel = false;
					ipc->IpcSessionShared->UsingUdpAccel = false;
				}

				// Send heartbeat
				if (last_sent_heartbeat == 0 || (last_sent_heartbeat + (UINT64)heartbeat_interval) <= now)
				{
					last_sent_heartbeat = now;
					if (FifoSize(send_fifo) <= MAX_BUFFERING_PACKET_SIZE)
					{
						UCHAR packet_type = MVPN_PACKET_TYPE_HEARTBEAT;
						USHORT packet_size = 0;
						WriteFifo(send_fifo, &magic_number, 4);
						WriteFifo(send_fifo, &packet_type, 1);
						WriteFifo(send_fifo, &packet_size, 2);
					}
				}

				// IPC --> send_fifo or UDP accelerator
				if (l3_ipv4_enable == false)
				{
					// Ethernet
					while (true)
					{
						BLOCK *l2_packet = IPCRecvL2(ipc);
						UCHAR packet_type;
						USHORT packet_size;
						if (l2_packet == NULL)
						{
							break;
						}
						if (UdpAccelIsSendReady(udp_accel, true))
						{
							// Send via UDP accelerator
							UdpAccelSend(udp_accel, l2_packet->Buf, l2_packet->Size,
								MVPN_PACKET_TYPE_ETHERNET, udp_accel->MaxUdpPacketSize,
								false);
						}
						else
						{
							// Send via WebSocket
							if (FifoSize(send_fifo) <= MAX_BUFFERING_PACKET_SIZE)
							{
								packet_size = Endian16(l2_packet->Size);
								packet_type = MVPN_PACKET_TYPE_ETHERNET;
								WriteFifo(send_fifo, &magic_number, 4);
								WriteFifo(send_fifo, &packet_type, 1);
								WriteFifo(send_fifo, &packet_size, 2);
								WriteFifo(send_fifo, l2_packet->Buf, (USHORT)l2_packet->Size);
							}
						}
						FreeBlock(l2_packet);
					}
				}
				else
				{
					UINT num = 0;

L_V4_RETRY:
					// IPv4
					IPCProcessL3Events(ipc);

					while (true)
					{
						BLOCK *l3_packet = IPCRecvIPv4(ipc);
						UCHAR packet_type;
						USHORT packet_size;
						if (l3_packet == NULL)
						{
							num++;
							if (num <= 1)
							{
								goto L_V4_RETRY;
							}
							break;
						}
						if (UdpAccelIsSendReady(udp_accel, true))
						{
							// Send via UDP accelerator
							UdpAccelSend(udp_accel, l3_packet->Buf, l3_packet->Size,
								MVPN_PACKET_TYPE_IPV4, udp_accel->MaxUdpPacketSize,
								false);
						}
						else
						{
							// Send via WebSocket
							if (FifoSize(send_fifo) <= MAX_BUFFERING_PACKET_SIZE)
							{
								packet_size = Endian16(l3_packet->Size);
								packet_type = MVPN_PACKET_TYPE_IPV4;
								WriteFifo(send_fifo, &magic_number, 4);
								WriteFifo(send_fifo, &packet_type, 1);
								WriteFifo(send_fifo, &packet_size, 2);
								WriteFifo(send_fifo, l3_packet->Buf, (USHORT)l3_packet->Size);
							}
						}
						FreeBlock(l3_packet);
					}
				}

				// send_fifo --> MVPN Client
				while (FifoSize(send_fifo) >= 1)
				{
					UINT r = WsSendAsync(w, ((UCHAR *)send_fifo->p) + send_fifo->pos, send_fifo->size);
					if (r == 0)
					{
						has_error = true;
						break;
					}
					else if (r == INFINITE)
					{
						break;
					}
					else
					{
						ReadFifo(send_fifo, NULL, r);
					}
				}

				if (WsTrySendAsync(w) == false)
				{
					has_error = true;
				}

				// MVPN Client --> recv_fifo
				while (FifoSize(recv_fifo) <= MAX_BUFFERING_PACKET_SIZE)
				{
					r = WsRecvAsync(w, tmp_buf, tmp_buf_size);
					if (r == 0)
					{
						has_error = true;
						break;
					}
					else if (r == INFINITE)
					{
						break;
					}
					else
					{
						//Debug("recv %u\n", r);
						WriteFifo(recv_fifo, tmp_buf, r);
					}
				}

				// recv_fifo --> IPC
				while (true)
				{
					UINT u32;
					UINT packet_size;
					UCHAR packet_type;
					UCHAR *packet_data;
					if (FifoSize(recv_fifo) < 7)
					{
						break;
					}
					packet_size = READ_USHORT(FifoPtr(recv_fifo) + 5);
					if (FifoSize(recv_fifo) < (7 + packet_size))
					{
						break;
					}

					ReadFifo(recv_fifo, &u32, 4);
					if (u32 != magic_number)
					{
						break;
					}

					ReadFifo(recv_fifo, &packet_type, 1);
					ReadFifo(recv_fifo, NULL, 2);

					packet_data = Malloc(packet_size);

					ReadFifo(recv_fifo, packet_data, packet_size);

					if (packet_type == MVPN_PACKET_TYPE_ETHERNET)
					{
						if (l3_ipv4_enable == false)
						{
							IPCSendL2(ipc, packet_data, packet_size);
						}
					}
					else if (packet_type == MVPN_PACKET_TYPE_IPV4)
					{
						if (l3_ipv4_enable)
						{
							IPCSendIPv4(ipc, packet_data, packet_size);
						}
					}

					Free(packet_data);

					last_comm_recv = now;
				}

				// UDP Accel --> IPC
				if (udp_accel != NULL)
				{
					while (true)
					{
						UINT packet_size;
						UCHAR packet_type;
						UCHAR *packet_data;
						BLOCK *b = GetNext(udp_accel->RecvBlockQueue);
						if (b == NULL)
						{
							break;
						}

						packet_type = b->RawFlagRetUdpAccel;
						packet_data = b->Buf;
						packet_size = b->Size;

						if (packet_type == MVPN_PACKET_TYPE_ETHERNET)
						{
							if (l3_ipv4_enable == false)
							{
								IPCSendL2(ipc, packet_data, packet_size);
							}
						}
						else if (packet_type == MVPN_PACKET_TYPE_IPV4)
						{
							if (l3_ipv4_enable)
							{
								IPCSendIPv4(ipc, packet_data, packet_size);
							}
						}

						FreeBlock(b);
					}
				}

				if (IsIPCConnected(ipc) == false)
				{
					has_error = true;
				}

				if (now > (last_comm_recv + (UINT64)disconnect_timeout))
				{
					has_error = true;
				}

				IPCProcessInterrupts(ipc);

				if (has_error)
				{
					break;
				}

				// Wait until the next event occurs
				next_interval = GetNextIntervalForInterrupt(ipc->Interrupt);
				next_interval = MIN(next_interval, SELECT_TIME);
				next_interval = MIN(next_interval, (UINT)((last_sent_heartbeat + (UINT64)heartbeat_interval) - now));
				WaitSockEvent(sock_event, next_interval);
			}

			ReleaseSockEvent(sock_event);
			ReleaseFifo(send_fifo);
			ReleaseFifo(recv_fifo);
			Free(tmp_buf);
		}
	}

	if (l3_ipv4_dhcp_allocated)
	{
		IPCDhcpFreeIP(ipc, &l3_ipv4_dhcp_server);
		IPCProcessL3Events(ipc);
	}

LABEL_CLEANUP:
	if (ret != ERR_NO_ERROR)
	{
		PACK *ret_pack = WsNewErrorPack(ret);
		WsSendPack(w, ret_pack);
		FreePack(ret_pack);
	}
	FreeUdpAccel(udp_accel);
	FreeIPC(ipc);
	FreePack(client_hello);
	FreePack(server_hello);

	return 0;
}









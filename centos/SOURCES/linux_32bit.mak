# SoftEther VPN Source Code
# 
# Copyright (c) 2012-2015 SoftEther VPN Project at University of Tsukuba, Japan.
# Copyright (c) 2012-2015 Daiyuu Nobori.
# All Rights Reserved.
# 
# http://www.softether.org/
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License version 2
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# 
# Platform: os=Linux, bits=32bit

# Variables
CC=gcc

OPTIONS_COMPILE_DEBUG=-D_DEBUG -DDEBUG -DUNIX -DUNIX_LINUX -D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64 -I./src/ -I./src/Cedar/ -I./src/Mayaqua/ -g -fsigned-char

OPTIONS_LINK_DEBUG=-g -fsigned-char -lm -ldl -lrt -lpthread -lssl -lcrypto -lreadline -lncurses -lz

OPTIONS_COMPILE_RELEASE=-DNDEBUG -DVPN_SPEED -DUNIX -DUNIX_LINUX -D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64 -I./src/ -I./src/Cedar/ -I./src/Mayaqua/ -O2 -fsigned-char

OPTIONS_LINK_RELEASE=-O2 -fsigned-char -lm -ldl -lrt -lpthread -lssl -lcrypto -lreadline -lncurses -lz

INSTALL_BINDIR=$(DESTDIR)/usr/bin/
INSTALL_VPNSERVER_DIR=$(DESTDIR)/usr/vpnserver/
INSTALL_VPNBRIDGE_DIR=$(DESTDIR)/usr/vpnbridge/
INSTALL_VPNCLIENT_DIR=$(DESTDIR)/usr/vpnclient/
INSTALL_VPNCMD_DIR=$(DESTDIR)/usr/vpncmd/

ifeq ($(DEBUG),YES)
	OPTIONS_COMPILE=$(OPTIONS_COMPILE_DEBUG)
	OPTIONS_LINK=$(OPTIONS_LINK_DEBUG)
else
	OPTIONS_COMPILE=$(OPTIONS_COMPILE_RELEASE)
	OPTIONS_LINK=$(OPTIONS_LINK_RELEASE)
endif

# Files
HEADERS_MAYAQUA=src/Mayaqua/Cfg.h src/Mayaqua/cryptoki.h src/Mayaqua/Encrypt.h src/Mayaqua/FileIO.h src/Mayaqua/intelaes/iaesni.h src/Mayaqua/Internat.h src/Mayaqua/Kernel.h src/Mayaqua/Mayaqua.h src/Mayaqua/MayaType.h src/Mayaqua/Memory.h src/Mayaqua/Microsoft.h src/Mayaqua/Network.h src/Mayaqua/Object.h src/Mayaqua/OS.h src/Mayaqua/Pack.h src/Mayaqua/pkcs11.h src/Mayaqua/pkcs11f.h src/Mayaqua/pkcs11t.h src/Mayaqua/Secure.h src/Mayaqua/Str.h src/Mayaqua/Table.h src/Mayaqua/TcpIp.h src/Mayaqua/Tick64.h src/Mayaqua/Tracking.h src/Mayaqua/TunTap.h src/Mayaqua/Unix.h src/Mayaqua/Win32.h src/Mayaqua/zlib/zconf.h src/Mayaqua/zlib/zlib.h
HEADERS_CEDAR=src/Cedar/Account.h src/Cedar/Admin.h src/Cedar/AzureClient.h src/Cedar/AzureServer.h src/Cedar/Bridge.h src/Cedar/BridgeUnix.h src/Cedar/BridgeWin32.h src/Cedar/Cedar.h src/Cedar/CedarPch.h src/Cedar/CedarType.h src/Cedar/Client.h src/Cedar/CM.h src/Cedar/CMInner.h src/Cedar/Command.h src/Cedar/Connection.h src/Cedar/Console.h src/Cedar/Database.h src/Cedar/DDNS.h src/Cedar/EM.h src/Cedar/EMInner.h src/Cedar/EtherLog.h src/Cedar/Hub.h src/Cedar/Interop_OpenVPN.h src/Cedar/Interop_SSTP.h src/Cedar/IPsec.h src/Cedar/IPsec_EtherIP.h src/Cedar/IPsec_IKE.h src/Cedar/IPsec_IkePacket.h src/Cedar/IPsec_IPC.h src/Cedar/IPsec_L2TP.h src/Cedar/IPsec_PPP.h src/Cedar/IPsec_Win7.h src/Cedar/IPsec_Win7Inner.h src/Cedar/Layer3.h src/Cedar/Link.h src/Cedar/Listener.h src/Cedar/Logging.h src/Cedar/Nat.h src/Cedar/NativeStack.h src/Cedar/netcfgn.h src/Cedar/netcfgx.h src/Cedar/NM.h src/Cedar/NMInner.h src/Cedar/NullLan.h src/Cedar/Protocol.h src/Cedar/Radius.h src/Cedar/Remote.h src/Cedar/Sam.h src/Cedar/SecureInfo.h src/Cedar/SecureNAT.h src/Cedar/SeLowUser.h src/Cedar/Server.h src/Cedar/Session.h src/Cedar/SM.h src/Cedar/SMInner.h src/Cedar/SW.h src/Cedar/SWInner.h src/Cedar/UdpAccel.h src/Cedar/UT.h src/Cedar/VG.h src/Cedar/Virtual.h src/Cedar/VLan.h src/Cedar/VLanUnix.h src/Cedar/VLanWin32.h src/Cedar/WaterMark.h src/Cedar/WebUI.h src/Cedar/Win32Com.h src/Cedar/winpcap/bittypes.h src/Cedar/winpcap/bucket_lookup.h src/Cedar/winpcap/count_packets.h src/Cedar/winpcap/Devioctl.h src/Cedar/winpcap/Gnuc.h src/Cedar/winpcap/ip6_misc.h src/Cedar/winpcap/memory_t.h src/Cedar/winpcap/normal_lookup.h src/Cedar/winpcap/Ntddndis.h src/Cedar/winpcap/Ntddpack.h src/Cedar/winpcap/Packet32.h src/Cedar/winpcap/pcap.h src/Cedar/winpcap/pcap-bpf.h src/Cedar/winpcap/pcap-int.h src/Cedar/winpcap/pcap-stdinc.h src/Cedar/winpcap/pthread.h src/Cedar/winpcap/remote-ext.h src/Cedar/winpcap/sched.h src/Cedar/winpcap/semaphore.h src/Cedar/winpcap/tcp_session.h src/Cedar/winpcap/time_calls.h src/Cedar/winpcap/tme.h src/Cedar/winpcap/Win32-Extensions.h src/Cedar/WinUi.h src/Cedar/Wpc.h
OBJECTS_MAYAQUA=tmp/objs/Mayaqua/Cfg.o tmp/objs/Mayaqua/Encrypt.o tmp/objs/Mayaqua/FileIO.o tmp/objs/Mayaqua/Internat.o tmp/objs/Mayaqua/Kernel.o tmp/objs/Mayaqua/Mayaqua.o tmp/objs/Mayaqua/Memory.o tmp/objs/Mayaqua/Microsoft.o tmp/objs/Mayaqua/Network.o tmp/objs/Mayaqua/Object.o tmp/objs/Mayaqua/OS.o tmp/objs/Mayaqua/Pack.o tmp/objs/Mayaqua/Secure.o tmp/objs/Mayaqua/Str.o tmp/objs/Mayaqua/Table.o tmp/objs/Mayaqua/TcpIp.o tmp/objs/Mayaqua/Tick64.o tmp/objs/Mayaqua/Tracking.o tmp/objs/Mayaqua/Unix.o tmp/objs/Mayaqua/Win32.o
OBJECTS_CEDAR=tmp/objs/Cedar/Account.o tmp/objs/Cedar/Admin.o tmp/objs/Cedar/AzureClient.o tmp/objs/Cedar/AzureServer.o tmp/objs/Cedar/Bridge.o tmp/objs/Cedar/BridgeUnix.o tmp/objs/Cedar/BridgeWin32.o tmp/objs/Cedar/Cedar.o tmp/objs/Cedar/CedarPch.o tmp/objs/Cedar/Client.o tmp/objs/Cedar/CM.o tmp/objs/Cedar/Command.o tmp/objs/Cedar/Connection.o tmp/objs/Cedar/Console.o tmp/objs/Cedar/Database.o tmp/objs/Cedar/DDNS.o tmp/objs/Cedar/EM.o tmp/objs/Cedar/EtherLog.o tmp/objs/Cedar/Hub.o tmp/objs/Cedar/Interop_OpenVPN.o tmp/objs/Cedar/Interop_SSTP.o tmp/objs/Cedar/IPsec.o tmp/objs/Cedar/IPsec_EtherIP.o tmp/objs/Cedar/IPsec_IKE.o tmp/objs/Cedar/IPsec_IkePacket.o tmp/objs/Cedar/IPsec_IPC.o tmp/objs/Cedar/IPsec_L2TP.o tmp/objs/Cedar/IPsec_PPP.o tmp/objs/Cedar/IPsec_Win7.o tmp/objs/Cedar/Layer3.o tmp/objs/Cedar/Link.o tmp/objs/Cedar/Listener.o tmp/objs/Cedar/Logging.o tmp/objs/Cedar/Nat.o tmp/objs/Cedar/NativeStack.o tmp/objs/Cedar/NM.o tmp/objs/Cedar/NullLan.o tmp/objs/Cedar/Protocol.o tmp/objs/Cedar/Radius.o tmp/objs/Cedar/Remote.o tmp/objs/Cedar/Sam.o tmp/objs/Cedar/SecureInfo.o tmp/objs/Cedar/SecureNAT.o tmp/objs/Cedar/SeLowUser.o tmp/objs/Cedar/Server.o tmp/objs/Cedar/Session.o tmp/objs/Cedar/SM.o tmp/objs/Cedar/SW.o tmp/objs/Cedar/UdpAccel.o tmp/objs/Cedar/UT.o tmp/objs/Cedar/VG.o tmp/objs/Cedar/Virtual.o tmp/objs/Cedar/VLan.o tmp/objs/Cedar/VLanUnix.o tmp/objs/Cedar/VLanWin32.o tmp/objs/Cedar/WaterMark.o tmp/objs/Cedar/WebUI.o tmp/objs/Cedar/WinUi.o tmp/objs/Cedar/Wpc.o
HAMCORE_FILES=src/bin/hamcore/backup_dir_readme.txt src/bin/hamcore/empty.config src/bin/hamcore/empty_sevpnclient.config src/bin/hamcore/eula.txt src/bin/hamcore/install_src.dat src/bin/hamcore/lang.config src/bin/hamcore/languages.txt src/bin/hamcore/legal.txt src/bin/hamcore/openvpn_readme.pdf src/bin/hamcore/openvpn_readme.txt src/bin/hamcore/openvpn_sample.ovpn src/bin/hamcore/SOURCES_OF_BINARY_FILES.TXT src/bin/hamcore/strtable_cn.stb src/bin/hamcore/strtable_en.stb src/bin/hamcore/strtable_ja.stb src/bin/hamcore/vpnweb_sample_cn.htm src/bin/hamcore/vpnweb_sample_en.htm src/bin/hamcore/vpnweb_sample_ja.htm src/bin/hamcore/warning_cn.txt src/bin/hamcore/warning_en.txt src/bin/hamcore/warning_ja.txt src/bin/hamcore/webui/cryptcom.cgi src/bin/hamcore/webui/edituser.cgi src/bin/hamcore/webui/error.cgi src/bin/hamcore/webui/hub.cgi src/bin/hamcore/webui/license.cgi src/bin/hamcore/webui/listener.cgi src/bin/hamcore/webui/localbridge.cgi src/bin/hamcore/webui/login.cgi src/bin/hamcore/webui/newhub.cgi src/bin/hamcore/webui/redirect.cgi src/bin/hamcore/webui/securenat.cgi src/bin/hamcore/webui/server.cgi src/bin/hamcore/webui/session.cgi src/bin/hamcore/webui/user.cgi src/bin/hamcore/webui/webui.css

# Build Action
default:	build

build:	$(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR) bin/vpnserver/vpnserver bin/vpnclient/vpnclient bin/vpnbridge/vpnbridge bin/vpncmd/vpncmd

# Mayaqua Kernel Code
tmp/objs/Mayaqua/Cfg.o: src/Mayaqua/Cfg.c $(HEADERS_MAYAQUA)
	@mkdir -p tmp/
	@mkdir -p tmp/objs/
	@mkdir -p tmp/objs/Mayaqua/
	@mkdir -p tmp/objs/Cedar/
	@mkdir -p tmp/as/
	@mkdir -p bin/
	@mkdir -p bin/vpnserver/
	@mkdir -p bin/vpnclient/
	@mkdir -p bin/vpnbridge/
	@mkdir -p bin/vpncmd/
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Cfg.c -o tmp/objs/Mayaqua/Cfg.o

tmp/objs/Mayaqua/Encrypt.o: src/Mayaqua/Encrypt.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Encrypt.c -o tmp/objs/Mayaqua/Encrypt.o

tmp/objs/Mayaqua/FileIO.o: src/Mayaqua/FileIO.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/FileIO.c -o tmp/objs/Mayaqua/FileIO.o

tmp/objs/Mayaqua/Internat.o: src/Mayaqua/Internat.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Internat.c -o tmp/objs/Mayaqua/Internat.o

tmp/objs/Mayaqua/Kernel.o: src/Mayaqua/Kernel.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Kernel.c -o tmp/objs/Mayaqua/Kernel.o

tmp/objs/Mayaqua/Mayaqua.o: src/Mayaqua/Mayaqua.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Mayaqua.c -o tmp/objs/Mayaqua/Mayaqua.o

tmp/objs/Mayaqua/Memory.o: src/Mayaqua/Memory.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Memory.c -o tmp/objs/Mayaqua/Memory.o

tmp/objs/Mayaqua/Microsoft.o: src/Mayaqua/Microsoft.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Microsoft.c -o tmp/objs/Mayaqua/Microsoft.o

tmp/objs/Mayaqua/Network.o: src/Mayaqua/Network.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Network.c -o tmp/objs/Mayaqua/Network.o

tmp/objs/Mayaqua/Object.o: src/Mayaqua/Object.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Object.c -o tmp/objs/Mayaqua/Object.o

tmp/objs/Mayaqua/OS.o: src/Mayaqua/OS.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/OS.c -o tmp/objs/Mayaqua/OS.o

tmp/objs/Mayaqua/Pack.o: src/Mayaqua/Pack.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Pack.c -o tmp/objs/Mayaqua/Pack.o

tmp/objs/Mayaqua/Secure.o: src/Mayaqua/Secure.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Secure.c -o tmp/objs/Mayaqua/Secure.o

tmp/objs/Mayaqua/Str.o: src/Mayaqua/Str.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Str.c -o tmp/objs/Mayaqua/Str.o

tmp/objs/Mayaqua/Table.o: src/Mayaqua/Table.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Table.c -o tmp/objs/Mayaqua/Table.o

tmp/objs/Mayaqua/TcpIp.o: src/Mayaqua/TcpIp.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/TcpIp.c -o tmp/objs/Mayaqua/TcpIp.o

tmp/objs/Mayaqua/Tick64.o: src/Mayaqua/Tick64.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Tick64.c -o tmp/objs/Mayaqua/Tick64.o

tmp/objs/Mayaqua/Tracking.o: src/Mayaqua/Tracking.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Tracking.c -o tmp/objs/Mayaqua/Tracking.o

tmp/objs/Mayaqua/Unix.o: src/Mayaqua/Unix.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Unix.c -o tmp/objs/Mayaqua/Unix.o

tmp/objs/Mayaqua/Win32.o: src/Mayaqua/Win32.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Win32.c -o tmp/objs/Mayaqua/Win32.o

# Cedar Communication Module Code
tmp/objs/Cedar/Account.o: src/Cedar/Account.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Account.c -o tmp/objs/Cedar/Account.o

tmp/objs/Cedar/Admin.o: src/Cedar/Admin.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Admin.c -o tmp/objs/Cedar/Admin.o

tmp/objs/Cedar/AzureClient.o: src/Cedar/AzureClient.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/AzureClient.c -o tmp/objs/Cedar/AzureClient.o

tmp/objs/Cedar/AzureServer.o: src/Cedar/AzureServer.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/AzureServer.c -o tmp/objs/Cedar/AzureServer.o

tmp/objs/Cedar/Bridge.o: src/Cedar/Bridge.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) src/Cedar/BridgeUnix.c
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Bridge.c -o tmp/objs/Cedar/Bridge.o

tmp/objs/Cedar/BridgeUnix.o: src/Cedar/BridgeUnix.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/BridgeUnix.c -o tmp/objs/Cedar/BridgeUnix.o

tmp/objs/Cedar/BridgeWin32.o: src/Cedar/BridgeWin32.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/BridgeWin32.c -o tmp/objs/Cedar/BridgeWin32.o

tmp/objs/Cedar/Cedar.o: src/Cedar/Cedar.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Cedar.c -o tmp/objs/Cedar/Cedar.o

tmp/objs/Cedar/CedarPch.o: src/Cedar/CedarPch.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/CedarPch.c -o tmp/objs/Cedar/CedarPch.o

tmp/objs/Cedar/Client.o: src/Cedar/Client.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Client.c -o tmp/objs/Cedar/Client.o

tmp/objs/Cedar/CM.o: src/Cedar/CM.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/CM.c -o tmp/objs/Cedar/CM.o

tmp/objs/Cedar/Command.o: src/Cedar/Command.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Command.c -o tmp/objs/Cedar/Command.o

tmp/objs/Cedar/Connection.o: src/Cedar/Connection.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Connection.c -o tmp/objs/Cedar/Connection.o

tmp/objs/Cedar/Console.o: src/Cedar/Console.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Console.c -o tmp/objs/Cedar/Console.o

tmp/objs/Cedar/Database.o: src/Cedar/Database.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Database.c -o tmp/objs/Cedar/Database.o

tmp/objs/Cedar/DDNS.o: src/Cedar/DDNS.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/DDNS.c -o tmp/objs/Cedar/DDNS.o

tmp/objs/Cedar/EM.o: src/Cedar/EM.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/EM.c -o tmp/objs/Cedar/EM.o

tmp/objs/Cedar/EtherLog.o: src/Cedar/EtherLog.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/EtherLog.c -o tmp/objs/Cedar/EtherLog.o

tmp/objs/Cedar/Hub.o: src/Cedar/Hub.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Hub.c -o tmp/objs/Cedar/Hub.o

tmp/objs/Cedar/Interop_OpenVPN.o: src/Cedar/Interop_OpenVPN.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Interop_OpenVPN.c -o tmp/objs/Cedar/Interop_OpenVPN.o

tmp/objs/Cedar/Interop_SSTP.o: src/Cedar/Interop_SSTP.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Interop_SSTP.c -o tmp/objs/Cedar/Interop_SSTP.o

tmp/objs/Cedar/IPsec.o: src/Cedar/IPsec.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/IPsec.c -o tmp/objs/Cedar/IPsec.o

tmp/objs/Cedar/IPsec_EtherIP.o: src/Cedar/IPsec_EtherIP.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/IPsec_EtherIP.c -o tmp/objs/Cedar/IPsec_EtherIP.o

tmp/objs/Cedar/IPsec_IKE.o: src/Cedar/IPsec_IKE.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/IPsec_IKE.c -o tmp/objs/Cedar/IPsec_IKE.o

tmp/objs/Cedar/IPsec_IkePacket.o: src/Cedar/IPsec_IkePacket.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/IPsec_IkePacket.c -o tmp/objs/Cedar/IPsec_IkePacket.o

tmp/objs/Cedar/IPsec_IPC.o: src/Cedar/IPsec_IPC.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/IPsec_IPC.c -o tmp/objs/Cedar/IPsec_IPC.o

tmp/objs/Cedar/IPsec_L2TP.o: src/Cedar/IPsec_L2TP.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/IPsec_L2TP.c -o tmp/objs/Cedar/IPsec_L2TP.o

tmp/objs/Cedar/IPsec_PPP.o: src/Cedar/IPsec_PPP.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/IPsec_PPP.c -o tmp/objs/Cedar/IPsec_PPP.o

tmp/objs/Cedar/IPsec_Win7.o: src/Cedar/IPsec_Win7.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/IPsec_Win7.c -o tmp/objs/Cedar/IPsec_Win7.o

tmp/objs/Cedar/Layer3.o: src/Cedar/Layer3.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Layer3.c -o tmp/objs/Cedar/Layer3.o

tmp/objs/Cedar/Link.o: src/Cedar/Link.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Link.c -o tmp/objs/Cedar/Link.o

tmp/objs/Cedar/Listener.o: src/Cedar/Listener.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Listener.c -o tmp/objs/Cedar/Listener.o

tmp/objs/Cedar/Logging.o: src/Cedar/Logging.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Logging.c -o tmp/objs/Cedar/Logging.o

tmp/objs/Cedar/Nat.o: src/Cedar/Nat.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Nat.c -o tmp/objs/Cedar/Nat.o

tmp/objs/Cedar/NativeStack.o: src/Cedar/NativeStack.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/NativeStack.c -o tmp/objs/Cedar/NativeStack.o

tmp/objs/Cedar/NM.o: src/Cedar/NM.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/NM.c -o tmp/objs/Cedar/NM.o

tmp/objs/Cedar/NullLan.o: src/Cedar/NullLan.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/NullLan.c -o tmp/objs/Cedar/NullLan.o

tmp/objs/Cedar/Protocol.o: src/Cedar/Protocol.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Protocol.c -o tmp/objs/Cedar/Protocol.o

tmp/objs/Cedar/Radius.o: src/Cedar/Radius.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Radius.c -o tmp/objs/Cedar/Radius.o

tmp/objs/Cedar/Remote.o: src/Cedar/Remote.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Remote.c -o tmp/objs/Cedar/Remote.o

tmp/objs/Cedar/Sam.o: src/Cedar/Sam.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Sam.c -o tmp/objs/Cedar/Sam.o

tmp/objs/Cedar/SecureInfo.o: src/Cedar/SecureInfo.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/SecureInfo.c -o tmp/objs/Cedar/SecureInfo.o

tmp/objs/Cedar/SecureNAT.o: src/Cedar/SecureNAT.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/SecureNAT.c -o tmp/objs/Cedar/SecureNAT.o

tmp/objs/Cedar/SeLowUser.o: src/Cedar/SeLowUser.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/SeLowUser.c -o tmp/objs/Cedar/SeLowUser.o

tmp/objs/Cedar/Server.o: src/Cedar/Server.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Server.c -o tmp/objs/Cedar/Server.o

tmp/objs/Cedar/Session.o: src/Cedar/Session.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Session.c -o tmp/objs/Cedar/Session.o

tmp/objs/Cedar/SM.o: src/Cedar/SM.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/SM.c -o tmp/objs/Cedar/SM.o

tmp/objs/Cedar/SW.o: src/Cedar/SW.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/SW.c -o tmp/objs/Cedar/SW.o

tmp/objs/Cedar/UdpAccel.o: src/Cedar/UdpAccel.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/UdpAccel.c -o tmp/objs/Cedar/UdpAccel.o

tmp/objs/Cedar/UT.o: src/Cedar/UT.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/UT.c -o tmp/objs/Cedar/UT.o

tmp/objs/Cedar/VG.o: src/Cedar/VG.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/VG.c -o tmp/objs/Cedar/VG.o

tmp/objs/Cedar/Virtual.o: src/Cedar/Virtual.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Virtual.c -o tmp/objs/Cedar/Virtual.o

tmp/objs/Cedar/VLan.o: src/Cedar/VLan.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/VLan.c -o tmp/objs/Cedar/VLan.o

tmp/objs/Cedar/VLanUnix.o: src/Cedar/VLanUnix.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/VLanUnix.c -o tmp/objs/Cedar/VLanUnix.o

tmp/objs/Cedar/VLanWin32.o: src/Cedar/VLanWin32.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/VLanWin32.c -o tmp/objs/Cedar/VLanWin32.o

tmp/objs/Cedar/WaterMark.o: src/Cedar/WaterMark.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/WaterMark.c -o tmp/objs/Cedar/WaterMark.o

tmp/objs/Cedar/WebUI.o: src/Cedar/WebUI.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/WebUI.c -o tmp/objs/Cedar/WebUI.o

tmp/objs/Cedar/WinUi.o: src/Cedar/WinUi.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/WinUi.c -o tmp/objs/Cedar/WinUi.o

tmp/objs/Cedar/Wpc.o: src/Cedar/Wpc.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Wpc.c -o tmp/objs/Cedar/Wpc.o

# hamcore.se2 Archive File
src/bin/BuiltHamcoreFiles/unix/hamcore.se2: tmp/hamcorebuilder $(HAMCORE_FILES)
	@mkdir -p src/bin/BuiltHamcoreFiles/unix/
	tmp/hamcorebuilder src/bin/hamcore/ src/bin/BuiltHamcoreFiles/unix/hamcore.se2

# hamcorebuilder Utility
tmp/hamcorebuilder: src/hamcorebuilder/hamcorebuilder.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	@mkdir -p tmp/
	$(CC) $(OPTIONS_COMPILE) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR) src/hamcorebuilder/hamcorebuilder.c $(OPTIONS_LINK) -o tmp/hamcorebuilder

# vpnserver
bin/vpnserver/vpnserver: tmp/as/vpnserver.a bin/vpnserver/hamcore.se2 $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) tmp/as/vpnserver.a $(OPTIONS_LINK) -o bin/vpnserver/vpnserver

tmp/as/vpnserver.a: tmp/objs/vpnserver.o $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	rm -f tmp/as/vpnserver.a
	ar r tmp/as/vpnserver.a $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR) tmp/objs/vpnserver.o
	ranlib tmp/as/vpnserver.a

bin/vpnserver/hamcore.se2: src/bin/BuiltHamcoreFiles/unix/hamcore.se2
	cp src/bin/BuiltHamcoreFiles/unix/hamcore.se2 bin/vpnserver/hamcore.se2

tmp/objs/vpnserver.o: src/vpnserver/vpnserver.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/vpnserver/vpnserver.c -o tmp/objs/vpnserver.o

# vpnclient
bin/vpnclient/vpnclient: tmp/as/vpnclient.a bin/vpnclient/hamcore.se2 $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) tmp/as/vpnclient.a $(OPTIONS_LINK) -o bin/vpnclient/vpnclient

tmp/as/vpnclient.a: tmp/objs/vpnclient.o $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	rm -f tmp/as/vpnclient.a
	ar r tmp/as/vpnclient.a $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR) tmp/objs/vpnclient.o
	ranlib tmp/as/vpnclient.a

bin/vpnclient/hamcore.se2: src/bin/BuiltHamcoreFiles/unix/hamcore.se2
	cp src/bin/BuiltHamcoreFiles/unix/hamcore.se2 bin/vpnclient/hamcore.se2

tmp/objs/vpnclient.o: src/vpnclient/vpncsvc.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/vpnclient/vpncsvc.c -o tmp/objs/vpnclient.o

# vpnbridge
bin/vpnbridge/vpnbridge: tmp/as/vpnbridge.a bin/vpnbridge/hamcore.se2 $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) tmp/as/vpnbridge.a $(OPTIONS_LINK) -o bin/vpnbridge/vpnbridge

tmp/as/vpnbridge.a: tmp/objs/vpnbridge.o $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	rm -f tmp/as/vpnbridge.a
	ar r tmp/as/vpnbridge.a $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR) tmp/objs/vpnbridge.o
	ranlib tmp/as/vpnbridge.a

bin/vpnbridge/hamcore.se2: src/bin/BuiltHamcoreFiles/unix/hamcore.se2
	cp src/bin/BuiltHamcoreFiles/unix/hamcore.se2 bin/vpnbridge/hamcore.se2

tmp/objs/vpnbridge.o: src/vpnbridge/vpnbridge.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/vpnbridge/vpnbridge.c -o tmp/objs/vpnbridge.o

# vpncmd
bin/vpncmd/vpncmd: tmp/as/vpncmd.a bin/vpncmd/hamcore.se2 $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) tmp/as/vpncmd.a $(OPTIONS_LINK) -o bin/vpncmd/vpncmd

tmp/as/vpncmd.a: tmp/objs/vpncmd.o $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	rm -f tmp/as/vpncmd.a
	ar r tmp/as/vpncmd.a $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR) tmp/objs/vpncmd.o
	ranlib tmp/as/vpncmd.a

bin/vpncmd/hamcore.se2: src/bin/BuiltHamcoreFiles/unix/hamcore.se2
	cp src/bin/BuiltHamcoreFiles/unix/hamcore.se2 bin/vpncmd/hamcore.se2

tmp/objs/vpncmd.o: src/vpncmd/vpncmd.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/vpncmd/vpncmd.c -o tmp/objs/vpncmd.o

# Install
install: $(INSTALL_BINDIR)vpnserver $(INSTALL_BINDIR)vpnbridge $(INSTALL_BINDIR)vpnclient $(INSTALL_BINDIR)vpncmd
	@echo
	@echo "--------------------------------------------------------------------"
	@echo "Installation completed successfully."
	@echo
	@echo "Execute 'vpnserver start' to run the SoftEther VPN Server background service."
	@echo "Execute 'vpnbridge start' to run the SoftEther VPN Bridge background service."
	@echo "Execute 'vpnclient start' to run the SoftEther VPN Client background service."
	@echo "Execute 'vpncmd' to run SoftEther VPN Command-Line Utility to configure VPN Server, VPN Bridge or VPN Client."
	@echo "--------------------------------------------------------------------"
	@echo

$(INSTALL_BINDIR)vpnserver: bin/vpnserver/hamcore.se2 bin/vpnserver/vpnserver
	install -d $(INSTALL_VPNSERVER_DIR)
	install -m 600 bin/vpnserver/hamcore.se2 $(INSTALL_VPNSERVER_DIR)hamcore.se2
	install -m 755 bin/vpnserver/vpnserver $(INSTALL_VPNSERVER_DIR)vpnserver
#	echo "#!/bin/sh" > $(INSTALL_BINDIR)vpnserver
#	echo $(INSTALL_VPNSERVER_DIR)vpnserver '"$$@"' >> $(INSTALL_BINDIR)vpnserver
#	echo 'exit $$?' >> $(INSTALL_BINDIR)vpnserver
#	chmod 755 $(INSTALL_BINDIR)vpnserver

$(INSTALL_BINDIR)vpnbridge: bin/vpnbridge/hamcore.se2 bin/vpnbridge/vpnbridge
	install -d $(INSTALL_VPNBRIDGE_DIR)
	install -m 600 bin/vpnbridge/hamcore.se2 $(INSTALL_VPNBRIDGE_DIR)hamcore.se2
	install -m 755 bin/vpnbridge/vpnbridge $(INSTALL_VPNBRIDGE_DIR)vpnbridge
#	echo "#!/bin/sh" > $(INSTALL_BINDIR)vpnbridge
#	echo $(INSTALL_VPNBRIDGE_DIR)vpnbridge '"$$@"' >> $(INSTALL_BINDIR)vpnbridge
#	echo 'exit $$?' >> $(INSTALL_BINDIR)vpnbridge
#	chmod 755 $(INSTALL_BINDIR)vpnbridge

$(INSTALL_BINDIR)vpnclient: bin/vpnclient/hamcore.se2 bin/vpnclient/vpnclient
	install -d $(INSTALL_VPNCLIENT_DIR)
	install -m 600 bin/vpnclient/hamcore.se2 $(INSTALL_VPNCLIENT_DIR)hamcore.se2
	install -m 755 bin/vpnclient/vpnclient $(INSTALL_VPNCLIENT_DIR)vpnclient
#	echo "#!/bin/sh" > $(INSTALL_BINDIR)vpnclient
#	echo $(INSTALL_VPNCLIENT_DIR)vpnclient '"$$@"' >> $(INSTALL_BINDIR)vpnclient
#	echo 'exit $$?' >> $(INSTALL_BINDIR)vpnclient
#	chmod 755 $(INSTALL_BINDIR)vpnclient

$(INSTALL_BINDIR)vpncmd: bin/vpncmd/hamcore.se2 bin/vpncmd/vpncmd
	install -d $(INSTALL_VPNCMD_DIR)
	install -m 600 bin/vpncmd/hamcore.se2 $(INSTALL_VPNCMD_DIR)hamcore.se2
	install -m 755 bin/vpncmd/vpncmd $(INSTALL_VPNCMD_DIR)vpncmd
#	echo "#!/bin/sh" > $(INSTALL_BINDIR)vpncmd
#	echo $(INSTALL_VPNCMD_DIR)vpncmd '"$$@"' >> $(INSTALL_BINDIR)vpncmd
#	echo 'exit $$?' >> $(INSTALL_BINDIR)vpncmd
#	chmod 755 $(INSTALL_BINDIR)vpncmd

# Clean
clean:
	-rm -f $(OBJECTS_MAYAQUA)
	-rm -f $(OBJECTS_CEDAR)
	-rm -f tmp/objs/vpnserver.o
	-rm -f tmp/as/vpnserver.a
	-rm -f bin/vpnserver/vpnserver
	-rm -f bin/vpnserver/hamcore.se2
	-rm -f tmp/objs/vpnclient.o
	-rm -f tmp/as/vpnclient.a
	-rm -f bin/vpnclient/vpnclient
	-rm -f bin/vpnclient/hamcore.se2
	-rm -f tmp/objs/vpnbridge.o
	-rm -f tmp/as/vpnbridge.a
	-rm -f bin/vpnbridge/vpnbridge
	-rm -f bin/vpnbridge/hamcore.se2
	-rm -f tmp/objs/vpncmd.o
	-rm -f tmp/as/vpncmd.a
	-rm -f bin/vpncmd/vpncmd
	-rm -f bin/vpncmd/hamcore.se2
	-rm -f tmp/hamcorebuilder
	-rm -f src/bin/BuiltHamcoreFiles/unix/hamcore.se2

# Help Strings
help:
	@echo "make [DEBUG=YES]"
	@echo "make install"
	@echo "make clean"


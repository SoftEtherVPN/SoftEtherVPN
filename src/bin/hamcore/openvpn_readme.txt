======================================================================

     How to Use the Auto-Generated OpenVPN Configuration Samples
       OpenVPN 用の自動生成された設定サンプルファイルの使い方
                如何使用自动生成的 OpenVPN 配置案例

======================================================================

This document is written in English, Japanese and Simplified-Chinese.
このドキュメントは英語、日本語、中国語 (簡体字) で記載されています。
本文档是英语，日语和简体中文。


*****************************
***                       ***
***        English        ***
***                       ***
*****************************


How to Use the Auto-Generated OpenVPN Configuration Samples
<< !! READ IT CAREFULLY BEFORE YOU USE !! >>


* 1. About Files
When you open the ZIP archive, the following files with the
structured-directory will be expanded.
Extract there files including sub-directory structure toward any destination
directory, and use parts according to your necessary.

< The Configuration File for L3 (IP Routing) >
  openvpn_remote_access_l3.ovpn

< The Configuration File for L2 (Ethernet Bridging) >
  openvpn_site_to_site_bridge_l2.ovpn

The extension ".ovpn" means a configuration file. You can specify the
configuration file into OpenVPN to initiate a VPN connection.


* 2. How Different between L3 and L2?
Use L3 (IP Routing) if you want to install OpenVPN on the normal computer (for
example, a lap top PC), and make it connect to PacketiX VPN Server or SoftEther
VPN Server for the purpose of establishing a "Remote-Access VPN Connection" .
In this case, the IP address will be assigned on the virtual network adapter
of OpenVPN automatically when the OpenVPN will connect to the Virtual HUB on
the VPN Server successfully and request an IP address and other network
parameters (e.g. DNS server address).

In other hand, if you want to build a "Site-to-Site VPN Connection" ,
use L2 (Ethernet Bridging) for OpenVPN on the computer which is set up on the
remote place for bridging. No IP-specific treatment will be done. All Ethernet
packets (MAC frames) will exchanged transparently between two or more sites.
Any computers or network equipments (e.g. routers) will be able to communicate
to other sites mutually.

VPN Server will treat a virtual VPN session from L3-mode OpenVPN as
a "VPN Client" session.
VPN Server will treat a virtual VPN session from L2-mode OpenVPN as
a "VPN Bridge" session.


* 3. How to Specify the Username and Password?
The prompt of username and password will be shown when you try to use this
configuration. You have to enter the same username and password which has
already been defined on the Virtual HUB of VPN Server.

Please note that you have to create an user on the Virtual HUB in advance.

If there are two or more Virtual HUBs on the VPN Server, you have to specify
the username as:

  "Username@Virtual-HUB-Name"

or:

  "Virtual-HUB-Name\Username"

to choose which Virtual HUB to be connected. You can also choose which
Virtual HUB should be elected as a "Default HUB" when the specification of
the name of Virtual HUB will be omitted.

Please be advised that you can make OpenVPN to enter the username and password
automatically without showing a prompt. How to do it is described on the
OpenVPN manual.


* 4. About Protocol and Port Number
Both TCP and UDP are available to connect to the VPN Server by OpenVPN.

If you use TCP, the port number is same as any of the "TCP Listener Port" on
the VPN Server which is originally defined in order to accept inbound
TCP-based VPN Client session.

If you use UDP, the port number must be one of UDP ports which are defined on
the VPN Server configuration in advance. Do not confuse between TCP and UDP
since they are not concerned mutually.

You can also specify the proxy-server address if the connection should be
relayed by the proxy-server. Specify it on the configuration file.


* 5. Closing
OpenVPN is independent software from PacketiX VPN / SoftEther VPN.
It is an open-source application which was developer by third-party.
Refer to http://openvpn.net/ if you need more how to use OpenVPN.



*****************************
***                       ***
***   Japanese (日本語)   ***
***                       ***
*****************************

OpenVPN 用の自動生成された設定サンプルファイルの使い方
<< !! 使用前に必ずお読みください !! >>


* 1. ファイル構成
ZIP ファイルを開くと、以下のようなディレクトリ構造のファイルが出力されます。
これらのファイルをすべてサブフォルダごと任意のディレクトリに展開し、必要な
ファイルをお使いください。

< L3 (IP ルーティング) 用の接続設定 >
  openvpn_remote_access_l3.ovpn

< L2 (Ethernet ブリッジ) 用の接続設定 >
  openvpn_site_to_site_bridge_l2.ovpn

拡張子が .ovpn のファイルが接続設定の本体です。このファイルを OpenVPN
プログラムに指定して OpenVPN 接続を始動してください。


* 2. L3 と L2 の違い
普通のコンピュータ (ラップトップ PC など) に OpenVPN をインストールし、
そのコンピュータを PacketiX VPN Server / SoftEther VPN Server に
リモートアクセス VPN 接続する場合は、L3 (IP ルーティング) 用の接続設定
を使用してください。この場合は、接続先の仮想 HUB に接続を試行し、
仮想 HUB のセグメントからアクセスすることができる DHCP サーバーから
IP アドレスの取得を試み、取得に成功した IP アドレスや DNS サーバーなど
のネットワーク情報がクライアント PC の仮想 LAN カードに自動的に割当てられ
ます。

一方、拠点間接続 VPN を構築する場合は、遠隔拠点に設置する VPN ブリッジ用
のコンピュータ上で動作させる OpenVPN には L2 (Ethernet ブリッジ) 用の
接続設定を使用してください。この場合は、IP に特化した処理は一切行われま
せん。すべての Ethernet パケット (MAC フレーム) が拠点間で相互に透過的に
交換されることになります。両方の拠点の Ethernet セグメントに接続されている
すべてのコンピュータやルータなどの通信機器同士は自由に通信することができる
ようになります。

L3 モードで接続する場合は、VPN Server はその接続を「VPN Client」ソフトウェア
からの接続と同一のものと見なした振る舞いをします。

L2 モードで接続する場合は、VPN Server はその接続を「VPN Bridge」ソフトウェア
からの接続と同一のものと見なした振る舞いをします。


* 3. 接続時に指定するべきユーザー名とパスワードについて
このサンプル設定ファイルを用いて VPN Server に接続しようとすると、
ユーザー名とパスワードの入力が要求されます。ここで入力すべきユーザー名と
パスワードは、接続先の VPN Server の仮想 HUB に登録されているユーザー名と
パスワードと同一のものです。

OpenVPN の接続を受付けるためには、あらかじめ仮想 HUB にユーザーを登録して
おく必要があります。

なお、VPN Server に 2 個以上の仮想 HUB が設置されている場合は、ユーザー名
の指定方法として、

   "ユーザー名@仮想 HUB 名"

あるいは

   "仮想 HUB 名\ユーザー名"

のように指定してください。
この場合において、仮想 HUB 名を省略した場合に標準で選択されるべきデフォルト
の仮想 HUB をあらかじめ VPN Server 側の設定において指定しておくことも可能です。

ユーザー名とパスワードの入力を毎回行うことが困難な場合は、代わりに
設定ファイルおよび外部テキストファイルにユーザー名とパスワードを記載して自動的
に入力させるようにすることもできます。そのための方法は OpenVPN のマニュアルを
参照してください。


* 4. プロトコルやポート番号について
接続先の VPN Server に対して通信を行うためのプロトコルには TCP と UDP があり、
どちらも利用可能です。

TCP を利用する場合は、ポート番号は VPN Server が正規の VPN Client ソフトウェア
に対してサービスを提供するための TCP リスナポートと同一です。もしリスナポート
が複数定義されている場合は、いずれのリスナポートにも OpenVPN プロトコルで接続
できます。

UDP を利用する場合は、ポート番号はあらかじめ VPN Server 側で指定されている
UDP ポート番号を指定する必要があります。TCP と UDP のポート番号は互いに無関係
ですので、混乱しないようにしてください。

TCP を利用する場合でプロキシサーバーを利用する場合は、そのための設定を設定
ファイルに追加する必要があります。


* 5. 最後に
OpenVPN は PacketiX VPN / SoftEther VPN とは独立した、サードパーティによって
開発されたオープンソースのプログラムです。OpenVPN の使い方については、
http://openvpn.net/ を参照してください。



*****************************
***                       ***
***  Chinese (简体中文)   ***
***                       ***
*****************************

如何使用自动生成的 OpenVPN 配置案例
<< !! 使用前请仔细阅读 !! >>


* 1. 关于文件
当您打开 ZIP 压缩包, 以下文件结构目录将被展现。
解压缩这些文件, 包括子目录结构到任何目的地目录, 并使用你需要的部分。

< The Configuration File for L3 (IP Routing) >
  openvpn_remote_access_l3.ovpn

< The Configuration File for L2 (Ethernet Bridging) >
  openvpn_site_to_site_bridge_l2.ovpn

扩展名 ".ovpn" 表示一个配置文件。您可以指定配置文件到 OpenVPN 来发起一个
VPN 连接。


* 2. L3 和 L2 之间有什么不同 ?
如果你想在普通电脑上安装 OpenVPN (例如, 笔记本电脑), 使用 L3 (IP 路由)
并使其连接到 PacketiX VPN 服务器或 SoftEther VPN 服务器以建立 "远程访问
VPN 连接" 的目的。
在这种情况下, 当 OpenVPN 成功连接到 VPN 服务器的虚拟 HUB 并请求一个 IP
地址和其他网络参数 (如 DNS 服务器地址) 时,
IP 地址将被自动分配到 OpenVPN 的虚拟网卡上。

另一方面, 如果你想建立一个 "站点到站点的 VPN 连接" , 在远程地点要建立桥接的
那台电脑上使用 OpenVPN L2 (以太网桥)。
不需要进行具体的 IP 操作。所有的以太网数据包 (MAC 帧) 将在两个或多个站点之
间透明地交换。
任何电脑或网络设备 (如路由器) 能够与其他站点相互通信。

VPN 服务器将把 OpenVPN L3 模式的虚拟 VPN 会话当作一个 "VPN 客户端" 会话。
VPN 服务器将把 OpenVPN L2 模式的虚拟 VPN 会话当作一个 "VPN桥" 会话。


* 3. 如何指定用户名和密码 ?
当您尝试使用此配置时, 会出现输入用户名和密码的提示。
您应输入已在 VPN 服务器的虚拟 HUB 上定义好的、相同的用户名和密码。

请注意, 您必须提前在虚拟 HUB 上创建一个用户。

如果在 VPN 服务器上有两个或多个虚拟 HUB, 你应指定用户名为:

  "Username@Virtual-HUB-Name"

或:

  "Virtual-HUB-Name\Username"

选择要连接的虚拟 HUB。当虚拟 HUB 的名称参数被省略时, 您也可以选择作为
"默认 HUB" 的虚拟 HUB。

请注意, 您可以使 OpenVPN 自动输入用户名和密码, 而不显示提示信息。
如何做到这一点, 在 OpenVPN 手册中有描述。


* 4. 关于协议和端口号
通过 OpenVPN,TCP 和 UDP 都可以连接到 VPN 服务器。

如果您使用 TCP, 端口号与为了接受入站的、基于 TCP 的、VPN 客户端会话而在
VPN 服务器上最初定义好的任一 "TCP 侦听端口" 相同。

如果您使用 UDP, 端口号必须是预先在 VPN 服务器配置时定义好的 UDP 端口之一。
不要混淆 TCP 和 UDP, 因为它们是互不相关的。

如果连接需要通过代理服务器中转, 您还可以指定代理服务器地址。在配置文件中
指定。


* 5. 结束
OpenVPN 对于 PacketiX VPN / SoftEther VPN 是一个独立软件。
它是一个开源应用程序, 由第三方开发。
如果你想知道如何使用 OpenVPN 的更多信息, 请参考 http://openvpn.net/ 。


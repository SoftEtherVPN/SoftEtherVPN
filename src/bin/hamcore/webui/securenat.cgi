<html><head><meta http-equiv="content-type" content="text/html; charset=UTF-8"/>
<title>Virtual HUB page</title>
<link rel=stylesheet type=text/css href=/webui/webui.css>
</head><body>

<h2>仮想 NAT および仮想 DHCP 機能 (Secure NAT) の設定</h2>

<h3>SecureNAT 機能の有効 / 無効の設定</h3>
<table border=2>
<tr><td>SecureNAT 機能：</td><td>
<!--ENABLESNATa href="{LINK_SECURENAT}?HUB={HUBNAME}&CMD=ENABLE&KEY={SESSIONKEY}"ENABLESNAT-->有効<!--ENABLESNAT/aENABLESNAT-->
<!--DISABLESNATa href="{LINK_SECURENAT}?HUB={HUBNAME}&CMD=DISABLE&KEY={SESSIONKEY}"DISABLESNAT-->無効<!--DISABLESNAT/aDISABLESNAT-->
</td></table>

<h2>SecureNAT オプションの設定</h2>
<form  method="get" action="{LINK_SECURENAT}">
<h3>仮想 ホストの設定</h3>
<table border=2>
<tr><td>MAC アドレス</td><td><input type=text name="HOSTMAC" value="{HOSTMAC}" maxlength="17"></td></tr>
<tr><td>IP アドレス</td><td><input type=text name="HOSTIP" value="{HOSTIP}" maxlength="15"></td></tr>
<tr><td>サブネットマスク</td><td><input type=text name="HOSTMASK" value="{HOSTMASK}" maxlength="15"></td></tr>
</table>

<h3>仮想 NAT の設定</h3>
<input type="checkbox" name="NATCHECK" value="on" {NATCHECK}>仮想 NAT 機能を使用する 
<table border=2>
<tr><td>MTU 値</td><td><input type=text name="NATMTU" value="{NATMTU}">バイト</td></tr>
<tr><td>TCP セッションのタイムアウト</td><td><input type=text name="NATTCPTIMEOUT" value="{NATTCPTIMEOUT}">秒</td></tr>
<tr><td>UDP セッションのタイムアウト</td><td><input type=text name="NATUDPTIMEOUT" value="{NATUDPTIMEOUT}">秒</td></tr>
</table>
<input type=checkbox name="NATSAVELOG" value="on" {NATSAVELOG}>仮想 NAT の動作を、仮想 HUB のセキュリティログに保存する

<h3>仮想 DHCP サーバーの設定</h3>
<input type="checkbox" name="DHCPCHECK" value="on" {DHCPCHECK}>仮想 DHCP サーバー機能を使用する 
<table border=2>
<tr><td>配布 IP アドレス帯</td><td><input type=text name="DHCPIPS" value="{DHCPIPS}">から</td></tr>
<tr><td>				  </td><td><input type=text name="DHCPIPE" value="{DHCPIPE}">まで</td></tr>
<tr><td>サブネットマスク</td><td><input type=text name="DHCPMASK" value="{DHCPMASK}"></td></tr>
<tr><td>リース期限</td><td><input type=text name="DHCPEXPIRE" value="{DHCPEXPIRE}">秒</td></tr>
</table>

<h4>クライアントに割り当てるオプションの設定</h4>
<table border=2>
<tr><td>デフォルトゲートウェイのアドレス</td><td><input type=text name="DHCPGW" value="{DHCPGW}"></td></tr>
<tr><td>DNS サーバーのアドレス</td><td><input type=text name="DHCPDNS" value="{DHCPDNS}"></td></tr>
<tr><td>ドメイン名</td><td><input type=text name="DHCPDOMAIN" value="{DHCPDOMAIN}"></td></tr>
</table>

<input type=hidden name=KEY value="{SESSIONKEY}">
<input type=hidden name=HUB value="{HUBNAME}">
<input type=hidden name=CMD value="SAVE">
<input type=submit value="設定を保存する">
</form>

<p>
<a href="{LINK_HUB}?HUB={HUBNAME}&KEY={SESSIONKEY}">仮想 HUB の管理画面に戻る</a>

</body></html>


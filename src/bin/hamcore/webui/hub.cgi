<html>
<head><meta http-equiv="content-type" content="text/html; charset=UTF-8"/>
<title>Virtual HUB page</title>
<link rel=stylesheet type=text/css href=/webui/webui.css>
</head><body>

<h2>仮想 HUB の管理</h2>


<h3>管理コマンド</h3>
<table>
<tr><td><!--ENABLE_ONLINEa href="{LINK_HUB}?HUB={HUBNAME}&CMD=ONLINE&KEY={SESSIONKEY}"ENABLE_ONLINE-->オンライン<!--ENABLE_ONLINE/aENABLE_ONLINE-->
<!--ENABLE_OFFLINEa href="{LINK_HUB}?HUB={HUBNAME}&CMD=OFFLINE&KEY={SESSIONKEY}"ENABLE_OFFLINE-->オフライン<ENABLE_OFFLINE/aENABLE_OFFLINE--></td></tr>
<tr><td><a href="{LINK_USER}?HUB={HUBNAME}&KEY={SESSIONKEY}">ユーザーの管理</a></td></tr>
<tr><td><a href="{LINK_SECURENAT}?KEY={SESSIONKEY}&HUB={HUBNAME}">仮想 NAT および仮想 DHCP サーバー機能</td></tr>
<tr><td><a href="{LINK_SESSION}?HUB={HUBNAME}&KEY={SESSIONKEY}">セッションの管理</a></td></tr>
</table>


<h3>仮想 HUB の状態</h3>
<table border=2>
<tr><td>仮想 HUB 名</td><td>{HUBNAME}</td></tr>
<tr><td>状態</td><td>{HUBSTATE}</td></tr>
<tr><td>種類</td><td>{HUBTYPE}</td></tr>
<tr><td>SecureNAT 機能</td><td>{HUBSNAT}</td></tr>
<tr><td>セッション数</td><td>{HUBSESSIONS}</td></tr>
<tr><td>アクセスリスト数</td><td>{HUBACLS}</td></tr>
<tr><td>ユーザー数</td><td>{HUBUSERS}</td></tr>
<tr><td>グループ数</td><td>{HUBGROUPS}</td></tr>
<tr><td>MAC テーブルエントリ数</td><td>{HUBMACTBLS}</td></tr>
<tr><td>IP テーブルエントリ数</td><td>{HUBIPTBLS}</td></tr>
<tr><td>ログイン回数</td><td>{HUBLOGINS}</td></tr>
<tr><td>最終ログイン日時</td><td>{HUBLASTLOGIN}</td></tr>
<tr><td>最終通信日時</td><td>{HUBLASTCOMM}</td></tr>
<tr><td>送信ユニキャストパケット数</td><td>{HUBTXUNIPKTS}</td></tr>
<tr><td>送信ユニキャスト合計サイズ</td><td>{HUBTXUNISIZE}</td></tr>
<tr><td>送信ブロードキャストパケット数</td><td>{HUBTXBRPKTS}</td></tr>
<tr><td>送信ブロードキャスト合計サイズ</td><td>{HUBTXBRSIZE}</td></tr>
<tr><td>受信ユニキャストパケット数</td><td>{HUBRXUNIPKTS}</td></tr>
<tr><td>受信ユニキャスト合計サイズ</td><td>{HUBRXUNISIZE}</td></tr>
<tr><td>受信ブロードキャストパケット数</td><td>{HUBRXBRPKTS}</td></tr>
<tr><td>受信ブロードキャスト合計サイズ</td><td>{HUBRXBRSIZE}</td></tr>
</table>

<br>
<a href="{LINK_SERVER}?KEY=SESSIONKEY">サーバーの管理画面に戻る</a>

</body></html>

<!--STRMAP:HUB_ONLINE:オンライン,HUB_OFFLINE:オフライン,SECNAT_ON:有効,SECNAT_OFF:無効:STRMAP-->


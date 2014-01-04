<html><head><meta http-equiv="content-type" content="text/html; charset=UTF-8" />
<title>Server page</title>
<link rel=stylesheet type=text/css href=/webui/webui.css>
</head><body>
<h2>VPN サーバーの管理</h2>

<h3>仮想 HUB の一覧</h3>
<table border=2><tr><td><a href="{LINK_NEWHUB}?KEY={SESSIONKEY}">新規作成</a>
</td><td>仮想 HUB 名</td><td>状態</td><td>種類</td><td>ユーザー</td><td>グループ</td><td>セッション</td>
<td>MAC</td><td>IP</td><td>ログイン回数</td><td>最終ログイン日時</td><td>最終通信日時</td></tr>
<!--HUBS_TMPL:<tr><td><a href="{LINK_HUB}?KEY={SESSIONKEY}&HUB={HUBNAME}&CMD=DELETE">削除</a></td><td><a href="{LINK_HUB}?KEY={SESSIONKEY}&HUB={HUBNAME}">{HUBNAME}</a></td><td>{HUBSTATE}</td><td>{HUBTYPE}</td><td>{HUBUSERS}</td><td>{HUBGROUPS}</td><td>{HUBSESSIONS}</td><td>{HUBMACS}</td><td>{HUBIPS}</td><td>{HUBLOGINS}</td><td>{HUBLASTLOGINDATE}</td><td>{HUBLASTCOMMDATE}</td></tr>:HUBS_TMPL-->
<!--HUBS-->
</table>
<br>
<h3>リスナーの一覧</h3>
<table>
<tr><td>
<table border=2><tr><td>ポート番号</td><td>状態</td><td><a href="{LISTENER_LINK}?KEY={SESSIONKEY}&CMD=CREATE">新規作成</a></td></tr>
<!--LISTENER_TMPL:<tr><td>TCP {PORTNUM}</td><td>{PORT_STATE}</td><td>
<a href="{LISTENER_LINK}?KEY={SESSIONKEY}&CMD=DEL&PORT={PORTNUM}">削除</a>
<!--STARTAa href="{LISTENER_LINK}?KEY={SESSIONKEY}&CMD=START&PORT={PORTNUM}"STARTA-->開始<!--STARTA/aSTARTA-->
<!--STOPAa href="{LISTENER_LINK}?KEY={SESSIONKEY}&CMD=STOP&PORT={PORTNUM}"STOPA-->停止<!--STOPA/aSTOPA--></td></tr>
:LISTENER_TMPL-->
<!--LISTENERS-->
</table>
</td>
<td>
<table border=2>
<!--
<tr><td><a href="{LISTENER_LINK}?KEY={SESSIONKEY}">暗号化とネットワークの設定</a></td></tr>
<tr><td><a href="{LISTENER_LINK}?KEY={SESSIONKEY}">サーバー状態</a></td></tr>
-->
<tr><td><a href="{LINK_LICENSE}?KEY={SESSIONKEY}">ライセンスの管理</a></td></tr>
<tr><td><a href="{LINK_LOCALBRIDGE}?KEY={SESSIONKEY}">ローカルブリッジの設定</a></td></tr>
</table>
</td>
</tr>
</table>

</body></html>

<!--STRMAP:HUB_ONLINE:オンライン,HUB_OFFLINE:オフライン,HUB_STANDALONE:スタンドアロン,HUB_DYNAMIC:ダイナミック,HUB_STATIC:スタティック,LISTENER_ONLINE:動作中,LISTENER_OFFLINE:停止中,LISTENER_ERROR:エラー:STRMAP-->

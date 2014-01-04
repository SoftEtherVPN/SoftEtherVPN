<html><head><meta http-equiv="content-type" content="text/html; charset=UTF-8" />
<title>User page</title>
<link rel=stylesheet type=text/css href=/webui/webui.css>
</head><body>

<h2>仮想 HUB「{HUBNAME}」に接続中のセッション</h2>

<table border=2>
<tr><td>コマンド</td><td>セッション名</td><td>接続しているサーバー</td><td>ユーザー名</td><td>接続元ホスト名</td><td>TCP コネクション</td><td>転送バイト数</td><td>転送パケット数</td></tr>
<!--SESSION_TMPL:<tr><td><a href="{LINK_SESSION}?HUB={HUBNAME}&KEY={SESSIONKEY}&CMD=DEL&SESSION={SESSION}">切断</a></td><td>{SESSION_NAME}</td><td>{SESSION_SERVER}</td><td>{SESSION_USER}</td><td>{SESSION_HOST}</td><td>{SESSION_TCP}</td><td>{SESSION_BYTES}</td><td>{SESSION_PKTS}</td></tr>:SESSION_TMPL-->
<!--SESSIONS-->
</table>
<p>
<a href="{LINK_HUB}?KEY={SESSIONKEY}&HUB={HUBNAME}">仮想 HUB「{HUBNAME}」の管理画面に戻る。</a>
</body></html>


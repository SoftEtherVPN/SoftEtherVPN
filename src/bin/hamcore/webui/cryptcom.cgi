<html><head><meta http-equiv="content-type" content="text/html; charset=UTF-8"/>
<title>Virtual HUB page</title>
<link rel=stylesheet type=text/css href=/webui/webui.css>
</head><body>

<h2>暗号化と通信関係の設定</h2>

<form method="get" action="cryptcom.cgi">

<h3>使用する暗号化アルゴリズム</h3>
暗号化アルゴリズム名<select name="CRYPT" value="{CRYPT}">
<!--CRYPT_TMPL<option value="{CRYPTTYPE}">{CRYPTTYPE}CRYPT_TMPL-->
<!--CRYPTLIST-->
<p/>
<h3>サーバー証明書</h3>
サーバー証明書：{SERVERCERT}
<table>
<tr>
<td>証明書のインポート</td><td>証明書のエクスポート</td><td>証明書の表示</td>
</tr>
</table>

<h3>syslog 送信機能</h3>
<select name="SYSLOG">
<option value="">
</select>

<h3>インターネット接続の維持機能</h3>
<input type="checkbox" CHECKED>インターネット接続の維持機能を使用する
<table border=2>
<tr><td>ホスト名</td><td><input type=text name="HOSTNAME" value="{HOSTNAME}"></td></tr>
<tr><td>ポート番号</td><td><input type=text name="PORTNUM" value="{PORTNUM}"></td></tr>
<tr><td>パケット送出間隔</td><td><input type=text name="INTERVAL" value="{INTERVAL}">秒</td></tr>
プロトコル
<input type="radio" name="proto" value="TCP">TCP/IP <input type="radio" name="proto" value="UDP">UDP/IP
</table>

<h3>管理パスワード</h3>
管理パスワードの変更
<br/>
<tr>
<td><input type=hidden name=KEY value="{SESSIONKEY}"><input type=hidden name=CMD value="SAVE"><input type=submit value="設定を保存する"></td>
</tr>
</form>
<br>
<a href="{LINK_SERVER}?KEY={SESSIONKEY}">サーバーの管理画面に戻る</a>

</body></html>


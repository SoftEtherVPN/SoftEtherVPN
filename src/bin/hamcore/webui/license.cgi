<html><head><meta http-equiv="content-type" content="text/html; charset=UTF-8" />
<title>Virtual HUB page</title>
<link rel=stylesheet type=text/css href=/webui/webui.css>
</head><body>

<h2>ライセンスの追加と削除</h2>

<h3>登録されているライセンスの一覧</h3>
<table border=2>
<tr><td>番号</td><td>ライセンスキー</td><td>ライセンス種類名</td><td>状態</td><td>有効期限</td><td>ライセンス ID</td>
<td>ライセンス種類 ID</td><td>サーバー ID</td><td>シリアル ID</td></tr>
<!--LICENSES_TMPL:<tr><td><a href="{LINK_LICENSE}?KEY={SESSIONKEY}&CMD=DEL&ID={ID}">削除</a></td><td>{LICENSEKEY}</td><td>{LICENSENAME}</td><td>{STATUS}</td><td>{EXPIRES}</td><td>{LICENSEID}</td><td>{PRODUCTID}</td><td>{SYSTEMID}</td><td>{SERIALID}</td></tr>:LICENSES_TMPL-->
<!--LICENSES-->
</table>

<h3>現在の PacketiX VPN Server のライセンスモード</h3>
<table border=2>
<tr><td>製品エディション名</td><td>{LSEDITIONNAME}</td></tr>
<tr><td>現在のサーバー ID</td><td>{LSSERVERID}</td></tr>
<tr><td>現在の製品ライセンスの有効期限</td><td>{LSEXPIRES}</td></tr>
<tr><td>クライアント接続ライセンス数</td><td>{LSNUMCLIENTS}</td></tr>
<tr><td>ブリッジ接続ライセンス数</td><td>{LSNUMBRIDGES}</td></tr>
</table>

<h3>ライセンスの追加</h3>
<form method=get action="{LINK_LICENSE}">
<tr><td>ライセンスキーを入力してください：</td><td><input type=text name="KEYSTRINGS" maxlength="41"></td></tr>
<input type=hidden name=KEY value="{SESSIONKEY}">
<input type=hidden name=CMD value="ADD"><input type=submit value="追加">
</form>

<br>
<a href="{LINK_SERVER}?KEY={SESSIONKEY}">サーバーの管理画面に戻る</a>

</body></html>
<!--STRMAP:NOEXPIRE:無期限,LICENSE_INFINITE:無制限-->

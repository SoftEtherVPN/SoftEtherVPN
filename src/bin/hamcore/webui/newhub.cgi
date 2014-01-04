<html><head><meta http-equiv="content-type" content="text/html; charset=UTF-8" />
<title>Lisner Creation</title>
<link rel=stylesheet type=text/css href=/webui/webui.css>
</head><body>
<h2>新しい仮想 HUB の作成</h2>
<form method=get action="{LINK_NEWHUB}">
<table>
<tr><td>作成する仮想 HUB の名前：</td><td><input type=text name=NAME></td></tr>
<tr><td>管理パスワード：</td><td><input type=password name=PASSWD></td></tr>
<tr><td>管理パスワード（確認）：</td><td><input type=password name=PASSWD2></td></tr>
</table>
<input type=hidden name=KEY value="{SESSIONKEY}">
<input type=hidden name=CMD value="CREATE">
<input type=submit value="作成">
</form>
<a href="{LINK_SERVER}?KEY={SESSIONKEY}">サーバー管理画面に戻る</a>
</body></html>


<html><head><meta http-equiv="content-type" content="text/html; charset=UTF-8" />
<title>User page</title>
<link rel=stylesheet type=text/css href=/webui/webui.css>
</head><body>

<h2>ユーザーの編集</h2>

<form action="{LINK_EDITUSER}" method=get>
<input type=hidden name=KEY value={SESSIONKEY}>
<input type=hidden name=HUB value={HUBNAME}>
<input type=hidden name=CMD value={CMDNAME}>
<!--{USERNAMEHIDDEN}input type=hidden name=USER value={USERNAME}{USERNAMEHIDDEN}-->

<table border=2>
<tr><td>ユーザー名：</td><td>{USERNAME}<!--{USERNAMEINPUT}input type=text name="USER"{USERNAMEINPUT}--></td></tr>
<tr><td>本名：</td><td>{REALNAME}</td></tr>
<tr><td>説明：</td><td>{NOTETEXT}</td></tr>
<tr><td>グループ名：</td><td>{GROUPNAME}</td></tr>
<tr><td>アカウントの有効期限：</td><td>{EXPIREDATE}</td></tr>
<tr><td>認証方法：</td><td>
	<input type=radio name=AUTHTYPE value="ANONYMOUS" {SELANONYM}>匿名認証<br>
	<input type=radio name=AUTHTYPE value="PASSWORD" {SELPASSWD}>パスワード認証
</td></tr>
<tr><td>パスワード：</td><td><input type=password name="PASSWORD" value="{PASSWORD}"></td></tr>
<tr><td>パスワード(確認)：</td><td><input type=password name="PASSWORD2" value="{PASSWORD}"></td></tr>
</table>
<input type=submit name="set" value="設定する">
<br>
<a href="{LINK_USER}?KEY={SESSIONKEY}&HUB={HUBNAME}">仮想 HUB「{HUBNAME}」のユーザー一覧に戻る</a>
</form>
</body></html>


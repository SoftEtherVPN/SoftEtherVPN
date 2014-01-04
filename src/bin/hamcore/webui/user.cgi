<html><head><meta http-equiv="content-type" content="text/html; charset=UTF-8" />
<title>User page</title>
<link rel=stylesheet type=text/css href=/webui/webui.css>
</head><body>

<h2>仮想 HUB「{HUBNAME}」のユーザーの管理</h2>
<table border=2><tr><td><a href="{LINK_EDITUSER}?KEY={SESSIONKEY}&HUB={HUBNAME}">新規作成</a></td><td>ユーザー名</td><td>本名</td><td>所属グループ</td><td>説明</td>
<td>認証方法</td><td>ログイン回数</td><td>最終ログイン日時</td></tr>
<!--USER_TMPL:<tr><td><a href="{LINK_EDITUSER}?USER=%S&HUB={HUBNAME}&KEY={SESSIONKEY}">編集</a>
 <a href="{LINK_USER}?CMD=DEL&USER=%S&HUB={HUBNAME}&KEY={SESSIONKEY}">削除</a></td>
<td>%S</td><td>%s</td><td>%S</td><td>%s</td>
<td>%s</td><td>%d</td><td>%s</td></tr>-->
<!--USERS-->
</table>
<br>
<a href="{LINK_HUB}?KEY={SESSIONKEY}&HUB={HUBNAME}">仮想 HUB「{HUBNAME}」の管理画面に戻る。</a>
</body></html>


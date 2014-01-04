<html><head><meta http-equiv="content-type" content="text/html; charset=UTF-8" />
<title>Virtual HUB page</title>
<link rel=stylesheet type=text/css href=/webui/webui.css>
</head><body>

<h2>ローカルブリッジ接続の設定</h2>

<h3>ローカルブリッジ接続の一覧</h3>
<table border=2>
<tr><td><!--番号--></td><td>仮想 HUB 名</td><td>ブリッジ先 LAN カード又は tap デバイス名</td><td>状態</td></tr>
<!--LBLIST_TMPL<tr><td><a href="{LINK_LOCALBRIDGE}?KEY={SESSIONKEY}&CMD=DEL&LISTID={LISTID}">削除</a></td><td>{HUBNAME}</td><td>{DEVICENAME}</td><td>{STATUS}</td></tr>LBLIST_TMPL-->
<!--LBLIST-->
</table>

<h3>新しいローカルブリッジの定義</h3>
<form method=get action="{LINK_LOCALBRIDGE}">
<table>
<tr>
<td>仮想 HUB 名：</td><td><select name="LBHUBNAME">
<!--HUBS_TMPL<option value="{LBHUBNAME}">{LBHUBNAME}HUBS_TMPL-->
<!--HUBS-->
</select>
</td>
</tr>
<tr>
<td>作成する種類：</td>
<td><input type="radio" name=TAPMODE value="NO" checked>物理的な既存の LAN カードとのブリッジ接続<br>
<input type="radio" name=TAPMODE value="YES">新しい tap デバイスとのブリッジ接続</td>
</tr>
<tr>
<td>デバイス名：</td>
<td><select name="DEVID">
<!--LBDEVLIST_TMPL<option value="{DEVID}">{ABLEDEVICE}LBDEVLIST_TMPL-->
<!--LBDEVLIST-->
</select>
</td>
</tr>
<tr>
<td>新しい tap デバイス名</td><td><input type=text name="TAPNMAME" maxlength="11"></td>
</tr>
<tr>
<td><input type=hidden name=KEY value="{SESSIONKEY}"><input type=hidden name=CMD value="CREATE"><input type=submit value="追加"></td>
</tr>
</table>
</form>

<br>
<a href="{LINK_SERVER}?KEY={SESSIONKEY}">サーバーの管理画面に戻る</a>

</body></html>

<!--STRMAP:BRIDGE_ONLINE:オンライン,BRIDGE_OFFLINE:オフライン,BRIDGE_ERROR:エラー発生-->

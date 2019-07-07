// Test sample code for SoftEther VPN Server JSON-RPC Stub
// Runs on both web browsers and Node.js
// 
// Licensed under the Apache License 2.0
// Copyright (c) 2014-2018 SoftEther VPN Project

// On the web browser uncomment below imports as necessary to support old browsers.
import "core-js/es/promise";
import "core-js/es/string";
import "whatwg-fetch";

import $ = require('jquery');

// Import the vpnrpc.ts RPC stub.
import * as VPN from "vpnrpc/dist/vpnrpc";

// Output JSON-RPC request / reply strings to the debug console.
VPN.VpnServerRpc.SetDebugMode(true);

let api: VPN.VpnServerRpc;
// Creating the VpnServerRpc class instance here.
if (VPN.VpnServerRpc.IsNodeJS() === false) // // Determine if this JavaScript environment is on the Node.js or not
{
    // On the web browser. We do not need to specify any hostname, port or credential as the web browser already knows it.
    api = new VPN.VpnServerRpc();
}
else
{
    // On the Node.js. We need to specify the target VPN Server's hostname, port and credential.
    api = new VPN.VpnServerRpc("127.0.0.1", 443, "", "PASSWORD_HERE", false);
}


/** API test for 'Test', test RPC function */
export async function Test_Test(): Promise<void>
{
    console.log("Begin: Test_Test");
    let a: VPN.VpnRpcTest = new VPN.VpnRpcTest(
        {
            IntValue_u32: 12345,
        });
    let b: VPN.VpnRpcTest = await api.Test(a);
    console.log(b);
    console.log("End: Test_Test");
    console.log("-----");
    console.log();
}

export async function ListVirtualHubs(id: string): Promise<void>
{
    let ul: JQuery<HTMLElement> = $(id);

    ul.children().remove();

    let hubList = await api.EnumHub();

    hubList.HubList.forEach(hub =>
    {
        ul.append("<li><strong><a href='./hub.html?" + hub.HubName_str + "'>" + hub.HubName_str + "</a></strong><br>" + ConcatKeysToHtml(hub) + "</li>");
    });
}

export async function ShowVpnServerInfo(idInfo: string, idStatus: string): Promise<void>
{
    let infoList = $(idInfo);
    let statusList = $(idStatus);

    let serverInfo = await api.GetServerInfo();

    let serverStatus = await api.GetServerStatus();

    Object.keys(serverInfo).forEach(key =>
    {
        infoList.append("<li>" + key + ": \"" + (<any>serverInfo)[key] + "\"</li>");
    });

    Object.keys(serverStatus).forEach(key =>
    {
        statusList.append("<li>" + key + ": \"" + (<any>serverStatus)[key] + "\"</li>");
    });
}

export async function CreateNewHub(hubName: string, idList: string): Promise<void>
{
    if (hubName == null || hubName == "")
    {
        alert("Virtual Hub name is empty.");
        return;
    }

    try
    {
        let param: VPN.VpnRpcCreateHub = new VPN.VpnRpcCreateHub(
            {
                HubName_str: hubName,
                Online_bool: true,
                HubType_u32: VPN.VpnRpcHubType.Standalone,
            });
        
        await api.CreateHub(param);
      
        ListVirtualHubs(idList);

        alert("The Virtual Hub '" + hubName + "' is created.");
    }
    catch (ex)
    {
        alert(ex);
    }
}

function ConcatKeysToHtml(obj: any): string
{
    let ret: string = "";

    Object.keys(obj).forEach(key =>
    {
        ret += key + ": \"" + (<any>obj)[key] + "\"<BR>";
    });

    return ret;
}

export async function DeleteVirtualHub(queryString: string): Promise<void>
{
    let hubNameInput = queryString;
    if (hubNameInput.length >= 1 && hubNameInput.charAt(0) == "?") hubNameInput = hubNameInput.substring(1);

    try
    {
        let deleteHubParam: VPN.VpnRpcDeleteHub = new VPN.VpnRpcDeleteHub(
            {
                HubName_str: hubNameInput,
            });

        await api.DeleteHub(deleteHubParam);

        alert("The Virtual Hub '" + hubNameInput + "' is deleted.");

        window.location.href = "./";
    }
    catch (ex)
    {
        alert(ex);
    }
}

export async function HubAdminPage(queryString: string): Promise<void>
{
    let hubNameInput = queryString;
    if (hubNameInput.length >= 1 && hubNameInput.charAt(0) == "?") hubNameInput = hubNameInput.substring(1);

    try
    {
        let getHubParam: VPN.VpnRpcCreateHub = new VPN.VpnRpcCreateHub(
            {
                HubName_str: hubNameInput,
            });
        
        let hubInfo = await api.GetHub(getHubParam);

        $("#HUB_NAME").append("Virtual Hub \"" + hubInfo.HubName_str + "\"");

        // User list
        let enumUserParam: VPN.VpnRpcEnumUser = new VPN.VpnRpcEnumUser(
            {
                HubName_str: hubInfo.HubName_str,
            });
        
        let enumUserRet = await api.EnumUser(enumUserParam);

        let userListHtmlItem = $("#USERS_LIST");

        enumUserRet.UserList.forEach(user =>
        {
            userListHtmlItem.append("<li><strong>" + user.Name_str + "</strong><BR>" + ConcatKeysToHtml(user) + "</li>");
        });

        // Sessions list
        let enumSessionParam: VPN.VpnRpcEnumSession = new VPN.VpnRpcEnumSession(
            {
                HubName_str: hubInfo.HubName_str,
            });

        let enumSessionsRet = await api.EnumSession(enumSessionParam);

        let sessionListHtmlItem = $("#SESSIONS_LIST");

        enumSessionsRet.SessionList.forEach(session =>
        {
            sessionListHtmlItem.append("<li><strong>" + session.Name_str + "</strong><br>" + ConcatKeysToHtml(session) + "</li>");
        });
    }
    catch (ex)
    {
        alert(ex);
    }
}




// SoftEther VPN Server JSON-RPC Stub code for C#
// 
// VpnServerRpcTest.cs - Test sample code for SoftEther VPN Server JSON-RPC Stub
//
// This sample code shows how to call all available RPC functions.
// You can copy and paste test code to write your own C# codes.
//
// Automatically generated at __TIMESTAMP__ by vpnserver-jsonrpc-codegen
//
// Licensed under the Apache License 2.0
// Copyright (c) 2014-__YEAR__ SoftEther VPN Project

using System;
using SoftEther.VPNServerRpc;

class VPNRPCTest
{
    VpnServerRpc api;

    Random rand = new Random();

    string hub_name = "TEST";

    public VPNRPCTest()
    {
        api = new VpnServerRpc("127.0.0.1", 443, "PASSWORD_HERE", "");       // Speficy your VPN Server's password here.
    }

    /// <summary>
    /// Tests all VPN APIs
    /// </summary>
    public void Test_All()
    {
        hub_name = "TEST";

        Test_Test();

        Test_GetServerInfo();
        Test_GetServerStatus();

        uint new_listener_port = Test_CreateListener();
        Test_EnableListener(new_listener_port, false);
        Test_EnumListener();
        Test_EnableListener(new_listener_port, true);
        Test_EnumListener();
        Test_DeleteListener(new_listener_port);

        Test_SetServerPassword();

        Test_GetFarmSetting();

        if (false)
        {

            Test_SetFarmSetting();

            VpnRpcEnumFarm farm_members = Test_EnumFarmMember();

            foreach (VpnRpcEnumFarmItem farm_member in farm_members.FarmMemberList)
            {
                Test_GetFarmInfo(farm_member.Id_u32);
            }

            Test_GetFarmConnectionStatus();
        }
        else if (false)
        {
            Console.WriteLine("abc");
        }
        else
        {
            Console.WriteLine("def");
        }

        Test_GetServerCert();

        Test_SetServerCert();

        Test_GetServerCipher();

        Test_SetServerCipher();

        VpnRpcEnumConnection enum_connection = Test_EnumConnection();

        foreach (VpnRpcEnumConnectionItem connecton in enum_connection.ConnectionList)
        {
            Test_GetConnectionInfo(connecton.Name_str);
            //Test_DisconnectConnection(connecton.Name_str);
        }

        hub_name = Test_CreateHub();

        Test_SetHub();
        Test_GetHub();
        Test_EnumHub();
        Test_SetHubRadius();
        Test_GetHubRadius();

        Test_SetHubOnline();
        Test_GetHubStatus();

        VpnRpcHubLog hub_log_settings = Test_GetHubLog();
        Test_SetHubLog(hub_log_settings);

        Test_AddCa();
        VpnRpcHubEnumCA enum_ca = Test_EnumCa();
        foreach (VpnRpcHubEnumCAItem ca in enum_ca.CAList)
        {
            Test_GetCa(ca.Key_u32);
            Test_DeleteCa(ca.Key_u32);
        }

        Test_CreateLink();
        Test_GetLink();
        Test_SetLink();
        Test_SetLinkOffline();
        Test_SetLinkOnline();
        VpnRpcEnumLink enum_link = Test_EnumLink();
        foreach (var link in enum_link.LinkList)
        {
            Test_GetLinkStatus(link.AccountName_utf);
        }
        System.Threading.Thread.Sleep(3000);
        Test_RenameLink();
        Test_DeleteLink();

        Test_AddAccess();
        Test_EnumAccess();
        Test_DeleteAccess();
        Test_SetAccessList();

        Test_CreateGroup();
        Test_SetGroup();
        Test_GetGroup();

        Test_CreateUser();
        Test_SetUser();
        Test_GetUser();
        Test_EnumUser();
        Test_EnumGroup();

        Test_DeleteUser();
        Test_DeleteGroup();

        VpnRpcEnumSession enum_session = Test_EnumSession();

        foreach (VpnRpcEnumSessionItem session in enum_session.SessionList)
        {
            Test_GetSessionStatus(session.Name_str);

            Test_DeleteSession(session.Name_str);
        }

        VpnRpcEnumMacTable enum_mac = Test_EnumMacTable();

        foreach (VpnRpcEnumMacTableItem mac in enum_mac.MacTable)
        {
            Test_DeleteMacTable(mac.Key_u32);
        }

        VpnRpcEnumIpTable enum_ip = Test_EnumIpTable();

        foreach (VpnRpcEnumIpTableItem ip in enum_ip.IpTable)
        {
            Test_DeleteIpTable(ip.Key_u32);
        }

        Test_SetKeep();
        Test_GetKeep();

        Test_EnableSecureNAT();
        Test_GetSecureNATOption();
        Test_SetSecureNATOption();
        Test_EnumNAT();
        Test_EnumDHCP();
        Test_GetSecureNATStatus();
        Test_DisableSecureNAT();

        Test_EnumEthernet();
        //Test_AddLocalBridge();
        Test_EnumLocalBridge();
        //Test_DeleteLocalBridge();
        Test_GetBridgeSupport();

        Test_GetCaps();
        Test_GetConfig();
        //Test_SetConfig();

        Test_GetDefaultHubAdminOptions();
        Test_GetHubAdminOptions();
        Test_SetHubAdminOptions();
        Test_GetHubExtOptions();
        Test_SetHubExtOptions();

        Test_AddL3Switch();
        Test_AddL3If();
        Test_EnumL3Switch();
        Test_EnumL3If();
        Test_AddL3Table();
        Test_EnumL3Table();
        Test_DelL3Table();
        Test_StartL3Switch();
        Test_StopL3Switch();
        Test_DelL3If();
        Test_DelL3Switch();

        Test_AddCrl();
        VpnRpcEnumCrl enum_crl = Test_EnumCrl();
        foreach (VpnRpcEnumCrlItem crl in enum_crl.CRLList)
        {
            VpnRpcCrl got_crl = Test_GetCrl(crl.Key_u32);

            got_crl.CommonName_utf = got_crl.CommonName_utf + "_a";
            Test_SetCrl(got_crl);
        }

        enum_crl = Test_EnumCrl();
        foreach (VpnRpcEnumCrlItem crl in enum_crl.CRLList)
        {
            Test_DelCrl(crl.Key_u32);
        }

        Test_SetAcList();
        Test_GetAcList();

        VpnRpcEnumLogFile enum_log_file = Test_EnumLogFile();
        foreach (VpnRpcEnumLogFileItem log in enum_log_file.LogFiles)
        {
            Test_ReadLogFile(log.FilePath_str);

            break;
        }

        Test_SetSysLog(true);
        Test_GetSysLog();
        Test_SetSysLog(false);

        Test_SetHubMsg();
        Test_GetHubMsg();
        Test_GetAdminMsg();
        Test_Flush();

        Test_SetIPsecServices();
        Test_GetIPsecServices();

        Test_AddEtherIpId();
        VpnRpcEnumEtherIpId enum_etherip_id = Test_EnumEtherIpId();
        foreach (VpnEtherIpId etherip_id in enum_etherip_id.Settings)
        {
            Test_GetEtherIpId(etherip_id.Id_str);
            Test_DeleteEtherIpId(etherip_id.Id_str);
        }

        Test_SetOpenVpnSstpConfig();
        Test_GetOpenVpnSstpConfig();

        Test_GetDDnsClientStatus();
        Test_SetDDnsInternetSetting();
        Test_GetDDnsInternetSetting();

        Test_ChangeDDnsClientHostname();
        Test_RegenerateServerCert();
        Test_MakeOpenVpnConfigFile();
        Test_SetSpecialListener();
        Test_GetSpecialListener();

        Test_GetAzureStatus();
        Test_SetAzureStatus();
        Test_SetVgsConfig();
        Test_GetVgsConfig();

        Test_DeleteHub();
        //Test_RebootServer();

        return;
    }


    /// <summary>
    /// API test for 'Test', test RPC function
    /// </summary>
    public void Test_Test()
    {
        Console.WriteLine("Begin: Test_Test");

        VpnRpcTest a = new VpnRpcTest() { IntValue_u32 = 12345 };

        VpnRpcTest b = api.Test(a);

        print_object(b);

        Console.WriteLine("End: Test_Test");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetServerInfo', Get server information
    /// </summary>
    public void Test_GetServerInfo()
    {
        Console.WriteLine("Begin: Test_GetServerInfo");

        VpnRpcServerInfo info = api.GetServerInfo();

        print_object(info);

        Console.WriteLine("End: Test_GetServerInfo");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetServerStatus', Get server status
    /// </summary>
    public void Test_GetServerStatus()
    {
        Console.WriteLine("Begin: Test_GetServerStatus");

        VpnRpcServerStatus out_rpc_server_status = api.GetServerStatus();

        print_object(out_rpc_server_status);

        Console.WriteLine("End: Test_GetServerStatus");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'CreateListener', Create a listener
    /// </summary>
    public uint Test_CreateListener()
    {
        Console.WriteLine("Begin: Test_CreateListener");

        uint port = (uint)rand.Next(1025, 65534);

        Console.WriteLine("Creating a new listener port: Port " + port);
        VpnRpcListener in_rpc_listener = new VpnRpcListener() { Enable_bool = true, Port_u32 = port, };
        VpnRpcListener out_rpc_listener = api.CreateListener(in_rpc_listener);

        Console.WriteLine("Done.");
        Console.WriteLine("End: Test_CreateListener");
        Console.WriteLine("-----");
        Console.WriteLine();

        return port;
    }

    /// <summary>
    /// API test for 'EnumListener', Enumerating listeners
    /// </summary>
    public void Test_EnumListener()
    {
        Console.WriteLine("Begin: Test_EnumListener");

        VpnRpcListenerList out_rpc_listener_list = api.EnumListener();

        print_object(out_rpc_listener_list);

        Console.WriteLine("End: Test_EnumListener");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'DeleteListener', Delete a listener
    /// </summary>
    public void Test_DeleteListener(uint port)
    {
        Console.WriteLine("Begin: Test_DeleteListener");

        Console.WriteLine("Deleting a new listener port: Port" + port);
        VpnRpcListener in_rpc_listener = new VpnRpcListener() { Port_u32 = port };
        VpnRpcListener out_rpc_listener = api.DeleteListener(in_rpc_listener);

        Console.WriteLine("Done.");
        Console.WriteLine("End: Test_DeleteListener");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnableListener', Enable / Disable listener
    /// </summary>
    public void Test_EnableListener(uint port, bool enabled)
    {
        Console.WriteLine("Begin: Test_EnableListener");

        if (enabled)
        {
            Console.WriteLine("Enabling listener port = " + port);
        }
        else
        {
            Console.WriteLine("Disabling listener port = " + port);
        }

        VpnRpcListener in_rpc_listener = new VpnRpcListener() { Port_u32 = port, Enable_bool = enabled };
        VpnRpcListener out_rpc_listener = api.EnableListener(in_rpc_listener);

        Console.WriteLine("Done.");

        Console.WriteLine("End: Test_EnableListener");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetServerPassword', Set server password
    /// </summary>
    public void Test_SetServerPassword()
    {
        string password = "microsoft";

        Console.WriteLine("Begin: Test_SetServerPassword");

        Console.WriteLine("Set the server administrator password to '" + password + "'.");

        VpnRpcSetPassword in_rpc_set_password = new VpnRpcSetPassword() { PlainTextPassword_str = password };
        VpnRpcSetPassword out_rpc_set_password = api.SetServerPassword(in_rpc_set_password);

        Console.WriteLine("Done.");

        Console.WriteLine("End: Test_SetServerPassword");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetFarmSetting', Set clustering configuration
    /// </summary>
    public void Test_SetFarmSetting()
    {
        Console.WriteLine("Begin: Test_SetFarmSetting");

        VpnRpcFarm in_rpc_farm = new VpnRpcFarm()
        {
            ServerType_u32 = VpnRpcServerType.FarmController,
            NumPort_u32 = 2,
            Ports_u32 = new uint[] { 443, 444, 445 },
            PublicIp_ip = "1.2.3.4",
            ControllerName_str = "controller",
            MemberPasswordPlaintext_str = "microsoft",
            ControllerPort_u32 = 443,
            Weight_u32 = 100,
            ControllerOnly_bool = false,
        };

        VpnRpcFarm out_rpc_farm = api.SetFarmSetting(in_rpc_farm);

        Console.WriteLine("End: Test_SetFarmSetting");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetFarmSetting', Get clustering configuration
    /// </summary>
    public void Test_GetFarmSetting()
    {
        Console.WriteLine("Begin: Test_GetFarmSetting");

        // VpnRpcFarm in_rpc_farm = new VpnRpcFarm();
        VpnRpcFarm out_rpc_farm = api.GetFarmSetting();

        print_object(out_rpc_farm);

        Console.WriteLine("End: Test_GetFarmSetting");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetFarmInfo', Get cluster member information
    /// </summary>
    public void Test_GetFarmInfo(uint id)
    {
        Console.WriteLine("Begin: Test_GetFarmInfo");

        VpnRpcFarmInfo in_rpc_farm_info = new VpnRpcFarmInfo() { Id_u32 = id };
        VpnRpcFarmInfo out_rpc_farm_info = api.GetFarmInfo(in_rpc_farm_info);

        print_object(out_rpc_farm_info);

        Console.WriteLine("End: Test_GetFarmInfo");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumFarmMember', Enumerate cluster members
    /// </summary>
    public VpnRpcEnumFarm Test_EnumFarmMember()
    {
        Console.WriteLine("Begin: Test_EnumFarmMember");

        VpnRpcEnumFarm out_rpc_enum_farm = api.EnumFarmMember();

        print_object(out_rpc_enum_farm);

        Console.WriteLine("End: Test_EnumFarmMember");
        Console.WriteLine("-----");
        Console.WriteLine();

        return out_rpc_enum_farm;
    }

    /// <summary>
    /// API test for 'GetFarmConnectionStatus', Get status of connection to cluster controller
    /// </summary>
    public void Test_GetFarmConnectionStatus()
    {
        Console.WriteLine("Begin: Test_GetFarmConnectionStatus");

        VpnRpcFarmConnectionStatus out_rpc_farm_connection_status = api.GetFarmConnectionStatus();

        print_object(out_rpc_farm_connection_status);

        Console.WriteLine("End: Test_GetFarmConnectionStatus");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetServerCert', Set the server certification
    /// </summary>
    public void Test_SetServerCert()
    {
        Console.WriteLine("Begin: Test_SetServerCert");

        VpnRpcKeyPair in_rpc_key_pair = new VpnRpcKeyPair()
        {
            Cert_bin = new byte[]
            {
0x2d,0x2d,0x2d,0x2d,0x2d,0x42,0x45,0x47,0x49,0x4e,0x20,0x43,0x45,0x52,0x54,0x49,
0x46,0x49,0x43,0x41,0x54,0x45,0x2d,0x2d,0x2d,0x2d,0x2d,0x0a,0x4d,0x49,0x49,0x44,
0x72,0x6a,0x43,0x43,0x41,0x70,0x61,0x67,0x41,0x77,0x49,0x42,0x41,0x67,0x49,0x42,
0x41,0x44,0x41,0x4e,0x42,0x67,0x6b,0x71,0x68,0x6b,0x69,0x47,0x39,0x77,0x30,0x42,
0x41,0x51,0x73,0x46,0x41,0x44,0x42,0x57,0x4d,0x51,0x77,0x77,0x43,0x67,0x59,0x44,
0x56,0x51,0x51,0x44,0x44,0x41,0x4e,0x68,0x59,0x57,0x45,0x78,0x0a,0x46,0x54,0x41,
0x54,0x42,0x67,0x4e,0x56,0x42,0x41,0x6f,0x4d,0x44,0x4f,0x4f,0x42,0x72,0x2b,0x4f,
0x42,0x71,0x75,0x4f,0x42,0x6a,0x2b,0x4f,0x42,0x6e,0x54,0x45,0x4c,0x4d,0x41,0x6b,
0x47,0x41,0x31,0x55,0x45,0x42,0x68,0x4d,0x43,0x53,0x6c,0x41,0x78,0x45,0x44,0x41,
0x4f,0x42,0x67,0x4e,0x56,0x42,0x41,0x67,0x4d,0x42,0x30,0x6c,0x69,0x0a,0x59,0x58,
0x4a,0x68,0x61,0x32,0x6b,0x78,0x45,0x44,0x41,0x4f,0x42,0x67,0x4e,0x56,0x42,0x41,
0x63,0x4d,0x42,0x31,0x52,0x7a,0x64,0x57,0x74,0x31,0x59,0x6d,0x45,0x77,0x48,0x68,
0x63,0x4e,0x4d,0x54,0x67,0x78,0x4d,0x44,0x45,0x78,0x4d,0x6a,0x4d,0x7a,0x4e,0x54,
0x41,0x78,0x57,0x68,0x63,0x4e,0x4e,0x44,0x49,0x78,0x4d,0x44,0x41,0x31,0x0a,0x4d,
0x6a,0x4d,0x7a,0x4e,0x54,0x41,0x78,0x57,0x6a,0x42,0x57,0x4d,0x51,0x77,0x77,0x43,
0x67,0x59,0x44,0x56,0x51,0x51,0x44,0x44,0x41,0x4e,0x68,0x59,0x57,0x45,0x78,0x46,
0x54,0x41,0x54,0x42,0x67,0x4e,0x56,0x42,0x41,0x6f,0x4d,0x44,0x4f,0x4f,0x42,0x72,
0x2b,0x4f,0x42,0x71,0x75,0x4f,0x42,0x6a,0x2b,0x4f,0x42,0x6e,0x54,0x45,0x4c,0x0a,
0x4d,0x41,0x6b,0x47,0x41,0x31,0x55,0x45,0x42,0x68,0x4d,0x43,0x53,0x6c,0x41,0x78,
0x45,0x44,0x41,0x4f,0x42,0x67,0x4e,0x56,0x42,0x41,0x67,0x4d,0x42,0x30,0x6c,0x69,
0x59,0x58,0x4a,0x68,0x61,0x32,0x6b,0x78,0x45,0x44,0x41,0x4f,0x42,0x67,0x4e,0x56,
0x42,0x41,0x63,0x4d,0x42,0x31,0x52,0x7a,0x64,0x57,0x74,0x31,0x59,0x6d,0x45,0x77,
0x0a,0x67,0x67,0x45,0x69,0x4d,0x41,0x30,0x47,0x43,0x53,0x71,0x47,0x53,0x49,0x62,
0x33,0x44,0x51,0x45,0x42,0x41,0x51,0x55,0x41,0x41,0x34,0x49,0x42,0x44,0x77,0x41,
0x77,0x67,0x67,0x45,0x4b,0x41,0x6f,0x49,0x42,0x41,0x51,0x44,0x58,0x45,0x63,0x76,
0x72,0x59,0x37,0x56,0x2b,0x7a,0x64,0x42,0x79,0x72,0x64,0x4e,0x78,0x4a,0x59,0x45,
0x6d,0x0a,0x61,0x41,0x4e,0x59,0x55,0x4f,0x37,0x76,0x57,0x34,0x68,0x64,0x41,0x35,
0x49,0x42,0x49,0x46,0x6d,0x4d,0x70,0x6e,0x62,0x79,0x69,0x4e,0x6e,0x5a,0x77,0x36,
0x57,0x39,0x6f,0x61,0x67,0x78,0x33,0x5a,0x49,0x65,0x65,0x48,0x56,0x59,0x62,0x52,
0x69,0x4b,0x36,0x41,0x66,0x46,0x74,0x53,0x31,0x32,0x2b,0x45,0x31,0x4d,0x59,0x31,
0x64,0x32,0x0a,0x61,0x71,0x51,0x31,0x53,0x72,0x49,0x43,0x39,0x51,0x35,0x55,0x6e,
0x5a,0x61,0x42,0x72,0x62,0x57,0x32,0x32,0x6d,0x4e,0x75,0x6c,0x4d,0x34,0x2f,0x6c,
0x49,0x4a,0x72,0x48,0x70,0x51,0x55,0x68,0x50,0x78,0x6f,0x62,0x79,0x34,0x2f,0x36,
0x4e,0x41,0x37,0x71,0x4b,0x67,0x55,0x48,0x69,0x79,0x4f,0x64,0x33,0x4a,0x42,0x70,
0x4f,0x66,0x77,0x0a,0x38,0x54,0x76,0x53,0x74,0x51,0x78,0x34,0x4c,0x38,0x59,0x64,
0x4b,0x51,0x35,0x68,0x74,0x7a,0x6b,0x32,0x68,0x70,0x52,0x4a,0x4c,0x30,0x6c,0x4b,
0x67,0x47,0x31,0x57,0x34,0x75,0x4b,0x32,0x39,0x39,0x42,0x74,0x7a,0x64,0x41,0x67,
0x66,0x42,0x76,0x43,0x54,0x33,0x41,0x31,0x61,0x53,0x70,0x6a,0x49,0x47,0x74,0x6e,
0x69,0x72,0x49,0x31,0x0a,0x46,0x4c,0x52,0x58,0x47,0x79,0x38,0x31,0x31,0x57,0x4a,
0x39,0x4a,0x68,0x68,0x34,0x41,0x4b,0x4c,0x66,0x79,0x56,0x70,0x42,0x4a,0x67,0x65,
0x34,0x73,0x56,0x72,0x36,0x4e,0x75,0x75,0x49,0x66,0x32,0x71,0x47,0x31,0x6f,0x79,
0x31,0x30,0x70,0x61,0x51,0x4e,0x65,0x71,0x32,0x33,0x55,0x47,0x61,0x59,0x74,0x2f,
0x7a,0x55,0x56,0x4a,0x77,0x0a,0x55,0x74,0x30,0x57,0x45,0x6b,0x58,0x38,0x48,0x4f,
0x63,0x62,0x33,0x75,0x49,0x6f,0x54,0x6d,0x61,0x4f,0x34,0x72,0x48,0x42,0x55,0x4a,
0x71,0x45,0x79,0x39,0x51,0x58,0x7a,0x53,0x57,0x77,0x43,0x35,0x78,0x45,0x43,0x64,
0x37,0x43,0x4a,0x53,0x53,0x68,0x31,0x30,0x4f,0x75,0x6e,0x6c,0x75,0x4c,0x32,0x4d,
0x47,0x65,0x5a,0x47,0x6e,0x76,0x0a,0x41,0x67,0x4d,0x42,0x41,0x41,0x47,0x6a,0x67,
0x59,0x59,0x77,0x67,0x59,0x4d,0x77,0x44,0x77,0x59,0x44,0x56,0x52,0x30,0x54,0x41,
0x51,0x48,0x2f,0x42,0x41,0x55,0x77,0x41,0x77,0x45,0x42,0x2f,0x7a,0x41,0x4c,0x42,
0x67,0x4e,0x56,0x48,0x51,0x38,0x45,0x42,0x41,0x4d,0x43,0x41,0x66,0x59,0x77,0x59,
0x77,0x59,0x44,0x56,0x52,0x30,0x6c,0x0a,0x42,0x46,0x77,0x77,0x57,0x67,0x59,0x49,
0x4b,0x77,0x59,0x42,0x42,0x51,0x55,0x48,0x41,0x77,0x45,0x47,0x43,0x43,0x73,0x47,
0x41,0x51,0x55,0x46,0x42,0x77,0x4d,0x43,0x42,0x67,0x67,0x72,0x42,0x67,0x45,0x46,
0x42,0x51,0x63,0x44,0x41,0x77,0x59,0x49,0x4b,0x77,0x59,0x42,0x42,0x51,0x55,0x48,
0x41,0x77,0x51,0x47,0x43,0x43,0x73,0x47,0x0a,0x41,0x51,0x55,0x46,0x42,0x77,0x4d,
0x46,0x42,0x67,0x67,0x72,0x42,0x67,0x45,0x46,0x42,0x51,0x63,0x44,0x42,0x67,0x59,
0x49,0x4b,0x77,0x59,0x42,0x42,0x51,0x55,0x48,0x41,0x77,0x63,0x47,0x43,0x43,0x73,
0x47,0x41,0x51,0x55,0x46,0x42,0x77,0x4d,0x49,0x42,0x67,0x67,0x72,0x42,0x67,0x45,
0x46,0x42,0x51,0x63,0x44,0x43,0x54,0x41,0x4e,0x0a,0x42,0x67,0x6b,0x71,0x68,0x6b,
0x69,0x47,0x39,0x77,0x30,0x42,0x41,0x51,0x73,0x46,0x41,0x41,0x4f,0x43,0x41,0x51,
0x45,0x41,0x46,0x6d,0x34,0x37,0x47,0x55,0x70,0x50,0x57,0x35,0x2b,0x37,0x69,0x46,
0x74,0x69,0x6c,0x6f,0x6b,0x35,0x32,0x49,0x6f,0x54,0x57,0x72,0x74,0x46,0x67,0x32,
0x79,0x69,0x36,0x6b,0x49,0x32,0x69,0x52,0x4e,0x51,0x0a,0x4b,0x75,0x67,0x48,0x55,
0x49,0x4f,0x34,0x4b,0x53,0x71,0x4a,0x56,0x42,0x50,0x38,0x61,0x4b,0x4f,0x61,0x54,
0x5a,0x47,0x45,0x31,0x4b,0x4d,0x68,0x2f,0x59,0x6a,0x68,0x36,0x71,0x2f,0x67,0x50,
0x61,0x6c,0x67,0x64,0x2f,0x38,0x44,0x6d,0x72,0x78,0x53,0x4a,0x6d,0x55,0x78,0x33,
0x62,0x4e,0x62,0x38,0x52,0x59,0x36,0x70,0x4b,0x7a,0x74,0x0a,0x5a,0x64,0x75,0x53,
0x61,0x53,0x2b,0x57,0x55,0x30,0x59,0x74,0x2b,0x6c,0x47,0x35,0x76,0x56,0x67,0x61,
0x70,0x48,0x45,0x71,0x36,0x79,0x71,0x4c,0x62,0x65,0x56,0x78,0x51,0x4c,0x75,0x62,
0x54,0x69,0x6e,0x4f,0x66,0x56,0x56,0x5a,0x58,0x79,0x45,0x43,0x59,0x47,0x4d,0x73,
0x59,0x71,0x65,0x6e,0x4a,0x6a,0x4e,0x63,0x62,0x49,0x5a,0x4e,0x0a,0x79,0x4d,0x75,
0x72,0x46,0x63,0x67,0x30,0x34,0x36,0x4f,0x34,0x59,0x79,0x68,0x56,0x79,0x71,0x53,
0x69,0x74,0x43,0x59,0x37,0x68,0x2f,0x65,0x71,0x67,0x6b,0x50,0x4a,0x51,0x30,0x68,
0x6b,0x70,0x39,0x45,0x64,0x51,0x77,0x62,0x6e,0x38,0x56,0x6c,0x66,0x78,0x64,0x42,
0x58,0x77,0x51,0x34,0x4e,0x48,0x4b,0x30,0x4a,0x56,0x46,0x2f,0x33,0x0a,0x71,0x48,
0x61,0x68,0x4e,0x48,0x4f,0x35,0x64,0x62,0x4a,0x5a,0x57,0x59,0x41,0x62,0x42,0x44,
0x70,0x32,0x51,0x45,0x53,0x70,0x76,0x6f,0x2b,0x38,0x33,0x6c,0x68,0x34,0x64,0x6e,
0x58,0x6a,0x46,0x58,0x4d,0x43,0x48,0x76,0x52,0x68,0x35,0x31,0x79,0x2f,0x54,0x71,
0x79,0x42,0x34,0x56,0x76,0x72,0x52,0x4b,0x49,0x4b,0x74,0x54,0x6f,0x7a,0x0a,0x5a,
0x6a,0x48,0x59,0x49,0x63,0x62,0x6a,0x76,0x53,0x58,0x4d,0x7a,0x61,0x44,0x50,0x6a,
0x50,0x63,0x5a,0x47,0x6a,0x42,0x4a,0x6c,0x47,0x36,0x43,0x76,0x44,0x34,0x4c,0x6d,
0x59,0x7a,0x72,0x6b,0x48,0x34,0x31,0x63,0x7a,0x72,0x34,0x57,0x41,0x3d,0x3d,0x0a,
0x2d,0x2d,0x2d,0x2d,0x2d,0x45,0x4e,0x44,0x20,0x43,0x45,0x52,0x54,0x49,0x46,0x49,
0x43,0x41,0x54,0x45,0x2d,0x2d,0x2d,0x2d,0x2d,0x0a
            },
            Key_bin = new byte[]
            {
0x2d,0x2d,0x2d,0x2d,0x2d,0x42,0x45,0x47,0x49,0x4e,0x20,0x50,0x52,0x49,0x56,0x41,
0x54,0x45,0x20,0x4b,0x45,0x59,0x2d,0x2d,0x2d,0x2d,0x2d,0x0a,0x4d,0x49,0x49,0x45,
0x76,0x67,0x49,0x42,0x41,0x44,0x41,0x4e,0x42,0x67,0x6b,0x71,0x68,0x6b,0x69,0x47,
0x39,0x77,0x30,0x42,0x41,0x51,0x45,0x46,0x41,0x41,0x53,0x43,0x42,0x4b,0x67,0x77,
0x67,0x67,0x53,0x6b,0x41,0x67,0x45,0x41,0x41,0x6f,0x49,0x42,0x41,0x51,0x44,0x58,
0x45,0x63,0x76,0x72,0x59,0x37,0x56,0x2b,0x7a,0x64,0x42,0x79,0x0a,0x72,0x64,0x4e,
0x78,0x4a,0x59,0x45,0x6d,0x61,0x41,0x4e,0x59,0x55,0x4f,0x37,0x76,0x57,0x34,0x68,
0x64,0x41,0x35,0x49,0x42,0x49,0x46,0x6d,0x4d,0x70,0x6e,0x62,0x79,0x69,0x4e,0x6e,
0x5a,0x77,0x36,0x57,0x39,0x6f,0x61,0x67,0x78,0x33,0x5a,0x49,0x65,0x65,0x48,0x56,
0x59,0x62,0x52,0x69,0x4b,0x36,0x41,0x66,0x46,0x74,0x53,0x31,0x32,0x0a,0x2b,0x45,
0x31,0x4d,0x59,0x31,0x64,0x32,0x61,0x71,0x51,0x31,0x53,0x72,0x49,0x43,0x39,0x51,
0x35,0x55,0x6e,0x5a,0x61,0x42,0x72,0x62,0x57,0x32,0x32,0x6d,0x4e,0x75,0x6c,0x4d,
0x34,0x2f,0x6c,0x49,0x4a,0x72,0x48,0x70,0x51,0x55,0x68,0x50,0x78,0x6f,0x62,0x79,
0x34,0x2f,0x36,0x4e,0x41,0x37,0x71,0x4b,0x67,0x55,0x48,0x69,0x79,0x4f,0x0a,0x64,
0x33,0x4a,0x42,0x70,0x4f,0x66,0x77,0x38,0x54,0x76,0x53,0x74,0x51,0x78,0x34,0x4c,
0x38,0x59,0x64,0x4b,0x51,0x35,0x68,0x74,0x7a,0x6b,0x32,0x68,0x70,0x52,0x4a,0x4c,
0x30,0x6c,0x4b,0x67,0x47,0x31,0x57,0x34,0x75,0x4b,0x32,0x39,0x39,0x42,0x74,0x7a,
0x64,0x41,0x67,0x66,0x42,0x76,0x43,0x54,0x33,0x41,0x31,0x61,0x53,0x70,0x6a,0x0a,
0x49,0x47,0x74,0x6e,0x69,0x72,0x49,0x31,0x46,0x4c,0x52,0x58,0x47,0x79,0x38,0x31,
0x31,0x57,0x4a,0x39,0x4a,0x68,0x68,0x34,0x41,0x4b,0x4c,0x66,0x79,0x56,0x70,0x42,
0x4a,0x67,0x65,0x34,0x73,0x56,0x72,0x36,0x4e,0x75,0x75,0x49,0x66,0x32,0x71,0x47,
0x31,0x6f,0x79,0x31,0x30,0x70,0x61,0x51,0x4e,0x65,0x71,0x32,0x33,0x55,0x47,0x61,
0x0a,0x59,0x74,0x2f,0x7a,0x55,0x56,0x4a,0x77,0x55,0x74,0x30,0x57,0x45,0x6b,0x58,
0x38,0x48,0x4f,0x63,0x62,0x33,0x75,0x49,0x6f,0x54,0x6d,0x61,0x4f,0x34,0x72,0x48,
0x42,0x55,0x4a,0x71,0x45,0x79,0x39,0x51,0x58,0x7a,0x53,0x57,0x77,0x43,0x35,0x78,
0x45,0x43,0x64,0x37,0x43,0x4a,0x53,0x53,0x68,0x31,0x30,0x4f,0x75,0x6e,0x6c,0x75,
0x4c,0x0a,0x32,0x4d,0x47,0x65,0x5a,0x47,0x6e,0x76,0x41,0x67,0x4d,0x42,0x41,0x41,
0x45,0x43,0x67,0x67,0x45,0x41,0x54,0x77,0x34,0x52,0x6f,0x52,0x4c,0x6a,0x73,0x68,
0x72,0x42,0x56,0x6f,0x59,0x69,0x78,0x4f,0x4a,0x2b,0x57,0x4c,0x6d,0x2f,0x45,0x51,
0x57,0x65,0x37,0x6f,0x6a,0x38,0x31,0x51,0x50,0x73,0x39,0x56,0x45,0x49,0x32,0x62,
0x53,0x4f,0x0a,0x34,0x4a,0x51,0x42,0x55,0x42,0x53,0x6b,0x70,0x64,0x48,0x34,0x57,
0x32,0x77,0x51,0x75,0x2f,0x61,0x58,0x57,0x38,0x75,0x75,0x53,0x39,0x45,0x43,0x6d,
0x6d,0x41,0x41,0x75,0x45,0x79,0x4a,0x54,0x56,0x7a,0x75,0x31,0x32,0x35,0x58,0x73,
0x65,0x63,0x6c,0x44,0x41,0x55,0x38,0x49,0x55,0x70,0x54,0x2b,0x70,0x4c,0x35,0x79,
0x70,0x37,0x34,0x0a,0x45,0x62,0x76,0x4e,0x48,0x48,0x33,0x67,0x65,0x72,0x4f,0x67,
0x78,0x76,0x49,0x6a,0x50,0x64,0x67,0x77,0x62,0x66,0x6d,0x4d,0x49,0x59,0x48,0x62,
0x56,0x70,0x6e,0x49,0x30,0x77,0x32,0x42,0x43,0x44,0x51,0x76,0x74,0x64,0x64,0x57,
0x6f,0x42,0x74,0x41,0x33,0x43,0x54,0x6a,0x63,0x2f,0x43,0x56,0x67,0x73,0x47,0x77,
0x33,0x43,0x4e,0x72,0x0a,0x46,0x78,0x41,0x46,0x35,0x73,0x4a,0x34,0x63,0x5a,0x4c,
0x6e,0x5a,0x31,0x45,0x36,0x69,0x74,0x4c,0x54,0x50,0x69,0x6f,0x6a,0x74,0x76,0x48,
0x48,0x34,0x61,0x64,0x6d,0x68,0x68,0x43,0x61,0x42,0x49,0x78,0x76,0x47,0x2f,0x53,
0x6e,0x59,0x77,0x4e,0x35,0x38,0x37,0x55,0x5a,0x6d,0x37,0x4c,0x57,0x50,0x61,0x67,
0x4c,0x41,0x33,0x67,0x69,0x0a,0x48,0x4b,0x4f,0x2b,0x4b,0x79,0x42,0x51,0x39,0x33,
0x31,0x4e,0x4d,0x61,0x65,0x6a,0x36,0x6d,0x75,0x75,0x46,0x32,0x30,0x32,0x76,0x34,
0x37,0x6c,0x57,0x6b,0x64,0x50,0x4f,0x6e,0x52,0x43,0x69,0x6f,0x4d,0x58,0x30,0x63,
0x31,0x6a,0x36,0x76,0x32,0x61,0x59,0x34,0x34,0x77,0x55,0x4b,0x71,0x39,0x4d,0x52,
0x67,0x6f,0x52,0x76,0x4a,0x37,0x0a,0x41,0x39,0x77,0x65,0x72,0x4c,0x6b,0x68,0x35,
0x78,0x78,0x35,0x35,0x32,0x4f,0x74,0x71,0x50,0x36,0x73,0x61,0x6d,0x75,0x47,0x44,
0x52,0x78,0x31,0x42,0x70,0x36,0x53,0x4f,0x70,0x68,0x43,0x45,0x50,0x48,0x59,0x67,
0x51,0x4b,0x42,0x67,0x51,0x44,0x36,0x33,0x65,0x2b,0x52,0x75,0x6c,0x36,0x46,0x78,
0x47,0x43,0x76,0x67,0x70,0x6b,0x33,0x0a,0x57,0x67,0x2f,0x54,0x31,0x77,0x2f,0x59,
0x4b,0x6b,0x79,0x4f,0x49,0x46,0x4c,0x63,0x46,0x4c,0x57,0x71,0x42,0x44,0x71,0x6c,
0x6e,0x58,0x65,0x63,0x6c,0x6b,0x50,0x4b,0x6a,0x57,0x4e,0x2f,0x32,0x70,0x4a,0x6d,
0x4f,0x31,0x63,0x46,0x63,0x44,0x4a,0x46,0x59,0x64,0x32,0x45,0x49,0x45,0x72,0x76,
0x42,0x57,0x54,0x34,0x51,0x39,0x4d,0x42,0x0a,0x4e,0x35,0x6c,0x44,0x6b,0x47,0x75,
0x6a,0x34,0x2f,0x6b,0x68,0x56,0x6c,0x79,0x6e,0x77,0x62,0x64,0x42,0x6e,0x47,0x43,
0x34,0x61,0x34,0x48,0x4a,0x49,0x4a,0x76,0x61,0x35,0x63,0x70,0x49,0x63,0x57,0x65,
0x4a,0x72,0x35,0x61,0x57,0x33,0x69,0x44,0x36,0x68,0x53,0x73,0x61,0x6c,0x79,0x55,
0x76,0x4a,0x4d,0x6d,0x64,0x4d,0x42,0x6e,0x47,0x0a,0x37,0x2b,0x50,0x65,0x53,0x2b,
0x4e,0x73,0x4b,0x30,0x61,0x63,0x31,0x67,0x33,0x4d,0x6c,0x56,0x35,0x42,0x41,0x32,
0x70,0x55,0x54,0x77,0x4b,0x42,0x67,0x51,0x44,0x62,0x65,0x46,0x6d,0x2b,0x46,0x46,
0x35,0x62,0x76,0x6f,0x4b,0x7a,0x49,0x4c,0x6c,0x31,0x62,0x79,0x6b,0x6c,0x52,0x6b,
0x69,0x76,0x7a,0x6b,0x62,0x7a,0x49,0x6b,0x41,0x78,0x0a,0x35,0x56,0x6b,0x74,0x67,
0x36,0x4a,0x35,0x63,0x76,0x38,0x44,0x35,0x2b,0x72,0x71,0x50,0x75,0x6a,0x4f,0x66,
0x39,0x67,0x42,0x6a,0x4e,0x37,0x70,0x64,0x78,0x39,0x39,0x35,0x6b,0x47,0x49,0x78,
0x5a,0x39,0x6d,0x31,0x68,0x57,0x69,0x78,0x55,0x55,0x31,0x55,0x6f,0x38,0x72,0x70,
0x39,0x4a,0x69,0x47,0x4f,0x36,0x72,0x65,0x31,0x77,0x69,0x0a,0x6a,0x56,0x2f,0x4c,
0x31,0x64,0x37,0x55,0x66,0x39,0x48,0x6a,0x65,0x61,0x70,0x4f,0x46,0x62,0x34,0x6b,
0x72,0x71,0x52,0x58,0x54,0x65,0x75,0x4d,0x6e,0x35,0x35,0x44,0x33,0x64,0x70,0x79,
0x6a,0x51,0x4e,0x43,0x30,0x5a,0x50,0x72,0x61,0x6d,0x58,0x64,0x38,0x31,0x57,0x6f,
0x6f,0x56,0x77,0x58,0x59,0x41,0x66,0x69,0x46,0x76,0x4c,0x49,0x0a,0x6f,0x66,0x31,
0x37,0x51,0x67,0x67,0x49,0x59,0x51,0x4b,0x42,0x67,0x51,0x44,0x59,0x55,0x67,0x67,
0x43,0x34,0x58,0x49,0x67,0x5a,0x76,0x58,0x34,0x59,0x65,0x55,0x38,0x6c,0x61,0x79,
0x51,0x50,0x79,0x4b,0x71,0x67,0x38,0x37,0x2f,0x76,0x31,0x2b,0x7a,0x35,0x79,0x65,
0x2f,0x4d,0x32,0x5a,0x65,0x36,0x53,0x6e,0x37,0x48,0x4a,0x66,0x59,0x0a,0x55,0x5a,
0x4d,0x36,0x37,0x48,0x37,0x52,0x4b,0x4e,0x6f,0x68,0x46,0x6c,0x35,0x43,0x39,0x65,
0x44,0x4e,0x7a,0x67,0x72,0x50,0x6b,0x52,0x63,0x2f,0x2f,0x54,0x77,0x32,0x45,0x48,
0x74,0x59,0x68,0x33,0x42,0x4b,0x49,0x6f,0x72,0x77,0x39,0x45,0x64,0x78,0x59,0x4e,
0x6c,0x6b,0x2b,0x6a,0x4e,0x73,0x30,0x30,0x64,0x57,0x35,0x34,0x64,0x39,0x0a,0x65,
0x69,0x69,0x7a,0x7a,0x78,0x59,0x34,0x34,0x2f,0x41,0x32,0x70,0x39,0x52,0x49,0x4d,
0x67,0x79,0x35,0x49,0x52,0x77,0x76,0x53,0x73,0x6d,0x50,0x67,0x61,0x71,0x34,0x6f,
0x4b,0x4d,0x64,0x54,0x4e,0x4d,0x4f,0x73,0x30,0x4a,0x77,0x65,0x79,0x50,0x72,0x42,
0x65,0x49,0x41,0x72,0x62,0x46,0x43,0x67,0x51,0x4b,0x42,0x67,0x51,0x43,0x71,0x0a,
0x57,0x30,0x34,0x56,0x33,0x49,0x75,0x74,0x33,0x55,0x42,0x6f,0x75,0x50,0x4d,0x63,
0x63,0x38,0x2f,0x56,0x62,0x69,0x77,0x48,0x77,0x79,0x2b,0x52,0x6c,0x4c,0x6d,0x4e,
0x77,0x59,0x41,0x71,0x63,0x79,0x35,0x50,0x35,0x58,0x4b,0x4c,0x33,0x70,0x36,0x62,
0x65,0x33,0x2b,0x4d,0x6f,0x76,0x48,0x52,0x71,0x6a,0x35,0x78,0x72,0x4a,0x54,0x57,
0x0a,0x54,0x6a,0x2f,0x36,0x59,0x61,0x51,0x73,0x31,0x2b,0x72,0x74,0x63,0x51,0x45,
0x61,0x74,0x64,0x34,0x4b,0x50,0x66,0x64,0x78,0x53,0x2f,0x63,0x66,0x52,0x74,0x38,
0x71,0x74,0x75,0x42,0x77,0x51,0x61,0x2f,0x34,0x39,0x4d,0x72,0x41,0x4c,0x76,0x57,
0x43,0x4c,0x53,0x42,0x75,0x4b,0x74,0x33,0x49,0x49,0x75,0x53,0x2f,0x51,0x44,0x74,
0x43,0x0a,0x5a,0x4e,0x67,0x6d,0x36,0x4d,0x78,0x71,0x4e,0x6e,0x49,0x43,0x58,0x35,
0x46,0x34,0x36,0x6d,0x52,0x49,0x52,0x42,0x42,0x4f,0x32,0x4b,0x7a,0x6c,0x30,0x33,
0x68,0x62,0x51,0x6c,0x71,0x58,0x4c,0x5a,0x63,0x38,0x6f,0x51,0x4b,0x42,0x67,0x43,
0x53,0x77,0x66,0x46,0x7a,0x68,0x48,0x76,0x78,0x36,0x68,0x69,0x64,0x57,0x67,0x48,
0x4a,0x63,0x0a,0x77,0x79,0x76,0x64,0x6e,0x70,0x58,0x78,0x36,0x5a,0x4c,0x6e,0x6f,
0x61,0x7a,0x61,0x6f,0x48,0x47,0x74,0x4d,0x47,0x43,0x45,0x5a,0x49,0x50,0x66,0x6a,
0x4c,0x42,0x63,0x30,0x4d,0x74,0x79,0x45,0x64,0x53,0x4c,0x78,0x54,0x6c,0x35,0x59,
0x70,0x78,0x6f,0x6d,0x43,0x46,0x55,0x4d,0x33,0x55,0x63,0x59,0x4e,0x2f,0x50,0x5a,
0x66,0x58,0x41,0x0a,0x6d,0x36,0x31,0x45,0x6d,0x71,0x53,0x53,0x4d,0x56,0x63,0x47,
0x50,0x67,0x65,0x2f,0x43,0x34,0x44,0x42,0x5a,0x59,0x6a,0x53,0x45,0x71,0x62,0x67,
0x37,0x6d,0x73,0x52,0x30,0x33,0x37,0x42,0x58,0x54,0x48,0x6b,0x78,0x44,0x62,0x33,
0x71,0x48,0x46,0x54,0x6f,0x30,0x6b,0x48,0x57,0x4a,0x66,0x34,0x39,0x59,0x77,0x32,
0x73,0x77,0x6a,0x54,0x0a,0x72,0x4f,0x38,0x46,0x46,0x44,0x52,0x56,0x50,0x44,0x4c,
0x5a,0x61,0x37,0x36,0x47,0x67,0x79,0x41,0x55,0x4a,0x38,0x55,0x63,0x0a,0x2d,0x2d,
0x2d,0x2d,0x2d,0x45,0x4e,0x44,0x20,0x50,0x52,0x49,0x56,0x41,0x54,0x45,0x20,0x4b,
0x45,0x59,0x2d,0x2d,0x2d,0x2d,0x2d,0x0a
            },
        };

        VpnRpcKeyPair out_rpc_key_pair = api.SetServerCert(in_rpc_key_pair);

        print_object(out_rpc_key_pair);

        Console.WriteLine("End: Test_SetServerCert");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetServerCert', Get the server certification
    /// </summary>
    public void Test_GetServerCert()
    {
        Console.WriteLine("Begin: Test_GetServerCert");

        VpnRpcKeyPair out_rpc_key_pair = api.GetServerCert();

        print_object(out_rpc_key_pair);

        Console.WriteLine("End: Test_GetServerCert");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetServerCipher', Get cipher for SSL
    /// </summary>
    public void Test_GetServerCipher()
    {
        Console.WriteLine("Begin: Test_GetServerCipher");

        VpnRpcStr out_rpc_str = api.GetServerCipher();

        print_object(out_rpc_str);

        Console.WriteLine("End: Test_GetServerCipher");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetServerCipher', Set cipher for SSL to the server
    /// </summary>
    public void Test_SetServerCipher()
    {
        Console.WriteLine("Begin: Test_SetServerCipher");

        VpnRpcStr in_rpc_str = new VpnRpcStr() { String_str = "RC4-MD5" };
        VpnRpcStr out_rpc_str = api.SetServerCipher(in_rpc_str);

        print_object(out_rpc_str);

        Console.WriteLine("End: Test_SetServerCipher");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'CreateHub', Create a hub
    /// </summary>
    public string Test_CreateHub()
    {
        string hub_name = "Test_" + rand.Next(100000, 999999);
        Console.WriteLine("Begin: Test_CreateHub");

        VpnRpcCreateHub in_rpc_create_hub = new VpnRpcCreateHub()
        {
            HubName_str = hub_name,
            HubType_u32 = VpnRpcHubType.Standalone,
            Online_bool = true,
            AdminPasswordPlainText_str = "microsoft",
            MaxSession_u32 = 123,
            NoEnum_bool = false,
        };

        VpnRpcCreateHub out_rpc_create_hub = api.CreateHub(in_rpc_create_hub);

        print_object(out_rpc_create_hub);

        Console.WriteLine("End: Test_CreateHub");
        Console.WriteLine("-----");
        Console.WriteLine();

        return hub_name;
    }

    /// <summary>
    /// API test for 'SetHub', Set hub configuration
    /// </summary>
    public void Test_SetHub()
    {
        Console.WriteLine("Begin: Test_SetHub");

        VpnRpcCreateHub in_rpc_create_hub = new VpnRpcCreateHub()
        {
            HubName_str = hub_name,
            AdminPasswordPlainText_str = "aho",
            HubType_u32 = VpnRpcHubType.Standalone,
            NoEnum_bool = false,
            MaxSession_u32 = 128,
            Online_bool = true,
        };

        VpnRpcCreateHub out_rpc_create_hub = api.SetHub(in_rpc_create_hub);

        print_object(out_rpc_create_hub);

        Console.WriteLine("End: Test_SetHub");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetHub', Get hub configuration
    /// </summary>
    public void Test_GetHub()
    {
        Console.WriteLine("Begin: Test_GetHub");

        VpnRpcCreateHub in_rpc_create_hub = new VpnRpcCreateHub()
        {
            HubName_str = hub_name,
        };

        VpnRpcCreateHub out_rpc_create_hub = api.GetHub(in_rpc_create_hub);

        print_object(out_rpc_create_hub);

        Console.WriteLine("End: Test_GetHub");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumHub', Enumerate hubs
    /// </summary>
    public void Test_EnumHub()
    {
        Console.WriteLine("Begin: Test_EnumHub");

        VpnRpcEnumHub out_rpc_enum_hub = api.EnumHub();

        print_object(out_rpc_enum_hub);

        Console.WriteLine("End: Test_EnumHub");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'DeleteHub', Delete a hub
    /// </summary>
    public void Test_DeleteHub()
    {
        Console.WriteLine("Begin: Test_DeleteHub");

        VpnRpcDeleteHub in_rpc_delete_hub = new VpnRpcDeleteHub()
        {
            HubName_str = hub_name,
        };
        VpnRpcDeleteHub out_rpc_delete_hub = api.DeleteHub(in_rpc_delete_hub);

        print_object(out_rpc_delete_hub);

        Console.WriteLine("End: Test_DeleteHub");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetHubRadius', Get Radius options of the hub
    /// </summary>
    public void Test_GetHubRadius()
    {
        Console.WriteLine("Begin: Test_GetHubRadius");

        VpnRpcRadius in_rpc_radius = new VpnRpcRadius()
        {
            HubName_str = hub_name,
        };
        VpnRpcRadius out_rpc_radius = api.GetHubRadius(in_rpc_radius);

        print_object(out_rpc_radius);

        Console.WriteLine("End: Test_GetHubRadius");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetHubRadius', Set Radius options of the hub
    /// </summary>
    public void Test_SetHubRadius()
    {
        Console.WriteLine("Begin: Test_SetHubRadius");

        VpnRpcRadius in_rpc_radius = new VpnRpcRadius()
        {
            HubName_str = hub_name,
            RadiusServerName_str = "1.2.3.4",
            RadiusPort_u32 = 1234,
            RadiusSecret_str = "microsoft",
            RadiusRetryInterval_u32 = 1000,
        };
        VpnRpcRadius out_rpc_radius = api.SetHubRadius(in_rpc_radius);

        print_object(out_rpc_radius);

        Console.WriteLine("End: Test_SetHubRadius");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumConnection', Enumerate connections
    /// </summary>
    public VpnRpcEnumConnection Test_EnumConnection()
    {
        Console.WriteLine("Begin: Test_EnumConnection");

        VpnRpcEnumConnection out_rpc_enum_connection = api.EnumConnection();

        print_object(out_rpc_enum_connection);

        Console.WriteLine("End: Test_EnumConnection");
        Console.WriteLine("-----");
        Console.WriteLine();

        return out_rpc_enum_connection;
    }

    /// <summary>
    /// API test for 'DisconnectConnection', Disconnect a connection
    /// </summary>
    public void Test_DisconnectConnection(string connection_id)
    {
        Console.WriteLine("Begin: Test_DisconnectConnection");

        VpnRpcDisconnectConnection in_rpc_disconnect_connection = new VpnRpcDisconnectConnection()
        {
            Name_str = connection_id,
        };
        VpnRpcDisconnectConnection out_rpc_disconnect_connection = api.DisconnectConnection(in_rpc_disconnect_connection);

        print_object(out_rpc_disconnect_connection);

        Console.WriteLine("End: Test_DisconnectConnection");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetConnectionInfo', Get connection information
    /// </summary>
    public void Test_GetConnectionInfo(string name)
    {
        Console.WriteLine("Begin: Test_GetConnectionInfo");

        VpnRpcConnectionInfo in_rpc_connection_info = new VpnRpcConnectionInfo()
        {
            Name_str = name,
        };
        VpnRpcConnectionInfo out_rpc_connection_info = api.GetConnectionInfo(in_rpc_connection_info);

        print_object(out_rpc_connection_info);

        Console.WriteLine("End: Test_GetConnectionInfo");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetHubOnline', Make a hub on-line or off-line
    /// </summary>
    public void Test_SetHubOnline()
    {
        Console.WriteLine("Begin: Test_SetHubOnline");

        VpnRpcSetHubOnline in_rpc_set_hub_online = new VpnRpcSetHubOnline()
        {
            HubName_str = hub_name,
            Online_bool = true,
        };
        VpnRpcSetHubOnline out_rpc_set_hub_online = api.SetHubOnline(in_rpc_set_hub_online);

        print_object(out_rpc_set_hub_online);

        Console.WriteLine("End: Test_SetHubOnline");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetHubStatus', Get hub status
    /// </summary>
    public void Test_GetHubStatus()
    {
        Console.WriteLine("Begin: Test_GetHubStatus");

        VpnRpcHubStatus in_rpc_hub_status = new VpnRpcHubStatus()
        {
            HubName_str = hub_name,
        };
        VpnRpcHubStatus out_rpc_hub_status = api.GetHubStatus(in_rpc_hub_status);

        print_object(out_rpc_hub_status);

        Console.WriteLine("End: Test_GetHubStatus");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetHubLog', Set logging configuration into the hub
    /// </summary>
    public void Test_SetHubLog(VpnRpcHubLog in_rpc_hub_log)
    {
        Console.WriteLine("Begin: Test_SetHubLog");

        VpnRpcHubLog out_rpc_hub_log = api.SetHubLog(in_rpc_hub_log);

        print_object(out_rpc_hub_log);

        Console.WriteLine("End: Test_SetHubLog");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetHubLog', Get logging configuration of the hub
    /// </summary>
    public VpnRpcHubLog Test_GetHubLog()
    {
        Console.WriteLine("Begin: Test_GetHubLog");

        VpnRpcHubLog in_rpc_hub_log = new VpnRpcHubLog()
        {
            HubName_str = hub_name,
        };
        VpnRpcHubLog out_rpc_hub_log = api.GetHubLog(in_rpc_hub_log);

        print_object(out_rpc_hub_log);

        Console.WriteLine("End: Test_GetHubLog");
        Console.WriteLine("-----");
        Console.WriteLine();

        return out_rpc_hub_log;
    }

    /// <summary>
    /// API test for 'AddCa', Add CA(Certificate Authority) into the hub
    /// </summary>
    public void Test_AddCa()
    {
        Console.WriteLine("Begin: Test_AddCa");

        VpnRpcHubAddCA in_rpc_hub_add_ca = new VpnRpcHubAddCA()
        {
            HubName_str = hub_name,
            Cert_bin = new byte[]
            {
0x2d,0x2d,0x2d,0x2d,0x2d,0x42,0x45,0x47,0x49,0x4e,0x20,0x43,0x45,0x52,0x54,0x49,
0x46,0x49,0x43,0x41,0x54,0x45,0x2d,0x2d,0x2d,0x2d,0x2d,0x0a,0x4d,0x49,0x49,0x44,
0x72,0x6a,0x43,0x43,0x41,0x70,0x61,0x67,0x41,0x77,0x49,0x42,0x41,0x67,0x49,0x42,
0x41,0x44,0x41,0x4e,0x42,0x67,0x6b,0x71,0x68,0x6b,0x69,0x47,0x39,0x77,0x30,0x42,
0x41,0x51,0x73,0x46,0x41,0x44,0x42,0x57,0x4d,0x51,0x77,0x77,0x43,0x67,0x59,0x44,
0x56,0x51,0x51,0x44,0x44,0x41,0x4e,0x68,0x59,0x57,0x45,0x78,0x0a,0x46,0x54,0x41,
0x54,0x42,0x67,0x4e,0x56,0x42,0x41,0x6f,0x4d,0x44,0x4f,0x4f,0x42,0x72,0x2b,0x4f,
0x42,0x71,0x75,0x4f,0x42,0x6a,0x2b,0x4f,0x42,0x6e,0x54,0x45,0x4c,0x4d,0x41,0x6b,
0x47,0x41,0x31,0x55,0x45,0x42,0x68,0x4d,0x43,0x53,0x6c,0x41,0x78,0x45,0x44,0x41,
0x4f,0x42,0x67,0x4e,0x56,0x42,0x41,0x67,0x4d,0x42,0x30,0x6c,0x69,0x0a,0x59,0x58,
0x4a,0x68,0x61,0x32,0x6b,0x78,0x45,0x44,0x41,0x4f,0x42,0x67,0x4e,0x56,0x42,0x41,
0x63,0x4d,0x42,0x31,0x52,0x7a,0x64,0x57,0x74,0x31,0x59,0x6d,0x45,0x77,0x48,0x68,
0x63,0x4e,0x4d,0x54,0x67,0x78,0x4d,0x44,0x45,0x78,0x4d,0x6a,0x4d,0x7a,0x4e,0x54,
0x41,0x78,0x57,0x68,0x63,0x4e,0x4e,0x44,0x49,0x78,0x4d,0x44,0x41,0x31,0x0a,0x4d,
0x6a,0x4d,0x7a,0x4e,0x54,0x41,0x78,0x57,0x6a,0x42,0x57,0x4d,0x51,0x77,0x77,0x43,
0x67,0x59,0x44,0x56,0x51,0x51,0x44,0x44,0x41,0x4e,0x68,0x59,0x57,0x45,0x78,0x46,
0x54,0x41,0x54,0x42,0x67,0x4e,0x56,0x42,0x41,0x6f,0x4d,0x44,0x4f,0x4f,0x42,0x72,
0x2b,0x4f,0x42,0x71,0x75,0x4f,0x42,0x6a,0x2b,0x4f,0x42,0x6e,0x54,0x45,0x4c,0x0a,
0x4d,0x41,0x6b,0x47,0x41,0x31,0x55,0x45,0x42,0x68,0x4d,0x43,0x53,0x6c,0x41,0x78,
0x45,0x44,0x41,0x4f,0x42,0x67,0x4e,0x56,0x42,0x41,0x67,0x4d,0x42,0x30,0x6c,0x69,
0x59,0x58,0x4a,0x68,0x61,0x32,0x6b,0x78,0x45,0x44,0x41,0x4f,0x42,0x67,0x4e,0x56,
0x42,0x41,0x63,0x4d,0x42,0x31,0x52,0x7a,0x64,0x57,0x74,0x31,0x59,0x6d,0x45,0x77,
0x0a,0x67,0x67,0x45,0x69,0x4d,0x41,0x30,0x47,0x43,0x53,0x71,0x47,0x53,0x49,0x62,
0x33,0x44,0x51,0x45,0x42,0x41,0x51,0x55,0x41,0x41,0x34,0x49,0x42,0x44,0x77,0x41,
0x77,0x67,0x67,0x45,0x4b,0x41,0x6f,0x49,0x42,0x41,0x51,0x44,0x58,0x45,0x63,0x76,
0x72,0x59,0x37,0x56,0x2b,0x7a,0x64,0x42,0x79,0x72,0x64,0x4e,0x78,0x4a,0x59,0x45,
0x6d,0x0a,0x61,0x41,0x4e,0x59,0x55,0x4f,0x37,0x76,0x57,0x34,0x68,0x64,0x41,0x35,
0x49,0x42,0x49,0x46,0x6d,0x4d,0x70,0x6e,0x62,0x79,0x69,0x4e,0x6e,0x5a,0x77,0x36,
0x57,0x39,0x6f,0x61,0x67,0x78,0x33,0x5a,0x49,0x65,0x65,0x48,0x56,0x59,0x62,0x52,
0x69,0x4b,0x36,0x41,0x66,0x46,0x74,0x53,0x31,0x32,0x2b,0x45,0x31,0x4d,0x59,0x31,
0x64,0x32,0x0a,0x61,0x71,0x51,0x31,0x53,0x72,0x49,0x43,0x39,0x51,0x35,0x55,0x6e,
0x5a,0x61,0x42,0x72,0x62,0x57,0x32,0x32,0x6d,0x4e,0x75,0x6c,0x4d,0x34,0x2f,0x6c,
0x49,0x4a,0x72,0x48,0x70,0x51,0x55,0x68,0x50,0x78,0x6f,0x62,0x79,0x34,0x2f,0x36,
0x4e,0x41,0x37,0x71,0x4b,0x67,0x55,0x48,0x69,0x79,0x4f,0x64,0x33,0x4a,0x42,0x70,
0x4f,0x66,0x77,0x0a,0x38,0x54,0x76,0x53,0x74,0x51,0x78,0x34,0x4c,0x38,0x59,0x64,
0x4b,0x51,0x35,0x68,0x74,0x7a,0x6b,0x32,0x68,0x70,0x52,0x4a,0x4c,0x30,0x6c,0x4b,
0x67,0x47,0x31,0x57,0x34,0x75,0x4b,0x32,0x39,0x39,0x42,0x74,0x7a,0x64,0x41,0x67,
0x66,0x42,0x76,0x43,0x54,0x33,0x41,0x31,0x61,0x53,0x70,0x6a,0x49,0x47,0x74,0x6e,
0x69,0x72,0x49,0x31,0x0a,0x46,0x4c,0x52,0x58,0x47,0x79,0x38,0x31,0x31,0x57,0x4a,
0x39,0x4a,0x68,0x68,0x34,0x41,0x4b,0x4c,0x66,0x79,0x56,0x70,0x42,0x4a,0x67,0x65,
0x34,0x73,0x56,0x72,0x36,0x4e,0x75,0x75,0x49,0x66,0x32,0x71,0x47,0x31,0x6f,0x79,
0x31,0x30,0x70,0x61,0x51,0x4e,0x65,0x71,0x32,0x33,0x55,0x47,0x61,0x59,0x74,0x2f,
0x7a,0x55,0x56,0x4a,0x77,0x0a,0x55,0x74,0x30,0x57,0x45,0x6b,0x58,0x38,0x48,0x4f,
0x63,0x62,0x33,0x75,0x49,0x6f,0x54,0x6d,0x61,0x4f,0x34,0x72,0x48,0x42,0x55,0x4a,
0x71,0x45,0x79,0x39,0x51,0x58,0x7a,0x53,0x57,0x77,0x43,0x35,0x78,0x45,0x43,0x64,
0x37,0x43,0x4a,0x53,0x53,0x68,0x31,0x30,0x4f,0x75,0x6e,0x6c,0x75,0x4c,0x32,0x4d,
0x47,0x65,0x5a,0x47,0x6e,0x76,0x0a,0x41,0x67,0x4d,0x42,0x41,0x41,0x47,0x6a,0x67,
0x59,0x59,0x77,0x67,0x59,0x4d,0x77,0x44,0x77,0x59,0x44,0x56,0x52,0x30,0x54,0x41,
0x51,0x48,0x2f,0x42,0x41,0x55,0x77,0x41,0x77,0x45,0x42,0x2f,0x7a,0x41,0x4c,0x42,
0x67,0x4e,0x56,0x48,0x51,0x38,0x45,0x42,0x41,0x4d,0x43,0x41,0x66,0x59,0x77,0x59,
0x77,0x59,0x44,0x56,0x52,0x30,0x6c,0x0a,0x42,0x46,0x77,0x77,0x57,0x67,0x59,0x49,
0x4b,0x77,0x59,0x42,0x42,0x51,0x55,0x48,0x41,0x77,0x45,0x47,0x43,0x43,0x73,0x47,
0x41,0x51,0x55,0x46,0x42,0x77,0x4d,0x43,0x42,0x67,0x67,0x72,0x42,0x67,0x45,0x46,
0x42,0x51,0x63,0x44,0x41,0x77,0x59,0x49,0x4b,0x77,0x59,0x42,0x42,0x51,0x55,0x48,
0x41,0x77,0x51,0x47,0x43,0x43,0x73,0x47,0x0a,0x41,0x51,0x55,0x46,0x42,0x77,0x4d,
0x46,0x42,0x67,0x67,0x72,0x42,0x67,0x45,0x46,0x42,0x51,0x63,0x44,0x42,0x67,0x59,
0x49,0x4b,0x77,0x59,0x42,0x42,0x51,0x55,0x48,0x41,0x77,0x63,0x47,0x43,0x43,0x73,
0x47,0x41,0x51,0x55,0x46,0x42,0x77,0x4d,0x49,0x42,0x67,0x67,0x72,0x42,0x67,0x45,
0x46,0x42,0x51,0x63,0x44,0x43,0x54,0x41,0x4e,0x0a,0x42,0x67,0x6b,0x71,0x68,0x6b,
0x69,0x47,0x39,0x77,0x30,0x42,0x41,0x51,0x73,0x46,0x41,0x41,0x4f,0x43,0x41,0x51,
0x45,0x41,0x46,0x6d,0x34,0x37,0x47,0x55,0x70,0x50,0x57,0x35,0x2b,0x37,0x69,0x46,
0x74,0x69,0x6c,0x6f,0x6b,0x35,0x32,0x49,0x6f,0x54,0x57,0x72,0x74,0x46,0x67,0x32,
0x79,0x69,0x36,0x6b,0x49,0x32,0x69,0x52,0x4e,0x51,0x0a,0x4b,0x75,0x67,0x48,0x55,
0x49,0x4f,0x34,0x4b,0x53,0x71,0x4a,0x56,0x42,0x50,0x38,0x61,0x4b,0x4f,0x61,0x54,
0x5a,0x47,0x45,0x31,0x4b,0x4d,0x68,0x2f,0x59,0x6a,0x68,0x36,0x71,0x2f,0x67,0x50,
0x61,0x6c,0x67,0x64,0x2f,0x38,0x44,0x6d,0x72,0x78,0x53,0x4a,0x6d,0x55,0x78,0x33,
0x62,0x4e,0x62,0x38,0x52,0x59,0x36,0x70,0x4b,0x7a,0x74,0x0a,0x5a,0x64,0x75,0x53,
0x61,0x53,0x2b,0x57,0x55,0x30,0x59,0x74,0x2b,0x6c,0x47,0x35,0x76,0x56,0x67,0x61,
0x70,0x48,0x45,0x71,0x36,0x79,0x71,0x4c,0x62,0x65,0x56,0x78,0x51,0x4c,0x75,0x62,
0x54,0x69,0x6e,0x4f,0x66,0x56,0x56,0x5a,0x58,0x79,0x45,0x43,0x59,0x47,0x4d,0x73,
0x59,0x71,0x65,0x6e,0x4a,0x6a,0x4e,0x63,0x62,0x49,0x5a,0x4e,0x0a,0x79,0x4d,0x75,
0x72,0x46,0x63,0x67,0x30,0x34,0x36,0x4f,0x34,0x59,0x79,0x68,0x56,0x79,0x71,0x53,
0x69,0x74,0x43,0x59,0x37,0x68,0x2f,0x65,0x71,0x67,0x6b,0x50,0x4a,0x51,0x30,0x68,
0x6b,0x70,0x39,0x45,0x64,0x51,0x77,0x62,0x6e,0x38,0x56,0x6c,0x66,0x78,0x64,0x42,
0x58,0x77,0x51,0x34,0x4e,0x48,0x4b,0x30,0x4a,0x56,0x46,0x2f,0x33,0x0a,0x71,0x48,
0x61,0x68,0x4e,0x48,0x4f,0x35,0x64,0x62,0x4a,0x5a,0x57,0x59,0x41,0x62,0x42,0x44,
0x70,0x32,0x51,0x45,0x53,0x70,0x76,0x6f,0x2b,0x38,0x33,0x6c,0x68,0x34,0x64,0x6e,
0x58,0x6a,0x46,0x58,0x4d,0x43,0x48,0x76,0x52,0x68,0x35,0x31,0x79,0x2f,0x54,0x71,
0x79,0x42,0x34,0x56,0x76,0x72,0x52,0x4b,0x49,0x4b,0x74,0x54,0x6f,0x7a,0x0a,0x5a,
0x6a,0x48,0x59,0x49,0x63,0x62,0x6a,0x76,0x53,0x58,0x4d,0x7a,0x61,0x44,0x50,0x6a,
0x50,0x63,0x5a,0x47,0x6a,0x42,0x4a,0x6c,0x47,0x36,0x43,0x76,0x44,0x34,0x4c,0x6d,
0x59,0x7a,0x72,0x6b,0x48,0x34,0x31,0x63,0x7a,0x72,0x34,0x57,0x41,0x3d,0x3d,0x0a,
0x2d,0x2d,0x2d,0x2d,0x2d,0x45,0x4e,0x44,0x20,0x43,0x45,0x52,0x54,0x49,0x46,0x49,
0x43,0x41,0x54,0x45,0x2d,0x2d,0x2d,0x2d,0x2d,0x0a
            },
        };
        VpnRpcHubAddCA out_rpc_hub_add_ca = api.AddCa(in_rpc_hub_add_ca);

        print_object(out_rpc_hub_add_ca);

        Console.WriteLine("End: Test_AddCa");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumCa', Enumerate CA(Certificate Authority) in the hub
    /// </summary>
    public VpnRpcHubEnumCA Test_EnumCa()
    {
        Console.WriteLine("Begin: Test_EnumCa");

        VpnRpcHubEnumCA in_rpc_hub_enum_ca = new VpnRpcHubEnumCA()
        {
            HubName_str = hub_name,
        };
        VpnRpcHubEnumCA out_rpc_hub_enum_ca = api.EnumCa(in_rpc_hub_enum_ca);

        print_object(out_rpc_hub_enum_ca);

        Console.WriteLine("End: Test_EnumCa");
        Console.WriteLine("-----");
        Console.WriteLine();

        return out_rpc_hub_enum_ca;
    }

    /// <summary>
    /// API test for 'GetCa', Get CA(Certificate Authority) setting from the hub
    /// </summary>
    public void Test_GetCa(uint key)
    {
        Console.WriteLine("Begin: Test_GetCa");

        VpnRpcHubGetCA in_rpc_hub_get_ca = new VpnRpcHubGetCA()
        {
            HubName_str = hub_name,
            Key_u32 = key,
        };
        VpnRpcHubGetCA out_rpc_hub_get_ca = api.GetCa(in_rpc_hub_get_ca);

        print_object(out_rpc_hub_get_ca);

        Console.WriteLine("End: Test_GetCa");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'DeleteCa', Delete a CA(Certificate Authority) setting from the hub
    /// </summary>
    public void Test_DeleteCa(uint key)
    {
        Console.WriteLine("Begin: Test_DeleteCa");

        VpnRpcHubDeleteCA in_rpc_hub_delete_ca = new VpnRpcHubDeleteCA()
        {
            HubName_str = hub_name,
            Key_u32 = key,
        };
        VpnRpcHubDeleteCA out_rpc_hub_delete_ca = api.DeleteCa(in_rpc_hub_delete_ca);

        print_object(out_rpc_hub_delete_ca);

        Console.WriteLine("End: Test_DeleteCa");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetLinkOnline', Make a link into on-line
    /// </summary>
    public void Test_SetLinkOnline()
    {
        Console.WriteLine("Begin: Test_SetLinkOnline");

        VpnRpcLink in_rpc_link = new VpnRpcLink()
        {
            HubName_str = hub_name,
            AccountName_utf = "linktest",
        };
        VpnRpcLink out_rpc_link = api.SetLinkOnline(in_rpc_link);

        print_object(out_rpc_link);

        Console.WriteLine("End: Test_SetLinkOnline");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetLinkOffline', Make a link into off-line
    /// </summary>
    public void Test_SetLinkOffline()
    {
        Console.WriteLine("Begin: Test_SetLinkOffline");

        VpnRpcLink in_rpc_link = new VpnRpcLink()
        {
            HubName_str = hub_name,
            AccountName_utf = "linktest",
        };
        VpnRpcLink out_rpc_link = api.SetLinkOffline(in_rpc_link);

        print_object(out_rpc_link);

        Console.WriteLine("End: Test_SetLinkOffline");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'DeleteLink', Delete a link
    /// </summary>
    public void Test_DeleteLink()
    {
        Console.WriteLine("Begin: Test_DeleteLink");

        VpnRpcLink in_rpc_link = new VpnRpcLink()
        {
            HubName_str = hub_name,
            AccountName_utf = "linktest2",
        };
        VpnRpcLink out_rpc_link = api.DeleteLink(in_rpc_link);

        print_object(out_rpc_link);

        Console.WriteLine("End: Test_DeleteLink");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'RenameLink', Rename link (cascade connection)
    /// </summary>
    public void Test_RenameLink()
    {
        Console.WriteLine("Begin: Test_RenameLink");

        VpnRpcRenameLink in_rpc_rename_link = new VpnRpcRenameLink()
        {
            HubName_str = hub_name,
            OldAccountName_utf = "linktest",
            NewAccountName_utf = "linktest2",
        };
        VpnRpcRenameLink out_rpc_rename_link = api.RenameLink(in_rpc_rename_link);

        print_object(out_rpc_rename_link);

        Console.WriteLine("End: Test_RenameLink");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'CreateLink', Create a new link(cascade)
    /// </summary>
    public void Test_CreateLink()
    {
        Console.WriteLine("Begin: Test_CreateLink");

        VpnRpcCreateLink in_rpc_create_link = new VpnRpcCreateLink()
        {
            HubName_Ex_str = hub_name,
            CheckServerCert_bool = false,

            ClientOption_AccountName_utf = "linktest",
            ClientOption_Hostname_str = "1.2.3.4",
            ClientOption_Port_u32 = 443,
            ClientOption_ProxyType_u32 = 0,
            ClientOption_HubName_str = "ABC",
            ClientOption_MaxConnection_u32 = 16,
            ClientOption_UseEncrypt_bool = true,
            ClientOption_UseCompress_bool = false,
            ClientOption_HalfConnection_bool = true,
            ClientOption_AdditionalConnectionInterval_u32 = 2,
            ClientOption_ConnectionDisconnectSpan_u32 = 24,

            ClientAuth_AuthType_u32 = VpnRpcClientAuthType.PlainPassword,
            ClientAuth_Username_str = "181012",
            ClientAuth_PlainPassword_str = "microsoft",
            ClientAuth_HashedPassword_bin = new byte[0] { },
            ClientAuth_ClientX_bin = new byte[0] { },
            ClientAuth_ClientK_bin = new byte[0] { },

            SecPol_DHCPFilter_bool = true,
            SecPol_DHCPNoServer_bool = true,
            SecPol_DHCPForce_bool = true,
            SecPol_CheckMac_bool = true,
            SecPol_CheckIP_bool = true,
            SecPol_ArpDhcpOnly_bool = true,
            SecPol_PrivacyFilter_bool = true,
            SecPol_NoServer_bool = true,
            SecPol_NoBroadcastLimiter_bool = true,
            SecPol_MaxMac_u32 = 32,
            SecPol_MaxIP_u32 = 64,
            SecPol_MaxUpload_u32 = 960000,
            SecPol_MaxDownload_u32 = 1280000,
            SecPol_RSandRAFilter_bool = true,
            SecPol_RAFilter_bool = true,
            SecPol_DHCPv6Filter_bool = true,
            SecPol_DHCPv6NoServer_bool = true,
            SecPol_CheckIPv6_bool = true,
            SecPol_NoServerV6_bool = true,
            SecPol_MaxIPv6_u32 = 127,
            SecPol_FilterIPv4_bool = true,
            SecPol_FilterIPv6_bool = true,
            SecPol_FilterNonIP_bool = true,
            SecPol_NoIPv6DefaultRouterInRA_bool = true,
            SecPol_VLanId_u32 = 123,
            SecPol_Ver3_bool = true,
        };
        VpnRpcCreateLink out_rpc_create_link = api.CreateLink(in_rpc_create_link);

        print_object(out_rpc_create_link);

        Console.WriteLine("End: Test_CreateLink");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetLink', Get link configuration
    /// </summary>
    public void Test_GetLink()
    {
        Console.WriteLine("Begin: Test_GetLink");

        VpnRpcCreateLink in_rpc_create_link = new VpnRpcCreateLink()
        {
            HubName_Ex_str = hub_name,
            ClientOption_AccountName_utf = "linktest",
        };
        VpnRpcCreateLink out_rpc_create_link = api.GetLink(in_rpc_create_link);

        print_object(out_rpc_create_link);

        Console.WriteLine("End: Test_GetLink");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetLink', Set link configuration
    /// </summary>
    public void Test_SetLink()
    {
        Console.WriteLine("Begin: Test_SetLink");

        VpnRpcCreateLink in_rpc_create_link = new VpnRpcCreateLink()
        {
            HubName_Ex_str = hub_name,
            CheckServerCert_bool = false,

            ClientOption_AccountName_utf = "linktest",
            ClientOption_Hostname_str = "1.2.3.4",
            ClientOption_Port_u32 = 443,
            ClientOption_ProxyType_u32 = 0,
            ClientOption_HubName_str = "ABC",
            ClientOption_MaxConnection_u32 = 16,
            ClientOption_UseEncrypt_bool = true,
            ClientOption_UseCompress_bool = false,
            ClientOption_HalfConnection_bool = true,
            ClientOption_AdditionalConnectionInterval_u32 = 2,
            ClientOption_ConnectionDisconnectSpan_u32 = 24,

            ClientAuth_AuthType_u32 = VpnRpcClientAuthType.PlainPassword,
            ClientAuth_Username_str = "181012",
            ClientAuth_PlainPassword_str = "microsoft",
            ClientAuth_HashedPassword_bin = new byte[0] { },
            ClientAuth_ClientX_bin = new byte[0] { },
            ClientAuth_ClientK_bin = new byte[0] { },

            SecPol_DHCPFilter_bool = true,
            SecPol_DHCPNoServer_bool = true,
            SecPol_DHCPForce_bool = true,
            SecPol_CheckMac_bool = true,
            SecPol_CheckIP_bool = true,
            SecPol_ArpDhcpOnly_bool = true,
            SecPol_PrivacyFilter_bool = true,
            SecPol_NoServer_bool = true,
            SecPol_NoBroadcastLimiter_bool = true,
            SecPol_MaxMac_u32 = 32,
            SecPol_MaxIP_u32 = 64,
            SecPol_MaxUpload_u32 = 960000,
            SecPol_MaxDownload_u32 = 1280000,
            SecPol_RSandRAFilter_bool = true,
            SecPol_RAFilter_bool = true,
            SecPol_DHCPv6Filter_bool = true,
            SecPol_DHCPv6NoServer_bool = true,
            SecPol_CheckIPv6_bool = true,
            SecPol_NoServerV6_bool = true,
            SecPol_MaxIPv6_u32 = 127,
            SecPol_FilterIPv4_bool = true,
            SecPol_FilterIPv6_bool = true,
            SecPol_FilterNonIP_bool = true,
            SecPol_NoIPv6DefaultRouterInRA_bool = true,
            SecPol_VLanId_u32 = 123,
            SecPol_Ver3_bool = true,
        };
        VpnRpcCreateLink out_rpc_create_link = api.SetLink(in_rpc_create_link);

        print_object(out_rpc_create_link);

        Console.WriteLine("End: Test_SetLink");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumLink', Enumerate links
    /// </summary>
    public VpnRpcEnumLink Test_EnumLink()
    {
        Console.WriteLine("Begin: Test_EnumLink");

        VpnRpcEnumLink in_rpc_enum_link = new VpnRpcEnumLink()
        {
            HubName_str = hub_name,
        };
        VpnRpcEnumLink out_rpc_enum_link = api.EnumLink(in_rpc_enum_link);

        print_object(out_rpc_enum_link);

        Console.WriteLine("End: Test_EnumLink");
        Console.WriteLine("-----");
        Console.WriteLine();

        return out_rpc_enum_link;
    }

    /// <summary>
    /// API test for 'GetLinkStatus', Get link status
    /// </summary>
    public void Test_GetLinkStatus(string name)
    {
        Console.WriteLine("Begin: Test_GetLinkStatus");

        VpnRpcLinkStatus in_rpc_link_status = new VpnRpcLinkStatus()
        {
            HubName_Ex_str = hub_name,
            AccountName_utf = name,
        };
        VpnRpcLinkStatus out_rpc_link_status = api.GetLinkStatus(in_rpc_link_status);

        print_object(out_rpc_link_status);

        Console.WriteLine("End: Test_GetLinkStatus");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'AddAccess', Add access list entry
    /// </summary>
    public void Test_AddAccess()
    {
        Console.WriteLine("Begin: Test_AddAccess");

        VpnRpcAddAccess in_rpc_add_access_ipv4 = new VpnRpcAddAccess()
        {
            HubName_str = hub_name,

            AccessListSingle = new VpnAccess[1]
            {
                new VpnAccess()
                {
                    Note_utf = "IPv4 Test",
                    Active_bool = true,
                    Priority_u32 = 100,
                    Discard_bool = true,
                    IsIPv6_bool = false,
                    SrcIpAddress_ip = "192.168.0.0",
                    SrcSubnetMask_ip = "255.255.255.0",
                    DestIpAddress_ip = "10.0.0.0",
                    DestSubnetMask_ip = "255.255.0.0",
                    Protocol_u32 = VpnIpProtocolNumber.TCP,
                    SrcPortStart_u32 = 123,
                    SrcPortEnd_u32 = 456,
                    DestPortStart_u32 = 555,
                    DestPortEnd_u32 = 666,
                    SrcUsername_str = "dnobori",
                    DestUsername_str = "nekosan",
                    CheckSrcMac_bool = true,
                    SrcMacAddress_bin = new byte[] { 1, 2, 3, 0, 0, 0 },
                    SrcMacMask_bin = new byte[] { 255, 255, 255, 0, 0, 0 },
                    CheckTcpState_bool = true,
                    Established_bool = true,
                    Delay_u32 = 10,
                    Jitter_u32 = 20,
                    Loss_u32 = 30,
                    RedirectUrl_str = "aho",
                },
            },
        };
        VpnRpcAddAccess out_rpc_add_access_ipv4 = api.AddAccess(in_rpc_add_access_ipv4);

        VpnRpcAddAccess in_rpc_add_access_ipv6 = new VpnRpcAddAccess()
        {
            HubName_str = hub_name,

            AccessListSingle = new VpnAccess[1]
            {
                new VpnAccess()
                {
                    Note_utf = "IPv6 Test",
                    Active_bool = true,
                    Priority_u32 = 100,
                    Discard_bool = true,
                    IsIPv6_bool = true,
                    SrcIpAddress6_bin = new byte[] { 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
                    SrcSubnetMask6_bin = new byte[] { 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
                    Protocol_u32 = VpnIpProtocolNumber.UDP,
                    SrcPortStart_u32 = 123,
                    SrcPortEnd_u32 = 456,
                    DestPortStart_u32 = 555,
                    DestPortEnd_u32 = 666,
                    SrcUsername_str = "dnobori",
                    DestUsername_str = "nekosan",
                    CheckSrcMac_bool = true,
                    SrcMacAddress_bin = new byte[] { 1, 2, 3, 0, 0, 0 },
                    SrcMacMask_bin = new byte[] { 255, 255, 255, 0, 0, 0 },
                    CheckTcpState_bool = true,
                    Established_bool = true,
                    Delay_u32 = 10,
                    Jitter_u32 = 20,
                    Loss_u32 = 30,
                    RedirectUrl_str = "aho",
                },
            },
        };
        VpnRpcAddAccess out_rpc_add_access_ipv6 = api.AddAccess(in_rpc_add_access_ipv6);

        Console.WriteLine("End: Test_AddAccess");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'DeleteAccess', Delete access list entry
    /// </summary>
    public void Test_DeleteAccess()
    {
        Console.WriteLine("Begin: Test_DeleteAccess");

        VpnRpcDeleteAccess in_rpc_delete_access = new VpnRpcDeleteAccess()
        {
            HubName_str = hub_name,
            Id_u32 = 1,
        };
        VpnRpcDeleteAccess out_rpc_delete_access = api.DeleteAccess(in_rpc_delete_access);

        print_object(out_rpc_delete_access);

        Console.WriteLine("End: Test_DeleteAccess");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumAccess', Get access list
    /// </summary>
    public void Test_EnumAccess()
    {
        Console.WriteLine("Begin: Test_EnumAccess");

        VpnRpcEnumAccessList in_rpc_enum_access_list = new VpnRpcEnumAccessList()
        {
            HubName_str = hub_name,
        };
        VpnRpcEnumAccessList out_rpc_enum_access_list = api.EnumAccess(in_rpc_enum_access_list);

        print_object(out_rpc_enum_access_list);

        Console.WriteLine("End: Test_EnumAccess");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetAccessList', Set access list
    /// </summary>
    public void Test_SetAccessList()
    {
        Console.WriteLine("Begin: Test_SetAccessList");

        VpnRpcEnumAccessList in_rpc_enum_access_list = new VpnRpcEnumAccessList()
        {
            HubName_str = hub_name,
            AccessList = new VpnAccess[]
            {
                new VpnAccess()
                {
                    Note_utf = "IPv4 Test 2",
                    Active_bool = true,
                    Priority_u32 = 100,
                    Discard_bool = true,
                    IsIPv6_bool = false,
                    SrcIpAddress_ip = "192.168.0.0",
                    SrcSubnetMask_ip = "255.255.255.0",
                    DestIpAddress_ip = "10.0.0.0",
                    DestSubnetMask_ip = "255.255.0.0",
                    Protocol_u32 = VpnIpProtocolNumber.TCP,
                    SrcPortStart_u32 = 123,
                    SrcPortEnd_u32 = 456,
                    DestPortStart_u32 = 555,
                    DestPortEnd_u32 = 666,
                    SrcUsername_str = "dnobori",
                    DestUsername_str = "nekosan",
                    CheckSrcMac_bool = true,
                    SrcMacAddress_bin = new byte[] { 1, 2, 3, 0, 0, 0 },
                    SrcMacMask_bin = new byte[] { 255, 255, 255, 0, 0, 0 },
                    CheckTcpState_bool = true,
                    Established_bool = true,
                    Delay_u32 = 10,
                    Jitter_u32 = 20,
                    Loss_u32 = 30,
                    RedirectUrl_str = "aho",
                },
                new VpnAccess()
                {
                    Note_utf = "IPv6 Test 2",
                    Active_bool = true,
                    Priority_u32 = 100,
                    Discard_bool = true,
                    IsIPv6_bool = true,
                    SrcIpAddress6_bin = new byte[] { 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
                    SrcSubnetMask6_bin = new byte[] { 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
                    Protocol_u32 = VpnIpProtocolNumber.UDP,
                    SrcPortStart_u32 = 123,
                    SrcPortEnd_u32 = 456,
                    DestPortStart_u32 = 555,
                    DestPortEnd_u32 = 666,
                    SrcUsername_str = "dnobori",
                    DestUsername_str = "nekosan",
                    CheckSrcMac_bool = true,
                    SrcMacAddress_bin = new byte[] { 1, 2, 3, 0, 0, 0 },
                    SrcMacMask_bin = new byte[] { 255, 255, 255, 0, 0, 0 },
                    CheckTcpState_bool = true,
                    Established_bool = true,
                    Delay_u32 = 10,
                    Jitter_u32 = 20,
                    Loss_u32 = 30,
                    RedirectUrl_str = "aho",
                },
            }
        };
        VpnRpcEnumAccessList out_rpc_enum_access_list = api.SetAccessList(in_rpc_enum_access_list);

        print_object(out_rpc_enum_access_list);

        Console.WriteLine("End: Test_SetAccessList");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'CreateUser', Create a user
    /// </summary>
    public void Test_CreateUser()
    {
        Console.WriteLine("Begin: Test_CreateUser");

        VpnRpcSetUser in_rpc_set_user = new VpnRpcSetUser()
        {
            HubName_str = hub_name,
            Name_str = "test1",
            Realname_utf = "Cat man",
            Note_utf = "Hey!!!",
            AuthType_u32 = VpnRpcUserAuthType.Password,
            Auth_Password_str = "microsoft",
            Auth_UserCert_CertData = new byte[0] { },
            Auth_RootCert_Serial = new byte[0] { },
            Auth_RootCert_CommonName = "",
            Auth_Radius_RadiusUsername = "",
            Auth_NT_NTUsername = "",
            ExpireTime_dt = new DateTime(2019, 1, 1),
            UsePolicy_bool = true,
            SecPol_Access_bool = true,
            SecPol_DHCPFilter_bool = false,
            SecPol_DHCPNoServer_bool = true,
            SecPol_DHCPForce_bool = false,
            SecPol_NoBridge_bool = false,
            SecPol_NoRouting_bool = false,
            SecPol_CheckMac_bool = false,
            SecPol_CheckIP_bool = false,
            SecPol_ArpDhcpOnly_bool = false,
            SecPol_PrivacyFilter_bool = false,
            SecPol_NoServer_bool = false,
            SecPol_NoBroadcastLimiter_bool = false,
            SecPol_MonitorPort_bool = false,
            SecPol_MaxConnection_u32 = 32,
            SecPol_TimeOut_u32 = 15,
            SecPol_MaxMac_u32 = 1000,
            SecPol_MaxIP_u32 = 1000,
            SecPol_MaxUpload_u32 = 1000000000,
            SecPol_MaxDownload_u32 = 1000000000,
            SecPol_FixPassword_bool = false,
            SecPol_MultiLogins_u32 = 1000,
            SecPol_NoQoS_bool = false,
            SecPol_RSandRAFilter_bool = false,
            SecPol_RAFilter_bool = false,
            SecPol_DHCPv6Filter_bool = false,
            SecPol_DHCPv6NoServer_bool = false,
            SecPol_NoRoutingV6_bool = false,
            SecPol_CheckIPv6_bool = false,
            SecPol_NoServerV6_bool = false,
            SecPol_MaxIPv6_u32 = 1234,
            SecPol_NoSavePassword_bool = false,
            SecPol_AutoDisconnect_u32 = 0,
            SecPol_FilterIPv4_bool = false,
            SecPol_FilterIPv6_bool = false,
            SecPol_FilterNonIP_bool = false,
            SecPol_NoIPv6DefaultRouterInRA_bool = false,
            SecPol_NoIPv6DefaultRouterInRAWhenIPv6_bool = false,
            SecPol_VLanId_u32 = 0,
            SecPol_Ver3_bool = true,
        };
        VpnRpcSetUser out_rpc_set_user = api.CreateUser(in_rpc_set_user);

        Console.WriteLine("End: Test_CreateUser");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetUser', Set user setting
    /// </summary>
    public void Test_SetUser()
    {
        Console.WriteLine("Begin: Test_SetUser");

        VpnRpcSetUser in_rpc_set_user = new VpnRpcSetUser()
        {
            HubName_str = hub_name,
            Name_str = "test1",
            Realname_utf = "Cat man",
            Note_utf = "Hey!!!",
            GroupName_str = "group1",
            AuthType_u32 = VpnRpcUserAuthType.Anonymous,
            Auth_Password_str = "",
            Auth_UserCert_CertData = new byte[0] { },
            Auth_RootCert_Serial = new byte[0] { },
            Auth_RootCert_CommonName = "",
            Auth_Radius_RadiusUsername = "",
            Auth_NT_NTUsername = "",
            ExpireTime_dt = new DateTime(2019, 1, 1),
            UsePolicy_bool = true,
            SecPol_Access_bool = true,
            SecPol_DHCPFilter_bool = false,
            SecPol_DHCPNoServer_bool = true,
            SecPol_DHCPForce_bool = false,
            SecPol_NoBridge_bool = false,
            SecPol_NoRouting_bool = false,
            SecPol_CheckMac_bool = false,
            SecPol_CheckIP_bool = false,
            SecPol_ArpDhcpOnly_bool = false,
            SecPol_PrivacyFilter_bool = false,
            SecPol_NoServer_bool = false,
            SecPol_NoBroadcastLimiter_bool = false,
            SecPol_MonitorPort_bool = false,
            SecPol_MaxConnection_u32 = 32,
            SecPol_TimeOut_u32 = 15,
            SecPol_MaxMac_u32 = 1000,
            SecPol_MaxIP_u32 = 1000,
            SecPol_MaxUpload_u32 = 1000000000,
            SecPol_MaxDownload_u32 = 1000000000,
            SecPol_FixPassword_bool = false,
            SecPol_MultiLogins_u32 = 1000,
            SecPol_NoQoS_bool = false,
            SecPol_RSandRAFilter_bool = false,
            SecPol_RAFilter_bool = false,
            SecPol_DHCPv6Filter_bool = false,
            SecPol_DHCPv6NoServer_bool = false,
            SecPol_NoRoutingV6_bool = false,
            SecPol_CheckIPv6_bool = false,
            SecPol_NoServerV6_bool = false,
            SecPol_MaxIPv6_u32 = 1234,
            SecPol_NoSavePassword_bool = false,
            SecPol_AutoDisconnect_u32 = 0,
            SecPol_FilterIPv4_bool = false,
            SecPol_FilterIPv6_bool = false,
            SecPol_FilterNonIP_bool = false,
            SecPol_NoIPv6DefaultRouterInRA_bool = false,
            SecPol_NoIPv6DefaultRouterInRAWhenIPv6_bool = false,
            SecPol_VLanId_u32 = 0,
            SecPol_Ver3_bool = true,
        };
        VpnRpcSetUser out_rpc_set_user = api.SetUser(in_rpc_set_user);

        Console.WriteLine("End: Test_SetUser");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetUser', Get user setting
    /// </summary>
    public void Test_GetUser()
    {
        Console.WriteLine("Begin: Test_GetUser");

        VpnRpcSetUser in_rpc_set_user = new VpnRpcSetUser()
        {
            HubName_str = hub_name,
            Name_str = "test1",
        };
        VpnRpcSetUser out_rpc_set_user = api.GetUser(in_rpc_set_user);

        print_object(out_rpc_set_user);

        Console.WriteLine("End: Test_GetUser");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'DeleteUser', Delete a user
    /// </summary>
    public void Test_DeleteUser()
    {
        Console.WriteLine("Begin: Test_DeleteUser");

        VpnRpcDeleteUser in_rpc_delete_user = new VpnRpcDeleteUser()
        {
            HubName_str = hub_name,
            Name_str = "test1",
        };
        VpnRpcDeleteUser out_rpc_delete_user = api.DeleteUser(in_rpc_delete_user);

        Console.WriteLine("End: Test_DeleteUser");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumUser', Enumerate users
    /// </summary>
    public void Test_EnumUser()
    {
        Console.WriteLine("Begin: Test_EnumUser");

        VpnRpcEnumUser in_rpc_enum_user = new VpnRpcEnumUser()
        {
            HubName_str = hub_name,
        };
        VpnRpcEnumUser out_rpc_enum_user = api.EnumUser(in_rpc_enum_user);

        print_object(out_rpc_enum_user);

        Console.WriteLine("End: Test_EnumUser");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'CreateGroup', Create a group
    /// </summary>
    public void Test_CreateGroup()
    {
        Console.WriteLine("Begin: Test_CreateGroup");

        VpnRpcSetGroup in_rpc_set_group = new VpnRpcSetGroup()
        {
            HubName_str = hub_name,
            Name_str = "group1",
            Realname_utf = "Cat group",
            Note_utf = "This is it! This is it!!",
            UsePolicy_bool = true,
            SecPol_Access_bool = true,
            SecPol_DHCPFilter_bool = false,
            SecPol_DHCPNoServer_bool = true,
            SecPol_DHCPForce_bool = false,
            SecPol_NoBridge_bool = false,
            SecPol_NoRouting_bool = false,
            SecPol_CheckMac_bool = false,
            SecPol_CheckIP_bool = false,
            SecPol_ArpDhcpOnly_bool = false,
            SecPol_PrivacyFilter_bool = false,
            SecPol_NoServer_bool = false,
            SecPol_NoBroadcastLimiter_bool = false,
            SecPol_MonitorPort_bool = false,
            SecPol_MaxConnection_u32 = 32,
            SecPol_TimeOut_u32 = 15,
            SecPol_MaxMac_u32 = 1000,
            SecPol_MaxIP_u32 = 1000,
            SecPol_MaxUpload_u32 = 1000000000,
            SecPol_MaxDownload_u32 = 1000000000,
            SecPol_FixPassword_bool = false,
            SecPol_MultiLogins_u32 = 1000,
            SecPol_NoQoS_bool = false,
            SecPol_RSandRAFilter_bool = false,
            SecPol_RAFilter_bool = false,
            SecPol_DHCPv6Filter_bool = false,
            SecPol_DHCPv6NoServer_bool = false,
            SecPol_NoRoutingV6_bool = false,
            SecPol_CheckIPv6_bool = false,
            SecPol_NoServerV6_bool = false,
            SecPol_MaxIPv6_u32 = 1234,
            SecPol_NoSavePassword_bool = false,
            SecPol_AutoDisconnect_u32 = 0,
            SecPol_FilterIPv4_bool = false,
            SecPol_FilterIPv6_bool = false,
            SecPol_FilterNonIP_bool = false,
            SecPol_NoIPv6DefaultRouterInRA_bool = false,
            SecPol_NoIPv6DefaultRouterInRAWhenIPv6_bool = false,
            SecPol_VLanId_u32 = 0,
            SecPol_Ver3_bool = true,
        };
        VpnRpcSetGroup out_rpc_set_group = api.CreateGroup(in_rpc_set_group);

        print_object(out_rpc_set_group);

        Console.WriteLine("End: Test_CreateGroup");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetGroup', Set group setting
    /// </summary>
    public void Test_SetGroup()
    {
        Console.WriteLine("Begin: Test_SetGroup");

        VpnRpcSetGroup in_rpc_set_group = new VpnRpcSetGroup()
        {
            HubName_str = hub_name,
            Name_str = "group1",
            Realname_utf = "Cat group 2",
            Note_utf = "This is it! This is it!! 2",
            UsePolicy_bool = true,
            SecPol_Access_bool = true,
            SecPol_DHCPFilter_bool = false,
            SecPol_DHCPNoServer_bool = true,
            SecPol_DHCPForce_bool = false,
            SecPol_NoBridge_bool = false,
            SecPol_NoRouting_bool = false,
            SecPol_CheckMac_bool = false,
            SecPol_CheckIP_bool = false,
            SecPol_ArpDhcpOnly_bool = false,
            SecPol_PrivacyFilter_bool = false,
            SecPol_NoServer_bool = false,
            SecPol_NoBroadcastLimiter_bool = false,
            SecPol_MonitorPort_bool = false,
            SecPol_MaxConnection_u32 = 32,
            SecPol_TimeOut_u32 = 15,
            SecPol_MaxMac_u32 = 1000,
            SecPol_MaxIP_u32 = 1000,
            SecPol_MaxUpload_u32 = 1000000000,
            SecPol_MaxDownload_u32 = 1000000000,
            SecPol_FixPassword_bool = false,
            SecPol_MultiLogins_u32 = 1000,
            SecPol_NoQoS_bool = false,
            SecPol_RSandRAFilter_bool = false,
            SecPol_RAFilter_bool = false,
            SecPol_DHCPv6Filter_bool = false,
            SecPol_DHCPv6NoServer_bool = false,
            SecPol_NoRoutingV6_bool = false,
            SecPol_CheckIPv6_bool = false,
            SecPol_NoServerV6_bool = false,
            SecPol_MaxIPv6_u32 = 1234,
            SecPol_NoSavePassword_bool = false,
            SecPol_AutoDisconnect_u32 = 0,
            SecPol_FilterIPv4_bool = false,
            SecPol_FilterIPv6_bool = false,
            SecPol_FilterNonIP_bool = false,
            SecPol_NoIPv6DefaultRouterInRA_bool = false,
            SecPol_NoIPv6DefaultRouterInRAWhenIPv6_bool = false,
            SecPol_VLanId_u32 = 0,
            SecPol_Ver3_bool = true,
        };
        VpnRpcSetGroup out_rpc_set_group = api.SetGroup(in_rpc_set_group);

        print_object(out_rpc_set_group);

        Console.WriteLine("End: Test_SetGroup");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetGroup', Get group information
    /// </summary>
    public void Test_GetGroup()
    {
        Console.WriteLine("Begin: Test_GetGroup");

        VpnRpcSetGroup in_rpc_set_group = new VpnRpcSetGroup()
        {
            HubName_str = hub_name,
            Name_str = "group1",
        };
        VpnRpcSetGroup out_rpc_set_group = api.GetGroup(in_rpc_set_group);

        print_object(out_rpc_set_group);

        Console.WriteLine("End: Test_GetGroup");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'DeleteGroup', Delete a group
    /// </summary>
    public void Test_DeleteGroup()
    {
        Console.WriteLine("Begin: Test_DeleteGroup");

        VpnRpcDeleteUser in_rpc_delete_user = new VpnRpcDeleteUser()
        {
            HubName_str = hub_name,
            Name_str = "group1",
        };
        VpnRpcDeleteUser out_rpc_delete_user = api.DeleteGroup(in_rpc_delete_user);

        print_object(out_rpc_delete_user);

        Console.WriteLine("End: Test_DeleteGroup");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumGroup', Enumerate groups
    /// </summary>
    public void Test_EnumGroup()
    {
        Console.WriteLine("Begin: Test_EnumGroup");

        VpnRpcEnumGroup in_rpc_enum_group = new VpnRpcEnumGroup()
        {
            HubName_str = hub_name,
        };
        VpnRpcEnumGroup out_rpc_enum_group = api.EnumGroup(in_rpc_enum_group);

        print_object(out_rpc_enum_group);

        Console.WriteLine("End: Test_EnumGroup");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumSession', Enumerate sessions
    /// </summary>
    public VpnRpcEnumSession Test_EnumSession()
    {
        Console.WriteLine("Begin: Test_EnumSession");

        VpnRpcEnumSession in_rpc_enum_session = new VpnRpcEnumSession()
        {
            HubName_str = hub_name,
        };
        VpnRpcEnumSession out_rpc_enum_session = api.EnumSession(in_rpc_enum_session);

        print_object(out_rpc_enum_session);

        Console.WriteLine("End: Test_EnumSession");
        Console.WriteLine("-----");
        Console.WriteLine();

        return out_rpc_enum_session;
    }

    /// <summary>
    /// API test for 'GetSessionStatus', Get session status
    /// </summary>
    public void Test_GetSessionStatus(string session_name)
    {
        Console.WriteLine("Begin: Test_GetSessionStatus");

        VpnRpcSessionStatus in_rpc_session_status = new VpnRpcSessionStatus()
        {
            HubName_str = hub_name,
            Name_str = session_name,
        };
        VpnRpcSessionStatus out_rpc_session_status = api.GetSessionStatus(in_rpc_session_status);

        print_object(out_rpc_session_status);

        Console.WriteLine("End: Test_GetSessionStatus");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'DeleteSession', Delete a session
    /// </summary>
    public void Test_DeleteSession(string session_id)
    {
        Console.WriteLine("Begin: Test_DeleteSession");

        VpnRpcDeleteSession in_rpc_delete_session = new VpnRpcDeleteSession()
        {
            HubName_str = hub_name,
            Name_str = session_id,
        };
        VpnRpcDeleteSession out_rpc_delete_session = api.DeleteSession(in_rpc_delete_session);

        print_object(out_rpc_delete_session);

        Console.WriteLine("End: Test_DeleteSession");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumMacTable', Get MAC address table
    /// </summary>
    public VpnRpcEnumMacTable Test_EnumMacTable()
    {
        Console.WriteLine("Begin: Test_EnumMacTable");

        VpnRpcEnumMacTable in_rpc_enum_mac_table = new VpnRpcEnumMacTable()
        {
            HubName_str = hub_name,
        };
        VpnRpcEnumMacTable out_rpc_enum_mac_table = api.EnumMacTable(in_rpc_enum_mac_table);

        print_object(out_rpc_enum_mac_table);

        Console.WriteLine("End: Test_EnumMacTable");
        Console.WriteLine("-----");
        Console.WriteLine();

        return out_rpc_enum_mac_table;
    }

    /// <summary>
    /// API test for 'DeleteMacTable', Delete MAC address table entry
    /// </summary>
    public void Test_DeleteMacTable(uint key32)
    {
        Console.WriteLine("Begin: Test_DeleteMacTable");

        VpnRpcDeleteTable in_rpc_delete_table = new VpnRpcDeleteTable()
        {
            HubName_str = hub_name,
            Key_u32 = key32,
        };
        VpnRpcDeleteTable out_rpc_delete_table = api.DeleteMacTable(in_rpc_delete_table);

        Console.WriteLine("End: Test_DeleteMacTable");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumIpTable', Get IP address table
    /// </summary>
    public VpnRpcEnumIpTable Test_EnumIpTable()
    {
        Console.WriteLine("Begin: Test_EnumIpTable");

        VpnRpcEnumIpTable in_rpc_enum_ip_table = new VpnRpcEnumIpTable()
        {
            HubName_str = hub_name,
        };
        VpnRpcEnumIpTable out_rpc_enum_ip_table = api.EnumIpTable(in_rpc_enum_ip_table);

        print_object(out_rpc_enum_ip_table);

        Console.WriteLine("End: Test_EnumIpTable");
        Console.WriteLine("-----");
        Console.WriteLine();

        return out_rpc_enum_ip_table;
    }

    /// <summary>
    /// API test for 'DeleteIpTable', Delete IP address table entry
    /// </summary>
    public void Test_DeleteIpTable(uint key32)
    {
        Console.WriteLine("Begin: Test_DeleteIpTable");

        VpnRpcDeleteTable in_rpc_delete_table = new VpnRpcDeleteTable()
        {
            HubName_str = hub_name,
            Key_u32 = key32,
        };
        VpnRpcDeleteTable out_rpc_delete_table = api.DeleteIpTable(in_rpc_delete_table);

        print_object(out_rpc_delete_table);

        Console.WriteLine("End: Test_DeleteIpTable");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetKeep', Set keep-alive function setting
    /// </summary>
    public void Test_SetKeep()
    {
        Console.WriteLine("Begin: Test_SetKeep");

        VpnRpcKeep in_rpc_keep = new VpnRpcKeep()
        {
            UseKeepConnect_bool = true,
            KeepConnectHost_str = "www.softether.org",
            KeepConnectPort_u32 = 123,
            KeepConnectProtocol_u32 = VpnRpcKeepAliveProtocol.UDP,
            KeepConnectInterval_u32 = 1,
        };
        VpnRpcKeep out_rpc_keep = api.SetKeep(in_rpc_keep);

        print_object(out_rpc_keep);

        Console.WriteLine("End: Test_SetKeep");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetKeep', Get keep-alive function setting
    /// </summary>
    public void Test_GetKeep()
    {
        Console.WriteLine("Begin: Test_GetKeep");

        VpnRpcKeep in_rpc_keep = new VpnRpcKeep()
        {
        };
        VpnRpcKeep out_rpc_keep = api.GetKeep(in_rpc_keep);

        print_object(out_rpc_keep);

        Console.WriteLine("End: Test_GetKeep");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnableSecureNAT', Enable SecureNAT function of the hub
    /// </summary>
    public void Test_EnableSecureNAT()
    {
        Console.WriteLine("Begin: Test_EnableSecureNAT");

        VpnRpcHub in_rpc_hub = new VpnRpcHub()
        {
            HubName_str = hub_name,
        };
        VpnRpcHub out_rpc_hub = api.EnableSecureNAT(in_rpc_hub);

        print_object(out_rpc_hub);

        Console.WriteLine("End: Test_EnableSecureNAT");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'DisableSecureNAT', Disable the SecureNAT function of the hub
    /// </summary>
    public void Test_DisableSecureNAT()
    {
        Console.WriteLine("Begin: Test_DisableSecureNAT");

        VpnRpcHub in_rpc_hub = new VpnRpcHub()
        {
            HubName_str = hub_name,
        };
        VpnRpcHub out_rpc_hub = api.DisableSecureNAT(in_rpc_hub);

        print_object(out_rpc_hub);

        Console.WriteLine("End: Test_DisableSecureNAT");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetSecureNATOption', Set SecureNAT options
    /// </summary>
    public void Test_SetSecureNATOption()
    {
        Console.WriteLine("Begin: Test_SetSecureNATOption");

        VpnVhOption in_vh_option = new VpnVhOption()
        {
            RpcHubName_str = hub_name,
            MacAddress_bin = new byte[] { 0x00, 0xAC, 0x00, 0x11, 0x22, 0x33 },
            Ip_ip = "10.0.0.254",
            Mask_ip = "255.255.255.0",
            UseNat_bool = true,
            Mtu_u32 = 1200,
            NatTcpTimeout_u32 = 100,
            NatUdpTimeout_u32 = 50,
            UseDhcp_bool = true,
            DhcpLeaseIPStart_ip = "10.0.0.101",
            DhcpLeaseIPEnd_ip = "10.0.0.199",
            DhcpSubnetMask_ip = "255.255.255.0",
            DhcpExpireTimeSpan_u32 = 3600,
            DhcpGatewayAddress_ip = "10.0.0.254",
            DhcpDnsServerAddress_ip = "10.0.0.254",
            DhcpDnsServerAddress2_ip = "8.8.8.8",
            DhcpDomainName_str = "lab.coe.ad.jp",
            SaveLog_bool = true,
            ApplyDhcpPushRoutes_bool = false,
            DhcpPushRoutes_str = "",
        };
        VpnVhOption out_vh_option = api.SetSecureNATOption(in_vh_option);

        print_object(out_vh_option);

        Console.WriteLine("End: Test_SetSecureNATOption");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetSecureNATOption', Get SecureNAT options
    /// </summary>
    public void Test_GetSecureNATOption()
    {
        Console.WriteLine("Begin: Test_GetSecureNATOption");

        VpnVhOption in_vh_option = new VpnVhOption()
        {
            RpcHubName_str = hub_name,
        };
        VpnVhOption out_vh_option = api.GetSecureNATOption(in_vh_option);

        print_object(out_vh_option);

        Console.WriteLine("End: Test_GetSecureNATOption");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumNAT', Enumerate NAT entries of the SecureNAT
    /// </summary>
    public void Test_EnumNAT()
    {
        Console.WriteLine("Begin: Test_EnumNAT");

        VpnRpcEnumNat in_rpc_enum_nat = new VpnRpcEnumNat()
        {
            HubName_str = hub_name,
        };
        VpnRpcEnumNat out_rpc_enum_nat = api.EnumNAT(in_rpc_enum_nat);

        print_object(out_rpc_enum_nat);

        Console.WriteLine("End: Test_EnumNAT");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumDHCP', Enumerate DHCP entries
    /// </summary>
    public void Test_EnumDHCP()
    {
        Console.WriteLine("Begin: Test_EnumDHCP");

        VpnRpcEnumDhcp in_rpc_enum_dhcp = new VpnRpcEnumDhcp()
        {
            HubName_str = hub_name,
        };
        VpnRpcEnumDhcp out_rpc_enum_dhcp = api.EnumDHCP(in_rpc_enum_dhcp);

        print_object(out_rpc_enum_dhcp);

        Console.WriteLine("End: Test_EnumDHCP");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetSecureNATStatus', Get status of the SecureNAT
    /// </summary>
    public void Test_GetSecureNATStatus()
    {
        Console.WriteLine("Begin: Test_GetSecureNATStatus");

        VpnRpcNatStatus in_rpc_nat_status = new VpnRpcNatStatus()
        {
            HubName_str = hub_name,
        };
        VpnRpcNatStatus out_rpc_nat_status = api.GetSecureNATStatus(in_rpc_nat_status);

        print_object(out_rpc_nat_status);

        Console.WriteLine("End: Test_GetSecureNATStatus");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumEthernet', Enumerate Ethernet devices
    /// </summary>
    public void Test_EnumEthernet()
    {
        Console.WriteLine("Begin: Test_EnumEthernet");

        VpnRpcEnumEth out_rpc_enum_eth = api.EnumEthernet();

        print_object(out_rpc_enum_eth);

        Console.WriteLine("End: Test_EnumEthernet");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'AddLocalBridge', Add a new local bridge
    /// </summary>
    public void Test_AddLocalBridge()
    {
        Console.WriteLine("Begin: Test_AddLocalBridge");

        VpnRpcLocalBridge in_rpc_localbridge = new VpnRpcLocalBridge()
        {
            DeviceName_str = "Intel(R) Ethernet Connection (2) I219-V (ID=3632031273)",
            HubNameLB_str = hub_name,
        };
        VpnRpcLocalBridge out_rpc_localbridge = api.AddLocalBridge(in_rpc_localbridge);

        print_object(out_rpc_localbridge);

        Console.WriteLine("End: Test_AddLocalBridge");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'DeleteLocalBridge', Delete a local bridge
    /// </summary>
    public void Test_DeleteLocalBridge()
    {
        Console.WriteLine("Begin: Test_DeleteLocalBridge");

        VpnRpcLocalBridge in_rpc_localbridge = new VpnRpcLocalBridge()
        {
            DeviceName_str = "Intel(R) Ethernet Connection (2) I219-V (ID=3632031273)",
            HubNameLB_str = hub_name,
        };
        VpnRpcLocalBridge out_rpc_localbridge = api.DeleteLocalBridge(in_rpc_localbridge);

        print_object(out_rpc_localbridge);

        Console.WriteLine("End: Test_DeleteLocalBridge");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumLocalBridge', Enumerate local bridges
    /// </summary>
    public void Test_EnumLocalBridge()
    {
        Console.WriteLine("Begin: Test_EnumLocalBridge");

        VpnRpcEnumLocalBridge out_rpc_enum_localbridge = api.EnumLocalBridge();

        print_object(out_rpc_enum_localbridge);

        Console.WriteLine("End: Test_EnumLocalBridge");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetBridgeSupport', Get availability to localbridge function
    /// </summary>
    public void Test_GetBridgeSupport()
    {
        Console.WriteLine("Begin: Test_GetBridgeSupport");

        VpnRpcBridgeSupport out_rpc_bridge_support = api.GetBridgeSupport();

        print_object(out_rpc_bridge_support);

        Console.WriteLine("End: Test_GetBridgeSupport");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'RebootServer', Reboot server itself
    /// </summary>
    public void Test_RebootServer()
    {
        Console.WriteLine("Begin: Test_RebootServer");

        VpnRpcTest in_rpc_test = new VpnRpcTest()
        {
        };
        VpnRpcTest out_rpc_test = api.RebootServer(in_rpc_test);

        print_object(out_rpc_test);

        Console.WriteLine("End: Test_RebootServer");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetCaps', Get capabilities
    /// </summary>
    public void Test_GetCaps()
    {
        Console.WriteLine("Begin: Test_GetCaps");

        VpnCapslist out_capslist = api.GetCaps();

        print_object(out_capslist);

        Console.WriteLine("End: Test_GetCaps");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetConfig', Get configuration file stream
    /// </summary>
    public void Test_GetConfig()
    {
        Console.WriteLine("Begin: Test_GetConfig");

        VpnRpcConfig out_rpc_config = api.GetConfig();

        print_object(out_rpc_config);

        Console.WriteLine("End: Test_GetConfig");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetConfig', Overwrite configuration file by specified data
    /// </summary>
    public void Test_SetConfig()
    {
        Console.WriteLine("Begin: Test_SetConfig");

        VpnRpcConfig in_rpc_config = new VpnRpcConfig()
        {
            FileData_bin = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, },
        };
        VpnRpcConfig out_rpc_config = api.SetConfig(in_rpc_config);

        Console.WriteLine("End: Test_SetConfig");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetDefaultHubAdminOptions', Get default hub administration options
    /// </summary>
    public void Test_GetDefaultHubAdminOptions()
    {
        Console.WriteLine("Begin: Test_GetDefaultHubAdminOptions");

        VpnRpcAdminOption in_rpc_admin_option = new VpnRpcAdminOption()
        {
            HubName_str = hub_name,
        };
        VpnRpcAdminOption out_rpc_admin_option = api.GetDefaultHubAdminOptions(in_rpc_admin_option);

        print_object(out_rpc_admin_option);

        Console.WriteLine("End: Test_GetDefaultHubAdminOptions");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetHubAdminOptions', Get hub administration options
    /// </summary>
    public void Test_GetHubAdminOptions()
    {
        Console.WriteLine("Begin: Test_GetHubAdminOptions");

        VpnRpcAdminOption in_rpc_admin_option = new VpnRpcAdminOption()
        {
            HubName_str = hub_name,
        };
        VpnRpcAdminOption out_rpc_admin_option = api.GetHubAdminOptions(in_rpc_admin_option);

        print_object(out_rpc_admin_option);

        Console.WriteLine("End: Test_GetHubAdminOptions");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetHubAdminOptions', Set hub administration options
    /// </summary>
    public void Test_SetHubAdminOptions()
    {
        Console.WriteLine("Begin: Test_SetHubAdminOptions");

        VpnRpcAdminOption in_rpc_admin_option = new VpnRpcAdminOption()
        {
            HubName_str = hub_name,
            AdminOptionList = new VpnAdminOption[]
            {
                new VpnAdminOption()
                {
                    Name_str = "no_securenat_enablenat",
                    Value_u32 = 1,
                }
            }
        };
        VpnRpcAdminOption out_rpc_admin_option = api.SetHubAdminOptions(in_rpc_admin_option);

        print_object(out_rpc_admin_option);

        Console.WriteLine("End: Test_SetHubAdminOptions");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetHubExtOptions', Get hub extended options
    /// </summary>
    public void Test_GetHubExtOptions()
    {
        Console.WriteLine("Begin: Test_GetHubExtOptions");

        VpnRpcAdminOption in_rpc_admin_option = new VpnRpcAdminOption()
        {
            HubName_str = hub_name,
        };
        VpnRpcAdminOption out_rpc_admin_option = api.GetHubExtOptions(in_rpc_admin_option);

        print_object(out_rpc_admin_option);

        Console.WriteLine("End: Test_GetHubExtOptions");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetHubExtOptions', Set hub extended options
    /// </summary>
    public void Test_SetHubExtOptions()
    {
        Console.WriteLine("Begin: Test_SetHubExtOptions");

        VpnRpcAdminOption in_rpc_admin_option = new VpnRpcAdminOption()
        {
            HubName_str = hub_name,
            AdminOptionList = new VpnAdminOption[]
            {
                new VpnAdminOption()
                {
                    Name_str = "SecureNAT_RandomizeAssignIp",
                    Value_u32 = 1,
                }
            }
        };
        VpnRpcAdminOption out_rpc_admin_option = api.SetHubExtOptions(in_rpc_admin_option);

        print_object(out_rpc_admin_option);

        Console.WriteLine("End: Test_SetHubExtOptions");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'AddL3Switch', Add a new virtual layer-3 switch
    /// </summary>
    public void Test_AddL3Switch()
    {
        Console.WriteLine("Begin: Test_AddL3Switch");

        VpnRpcL3Sw in_rpc_l3sw = new VpnRpcL3Sw()
        {
            Name_str = "L3SW1",
        };
        VpnRpcL3Sw out_rpc_l3sw = api.AddL3Switch(in_rpc_l3sw);

        print_object(out_rpc_l3sw);

        Console.WriteLine("End: Test_AddL3Switch");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'DelL3Switch', Delete a virtual layer-3 switch
    /// </summary>
    public void Test_DelL3Switch()
    {
        Console.WriteLine("Begin: Test_DelL3Switch");

        VpnRpcL3Sw in_rpc_l3sw = new VpnRpcL3Sw()
        {
            Name_str = "L3SW1",
        };
        VpnRpcL3Sw out_rpc_l3sw = api.DelL3Switch(in_rpc_l3sw);

        print_object(out_rpc_l3sw);

        Console.WriteLine("End: Test_DelL3Switch");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumL3Switch', Enumerate virtual layer-3 switches
    /// </summary>
    public void Test_EnumL3Switch()
    {
        Console.WriteLine("Begin: Test_EnumL3Switch");

        VpnRpcEnumL3Sw out_rpc_enum_l3sw = api.EnumL3Switch();

        print_object(out_rpc_enum_l3sw);

        Console.WriteLine("End: Test_EnumL3Switch");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'StartL3Switch', Start a virtual layer-3 switch
    /// </summary>
    public void Test_StartL3Switch()
    {
        Console.WriteLine("Begin: Test_StartL3Switch");

        VpnRpcL3Sw in_rpc_l3sw = new VpnRpcL3Sw()
        {
            Name_str = "L3SW1",
        };
        VpnRpcL3Sw out_rpc_l3sw = api.StartL3Switch(in_rpc_l3sw);

        print_object(out_rpc_l3sw);

        Console.WriteLine("End: Test_StartL3Switch");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'StopL3Switch', Stop a virtual layer-3 switch
    /// </summary>
    public void Test_StopL3Switch()
    {
        Console.WriteLine("Begin: Test_StopL3Switch");

        VpnRpcL3Sw in_rpc_l3sw = new VpnRpcL3Sw()
        {
            Name_str = "L3SW1",
        };
        VpnRpcL3Sw out_rpc_l3sw = api.StopL3Switch(in_rpc_l3sw);

        print_object(out_rpc_l3sw);

        Console.WriteLine("End: Test_StopL3Switch");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'AddL3If', Add new virtual interface on virtual L3 switch
    /// </summary>
    public void Test_AddL3If()
    {
        Console.WriteLine("Begin: Test_AddL3If");

        VpnRpcL3If in_rpc_l3if = new VpnRpcL3If()
        {
            Name_str = "L3SW1",
            HubName_str = hub_name,
            IpAddress_ip = "192.168.0.1",
            SubnetMask_ip = "255.255.255.0",
        };
        VpnRpcL3If out_rpc_l3if = api.AddL3If(in_rpc_l3if);

        print_object(out_rpc_l3if);

        Console.WriteLine("End: Test_AddL3If");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'DelL3If', Delete a virtual interface on virtual L3 switch
    /// </summary>
    public void Test_DelL3If()
    {
        Console.WriteLine("Begin: Test_DelL3If");

        VpnRpcL3If in_rpc_l3if = new VpnRpcL3If()
        {
            Name_str = "L3SW1",
            HubName_str = hub_name,
        };
        VpnRpcL3If out_rpc_l3if = api.DelL3If(in_rpc_l3if);

        print_object(out_rpc_l3if);

        Console.WriteLine("End: Test_DelL3If");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumL3If', Enumerate virtual interfaces on virtual L3 switch
    /// </summary>
    public void Test_EnumL3If()
    {
        Console.WriteLine("Begin: Test_EnumL3If");

        VpnRpcEnumL3If in_rpc_enum_l3if = new VpnRpcEnumL3If()
        {
            Name_str = "L3SW1",
        };
        VpnRpcEnumL3If out_rpc_enum_l3if = api.EnumL3If(in_rpc_enum_l3if);

        print_object(out_rpc_enum_l3if);

        Console.WriteLine("End: Test_EnumL3If");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'AddL3Table', Add new routing table entry on virtual L3 switch
    /// </summary>
    public void Test_AddL3Table()
    {
        Console.WriteLine("Begin: Test_AddL3Table");

        VpnRpcL3Table in_rpc_l3table = new VpnRpcL3Table()
        {
            Name_str = "L3SW1",
            NetworkAddress_ip = "10.0.0.0",
            SubnetMask_ip = "255.0.0.0",
            GatewayAddress_ip = "192.168.7.1",
            Metric_u32 = 10,
        };
        VpnRpcL3Table out_rpc_l3table = api.AddL3Table(in_rpc_l3table);

        print_object(out_rpc_l3table);

        Console.WriteLine("End: Test_AddL3Table");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'DelL3Table', Delete routing table entry on virtual L3 switch
    /// </summary>
    public void Test_DelL3Table()
    {
        Console.WriteLine("Begin: Test_DelL3Table");

        VpnRpcL3Table in_rpc_l3table = new VpnRpcL3Table()
        {
            Name_str = "L3SW1",
            NetworkAddress_ip = "10.0.0.0",
            SubnetMask_ip = "255.0.0.0",
            GatewayAddress_ip = "192.168.7.1",
            Metric_u32 = 10,
        };
        VpnRpcL3Table out_rpc_l3table = api.DelL3Table(in_rpc_l3table);

        print_object(out_rpc_l3table);

        Console.WriteLine("End: Test_DelL3Table");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumL3Table', Get routing table on virtual L3 switch
    /// </summary>
    public void Test_EnumL3Table()
    {
        Console.WriteLine("Begin: Test_EnumL3Table");

        VpnRpcEnumL3Table in_rpc_enum_l3table = new VpnRpcEnumL3Table()
        {
            Name_str = "L3SW1",
        };
        VpnRpcEnumL3Table out_rpc_enum_l3table = api.EnumL3Table(in_rpc_enum_l3table);

        print_object(out_rpc_enum_l3table);

        Console.WriteLine("End: Test_EnumL3Table");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumCrl', Get CRL (Certificate Revocation List) index
    /// </summary>
    public VpnRpcEnumCrl Test_EnumCrl()
    {
        Console.WriteLine("Begin: Test_EnumCrl");

        VpnRpcEnumCrl in_rpc_enum_crl = new VpnRpcEnumCrl()
        {
            HubName_str = hub_name,
        };
        VpnRpcEnumCrl out_rpc_enum_crl = api.EnumCrl(in_rpc_enum_crl);

        print_object(out_rpc_enum_crl);

        Console.WriteLine("End: Test_EnumCrl");
        Console.WriteLine("-----");
        Console.WriteLine();

        return out_rpc_enum_crl;
    }

    /// <summary>
    /// API test for 'AddCrl', Add new CRL (Certificate Revocation List) entry
    /// </summary>
    public void Test_AddCrl()
    {
        Console.WriteLine("Begin: Test_AddCrl");

        VpnRpcCrl in_rpc_crl = new VpnRpcCrl()
        {
            HubName_str = hub_name,
            CommonName_utf = "CN",
            Organization_utf = "Org",
            Unit_utf = "ICSCOE",
            Country_utf = "JP",
            State_utf = "Ibaraki",
            Local_utf = "Tsukuba",
            Serial_bin = new byte[] { 1, 2, 3, 4, 5 },
            DigestMD5_bin = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            DigestSHA1_bin = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 },
        };
        VpnRpcCrl out_rpc_crl = api.AddCrl(in_rpc_crl);

        print_object(out_rpc_crl);

        Console.WriteLine("End: Test_AddCrl");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'DelCrl', Delete CRL (Certificate Revocation List) entry
    /// </summary>
    public void Test_DelCrl(uint key)
    {
        Console.WriteLine("Begin: Test_DelCrl");

        VpnRpcCrl in_rpc_crl = new VpnRpcCrl()
        {
            HubName_str = hub_name,
            Key_u32 = key,
        };
        VpnRpcCrl out_rpc_crl = api.DelCrl(in_rpc_crl);

        print_object(out_rpc_crl);

        Console.WriteLine("End: Test_DelCrl");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetCrl', Get CRL (Certificate Revocation List) entry
    /// </summary>
    public VpnRpcCrl Test_GetCrl(uint key)
    {
        Console.WriteLine("Begin: Test_GetCrl");

        VpnRpcCrl in_rpc_crl = new VpnRpcCrl()
        {
            HubName_str = hub_name,
            Key_u32 = key,
        };
        VpnRpcCrl out_rpc_crl = api.GetCrl(in_rpc_crl);

        print_object(out_rpc_crl);

        Console.WriteLine("End: Test_GetCrl");
        Console.WriteLine("-----");
        Console.WriteLine();

        return out_rpc_crl;
    }

    /// <summary>
    /// API test for 'SetCrl', Set CRL (Certificate Revocation List) entry
    /// </summary>
    public void Test_SetCrl(VpnRpcCrl crl)
    {
        Console.WriteLine("Begin: Test_SetCrl");

        VpnRpcCrl out_rpc_crl = api.SetCrl(crl);

        print_object(out_rpc_crl);

        Console.WriteLine("End: Test_SetCrl");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetAcList', Set access control list
    /// </summary>
    public void Test_SetAcList()
    {
        Console.WriteLine("Begin: Test_SetAcList");

        VpnRpcAcList in_rpc_ac_list = new VpnRpcAcList()
        {
            HubName_str = hub_name,

            ACList = new VpnAc[]
            {
                new VpnAc()
                {
                    Deny_bool = true,
                    IpAddress_ip = "192.168.0.0",
                    SubnetMask_ip = "255.255.0.0",
                    Masked_bool = true,
                    Priority_u32 = 123,
                },
                new VpnAc()
                {
                    Deny_bool = false,
                    IpAddress_ip = "fe80::",
                    SubnetMask_ip = "8",
                    Masked_bool = true,
                    Priority_u32 = 123,
                },
            }
        };
        VpnRpcAcList out_rpc_ac_list = api.SetAcList(in_rpc_ac_list);

        print_object(out_rpc_ac_list);

        Console.WriteLine("End: Test_SetAcList");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetAcList', Get access control list
    /// </summary>
    public void Test_GetAcList()
    {
        Console.WriteLine("Begin: Test_GetAcList");

        VpnRpcAcList in_rpc_ac_list = new VpnRpcAcList()
        {
            HubName_str = hub_name,
        };
        VpnRpcAcList out_rpc_ac_list = api.GetAcList(in_rpc_ac_list);

        print_object(out_rpc_ac_list);

        Console.WriteLine("End: Test_GetAcList");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumLogFile', Enumerate log files
    /// </summary>
    public VpnRpcEnumLogFile Test_EnumLogFile()
    {
        Console.WriteLine("Begin: Test_EnumLogFile");

        VpnRpcEnumLogFile out_rpc_enum_log_file = api.EnumLogFile();

        print_object(out_rpc_enum_log_file);

        Console.WriteLine("End: Test_EnumLogFile");
        Console.WriteLine("-----");
        Console.WriteLine();

        return out_rpc_enum_log_file;
    }

    /// <summary>
    /// API test for 'ReadLogFile', Read a log file
    /// </summary>
    public void Test_ReadLogFile(string filename)
    {
        Console.WriteLine("Begin: Test_ReadLogFile");

        VpnRpcReadLogFile in_rpc_read_log_file = new VpnRpcReadLogFile()
        {
            FilePath_str = filename,
        };
        VpnRpcReadLogFile out_rpc_read_log_file = api.ReadLogFile(in_rpc_read_log_file);

        print_object(out_rpc_read_log_file);

        Console.WriteLine("End: Test_ReadLogFile");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetSysLog', Set syslog function setting
    /// </summary>
    public void Test_SetSysLog(bool flag)
    {
        Console.WriteLine("Begin: Test_SetSysLog");

        VpnSyslogSetting in_syslog_setting = new VpnSyslogSetting()
        {
            SaveType_u32 = flag ? VpnSyslogSaveType.ServerAndHubAllLog : VpnSyslogSaveType.None,
            Hostname_str = "1.2.3.4",
            Port_u32 = 123,
        };
        VpnSyslogSetting out_syslog_setting = api.SetSysLog(in_syslog_setting);

        print_object(out_syslog_setting);

        Console.WriteLine("End: Test_SetSysLog");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetSysLog', Get syslog function setting
    /// </summary>
    public void Test_GetSysLog()
    {
        Console.WriteLine("Begin: Test_GetSysLog");

        VpnSyslogSetting in_syslog_setting = new VpnSyslogSetting()
        {
        };
        VpnSyslogSetting out_syslog_setting = api.GetSysLog(in_syslog_setting);

        print_object(out_syslog_setting);

        Console.WriteLine("End: Test_GetSysLog");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetHubMsg', Set message of today on hub
    /// </summary>
    public void Test_SetHubMsg()
    {
        Console.WriteLine("Begin: Test_SetHubMsg");

        VpnRpcMsg in_rpc_msg = new VpnRpcMsg()
        {
            HubName_str = hub_name,
            Msg_bin = new byte[]
            {
0x57,0x6f,0x72,0x6b,0x69,0x6e,0x67,0x20,0x4d,0x65,0x6e,0x20,0x6f,0x66,0x20,0x41,
0x6c,0x6c,0x20,0x43,0x6f,0x75,0x6e,0x74,0x72,0x69,0x65,0x73,0x2c,0x20,0x55,0x6e,
0x69,0x74,0x65,0x21,0x20,0xe4,0xb8,0x87,0xe5,0x9b,0xbd,0xe3,0x81,0xae,0xe5,0x8a,
0xb4,0xe5,0x83,0x8d,0xe8,0x80,0x85,0xe3,0x82,0x88,0xe3,0x80,0x81,0xe5,0x9b,0xa3,
0xe7,0xb5,0x90,0xe3,0x81,0x9b,0xe3,0x82,0x88,0x21,0x20,0xd7,0x92,0xd7,0x91,0xd7,
0xa8,0xd7,0x99,0xd7,0x9d,0x20,0xd7,0xa2,0xd7,0x95,0xd7,0x91,0xd7,0x93,0xd7,0x99,
0xd7,0x9d,0x20,0xd7,0xa9,0xd7,0x9c,0x20,0xd7,0x9b,0xd7,0x9c,0x20,0xd7,0x94,0xd7,
0x9e,0xd7,0x93,0xd7,0x99,0xd7,0xa0,0xd7,0x95,0xd7,0xaa,0x2c,0x20,0xd7,0x94,0xd7,
0xaa,0xd7,0x90,0xd7,0x97,0xd7,0x93,0xd7,0x95,0x21
            },
        };
        VpnRpcMsg out_rpc_msg = api.SetHubMsg(in_rpc_msg);

        print_object(out_rpc_msg);

        Console.WriteLine("End: Test_SetHubMsg");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetHubMsg', Get message of today on hub
    /// </summary>
    public void Test_GetHubMsg()
    {
        Console.WriteLine("Begin: Test_GetHubMsg");

        VpnRpcMsg in_rpc_msg = new VpnRpcMsg()
        {
            HubName_str = hub_name,
        };
        VpnRpcMsg out_rpc_msg = api.GetHubMsg(in_rpc_msg);

        print_object(out_rpc_msg);

        Console.WriteLine("End: Test_GetHubMsg");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'Crash', Do Crash
    /// </summary>
    public void Test_Crash()
    {
        Console.WriteLine("Begin: Test_Crash");

        VpnRpcTest in_rpc_test = new VpnRpcTest()
        {
        };
        VpnRpcTest out_rpc_test = api.Crash(in_rpc_test);

        print_object(out_rpc_test);

        Console.WriteLine("End: Test_Crash");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetAdminMsg', Get message for administrators
    /// </summary>
    public void Test_GetAdminMsg()
    {
        Console.WriteLine("Begin: Test_GetAdminMsg");

        VpnRpcMsg out_rpc_msg = api.GetAdminMsg();

        print_object(out_rpc_msg);

        Console.WriteLine("End: Test_GetAdminMsg");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'Flush', Flush configuration file
    /// </summary>
    public void Test_Flush()
    {
        Console.WriteLine("Begin: Test_Flush");

        VpnRpcTest in_rpc_test = new VpnRpcTest()
        {
        };
        VpnRpcTest out_rpc_test = api.Flush(in_rpc_test);

        print_object(out_rpc_test);

        Console.WriteLine("End: Test_Flush");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetIPsecServices', Set IPsec service configuration
    /// </summary>
    public void Test_SetIPsecServices()
    {
        Console.WriteLine("Begin: Test_SetIPsecServices");

        VpnIPsecServices in_ipsec_services = new VpnIPsecServices()
        {
            L2TP_Raw_bool = false,
            L2TP_IPsec_bool = false,
            EtherIP_IPsec_bool = false,
            IPsec_Secret_str = "vpn",
            L2TP_DefaultHub_str = "HUB_ABC",
        };
        VpnIPsecServices out_ipsec_services = api.SetIPsecServices(in_ipsec_services);

        print_object(out_ipsec_services);

        Console.WriteLine("End: Test_SetIPsecServices");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetIPsecServices', Get IPsec service configuration
    /// </summary>
    public void Test_GetIPsecServices()
    {
        Console.WriteLine("Begin: Test_GetIPsecServices");

        VpnIPsecServices out_ipsec_services = api.GetIPsecServices();

        print_object(out_ipsec_services);

        Console.WriteLine("End: Test_GetIPsecServices");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'AddEtherIpId', Add EtherIP ID setting
    /// </summary>
    public void Test_AddEtherIpId()
    {
        Console.WriteLine("Begin: Test_AddEtherIpId");

        VpnEtherIpId in_etherip_id = new VpnEtherIpId()
        {
            Id_str = "testid",
            HubName_str = hub_name,
            UserName_str = "nekosan",
            Password_str = "torisan",
        };
        VpnEtherIpId out_etherip_id = api.AddEtherIpId(in_etherip_id);

        print_object(out_etherip_id);

        Console.WriteLine("End: Test_AddEtherIpId");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetEtherIpId', Get EtherIP ID setting
    /// </summary>
    public void Test_GetEtherIpId(string id)
    {
        Console.WriteLine("Begin: Test_GetEtherIpId");

        VpnEtherIpId in_etherip_id = new VpnEtherIpId()
        {
            Id_str = id,
        };
        VpnEtherIpId out_etherip_id = api.GetEtherIpId(in_etherip_id);

        print_object(out_etherip_id);

        Console.WriteLine("End: Test_GetEtherIpId");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'DeleteEtherIpId', Delete EtherIP ID setting
    /// </summary>
    public void Test_DeleteEtherIpId(string id)
    {
        Console.WriteLine("Begin: Test_DeleteEtherIpId");

        VpnEtherIpId in_etherip_id = new VpnEtherIpId()
        {
            Id_str = id,
        };
        VpnEtherIpId out_etherip_id = api.DeleteEtherIpId(in_etherip_id);

        print_object(out_etherip_id);

        Console.WriteLine("End: Test_DeleteEtherIpId");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'EnumEtherIpId', Enumerate EtherIP ID settings
    /// </summary>
    public VpnRpcEnumEtherIpId Test_EnumEtherIpId()
    {
        Console.WriteLine("Begin: Test_EnumEtherIpId");

        VpnRpcEnumEtherIpId out_rpc_enum_etherip_id = api.EnumEtherIpId();

        print_object(out_rpc_enum_etherip_id);

        Console.WriteLine("End: Test_EnumEtherIpId");
        Console.WriteLine("-----");
        Console.WriteLine();

        return out_rpc_enum_etherip_id;
    }

    /// <summary>
    /// API test for 'SetOpenVpnSstpConfig', Set configurations for OpenVPN and SSTP
    /// </summary>
    public void Test_SetOpenVpnSstpConfig()
    {
        Console.WriteLine("Begin: Test_SetOpenVpnSstpConfig");

        VpnOpenVpnSstpConfig in_openvpn_sstp_config = new VpnOpenVpnSstpConfig()
        {
            EnableOpenVPN_bool = true,
            OpenVPNPortList_str = "1 2 3 4 5",
            EnableSSTP_bool = true,
        };
        VpnOpenVpnSstpConfig out_openvpn_sstp_config = api.SetOpenVpnSstpConfig(in_openvpn_sstp_config);

        print_object(out_openvpn_sstp_config);

        Console.WriteLine("End: Test_SetOpenVpnSstpConfig");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetOpenVpnSstpConfig', Get configurations for OpenVPN and SSTP
    /// </summary>
    public void Test_GetOpenVpnSstpConfig()
    {
        Console.WriteLine("Begin: Test_GetOpenVpnSstpConfig");

        VpnOpenVpnSstpConfig out_openvpn_sstp_config = api.GetOpenVpnSstpConfig();

        print_object(out_openvpn_sstp_config);

        Console.WriteLine("End: Test_GetOpenVpnSstpConfig");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetDDnsClientStatus', Get status of DDNS client
    /// </summary>
    public void Test_GetDDnsClientStatus()
    {
        Console.WriteLine("Begin: Test_GetDDnsClientStatus");

        VpnDDnsClientStatus out_ddns_client_status = api.GetDDnsClientStatus();

        print_object(out_ddns_client_status);

        Console.WriteLine("End: Test_GetDDnsClientStatus");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'ChangeDDnsClientHostname', Change host-name for DDNS client
    /// </summary>
    public void Test_ChangeDDnsClientHostname()
    {
        Console.WriteLine("Begin: Test_ChangeDDnsClientHostname");

        VpnRpcTest in_rpc_test = new VpnRpcTest()
        {
            StrValue_str = "nekotest" + rand.Next(1000000000, 2100000000),
        };
        VpnRpcTest out_rpc_test = api.ChangeDDnsClientHostname(in_rpc_test);

        print_object(out_rpc_test);

        Console.WriteLine("End: Test_ChangeDDnsClientHostname");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'RegenerateServerCert', Regenerate server certification
    /// </summary>
    public void Test_RegenerateServerCert()
    {
        Console.WriteLine("Begin: Test_RegenerateServerCert");

        VpnRpcTest in_rpc_test = new VpnRpcTest()
        {
            StrValue_str = "abc.example.org",
        };

        VpnRpcTest out_rpc_test = api.RegenerateServerCert(in_rpc_test);

        print_object(out_rpc_test);

        Console.WriteLine("End: Test_RegenerateServerCert");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'MakeOpenVpnConfigFile', Generate OpenVPN configuration files
    /// </summary>
    public void Test_MakeOpenVpnConfigFile()
    {
        Console.WriteLine("Begin: Test_MakeOpenVpnConfigFile");

        VpnRpcReadLogFile out_rpc_read_log_file = api.MakeOpenVpnConfigFile();

        print_object(out_rpc_read_log_file);

        Console.WriteLine("End: Test_MakeOpenVpnConfigFile");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetSpecialListener', Set special listener status
    /// </summary>
    public void Test_SetSpecialListener()
    {
        Console.WriteLine("Begin: Test_SetSpecialListener");

        VpnRpcSpecialListener in_rpc_special_listener = new VpnRpcSpecialListener()
        {
            VpnOverDnsListener_bool = true,
            VpnOverIcmpListener_bool = true,
        };
        VpnRpcSpecialListener out_rpc_special_listener = api.SetSpecialListener(in_rpc_special_listener);

        print_object(out_rpc_special_listener);

        Console.WriteLine("End: Test_SetSpecialListener");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetSpecialListener', Get special listener status
    /// </summary>
    public void Test_GetSpecialListener()
    {
        Console.WriteLine("Begin: Test_GetSpecialListener");

        VpnRpcSpecialListener out_rpc_special_listener = api.GetSpecialListener();

        print_object(out_rpc_special_listener);

        Console.WriteLine("End: Test_GetSpecialListener");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetAzureStatus', Get Azure status
    /// </summary>
    public void Test_GetAzureStatus()
    {
        Console.WriteLine("Begin: Test_GetAzureStatus");

        VpnRpcAzureStatus out_rpc_azure_status = api.GetAzureStatus();

        print_object(out_rpc_azure_status);

        Console.WriteLine("End: Test_GetAzureStatus");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetAzureStatus', Set Azure status
    /// </summary>
    public void Test_SetAzureStatus()
    {
        Console.WriteLine("Begin: Test_SetAzureStatus");

        VpnRpcAzureStatus in_rpc_azure_status = new VpnRpcAzureStatus()
        {
            IsEnabled_bool = true,
        };
        VpnRpcAzureStatus out_rpc_azure_status = api.SetAzureStatus(in_rpc_azure_status);

        print_object(out_rpc_azure_status);

        Console.WriteLine("End: Test_SetAzureStatus");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetDDnsInternetSetting', Get DDNS proxy configuration
    /// </summary>
    public void Test_GetDDnsInternetSetting()
    {
        Console.WriteLine("Begin: Test_GetDDnsInternetSetting");

        VpnInternetSetting out_internet_setting = api.GetDDnsInternetSetting();

        print_object(out_internet_setting);

        Console.WriteLine("End: Test_GetDDnsInternetSetting");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetDDnsInternetSetting', Set DDNS proxy configuration
    /// </summary>
    public void Test_SetDDnsInternetSetting()
    {
        Console.WriteLine("Begin: Test_SetDDnsInternetSetting");

        VpnInternetSetting in_internet_setting = new VpnInternetSetting()
        {
            ProxyType_u32 = VpnRpcProxyType.Direct,
            ProxyHostName_str = "1.2.3.4",
            ProxyPort_u32 = 1234,
            ProxyUsername_str = "neko",
            ProxyPassword_str = "dog",
        };
        VpnInternetSetting out_internet_setting = api.SetDDnsInternetSetting(in_internet_setting);

        print_object(out_internet_setting);

        Console.WriteLine("End: Test_SetDDnsInternetSetting");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'SetVgsConfig', Setting VPN Gate Server Configuration
    /// </summary>
    public void Test_SetVgsConfig()
    {
        Console.WriteLine("Begin: Test_SetVgsConfig");

        VpnVgsConfig in_vgs_config = new VpnVgsConfig()
        {
            IsEnabled_bool = false,
            Message_utf = "Neko san!!!",
            Owner_utf = "Go go go!!!",
            Abuse_utf = "da.test@softether.co.jp",
            NoLog_bool = false,
            LogPermanent_bool = true,
            EnableL2TP_bool = true,
        };
        VpnVgsConfig out_vgs_config = api.SetVgsConfig(in_vgs_config);

        print_object(out_vgs_config);

        Console.WriteLine("End: Test_SetVgsConfig");
        Console.WriteLine("-----");
        Console.WriteLine();
    }

    /// <summary>
    /// API test for 'GetVgsConfig', Get VPN Gate configuration
    /// </summary>
    public void Test_GetVgsConfig()
    {
        Console.WriteLine("Begin: Test_GetVgsConfig");

        VpnVgsConfig out_vgs_config = api.GetVgsConfig();

        print_object(out_vgs_config);

        Console.WriteLine("End: Test_GetVgsConfig");
        Console.WriteLine("-----");
        Console.WriteLine();
    }


    void print_object(object obj)
    {
        var setting = new Newtonsoft.Json.JsonSerializerSettings()
        {
            NullValueHandling = Newtonsoft.Json.NullValueHandling.Include,
            ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Error,
        };
        string str = Newtonsoft.Json.JsonConvert.SerializeObject(obj, Newtonsoft.Json.Formatting.Indented, setting);
        Console.WriteLine(str);
    }
}

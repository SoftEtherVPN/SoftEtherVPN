"use strict";
// Test sample code for SoftEther VPN Server JSON-RPC Stub
// Runs on both web browsers and Node.js
// 
// sample.ts
// Automatically generated at 2019-05-29 18:21:39 by vpnserver-jsonrpc-codegen
// 
// This sample code shows how to call all available RPC functions.
// You can copy and paste test code to write your own web browser TypeScript / JavaScript codes.
//
// Licensed under the Apache License 2.0
// Copyright (c) 2014-2019 SoftEther VPN Project
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
exports.__esModule = true;
// On the web browser uncomment below imports as necessary to support old browsers.
// import "core-js/es6/promise";
// import "core-js/es6/string";
// import "whatwg-fetch";
// Import the vpnrpc.ts RPC stub.
var VPN = __importStar(require("./vpnrpc"));
// Output JSON-RPC request / reply strings to the debug console.
VPN.VpnServerRpc.SetDebugMode(true);
var api;
// Creating the VpnServerRpc class instance here.
if (VPN.VpnServerRpc.IsNodeJS() === false) // // Determine if this JavaScript environment is on the Node.js or not
 {
    // On the web browser. We do not need to specify any hostname, port or credential as the web browser already knows it.
    api = new VPN.VpnServerRpc();
}
else {
    // On the Node.js. We need to specify the target VPN Server's hostname, port and credential.
    api = new VPN.VpnServerRpc("127.0.0.1", 443, "", "PASSWORD_HERE", false);
}
// A variable for test
var hub_name = "test";
// Call the Test_All() function to test almost all VPN APIs.
Test_All();
/** Tests all VPN APIs */
function Test_All() {
    return __awaiter(this, void 0, void 0, function () {
        var new_listener_port, farm_members, _i, _a, farm_member, enum_connection, _b, _c, connecton, hub_log_settings, enum_ca, _d, _e, ca, enum_link, _f, _g, link, enum_session, _h, _j, session, enum_mac, _k, _l, mac, enum_ip, _m, _o, ip, enum_crl, _p, _q, crl, got_crl, _r, _s, crl, enum_log_file, _t, _u, log, enum_etherip_id, _v, _w, etherip_id;
        return __generator(this, function (_x) {
            switch (_x.label) {
                case 0:
                    hub_name = "TEST";
                    return [4 /*yield*/, Test_Test()];
                case 1:
                    _x.sent();
                    return [4 /*yield*/, Test_GetServerInfo()];
                case 2:
                    _x.sent();
                    return [4 /*yield*/, Test_GetServerStatus()];
                case 3:
                    _x.sent();
                    return [4 /*yield*/, Test_CreateListener()];
                case 4:
                    new_listener_port = _x.sent();
                    return [4 /*yield*/, Test_EnableListener(new_listener_port, false)];
                case 5:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumListener()];
                case 6:
                    _x.sent();
                    return [4 /*yield*/, Test_EnableListener(new_listener_port, true)];
                case 7:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumListener()];
                case 8:
                    _x.sent();
                    return [4 /*yield*/, Test_DeleteListener(new_listener_port)];
                case 9:
                    _x.sent();
                    return [4 /*yield*/, Test_SetServerPassword()];
                case 10:
                    _x.sent();
                    return [4 /*yield*/, Test_GetFarmSetting()];
                case 11:
                    _x.sent();
                    if (!false) return [3 /*break*/, 19];
                    return [4 /*yield*/, Test_SetFarmSetting()];
                case 12:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumFarmMember()];
                case 13:
                    farm_members = _x.sent();
                    _i = 0, _a = farm_members.FarmMemberList;
                    _x.label = 14;
                case 14:
                    if (!(_i < _a.length)) return [3 /*break*/, 17];
                    farm_member = _a[_i];
                    return [4 /*yield*/, Test_GetFarmInfo(farm_member.Id_u32)];
                case 15:
                    _x.sent();
                    _x.label = 16;
                case 16:
                    _i++;
                    return [3 /*break*/, 14];
                case 17: return [4 /*yield*/, Test_GetFarmConnectionStatus()];
                case 18:
                    _x.sent();
                    return [3 /*break*/, 20];
                case 19:
                    if (false) {
                        console.log("abc");
                    }
                    else {
                        console.log("def");
                    }
                    _x.label = 20;
                case 20: return [4 /*yield*/, Test_GetServerCert()];
                case 21:
                    _x.sent();
                    return [4 /*yield*/, Test_SetServerCert()];
                case 22:
                    _x.sent();
                    return [4 /*yield*/, Test_GetServerCipher()];
                case 23:
                    _x.sent();
                    return [4 /*yield*/, Test_SetServerCipher()];
                case 24:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumConnection()];
                case 25:
                    enum_connection = _x.sent();
                    _b = 0, _c = enum_connection.ConnectionList;
                    _x.label = 26;
                case 26:
                    if (!(_b < _c.length)) return [3 /*break*/, 29];
                    connecton = _c[_b];
                    return [4 /*yield*/, Test_GetConnectionInfo(connecton.Name_str)];
                case 27:
                    _x.sent();
                    _x.label = 28;
                case 28:
                    _b++;
                    return [3 /*break*/, 26];
                case 29: return [4 /*yield*/, Test_CreateHub()];
                case 30:
                    hub_name = _x.sent();
                    return [4 /*yield*/, Test_SetHub()];
                case 31:
                    _x.sent();
                    return [4 /*yield*/, Test_GetHub()];
                case 32:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumHub()];
                case 33:
                    _x.sent();
                    return [4 /*yield*/, Test_SetHubRadius()];
                case 34:
                    _x.sent();
                    return [4 /*yield*/, Test_GetHubRadius()];
                case 35:
                    _x.sent();
                    return [4 /*yield*/, Test_SetHubOnline()];
                case 36:
                    _x.sent();
                    return [4 /*yield*/, Test_GetHubStatus()];
                case 37:
                    _x.sent();
                    return [4 /*yield*/, Test_GetHubLog()];
                case 38:
                    hub_log_settings = _x.sent();
                    return [4 /*yield*/, Test_SetHubLog(hub_log_settings)];
                case 39:
                    _x.sent();
                    return [4 /*yield*/, Test_AddCa()];
                case 40:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumCa()];
                case 41:
                    enum_ca = _x.sent();
                    _d = 0, _e = enum_ca.CAList;
                    _x.label = 42;
                case 42:
                    if (!(_d < _e.length)) return [3 /*break*/, 46];
                    ca = _e[_d];
                    return [4 /*yield*/, Test_GetCa(ca.Key_u32)];
                case 43:
                    _x.sent();
                    return [4 /*yield*/, Test_DeleteCa(ca.Key_u32)];
                case 44:
                    _x.sent();
                    _x.label = 45;
                case 45:
                    _d++;
                    return [3 /*break*/, 42];
                case 46: return [4 /*yield*/, Test_CreateLink()];
                case 47:
                    _x.sent();
                    return [4 /*yield*/, Test_GetLink()];
                case 48:
                    _x.sent();
                    return [4 /*yield*/, Test_SetLink()];
                case 49:
                    _x.sent();
                    return [4 /*yield*/, Test_SetLinkOffline()];
                case 50:
                    _x.sent();
                    return [4 /*yield*/, Test_SetLinkOnline()];
                case 51:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumLink()];
                case 52:
                    enum_link = _x.sent();
                    _f = 0, _g = enum_link.LinkList;
                    _x.label = 53;
                case 53:
                    if (!(_f < _g.length)) return [3 /*break*/, 56];
                    link = _g[_f];
                    return [4 /*yield*/, Test_GetLinkStatus(link.AccountName_utf)];
                case 54:
                    _x.sent();
                    _x.label = 55;
                case 55:
                    _f++;
                    return [3 /*break*/, 53];
                case 56: return [4 /*yield*/, new Promise(function (r) { return setTimeout(r, 3000); })];
                case 57:
                    _x.sent();
                    return [4 /*yield*/, Test_RenameLink()];
                case 58:
                    _x.sent();
                    return [4 /*yield*/, Test_DeleteLink()];
                case 59:
                    _x.sent();
                    return [4 /*yield*/, Test_AddAccess()];
                case 60:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumAccess()];
                case 61:
                    _x.sent();
                    return [4 /*yield*/, Test_DeleteAccess()];
                case 62:
                    _x.sent();
                    return [4 /*yield*/, Test_SetAccessList()];
                case 63:
                    _x.sent();
                    return [4 /*yield*/, Test_CreateGroup()];
                case 64:
                    _x.sent();
                    return [4 /*yield*/, Test_SetGroup()];
                case 65:
                    _x.sent();
                    return [4 /*yield*/, Test_GetGroup()];
                case 66:
                    _x.sent();
                    return [4 /*yield*/, Test_CreateUser()];
                case 67:
                    _x.sent();
                    return [4 /*yield*/, Test_SetUser()];
                case 68:
                    _x.sent();
                    return [4 /*yield*/, Test_GetUser()];
                case 69:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumUser()];
                case 70:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumGroup()];
                case 71:
                    _x.sent();
                    return [4 /*yield*/, Test_DeleteUser()];
                case 72:
                    _x.sent();
                    return [4 /*yield*/, Test_DeleteGroup()];
                case 73:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumSession()];
                case 74:
                    enum_session = _x.sent();
                    _h = 0, _j = enum_session.SessionList;
                    _x.label = 75;
                case 75:
                    if (!(_h < _j.length)) return [3 /*break*/, 79];
                    session = _j[_h];
                    return [4 /*yield*/, Test_GetSessionStatus(session.Name_str)];
                case 76:
                    _x.sent();
                    return [4 /*yield*/, Test_DeleteSession(session.Name_str)];
                case 77:
                    _x.sent();
                    _x.label = 78;
                case 78:
                    _h++;
                    return [3 /*break*/, 75];
                case 79: return [4 /*yield*/, Test_EnumMacTable()];
                case 80:
                    enum_mac = _x.sent();
                    _k = 0, _l = enum_mac.MacTable;
                    _x.label = 81;
                case 81:
                    if (!(_k < _l.length)) return [3 /*break*/, 84];
                    mac = _l[_k];
                    return [4 /*yield*/, Test_DeleteMacTable(mac.Key_u32)];
                case 82:
                    _x.sent();
                    _x.label = 83;
                case 83:
                    _k++;
                    return [3 /*break*/, 81];
                case 84: return [4 /*yield*/, Test_EnumIpTable()];
                case 85:
                    enum_ip = _x.sent();
                    _m = 0, _o = enum_ip.IpTable;
                    _x.label = 86;
                case 86:
                    if (!(_m < _o.length)) return [3 /*break*/, 89];
                    ip = _o[_m];
                    return [4 /*yield*/, Test_DeleteIpTable(ip.Key_u32)];
                case 87:
                    _x.sent();
                    _x.label = 88;
                case 88:
                    _m++;
                    return [3 /*break*/, 86];
                case 89: return [4 /*yield*/, Test_SetKeep()];
                case 90:
                    _x.sent();
                    return [4 /*yield*/, Test_GetKeep()];
                case 91:
                    _x.sent();
                    return [4 /*yield*/, Test_EnableSecureNAT()];
                case 92:
                    _x.sent();
                    return [4 /*yield*/, Test_GetSecureNATOption()];
                case 93:
                    _x.sent();
                    return [4 /*yield*/, Test_SetSecureNATOption()];
                case 94:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumNAT()];
                case 95:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumDHCP()];
                case 96:
                    _x.sent();
                    return [4 /*yield*/, Test_GetSecureNATStatus()];
                case 97:
                    _x.sent();
                    return [4 /*yield*/, Test_DisableSecureNAT()];
                case 98:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumEthernet()];
                case 99:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumLocalBridge()];
                case 100:
                    _x.sent();
                    return [4 /*yield*/, Test_GetBridgeSupport()];
                case 101:
                    _x.sent();
                    return [4 /*yield*/, Test_GetCaps()];
                case 102:
                    _x.sent();
                    return [4 /*yield*/, Test_GetConfig()];
                case 103:
                    _x.sent();
                    return [4 /*yield*/, Test_GetDefaultHubAdminOptions()];
                case 104:
                    _x.sent();
                    return [4 /*yield*/, Test_GetHubAdminOptions()];
                case 105:
                    _x.sent();
                    return [4 /*yield*/, Test_SetHubAdminOptions()];
                case 106:
                    _x.sent();
                    return [4 /*yield*/, Test_GetHubExtOptions()];
                case 107:
                    _x.sent();
                    return [4 /*yield*/, Test_SetHubExtOptions()];
                case 108:
                    _x.sent();
                    return [4 /*yield*/, Test_AddL3Switch()];
                case 109:
                    _x.sent();
                    return [4 /*yield*/, Test_AddL3If()];
                case 110:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumL3Switch()];
                case 111:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumL3If()];
                case 112:
                    _x.sent();
                    return [4 /*yield*/, Test_AddL3Table()];
                case 113:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumL3Table()];
                case 114:
                    _x.sent();
                    return [4 /*yield*/, Test_DelL3Table()];
                case 115:
                    _x.sent();
                    return [4 /*yield*/, Test_StartL3Switch()];
                case 116:
                    _x.sent();
                    return [4 /*yield*/, Test_StopL3Switch()];
                case 117:
                    _x.sent();
                    return [4 /*yield*/, Test_DelL3If()];
                case 118:
                    _x.sent();
                    return [4 /*yield*/, Test_DelL3Switch()];
                case 119:
                    _x.sent();
                    return [4 /*yield*/, Test_AddCrl()];
                case 120:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumCrl()];
                case 121:
                    enum_crl = _x.sent();
                    _p = 0, _q = enum_crl.CRLList;
                    _x.label = 122;
                case 122:
                    if (!(_p < _q.length)) return [3 /*break*/, 126];
                    crl = _q[_p];
                    return [4 /*yield*/, Test_GetCrl(crl.Key_u32)];
                case 123:
                    got_crl = _x.sent();
                    got_crl.CommonName_utf = got_crl.CommonName_utf + "_a";
                    return [4 /*yield*/, Test_SetCrl(got_crl)];
                case 124:
                    _x.sent();
                    _x.label = 125;
                case 125:
                    _p++;
                    return [3 /*break*/, 122];
                case 126: return [4 /*yield*/, Test_EnumCrl()];
                case 127:
                    enum_crl = _x.sent();
                    _r = 0, _s = enum_crl.CRLList;
                    _x.label = 128;
                case 128:
                    if (!(_r < _s.length)) return [3 /*break*/, 131];
                    crl = _s[_r];
                    return [4 /*yield*/, Test_DelCrl(crl.Key_u32)];
                case 129:
                    _x.sent();
                    _x.label = 130;
                case 130:
                    _r++;
                    return [3 /*break*/, 128];
                case 131: return [4 /*yield*/, Test_SetAcList()];
                case 132:
                    _x.sent();
                    return [4 /*yield*/, Test_GetAcList()];
                case 133:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumLogFile()];
                case 134:
                    enum_log_file = _x.sent();
                    _t = 0, _u = enum_log_file.LogFiles;
                    _x.label = 135;
                case 135:
                    if (!(_t < _u.length)) return [3 /*break*/, 138];
                    log = _u[_t];
                    return [4 /*yield*/, Test_ReadLogFile(log.FilePath_str)];
                case 136:
                    _x.sent();
                    return [3 /*break*/, 138];
                case 137:
                    _t++;
                    return [3 /*break*/, 135];
                case 138: return [4 /*yield*/, Test_SetSysLog(true)];
                case 139:
                    _x.sent();
                    return [4 /*yield*/, Test_GetSysLog()];
                case 140:
                    _x.sent();
                    return [4 /*yield*/, Test_SetSysLog(false)];
                case 141:
                    _x.sent();
                    return [4 /*yield*/, Test_SetHubMsg()];
                case 142:
                    _x.sent();
                    return [4 /*yield*/, Test_GetHubMsg()];
                case 143:
                    _x.sent();
                    return [4 /*yield*/, Test_GetAdminMsg()];
                case 144:
                    _x.sent();
                    return [4 /*yield*/, Test_Flush()];
                case 145:
                    _x.sent();
                    return [4 /*yield*/, Test_SetIPsecServices()];
                case 146:
                    _x.sent();
                    return [4 /*yield*/, Test_GetIPsecServices()];
                case 147:
                    _x.sent();
                    return [4 /*yield*/, Test_AddEtherIpId()];
                case 148:
                    _x.sent();
                    return [4 /*yield*/, Test_EnumEtherIpId()];
                case 149:
                    enum_etherip_id = _x.sent();
                    _v = 0, _w = enum_etherip_id.Settings;
                    _x.label = 150;
                case 150:
                    if (!(_v < _w.length)) return [3 /*break*/, 154];
                    etherip_id = _w[_v];
                    return [4 /*yield*/, Test_GetEtherIpId(etherip_id.Id_str)];
                case 151:
                    _x.sent();
                    return [4 /*yield*/, Test_DeleteEtherIpId(etherip_id.Id_str)];
                case 152:
                    _x.sent();
                    _x.label = 153;
                case 153:
                    _v++;
                    return [3 /*break*/, 150];
                case 154: return [4 /*yield*/, Test_SetOpenVpnSstpConfig()];
                case 155:
                    _x.sent();
                    return [4 /*yield*/, Test_GetOpenVpnSstpConfig()];
                case 156:
                    _x.sent();
                    return [4 /*yield*/, Test_GetDDnsClientStatus()];
                case 157:
                    _x.sent();
                    return [4 /*yield*/, Test_SetDDnsInternetSettng()];
                case 158:
                    _x.sent();
                    return [4 /*yield*/, Test_GetDDnsInternetSettng()];
                case 159:
                    _x.sent();
                    return [4 /*yield*/, Test_ChangeDDnsClientHostname()];
                case 160:
                    _x.sent();
                    return [4 /*yield*/, Test_RegenerateServerCert()];
                case 161:
                    _x.sent();
                    return [4 /*yield*/, Test_MakeOpenVpnConfigFile()];
                case 162:
                    _x.sent();
                    return [4 /*yield*/, Test_SetSpecialListener()];
                case 163:
                    _x.sent();
                    return [4 /*yield*/, Test_GetSpecialListener()];
                case 164:
                    _x.sent();
                    return [4 /*yield*/, Test_GetAzureStatus()];
                case 165:
                    _x.sent();
                    return [4 /*yield*/, Test_SetAzureStatus()];
                case 166:
                    _x.sent();
                    return [4 /*yield*/, Test_SetVgsConfig()];
                case 167:
                    _x.sent();
                    return [4 /*yield*/, Test_GetVgsConfig()];
                case 168:
                    _x.sent();
                    return [4 /*yield*/, Test_DeleteHub()];
                case 169:
                    _x.sent();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'Test', test RPC function */
function Test_Test() {
    return __awaiter(this, void 0, void 0, function () {
        var a, b;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_Test");
                    a = new VPN.VpnRpcTest({
                        IntValue_u32: 12345
                    });
                    return [4 /*yield*/, api.Test(a)];
                case 1:
                    b = _a.sent();
                    console.log(b);
                    console.log("End: Test_Test");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetServerInfo', Get server information */
function Test_GetServerInfo() {
    return __awaiter(this, void 0, void 0, function () {
        var info;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetServerInfo");
                    return [4 /*yield*/, api.GetServerInfo()];
                case 1:
                    info = _a.sent();
                    console.log(info);
                    console.log("End: Test_GetServerInfo");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetServerStatus', Get server status */
function Test_GetServerStatus() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_server_status;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetServerStatus");
                    return [4 /*yield*/, api.GetServerStatus()];
                case 1:
                    out_rpc_server_status = _a.sent();
                    console.log(out_rpc_server_status);
                    console.log("End: Test_GetServerStatus");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'CreateListener', Create a listener */
function Test_CreateListener() {
    return __awaiter(this, void 0, void 0, function () {
        var port, in_rpc_listener, out_rpc_listener;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_CreateListener");
                    port = Math.floor((Math.random() * (65534 - 1025)) + 1025);
                    console.log("Creating a new listener port: Port " + port);
                    in_rpc_listener = new VPN.VpnRpcListener({
                        Enable_bool: true,
                        Port_u32: port
                    });
                    return [4 /*yield*/, api.CreateListener(in_rpc_listener)];
                case 1:
                    out_rpc_listener = _a.sent();
                    console.log("Done.");
                    console.log("End: Test_CreateListener");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/, port];
            }
        });
    });
}
/** API test for 'EnumListener', Enumerating listeners */
function Test_EnumListener() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_listener_list;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumListener");
                    return [4 /*yield*/, api.EnumListener()];
                case 1:
                    out_rpc_listener_list = _a.sent();
                    console.log(out_rpc_listener_list);
                    console.log("End: Test_EnumListener");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'DeleteListener', Delete a listener */
function Test_DeleteListener(port) {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_listener, out_rpc_listener;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_DeleteListener");
                    console.log("Deleting a new listener port: Port" + port);
                    in_rpc_listener = new VPN.VpnRpcListener({
                        Port_u32: port
                    });
                    return [4 /*yield*/, api.DeleteListener(in_rpc_listener)];
                case 1:
                    out_rpc_listener = _a.sent();
                    console.log("Done.");
                    console.log("End: Test_DeleteListener");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnableListener', Enable / Disable listener */
function Test_EnableListener(port, enabled) {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_listener, out_rpc_listener;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnableListener");
                    if (enabled) {
                        console.log("Enabling listener port = " + port);
                    }
                    else {
                        console.log("Disabling listener port = " + port);
                    }
                    in_rpc_listener = new VPN.VpnRpcListener({
                        Port_u32: port,
                        Enable_bool: enabled
                    });
                    return [4 /*yield*/, api.EnableListener(in_rpc_listener)];
                case 1:
                    out_rpc_listener = _a.sent();
                    console.log("Done.");
                    console.log("End: Test_EnableListener");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetServerPassword', Set server password */
function Test_SetServerPassword() {
    return __awaiter(this, void 0, void 0, function () {
        var password, in_rpc_set_password, out_rpc_set_password;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    password = "microsoft";
                    console.log("Begin: Test_SetServerPassword");
                    console.log("Set the server administrator password to '" + password + "'.");
                    in_rpc_set_password = new VPN.VpnRpcSetPassword({
                        PlainTextPassword_str: password
                    });
                    return [4 /*yield*/, api.SetServerPassword(in_rpc_set_password)];
                case 1:
                    out_rpc_set_password = _a.sent();
                    console.log("Done.");
                    console.log("End: Test_SetServerPassword");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetFarmSetting', Set clustering configuration */
function Test_SetFarmSetting() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_farm, out_rpc_farm;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetFarmSetting");
                    in_rpc_farm = new VPN.VpnRpcFarm({
                        ServerType_u32: VPN.VpnRpcServerType.FarmController,
                        NumPort_u32: 2,
                        Ports_u32: [443, 444, 445,],
                        PublicIp_ip: "1.2.3.4",
                        ControllerName_str: "controller",
                        MemberPasswordPlaintext_str: "microsoft",
                        ControllerPort_u32: 443,
                        Weight_u32: 100,
                        ControllerOnly_bool: false
                    });
                    return [4 /*yield*/, api.SetFarmSetting(in_rpc_farm)];
                case 1:
                    out_rpc_farm = _a.sent();
                    console.log("End: Test_SetFarmSetting");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetFarmSetting', Get clustering configuration */
function Test_GetFarmSetting() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_farm;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetFarmSetting");
                    return [4 /*yield*/, api.GetFarmSetting()];
                case 1:
                    out_rpc_farm = _a.sent();
                    console.log(out_rpc_farm);
                    console.log("End: Test_GetFarmSetting");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetFarmInfo', Get cluster member information */
function Test_GetFarmInfo(id) {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_farm_info, out_rpc_farm_info;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetFarmInfo");
                    in_rpc_farm_info = new VPN.VpnRpcFarmInfo({
                        Id_u32: id
                    });
                    return [4 /*yield*/, api.GetFarmInfo(in_rpc_farm_info)];
                case 1:
                    out_rpc_farm_info = _a.sent();
                    console.log(out_rpc_farm_info);
                    console.log("End: Test_GetFarmInfo");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumFarmMember', Enumerate cluster members */
function Test_EnumFarmMember() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_enum_farm;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumFarmMember");
                    return [4 /*yield*/, api.EnumFarmMember()];
                case 1:
                    out_rpc_enum_farm = _a.sent();
                    console.log(out_rpc_enum_farm);
                    console.log("End: Test_EnumFarmMember");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/, out_rpc_enum_farm];
            }
        });
    });
}
/** API test for 'GetFarmConnectionStatus', Get status of connection to cluster controller */
function Test_GetFarmConnectionStatus() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_farm_connection_status;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetFarmConnectionStatus");
                    return [4 /*yield*/, api.GetFarmConnectionStatus()];
                case 1:
                    out_rpc_farm_connection_status = _a.sent();
                    console.log(out_rpc_farm_connection_status);
                    console.log("End: Test_GetFarmConnectionStatus");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetServerCert', Set the server certification */
function Test_SetServerCert() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_key_pair, out_rpc_key_pair;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetServerCert");
                    in_rpc_key_pair = new VPN.VpnRpcKeyPair({
                        Cert_bin: new Uint8Array([0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x43, 0x45, 0x52, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x49, 0x49, 0x44, 0x72, 0x6a, 0x43, 0x43, 0x41, 0x70, 0x61, 0x67, 0x41, 0x77, 0x49, 0x42, 0x41, 0x67, 0x49, 0x42, 0x41, 0x44, 0x41, 0x4e, 0x42, 0x67, 0x6b, 0x71, 0x68, 0x6b, 0x69, 0x47, 0x39, 0x77, 0x30, 0x42, 0x41, 0x51, 0x73, 0x46, 0x41, 0x44, 0x42, 0x57, 0x4d, 0x51, 0x77, 0x77, 0x43, 0x67, 0x59, 0x44, 0x56, 0x51, 0x51, 0x44, 0x44, 0x41, 0x4e, 0x68, 0x59, 0x57, 0x45, 0x78, 0x0a, 0x46, 0x54, 0x41, 0x54, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x6f, 0x4d, 0x44, 0x4f, 0x4f, 0x42, 0x72, 0x2b, 0x4f, 0x42, 0x71, 0x75, 0x4f, 0x42, 0x6a, 0x2b, 0x4f, 0x42, 0x6e, 0x54, 0x45, 0x4c, 0x4d, 0x41, 0x6b, 0x47, 0x41, 0x31, 0x55, 0x45, 0x42, 0x68, 0x4d, 0x43, 0x53, 0x6c, 0x41, 0x78, 0x45, 0x44, 0x41, 0x4f, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x67, 0x4d, 0x42, 0x30, 0x6c, 0x69, 0x0a, 0x59, 0x58, 0x4a, 0x68, 0x61, 0x32, 0x6b, 0x78, 0x45, 0x44, 0x41, 0x4f, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x63, 0x4d, 0x42, 0x31, 0x52, 0x7a, 0x64, 0x57, 0x74, 0x31, 0x59, 0x6d, 0x45, 0x77, 0x48, 0x68, 0x63, 0x4e, 0x4d, 0x54, 0x67, 0x78, 0x4d, 0x44, 0x45, 0x78, 0x4d, 0x6a, 0x4d, 0x7a, 0x4e, 0x54, 0x41, 0x78, 0x57, 0x68, 0x63, 0x4e, 0x4e, 0x44, 0x49, 0x78, 0x4d, 0x44, 0x41, 0x31, 0x0a, 0x4d, 0x6a, 0x4d, 0x7a, 0x4e, 0x54, 0x41, 0x78, 0x57, 0x6a, 0x42, 0x57, 0x4d, 0x51, 0x77, 0x77, 0x43, 0x67, 0x59, 0x44, 0x56, 0x51, 0x51, 0x44, 0x44, 0x41, 0x4e, 0x68, 0x59, 0x57, 0x45, 0x78, 0x46, 0x54, 0x41, 0x54, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x6f, 0x4d, 0x44, 0x4f, 0x4f, 0x42, 0x72, 0x2b, 0x4f, 0x42, 0x71, 0x75, 0x4f, 0x42, 0x6a, 0x2b, 0x4f, 0x42, 0x6e, 0x54, 0x45, 0x4c, 0x0a, 0x4d, 0x41, 0x6b, 0x47, 0x41, 0x31, 0x55, 0x45, 0x42, 0x68, 0x4d, 0x43, 0x53, 0x6c, 0x41, 0x78, 0x45, 0x44, 0x41, 0x4f, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x67, 0x4d, 0x42, 0x30, 0x6c, 0x69, 0x59, 0x58, 0x4a, 0x68, 0x61, 0x32, 0x6b, 0x78, 0x45, 0x44, 0x41, 0x4f, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x63, 0x4d, 0x42, 0x31, 0x52, 0x7a, 0x64, 0x57, 0x74, 0x31, 0x59, 0x6d, 0x45, 0x77, 0x0a, 0x67, 0x67, 0x45, 0x69, 0x4d, 0x41, 0x30, 0x47, 0x43, 0x53, 0x71, 0x47, 0x53, 0x49, 0x62, 0x33, 0x44, 0x51, 0x45, 0x42, 0x41, 0x51, 0x55, 0x41, 0x41, 0x34, 0x49, 0x42, 0x44, 0x77, 0x41, 0x77, 0x67, 0x67, 0x45, 0x4b, 0x41, 0x6f, 0x49, 0x42, 0x41, 0x51, 0x44, 0x58, 0x45, 0x63, 0x76, 0x72, 0x59, 0x37, 0x56, 0x2b, 0x7a, 0x64, 0x42, 0x79, 0x72, 0x64, 0x4e, 0x78, 0x4a, 0x59, 0x45, 0x6d, 0x0a, 0x61, 0x41, 0x4e, 0x59, 0x55, 0x4f, 0x37, 0x76, 0x57, 0x34, 0x68, 0x64, 0x41, 0x35, 0x49, 0x42, 0x49, 0x46, 0x6d, 0x4d, 0x70, 0x6e, 0x62, 0x79, 0x69, 0x4e, 0x6e, 0x5a, 0x77, 0x36, 0x57, 0x39, 0x6f, 0x61, 0x67, 0x78, 0x33, 0x5a, 0x49, 0x65, 0x65, 0x48, 0x56, 0x59, 0x62, 0x52, 0x69, 0x4b, 0x36, 0x41, 0x66, 0x46, 0x74, 0x53, 0x31, 0x32, 0x2b, 0x45, 0x31, 0x4d, 0x59, 0x31, 0x64, 0x32, 0x0a, 0x61, 0x71, 0x51, 0x31, 0x53, 0x72, 0x49, 0x43, 0x39, 0x51, 0x35, 0x55, 0x6e, 0x5a, 0x61, 0x42, 0x72, 0x62, 0x57, 0x32, 0x32, 0x6d, 0x4e, 0x75, 0x6c, 0x4d, 0x34, 0x2f, 0x6c, 0x49, 0x4a, 0x72, 0x48, 0x70, 0x51, 0x55, 0x68, 0x50, 0x78, 0x6f, 0x62, 0x79, 0x34, 0x2f, 0x36, 0x4e, 0x41, 0x37, 0x71, 0x4b, 0x67, 0x55, 0x48, 0x69, 0x79, 0x4f, 0x64, 0x33, 0x4a, 0x42, 0x70, 0x4f, 0x66, 0x77, 0x0a, 0x38, 0x54, 0x76, 0x53, 0x74, 0x51, 0x78, 0x34, 0x4c, 0x38, 0x59, 0x64, 0x4b, 0x51, 0x35, 0x68, 0x74, 0x7a, 0x6b, 0x32, 0x68, 0x70, 0x52, 0x4a, 0x4c, 0x30, 0x6c, 0x4b, 0x67, 0x47, 0x31, 0x57, 0x34, 0x75, 0x4b, 0x32, 0x39, 0x39, 0x42, 0x74, 0x7a, 0x64, 0x41, 0x67, 0x66, 0x42, 0x76, 0x43, 0x54, 0x33, 0x41, 0x31, 0x61, 0x53, 0x70, 0x6a, 0x49, 0x47, 0x74, 0x6e, 0x69, 0x72, 0x49, 0x31, 0x0a, 0x46, 0x4c, 0x52, 0x58, 0x47, 0x79, 0x38, 0x31, 0x31, 0x57, 0x4a, 0x39, 0x4a, 0x68, 0x68, 0x34, 0x41, 0x4b, 0x4c, 0x66, 0x79, 0x56, 0x70, 0x42, 0x4a, 0x67, 0x65, 0x34, 0x73, 0x56, 0x72, 0x36, 0x4e, 0x75, 0x75, 0x49, 0x66, 0x32, 0x71, 0x47, 0x31, 0x6f, 0x79, 0x31, 0x30, 0x70, 0x61, 0x51, 0x4e, 0x65, 0x71, 0x32, 0x33, 0x55, 0x47, 0x61, 0x59, 0x74, 0x2f, 0x7a, 0x55, 0x56, 0x4a, 0x77, 0x0a, 0x55, 0x74, 0x30, 0x57, 0x45, 0x6b, 0x58, 0x38, 0x48, 0x4f, 0x63, 0x62, 0x33, 0x75, 0x49, 0x6f, 0x54, 0x6d, 0x61, 0x4f, 0x34, 0x72, 0x48, 0x42, 0x55, 0x4a, 0x71, 0x45, 0x79, 0x39, 0x51, 0x58, 0x7a, 0x53, 0x57, 0x77, 0x43, 0x35, 0x78, 0x45, 0x43, 0x64, 0x37, 0x43, 0x4a, 0x53, 0x53, 0x68, 0x31, 0x30, 0x4f, 0x75, 0x6e, 0x6c, 0x75, 0x4c, 0x32, 0x4d, 0x47, 0x65, 0x5a, 0x47, 0x6e, 0x76, 0x0a, 0x41, 0x67, 0x4d, 0x42, 0x41, 0x41, 0x47, 0x6a, 0x67, 0x59, 0x59, 0x77, 0x67, 0x59, 0x4d, 0x77, 0x44, 0x77, 0x59, 0x44, 0x56, 0x52, 0x30, 0x54, 0x41, 0x51, 0x48, 0x2f, 0x42, 0x41, 0x55, 0x77, 0x41, 0x77, 0x45, 0x42, 0x2f, 0x7a, 0x41, 0x4c, 0x42, 0x67, 0x4e, 0x56, 0x48, 0x51, 0x38, 0x45, 0x42, 0x41, 0x4d, 0x43, 0x41, 0x66, 0x59, 0x77, 0x59, 0x77, 0x59, 0x44, 0x56, 0x52, 0x30, 0x6c, 0x0a, 0x42, 0x46, 0x77, 0x77, 0x57, 0x67, 0x59, 0x49, 0x4b, 0x77, 0x59, 0x42, 0x42, 0x51, 0x55, 0x48, 0x41, 0x77, 0x45, 0x47, 0x43, 0x43, 0x73, 0x47, 0x41, 0x51, 0x55, 0x46, 0x42, 0x77, 0x4d, 0x43, 0x42, 0x67, 0x67, 0x72, 0x42, 0x67, 0x45, 0x46, 0x42, 0x51, 0x63, 0x44, 0x41, 0x77, 0x59, 0x49, 0x4b, 0x77, 0x59, 0x42, 0x42, 0x51, 0x55, 0x48, 0x41, 0x77, 0x51, 0x47, 0x43, 0x43, 0x73, 0x47, 0x0a, 0x41, 0x51, 0x55, 0x46, 0x42, 0x77, 0x4d, 0x46, 0x42, 0x67, 0x67, 0x72, 0x42, 0x67, 0x45, 0x46, 0x42, 0x51, 0x63, 0x44, 0x42, 0x67, 0x59, 0x49, 0x4b, 0x77, 0x59, 0x42, 0x42, 0x51, 0x55, 0x48, 0x41, 0x77, 0x63, 0x47, 0x43, 0x43, 0x73, 0x47, 0x41, 0x51, 0x55, 0x46, 0x42, 0x77, 0x4d, 0x49, 0x42, 0x67, 0x67, 0x72, 0x42, 0x67, 0x45, 0x46, 0x42, 0x51, 0x63, 0x44, 0x43, 0x54, 0x41, 0x4e, 0x0a, 0x42, 0x67, 0x6b, 0x71, 0x68, 0x6b, 0x69, 0x47, 0x39, 0x77, 0x30, 0x42, 0x41, 0x51, 0x73, 0x46, 0x41, 0x41, 0x4f, 0x43, 0x41, 0x51, 0x45, 0x41, 0x46, 0x6d, 0x34, 0x37, 0x47, 0x55, 0x70, 0x50, 0x57, 0x35, 0x2b, 0x37, 0x69, 0x46, 0x74, 0x69, 0x6c, 0x6f, 0x6b, 0x35, 0x32, 0x49, 0x6f, 0x54, 0x57, 0x72, 0x74, 0x46, 0x67, 0x32, 0x79, 0x69, 0x36, 0x6b, 0x49, 0x32, 0x69, 0x52, 0x4e, 0x51, 0x0a, 0x4b, 0x75, 0x67, 0x48, 0x55, 0x49, 0x4f, 0x34, 0x4b, 0x53, 0x71, 0x4a, 0x56, 0x42, 0x50, 0x38, 0x61, 0x4b, 0x4f, 0x61, 0x54, 0x5a, 0x47, 0x45, 0x31, 0x4b, 0x4d, 0x68, 0x2f, 0x59, 0x6a, 0x68, 0x36, 0x71, 0x2f, 0x67, 0x50, 0x61, 0x6c, 0x67, 0x64, 0x2f, 0x38, 0x44, 0x6d, 0x72, 0x78, 0x53, 0x4a, 0x6d, 0x55, 0x78, 0x33, 0x62, 0x4e, 0x62, 0x38, 0x52, 0x59, 0x36, 0x70, 0x4b, 0x7a, 0x74, 0x0a, 0x5a, 0x64, 0x75, 0x53, 0x61, 0x53, 0x2b, 0x57, 0x55, 0x30, 0x59, 0x74, 0x2b, 0x6c, 0x47, 0x35, 0x76, 0x56, 0x67, 0x61, 0x70, 0x48, 0x45, 0x71, 0x36, 0x79, 0x71, 0x4c, 0x62, 0x65, 0x56, 0x78, 0x51, 0x4c, 0x75, 0x62, 0x54, 0x69, 0x6e, 0x4f, 0x66, 0x56, 0x56, 0x5a, 0x58, 0x79, 0x45, 0x43, 0x59, 0x47, 0x4d, 0x73, 0x59, 0x71, 0x65, 0x6e, 0x4a, 0x6a, 0x4e, 0x63, 0x62, 0x49, 0x5a, 0x4e, 0x0a, 0x79, 0x4d, 0x75, 0x72, 0x46, 0x63, 0x67, 0x30, 0x34, 0x36, 0x4f, 0x34, 0x59, 0x79, 0x68, 0x56, 0x79, 0x71, 0x53, 0x69, 0x74, 0x43, 0x59, 0x37, 0x68, 0x2f, 0x65, 0x71, 0x67, 0x6b, 0x50, 0x4a, 0x51, 0x30, 0x68, 0x6b, 0x70, 0x39, 0x45, 0x64, 0x51, 0x77, 0x62, 0x6e, 0x38, 0x56, 0x6c, 0x66, 0x78, 0x64, 0x42, 0x58, 0x77, 0x51, 0x34, 0x4e, 0x48, 0x4b, 0x30, 0x4a, 0x56, 0x46, 0x2f, 0x33, 0x0a, 0x71, 0x48, 0x61, 0x68, 0x4e, 0x48, 0x4f, 0x35, 0x64, 0x62, 0x4a, 0x5a, 0x57, 0x59, 0x41, 0x62, 0x42, 0x44, 0x70, 0x32, 0x51, 0x45, 0x53, 0x70, 0x76, 0x6f, 0x2b, 0x38, 0x33, 0x6c, 0x68, 0x34, 0x64, 0x6e, 0x58, 0x6a, 0x46, 0x58, 0x4d, 0x43, 0x48, 0x76, 0x52, 0x68, 0x35, 0x31, 0x79, 0x2f, 0x54, 0x71, 0x79, 0x42, 0x34, 0x56, 0x76, 0x72, 0x52, 0x4b, 0x49, 0x4b, 0x74, 0x54, 0x6f, 0x7a, 0x0a, 0x5a, 0x6a, 0x48, 0x59, 0x49, 0x63, 0x62, 0x6a, 0x76, 0x53, 0x58, 0x4d, 0x7a, 0x61, 0x44, 0x50, 0x6a, 0x50, 0x63, 0x5a, 0x47, 0x6a, 0x42, 0x4a, 0x6c, 0x47, 0x36, 0x43, 0x76, 0x44, 0x34, 0x4c, 0x6d, 0x59, 0x7a, 0x72, 0x6b, 0x48, 0x34, 0x31, 0x63, 0x7a, 0x72, 0x34, 0x57, 0x41, 0x3d, 0x3d, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x43, 0x45, 0x52, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a,]),
                        Key_bin: new Uint8Array([0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x49, 0x49, 0x45, 0x76, 0x67, 0x49, 0x42, 0x41, 0x44, 0x41, 0x4e, 0x42, 0x67, 0x6b, 0x71, 0x68, 0x6b, 0x69, 0x47, 0x39, 0x77, 0x30, 0x42, 0x41, 0x51, 0x45, 0x46, 0x41, 0x41, 0x53, 0x43, 0x42, 0x4b, 0x67, 0x77, 0x67, 0x67, 0x53, 0x6b, 0x41, 0x67, 0x45, 0x41, 0x41, 0x6f, 0x49, 0x42, 0x41, 0x51, 0x44, 0x58, 0x45, 0x63, 0x76, 0x72, 0x59, 0x37, 0x56, 0x2b, 0x7a, 0x64, 0x42, 0x79, 0x0a, 0x72, 0x64, 0x4e, 0x78, 0x4a, 0x59, 0x45, 0x6d, 0x61, 0x41, 0x4e, 0x59, 0x55, 0x4f, 0x37, 0x76, 0x57, 0x34, 0x68, 0x64, 0x41, 0x35, 0x49, 0x42, 0x49, 0x46, 0x6d, 0x4d, 0x70, 0x6e, 0x62, 0x79, 0x69, 0x4e, 0x6e, 0x5a, 0x77, 0x36, 0x57, 0x39, 0x6f, 0x61, 0x67, 0x78, 0x33, 0x5a, 0x49, 0x65, 0x65, 0x48, 0x56, 0x59, 0x62, 0x52, 0x69, 0x4b, 0x36, 0x41, 0x66, 0x46, 0x74, 0x53, 0x31, 0x32, 0x0a, 0x2b, 0x45, 0x31, 0x4d, 0x59, 0x31, 0x64, 0x32, 0x61, 0x71, 0x51, 0x31, 0x53, 0x72, 0x49, 0x43, 0x39, 0x51, 0x35, 0x55, 0x6e, 0x5a, 0x61, 0x42, 0x72, 0x62, 0x57, 0x32, 0x32, 0x6d, 0x4e, 0x75, 0x6c, 0x4d, 0x34, 0x2f, 0x6c, 0x49, 0x4a, 0x72, 0x48, 0x70, 0x51, 0x55, 0x68, 0x50, 0x78, 0x6f, 0x62, 0x79, 0x34, 0x2f, 0x36, 0x4e, 0x41, 0x37, 0x71, 0x4b, 0x67, 0x55, 0x48, 0x69, 0x79, 0x4f, 0x0a, 0x64, 0x33, 0x4a, 0x42, 0x70, 0x4f, 0x66, 0x77, 0x38, 0x54, 0x76, 0x53, 0x74, 0x51, 0x78, 0x34, 0x4c, 0x38, 0x59, 0x64, 0x4b, 0x51, 0x35, 0x68, 0x74, 0x7a, 0x6b, 0x32, 0x68, 0x70, 0x52, 0x4a, 0x4c, 0x30, 0x6c, 0x4b, 0x67, 0x47, 0x31, 0x57, 0x34, 0x75, 0x4b, 0x32, 0x39, 0x39, 0x42, 0x74, 0x7a, 0x64, 0x41, 0x67, 0x66, 0x42, 0x76, 0x43, 0x54, 0x33, 0x41, 0x31, 0x61, 0x53, 0x70, 0x6a, 0x0a, 0x49, 0x47, 0x74, 0x6e, 0x69, 0x72, 0x49, 0x31, 0x46, 0x4c, 0x52, 0x58, 0x47, 0x79, 0x38, 0x31, 0x31, 0x57, 0x4a, 0x39, 0x4a, 0x68, 0x68, 0x34, 0x41, 0x4b, 0x4c, 0x66, 0x79, 0x56, 0x70, 0x42, 0x4a, 0x67, 0x65, 0x34, 0x73, 0x56, 0x72, 0x36, 0x4e, 0x75, 0x75, 0x49, 0x66, 0x32, 0x71, 0x47, 0x31, 0x6f, 0x79, 0x31, 0x30, 0x70, 0x61, 0x51, 0x4e, 0x65, 0x71, 0x32, 0x33, 0x55, 0x47, 0x61, 0x0a, 0x59, 0x74, 0x2f, 0x7a, 0x55, 0x56, 0x4a, 0x77, 0x55, 0x74, 0x30, 0x57, 0x45, 0x6b, 0x58, 0x38, 0x48, 0x4f, 0x63, 0x62, 0x33, 0x75, 0x49, 0x6f, 0x54, 0x6d, 0x61, 0x4f, 0x34, 0x72, 0x48, 0x42, 0x55, 0x4a, 0x71, 0x45, 0x79, 0x39, 0x51, 0x58, 0x7a, 0x53, 0x57, 0x77, 0x43, 0x35, 0x78, 0x45, 0x43, 0x64, 0x37, 0x43, 0x4a, 0x53, 0x53, 0x68, 0x31, 0x30, 0x4f, 0x75, 0x6e, 0x6c, 0x75, 0x4c, 0x0a, 0x32, 0x4d, 0x47, 0x65, 0x5a, 0x47, 0x6e, 0x76, 0x41, 0x67, 0x4d, 0x42, 0x41, 0x41, 0x45, 0x43, 0x67, 0x67, 0x45, 0x41, 0x54, 0x77, 0x34, 0x52, 0x6f, 0x52, 0x4c, 0x6a, 0x73, 0x68, 0x72, 0x42, 0x56, 0x6f, 0x59, 0x69, 0x78, 0x4f, 0x4a, 0x2b, 0x57, 0x4c, 0x6d, 0x2f, 0x45, 0x51, 0x57, 0x65, 0x37, 0x6f, 0x6a, 0x38, 0x31, 0x51, 0x50, 0x73, 0x39, 0x56, 0x45, 0x49, 0x32, 0x62, 0x53, 0x4f, 0x0a, 0x34, 0x4a, 0x51, 0x42, 0x55, 0x42, 0x53, 0x6b, 0x70, 0x64, 0x48, 0x34, 0x57, 0x32, 0x77, 0x51, 0x75, 0x2f, 0x61, 0x58, 0x57, 0x38, 0x75, 0x75, 0x53, 0x39, 0x45, 0x43, 0x6d, 0x6d, 0x41, 0x41, 0x75, 0x45, 0x79, 0x4a, 0x54, 0x56, 0x7a, 0x75, 0x31, 0x32, 0x35, 0x58, 0x73, 0x65, 0x63, 0x6c, 0x44, 0x41, 0x55, 0x38, 0x49, 0x55, 0x70, 0x54, 0x2b, 0x70, 0x4c, 0x35, 0x79, 0x70, 0x37, 0x34, 0x0a, 0x45, 0x62, 0x76, 0x4e, 0x48, 0x48, 0x33, 0x67, 0x65, 0x72, 0x4f, 0x67, 0x78, 0x76, 0x49, 0x6a, 0x50, 0x64, 0x67, 0x77, 0x62, 0x66, 0x6d, 0x4d, 0x49, 0x59, 0x48, 0x62, 0x56, 0x70, 0x6e, 0x49, 0x30, 0x77, 0x32, 0x42, 0x43, 0x44, 0x51, 0x76, 0x74, 0x64, 0x64, 0x57, 0x6f, 0x42, 0x74, 0x41, 0x33, 0x43, 0x54, 0x6a, 0x63, 0x2f, 0x43, 0x56, 0x67, 0x73, 0x47, 0x77, 0x33, 0x43, 0x4e, 0x72, 0x0a, 0x46, 0x78, 0x41, 0x46, 0x35, 0x73, 0x4a, 0x34, 0x63, 0x5a, 0x4c, 0x6e, 0x5a, 0x31, 0x45, 0x36, 0x69, 0x74, 0x4c, 0x54, 0x50, 0x69, 0x6f, 0x6a, 0x74, 0x76, 0x48, 0x48, 0x34, 0x61, 0x64, 0x6d, 0x68, 0x68, 0x43, 0x61, 0x42, 0x49, 0x78, 0x76, 0x47, 0x2f, 0x53, 0x6e, 0x59, 0x77, 0x4e, 0x35, 0x38, 0x37, 0x55, 0x5a, 0x6d, 0x37, 0x4c, 0x57, 0x50, 0x61, 0x67, 0x4c, 0x41, 0x33, 0x67, 0x69, 0x0a, 0x48, 0x4b, 0x4f, 0x2b, 0x4b, 0x79, 0x42, 0x51, 0x39, 0x33, 0x31, 0x4e, 0x4d, 0x61, 0x65, 0x6a, 0x36, 0x6d, 0x75, 0x75, 0x46, 0x32, 0x30, 0x32, 0x76, 0x34, 0x37, 0x6c, 0x57, 0x6b, 0x64, 0x50, 0x4f, 0x6e, 0x52, 0x43, 0x69, 0x6f, 0x4d, 0x58, 0x30, 0x63, 0x31, 0x6a, 0x36, 0x76, 0x32, 0x61, 0x59, 0x34, 0x34, 0x77, 0x55, 0x4b, 0x71, 0x39, 0x4d, 0x52, 0x67, 0x6f, 0x52, 0x76, 0x4a, 0x37, 0x0a, 0x41, 0x39, 0x77, 0x65, 0x72, 0x4c, 0x6b, 0x68, 0x35, 0x78, 0x78, 0x35, 0x35, 0x32, 0x4f, 0x74, 0x71, 0x50, 0x36, 0x73, 0x61, 0x6d, 0x75, 0x47, 0x44, 0x52, 0x78, 0x31, 0x42, 0x70, 0x36, 0x53, 0x4f, 0x70, 0x68, 0x43, 0x45, 0x50, 0x48, 0x59, 0x67, 0x51, 0x4b, 0x42, 0x67, 0x51, 0x44, 0x36, 0x33, 0x65, 0x2b, 0x52, 0x75, 0x6c, 0x36, 0x46, 0x78, 0x47, 0x43, 0x76, 0x67, 0x70, 0x6b, 0x33, 0x0a, 0x57, 0x67, 0x2f, 0x54, 0x31, 0x77, 0x2f, 0x59, 0x4b, 0x6b, 0x79, 0x4f, 0x49, 0x46, 0x4c, 0x63, 0x46, 0x4c, 0x57, 0x71, 0x42, 0x44, 0x71, 0x6c, 0x6e, 0x58, 0x65, 0x63, 0x6c, 0x6b, 0x50, 0x4b, 0x6a, 0x57, 0x4e, 0x2f, 0x32, 0x70, 0x4a, 0x6d, 0x4f, 0x31, 0x63, 0x46, 0x63, 0x44, 0x4a, 0x46, 0x59, 0x64, 0x32, 0x45, 0x49, 0x45, 0x72, 0x76, 0x42, 0x57, 0x54, 0x34, 0x51, 0x39, 0x4d, 0x42, 0x0a, 0x4e, 0x35, 0x6c, 0x44, 0x6b, 0x47, 0x75, 0x6a, 0x34, 0x2f, 0x6b, 0x68, 0x56, 0x6c, 0x79, 0x6e, 0x77, 0x62, 0x64, 0x42, 0x6e, 0x47, 0x43, 0x34, 0x61, 0x34, 0x48, 0x4a, 0x49, 0x4a, 0x76, 0x61, 0x35, 0x63, 0x70, 0x49, 0x63, 0x57, 0x65, 0x4a, 0x72, 0x35, 0x61, 0x57, 0x33, 0x69, 0x44, 0x36, 0x68, 0x53, 0x73, 0x61, 0x6c, 0x79, 0x55, 0x76, 0x4a, 0x4d, 0x6d, 0x64, 0x4d, 0x42, 0x6e, 0x47, 0x0a, 0x37, 0x2b, 0x50, 0x65, 0x53, 0x2b, 0x4e, 0x73, 0x4b, 0x30, 0x61, 0x63, 0x31, 0x67, 0x33, 0x4d, 0x6c, 0x56, 0x35, 0x42, 0x41, 0x32, 0x70, 0x55, 0x54, 0x77, 0x4b, 0x42, 0x67, 0x51, 0x44, 0x62, 0x65, 0x46, 0x6d, 0x2b, 0x46, 0x46, 0x35, 0x62, 0x76, 0x6f, 0x4b, 0x7a, 0x49, 0x4c, 0x6c, 0x31, 0x62, 0x79, 0x6b, 0x6c, 0x52, 0x6b, 0x69, 0x76, 0x7a, 0x6b, 0x62, 0x7a, 0x49, 0x6b, 0x41, 0x78, 0x0a, 0x35, 0x56, 0x6b, 0x74, 0x67, 0x36, 0x4a, 0x35, 0x63, 0x76, 0x38, 0x44, 0x35, 0x2b, 0x72, 0x71, 0x50, 0x75, 0x6a, 0x4f, 0x66, 0x39, 0x67, 0x42, 0x6a, 0x4e, 0x37, 0x70, 0x64, 0x78, 0x39, 0x39, 0x35, 0x6b, 0x47, 0x49, 0x78, 0x5a, 0x39, 0x6d, 0x31, 0x68, 0x57, 0x69, 0x78, 0x55, 0x55, 0x31, 0x55, 0x6f, 0x38, 0x72, 0x70, 0x39, 0x4a, 0x69, 0x47, 0x4f, 0x36, 0x72, 0x65, 0x31, 0x77, 0x69, 0x0a, 0x6a, 0x56, 0x2f, 0x4c, 0x31, 0x64, 0x37, 0x55, 0x66, 0x39, 0x48, 0x6a, 0x65, 0x61, 0x70, 0x4f, 0x46, 0x62, 0x34, 0x6b, 0x72, 0x71, 0x52, 0x58, 0x54, 0x65, 0x75, 0x4d, 0x6e, 0x35, 0x35, 0x44, 0x33, 0x64, 0x70, 0x79, 0x6a, 0x51, 0x4e, 0x43, 0x30, 0x5a, 0x50, 0x72, 0x61, 0x6d, 0x58, 0x64, 0x38, 0x31, 0x57, 0x6f, 0x6f, 0x56, 0x77, 0x58, 0x59, 0x41, 0x66, 0x69, 0x46, 0x76, 0x4c, 0x49, 0x0a, 0x6f, 0x66, 0x31, 0x37, 0x51, 0x67, 0x67, 0x49, 0x59, 0x51, 0x4b, 0x42, 0x67, 0x51, 0x44, 0x59, 0x55, 0x67, 0x67, 0x43, 0x34, 0x58, 0x49, 0x67, 0x5a, 0x76, 0x58, 0x34, 0x59, 0x65, 0x55, 0x38, 0x6c, 0x61, 0x79, 0x51, 0x50, 0x79, 0x4b, 0x71, 0x67, 0x38, 0x37, 0x2f, 0x76, 0x31, 0x2b, 0x7a, 0x35, 0x79, 0x65, 0x2f, 0x4d, 0x32, 0x5a, 0x65, 0x36, 0x53, 0x6e, 0x37, 0x48, 0x4a, 0x66, 0x59, 0x0a, 0x55, 0x5a, 0x4d, 0x36, 0x37, 0x48, 0x37, 0x52, 0x4b, 0x4e, 0x6f, 0x68, 0x46, 0x6c, 0x35, 0x43, 0x39, 0x65, 0x44, 0x4e, 0x7a, 0x67, 0x72, 0x50, 0x6b, 0x52, 0x63, 0x2f, 0x2f, 0x54, 0x77, 0x32, 0x45, 0x48, 0x74, 0x59, 0x68, 0x33, 0x42, 0x4b, 0x49, 0x6f, 0x72, 0x77, 0x39, 0x45, 0x64, 0x78, 0x59, 0x4e, 0x6c, 0x6b, 0x2b, 0x6a, 0x4e, 0x73, 0x30, 0x30, 0x64, 0x57, 0x35, 0x34, 0x64, 0x39, 0x0a, 0x65, 0x69, 0x69, 0x7a, 0x7a, 0x78, 0x59, 0x34, 0x34, 0x2f, 0x41, 0x32, 0x70, 0x39, 0x52, 0x49, 0x4d, 0x67, 0x79, 0x35, 0x49, 0x52, 0x77, 0x76, 0x53, 0x73, 0x6d, 0x50, 0x67, 0x61, 0x71, 0x34, 0x6f, 0x4b, 0x4d, 0x64, 0x54, 0x4e, 0x4d, 0x4f, 0x73, 0x30, 0x4a, 0x77, 0x65, 0x79, 0x50, 0x72, 0x42, 0x65, 0x49, 0x41, 0x72, 0x62, 0x46, 0x43, 0x67, 0x51, 0x4b, 0x42, 0x67, 0x51, 0x43, 0x71, 0x0a, 0x57, 0x30, 0x34, 0x56, 0x33, 0x49, 0x75, 0x74, 0x33, 0x55, 0x42, 0x6f, 0x75, 0x50, 0x4d, 0x63, 0x63, 0x38, 0x2f, 0x56, 0x62, 0x69, 0x77, 0x48, 0x77, 0x79, 0x2b, 0x52, 0x6c, 0x4c, 0x6d, 0x4e, 0x77, 0x59, 0x41, 0x71, 0x63, 0x79, 0x35, 0x50, 0x35, 0x58, 0x4b, 0x4c, 0x33, 0x70, 0x36, 0x62, 0x65, 0x33, 0x2b, 0x4d, 0x6f, 0x76, 0x48, 0x52, 0x71, 0x6a, 0x35, 0x78, 0x72, 0x4a, 0x54, 0x57, 0x0a, 0x54, 0x6a, 0x2f, 0x36, 0x59, 0x61, 0x51, 0x73, 0x31, 0x2b, 0x72, 0x74, 0x63, 0x51, 0x45, 0x61, 0x74, 0x64, 0x34, 0x4b, 0x50, 0x66, 0x64, 0x78, 0x53, 0x2f, 0x63, 0x66, 0x52, 0x74, 0x38, 0x71, 0x74, 0x75, 0x42, 0x77, 0x51, 0x61, 0x2f, 0x34, 0x39, 0x4d, 0x72, 0x41, 0x4c, 0x76, 0x57, 0x43, 0x4c, 0x53, 0x42, 0x75, 0x4b, 0x74, 0x33, 0x49, 0x49, 0x75, 0x53, 0x2f, 0x51, 0x44, 0x74, 0x43, 0x0a, 0x5a, 0x4e, 0x67, 0x6d, 0x36, 0x4d, 0x78, 0x71, 0x4e, 0x6e, 0x49, 0x43, 0x58, 0x35, 0x46, 0x34, 0x36, 0x6d, 0x52, 0x49, 0x52, 0x42, 0x42, 0x4f, 0x32, 0x4b, 0x7a, 0x6c, 0x30, 0x33, 0x68, 0x62, 0x51, 0x6c, 0x71, 0x58, 0x4c, 0x5a, 0x63, 0x38, 0x6f, 0x51, 0x4b, 0x42, 0x67, 0x43, 0x53, 0x77, 0x66, 0x46, 0x7a, 0x68, 0x48, 0x76, 0x78, 0x36, 0x68, 0x69, 0x64, 0x57, 0x67, 0x48, 0x4a, 0x63, 0x0a, 0x77, 0x79, 0x76, 0x64, 0x6e, 0x70, 0x58, 0x78, 0x36, 0x5a, 0x4c, 0x6e, 0x6f, 0x61, 0x7a, 0x61, 0x6f, 0x48, 0x47, 0x74, 0x4d, 0x47, 0x43, 0x45, 0x5a, 0x49, 0x50, 0x66, 0x6a, 0x4c, 0x42, 0x63, 0x30, 0x4d, 0x74, 0x79, 0x45, 0x64, 0x53, 0x4c, 0x78, 0x54, 0x6c, 0x35, 0x59, 0x70, 0x78, 0x6f, 0x6d, 0x43, 0x46, 0x55, 0x4d, 0x33, 0x55, 0x63, 0x59, 0x4e, 0x2f, 0x50, 0x5a, 0x66, 0x58, 0x41, 0x0a, 0x6d, 0x36, 0x31, 0x45, 0x6d, 0x71, 0x53, 0x53, 0x4d, 0x56, 0x63, 0x47, 0x50, 0x67, 0x65, 0x2f, 0x43, 0x34, 0x44, 0x42, 0x5a, 0x59, 0x6a, 0x53, 0x45, 0x71, 0x62, 0x67, 0x37, 0x6d, 0x73, 0x52, 0x30, 0x33, 0x37, 0x42, 0x58, 0x54, 0x48, 0x6b, 0x78, 0x44, 0x62, 0x33, 0x71, 0x48, 0x46, 0x54, 0x6f, 0x30, 0x6b, 0x48, 0x57, 0x4a, 0x66, 0x34, 0x39, 0x59, 0x77, 0x32, 0x73, 0x77, 0x6a, 0x54, 0x0a, 0x72, 0x4f, 0x38, 0x46, 0x46, 0x44, 0x52, 0x56, 0x50, 0x44, 0x4c, 0x5a, 0x61, 0x37, 0x36, 0x47, 0x67, 0x79, 0x41, 0x55, 0x4a, 0x38, 0x55, 0x63, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a,])
                    });
                    return [4 /*yield*/, api.SetServerCert(in_rpc_key_pair)];
                case 1:
                    out_rpc_key_pair = _a.sent();
                    console.log(out_rpc_key_pair);
                    console.log("End: Test_SetServerCert");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetServerCert', Get the server certification */
function Test_GetServerCert() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_key_pair;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetServerCert");
                    return [4 /*yield*/, api.GetServerCert()];
                case 1:
                    out_rpc_key_pair = _a.sent();
                    console.log(out_rpc_key_pair);
                    console.log("End: Test_GetServerCert");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetServerCipher', Get cipher for SSL */
function Test_GetServerCipher() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_str;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetServerCipher");
                    return [4 /*yield*/, api.GetServerCipher()];
                case 1:
                    out_rpc_str = _a.sent();
                    console.log(out_rpc_str);
                    console.log("End: Test_GetServerCipher");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetServerCipher', Set cipher for SSL to the server */
function Test_SetServerCipher() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_str, out_rpc_str;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetServerCipher");
                    in_rpc_str = new VPN.VpnRpcStr({
                        String_str: "RC4-MD5"
                    });
                    return [4 /*yield*/, api.SetServerCipher(in_rpc_str)];
                case 1:
                    out_rpc_str = _a.sent();
                    console.log(out_rpc_str);
                    console.log("End: Test_SetServerCipher");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'CreateHub', Create a hub */
function Test_CreateHub() {
    return __awaiter(this, void 0, void 0, function () {
        var hub_name, in_rpc_create_hub, out_rpc_create_hub;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    hub_name = "Test_" + Math.floor((Math.random() * (999999 - 100000)) + 100000);
                    console.log("Begin: Test_CreateHub");
                    in_rpc_create_hub = new VPN.VpnRpcCreateHub({
                        HubName_str: hub_name,
                        HubType_u32: VPN.VpnRpcHubType.Standalone,
                        Online_bool: true,
                        AdminPasswordPlainText_str: "microsoft",
                        MaxSession_u32: 123,
                        NoEnum_bool: false
                    });
                    return [4 /*yield*/, api.CreateHub(in_rpc_create_hub)];
                case 1:
                    out_rpc_create_hub = _a.sent();
                    console.log(out_rpc_create_hub);
                    console.log("End: Test_CreateHub");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/, hub_name];
            }
        });
    });
}
/** API test for 'SetHub', Set hub configuration */
function Test_SetHub() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_create_hub, out_rpc_create_hub;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetHub");
                    in_rpc_create_hub = new VPN.VpnRpcCreateHub({
                        HubName_str: hub_name,
                        AdminPasswordPlainText_str: "aho",
                        HubType_u32: VPN.VpnRpcHubType.Standalone,
                        NoEnum_bool: false,
                        MaxSession_u32: 128,
                        Online_bool: true
                    });
                    return [4 /*yield*/, api.SetHub(in_rpc_create_hub)];
                case 1:
                    out_rpc_create_hub = _a.sent();
                    console.log(out_rpc_create_hub);
                    console.log("End: Test_SetHub");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetHub', Get hub configuration */
function Test_GetHub() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_create_hub, out_rpc_create_hub;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetHub");
                    in_rpc_create_hub = new VPN.VpnRpcCreateHub({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.GetHub(in_rpc_create_hub)];
                case 1:
                    out_rpc_create_hub = _a.sent();
                    console.log(out_rpc_create_hub);
                    console.log("End: Test_GetHub");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumHub', Enumerate hubs */
function Test_EnumHub() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_enum_hub;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumHub");
                    return [4 /*yield*/, api.EnumHub()];
                case 1:
                    out_rpc_enum_hub = _a.sent();
                    console.log(out_rpc_enum_hub);
                    console.log("End: Test_EnumHub");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'DeleteHub', Delete a hub */
function Test_DeleteHub() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_delete_hub, out_rpc_delete_hub;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_DeleteHub");
                    in_rpc_delete_hub = new VPN.VpnRpcDeleteHub({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.DeleteHub(in_rpc_delete_hub)];
                case 1:
                    out_rpc_delete_hub = _a.sent();
                    console.log(out_rpc_delete_hub);
                    console.log("End: Test_DeleteHub");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetHubRadius', Get Radius options of the hub */
function Test_GetHubRadius() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_radius, out_rpc_radius;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetHubRadius");
                    in_rpc_radius = new VPN.VpnRpcRadius({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.GetHubRadius(in_rpc_radius)];
                case 1:
                    out_rpc_radius = _a.sent();
                    console.log(out_rpc_radius);
                    console.log("End: Test_GetHubRadius");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetHubRadius', Set Radius options of the hub */
function Test_SetHubRadius() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_radius, out_rpc_radius;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetHubRadius");
                    in_rpc_radius = new VPN.VpnRpcRadius({
                        HubName_str: hub_name,
                        RadiusServerName_str: "1.2.3.4",
                        RadiusPort_u32: 1234,
                        RadiusSecret_str: "microsoft",
                        RadiusRetryInterval_u32: 1000
                    });
                    return [4 /*yield*/, api.SetHubRadius(in_rpc_radius)];
                case 1:
                    out_rpc_radius = _a.sent();
                    console.log(out_rpc_radius);
                    console.log("End: Test_SetHubRadius");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumConnection', Enumerate connections */
function Test_EnumConnection() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_enum_connection;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumConnection");
                    return [4 /*yield*/, api.EnumConnection()];
                case 1:
                    out_rpc_enum_connection = _a.sent();
                    console.log(out_rpc_enum_connection);
                    console.log("End: Test_EnumConnection");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/, out_rpc_enum_connection];
            }
        });
    });
}
/** API test for 'DisconnectConnection', Disconnect a connection */
function Test_DisconnectConnection(connection_id) {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_disconnect_connection, out_rpc_disconnect_connection;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_DisconnectConnection");
                    in_rpc_disconnect_connection = new VPN.VpnRpcDisconnectConnection({
                        Name_str: connection_id
                    });
                    return [4 /*yield*/, api.DisconnectConnection(in_rpc_disconnect_connection)];
                case 1:
                    out_rpc_disconnect_connection = _a.sent();
                    console.log(out_rpc_disconnect_connection);
                    console.log("End: Test_DisconnectConnection");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetConnectionInfo', Get connection information */
function Test_GetConnectionInfo(name) {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_connection_info, out_rpc_connection_info;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetConnectionInfo");
                    in_rpc_connection_info = new VPN.VpnRpcConnectionInfo({
                        Name_str: name
                    });
                    return [4 /*yield*/, api.GetConnectionInfo(in_rpc_connection_info)];
                case 1:
                    out_rpc_connection_info = _a.sent();
                    console.log(out_rpc_connection_info);
                    console.log("End: Test_GetConnectionInfo");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetHubOnline', Make a hub on-line or off-line */
function Test_SetHubOnline() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_set_hub_online, out_rpc_set_hub_online;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetHubOnline");
                    in_rpc_set_hub_online = new VPN.VpnRpcSetHubOnline({
                        HubName_str: hub_name,
                        Online_bool: true
                    });
                    return [4 /*yield*/, api.SetHubOnline(in_rpc_set_hub_online)];
                case 1:
                    out_rpc_set_hub_online = _a.sent();
                    console.log(out_rpc_set_hub_online);
                    console.log("End: Test_SetHubOnline");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetHubStatus', Get hub status */
function Test_GetHubStatus() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_hub_status, out_rpc_hub_status;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetHubStatus");
                    in_rpc_hub_status = new VPN.VpnRpcHubStatus({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.GetHubStatus(in_rpc_hub_status)];
                case 1:
                    out_rpc_hub_status = _a.sent();
                    console.log(out_rpc_hub_status);
                    console.log("End: Test_GetHubStatus");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetHubLog', Set logging configuration into the hub */
function Test_SetHubLog(in_rpc_hub_log) {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_hub_log;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetHubLog");
                    return [4 /*yield*/, api.SetHubLog(in_rpc_hub_log)];
                case 1:
                    out_rpc_hub_log = _a.sent();
                    console.log(out_rpc_hub_log);
                    console.log("End: Test_SetHubLog");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetHubLog', Get logging configuration of the hub */
function Test_GetHubLog() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_hub_log, out_rpc_hub_log;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetHubLog");
                    in_rpc_hub_log = new VPN.VpnRpcHubLog({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.GetHubLog(in_rpc_hub_log)];
                case 1:
                    out_rpc_hub_log = _a.sent();
                    console.log(out_rpc_hub_log);
                    console.log("End: Test_GetHubLog");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/, out_rpc_hub_log];
            }
        });
    });
}
/** API test for 'AddCa', Add CA(Certificate Authority) into the hub */
function Test_AddCa() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_hub_add_ca, out_rpc_hub_add_ca;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_AddCa");
                    in_rpc_hub_add_ca = new VPN.VpnRpcHubAddCA({
                        HubName_str: hub_name,
                        Cert_bin: new Uint8Array([0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x43, 0x45, 0x52, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x49, 0x49, 0x44, 0x72, 0x6a, 0x43, 0x43, 0x41, 0x70, 0x61, 0x67, 0x41, 0x77, 0x49, 0x42, 0x41, 0x67, 0x49, 0x42, 0x41, 0x44, 0x41, 0x4e, 0x42, 0x67, 0x6b, 0x71, 0x68, 0x6b, 0x69, 0x47, 0x39, 0x77, 0x30, 0x42, 0x41, 0x51, 0x73, 0x46, 0x41, 0x44, 0x42, 0x57, 0x4d, 0x51, 0x77, 0x77, 0x43, 0x67, 0x59, 0x44, 0x56, 0x51, 0x51, 0x44, 0x44, 0x41, 0x4e, 0x68, 0x59, 0x57, 0x45, 0x78, 0x0a, 0x46, 0x54, 0x41, 0x54, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x6f, 0x4d, 0x44, 0x4f, 0x4f, 0x42, 0x72, 0x2b, 0x4f, 0x42, 0x71, 0x75, 0x4f, 0x42, 0x6a, 0x2b, 0x4f, 0x42, 0x6e, 0x54, 0x45, 0x4c, 0x4d, 0x41, 0x6b, 0x47, 0x41, 0x31, 0x55, 0x45, 0x42, 0x68, 0x4d, 0x43, 0x53, 0x6c, 0x41, 0x78, 0x45, 0x44, 0x41, 0x4f, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x67, 0x4d, 0x42, 0x30, 0x6c, 0x69, 0x0a, 0x59, 0x58, 0x4a, 0x68, 0x61, 0x32, 0x6b, 0x78, 0x45, 0x44, 0x41, 0x4f, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x63, 0x4d, 0x42, 0x31, 0x52, 0x7a, 0x64, 0x57, 0x74, 0x31, 0x59, 0x6d, 0x45, 0x77, 0x48, 0x68, 0x63, 0x4e, 0x4d, 0x54, 0x67, 0x78, 0x4d, 0x44, 0x45, 0x78, 0x4d, 0x6a, 0x4d, 0x7a, 0x4e, 0x54, 0x41, 0x78, 0x57, 0x68, 0x63, 0x4e, 0x4e, 0x44, 0x49, 0x78, 0x4d, 0x44, 0x41, 0x31, 0x0a, 0x4d, 0x6a, 0x4d, 0x7a, 0x4e, 0x54, 0x41, 0x78, 0x57, 0x6a, 0x42, 0x57, 0x4d, 0x51, 0x77, 0x77, 0x43, 0x67, 0x59, 0x44, 0x56, 0x51, 0x51, 0x44, 0x44, 0x41, 0x4e, 0x68, 0x59, 0x57, 0x45, 0x78, 0x46, 0x54, 0x41, 0x54, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x6f, 0x4d, 0x44, 0x4f, 0x4f, 0x42, 0x72, 0x2b, 0x4f, 0x42, 0x71, 0x75, 0x4f, 0x42, 0x6a, 0x2b, 0x4f, 0x42, 0x6e, 0x54, 0x45, 0x4c, 0x0a, 0x4d, 0x41, 0x6b, 0x47, 0x41, 0x31, 0x55, 0x45, 0x42, 0x68, 0x4d, 0x43, 0x53, 0x6c, 0x41, 0x78, 0x45, 0x44, 0x41, 0x4f, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x67, 0x4d, 0x42, 0x30, 0x6c, 0x69, 0x59, 0x58, 0x4a, 0x68, 0x61, 0x32, 0x6b, 0x78, 0x45, 0x44, 0x41, 0x4f, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x63, 0x4d, 0x42, 0x31, 0x52, 0x7a, 0x64, 0x57, 0x74, 0x31, 0x59, 0x6d, 0x45, 0x77, 0x0a, 0x67, 0x67, 0x45, 0x69, 0x4d, 0x41, 0x30, 0x47, 0x43, 0x53, 0x71, 0x47, 0x53, 0x49, 0x62, 0x33, 0x44, 0x51, 0x45, 0x42, 0x41, 0x51, 0x55, 0x41, 0x41, 0x34, 0x49, 0x42, 0x44, 0x77, 0x41, 0x77, 0x67, 0x67, 0x45, 0x4b, 0x41, 0x6f, 0x49, 0x42, 0x41, 0x51, 0x44, 0x58, 0x45, 0x63, 0x76, 0x72, 0x59, 0x37, 0x56, 0x2b, 0x7a, 0x64, 0x42, 0x79, 0x72, 0x64, 0x4e, 0x78, 0x4a, 0x59, 0x45, 0x6d, 0x0a, 0x61, 0x41, 0x4e, 0x59, 0x55, 0x4f, 0x37, 0x76, 0x57, 0x34, 0x68, 0x64, 0x41, 0x35, 0x49, 0x42, 0x49, 0x46, 0x6d, 0x4d, 0x70, 0x6e, 0x62, 0x79, 0x69, 0x4e, 0x6e, 0x5a, 0x77, 0x36, 0x57, 0x39, 0x6f, 0x61, 0x67, 0x78, 0x33, 0x5a, 0x49, 0x65, 0x65, 0x48, 0x56, 0x59, 0x62, 0x52, 0x69, 0x4b, 0x36, 0x41, 0x66, 0x46, 0x74, 0x53, 0x31, 0x32, 0x2b, 0x45, 0x31, 0x4d, 0x59, 0x31, 0x64, 0x32, 0x0a, 0x61, 0x71, 0x51, 0x31, 0x53, 0x72, 0x49, 0x43, 0x39, 0x51, 0x35, 0x55, 0x6e, 0x5a, 0x61, 0x42, 0x72, 0x62, 0x57, 0x32, 0x32, 0x6d, 0x4e, 0x75, 0x6c, 0x4d, 0x34, 0x2f, 0x6c, 0x49, 0x4a, 0x72, 0x48, 0x70, 0x51, 0x55, 0x68, 0x50, 0x78, 0x6f, 0x62, 0x79, 0x34, 0x2f, 0x36, 0x4e, 0x41, 0x37, 0x71, 0x4b, 0x67, 0x55, 0x48, 0x69, 0x79, 0x4f, 0x64, 0x33, 0x4a, 0x42, 0x70, 0x4f, 0x66, 0x77, 0x0a, 0x38, 0x54, 0x76, 0x53, 0x74, 0x51, 0x78, 0x34, 0x4c, 0x38, 0x59, 0x64, 0x4b, 0x51, 0x35, 0x68, 0x74, 0x7a, 0x6b, 0x32, 0x68, 0x70, 0x52, 0x4a, 0x4c, 0x30, 0x6c, 0x4b, 0x67, 0x47, 0x31, 0x57, 0x34, 0x75, 0x4b, 0x32, 0x39, 0x39, 0x42, 0x74, 0x7a, 0x64, 0x41, 0x67, 0x66, 0x42, 0x76, 0x43, 0x54, 0x33, 0x41, 0x31, 0x61, 0x53, 0x70, 0x6a, 0x49, 0x47, 0x74, 0x6e, 0x69, 0x72, 0x49, 0x31, 0x0a, 0x46, 0x4c, 0x52, 0x58, 0x47, 0x79, 0x38, 0x31, 0x31, 0x57, 0x4a, 0x39, 0x4a, 0x68, 0x68, 0x34, 0x41, 0x4b, 0x4c, 0x66, 0x79, 0x56, 0x70, 0x42, 0x4a, 0x67, 0x65, 0x34, 0x73, 0x56, 0x72, 0x36, 0x4e, 0x75, 0x75, 0x49, 0x66, 0x32, 0x71, 0x47, 0x31, 0x6f, 0x79, 0x31, 0x30, 0x70, 0x61, 0x51, 0x4e, 0x65, 0x71, 0x32, 0x33, 0x55, 0x47, 0x61, 0x59, 0x74, 0x2f, 0x7a, 0x55, 0x56, 0x4a, 0x77, 0x0a, 0x55, 0x74, 0x30, 0x57, 0x45, 0x6b, 0x58, 0x38, 0x48, 0x4f, 0x63, 0x62, 0x33, 0x75, 0x49, 0x6f, 0x54, 0x6d, 0x61, 0x4f, 0x34, 0x72, 0x48, 0x42, 0x55, 0x4a, 0x71, 0x45, 0x79, 0x39, 0x51, 0x58, 0x7a, 0x53, 0x57, 0x77, 0x43, 0x35, 0x78, 0x45, 0x43, 0x64, 0x37, 0x43, 0x4a, 0x53, 0x53, 0x68, 0x31, 0x30, 0x4f, 0x75, 0x6e, 0x6c, 0x75, 0x4c, 0x32, 0x4d, 0x47, 0x65, 0x5a, 0x47, 0x6e, 0x76, 0x0a, 0x41, 0x67, 0x4d, 0x42, 0x41, 0x41, 0x47, 0x6a, 0x67, 0x59, 0x59, 0x77, 0x67, 0x59, 0x4d, 0x77, 0x44, 0x77, 0x59, 0x44, 0x56, 0x52, 0x30, 0x54, 0x41, 0x51, 0x48, 0x2f, 0x42, 0x41, 0x55, 0x77, 0x41, 0x77, 0x45, 0x42, 0x2f, 0x7a, 0x41, 0x4c, 0x42, 0x67, 0x4e, 0x56, 0x48, 0x51, 0x38, 0x45, 0x42, 0x41, 0x4d, 0x43, 0x41, 0x66, 0x59, 0x77, 0x59, 0x77, 0x59, 0x44, 0x56, 0x52, 0x30, 0x6c, 0x0a, 0x42, 0x46, 0x77, 0x77, 0x57, 0x67, 0x59, 0x49, 0x4b, 0x77, 0x59, 0x42, 0x42, 0x51, 0x55, 0x48, 0x41, 0x77, 0x45, 0x47, 0x43, 0x43, 0x73, 0x47, 0x41, 0x51, 0x55, 0x46, 0x42, 0x77, 0x4d, 0x43, 0x42, 0x67, 0x67, 0x72, 0x42, 0x67, 0x45, 0x46, 0x42, 0x51, 0x63, 0x44, 0x41, 0x77, 0x59, 0x49, 0x4b, 0x77, 0x59, 0x42, 0x42, 0x51, 0x55, 0x48, 0x41, 0x77, 0x51, 0x47, 0x43, 0x43, 0x73, 0x47, 0x0a, 0x41, 0x51, 0x55, 0x46, 0x42, 0x77, 0x4d, 0x46, 0x42, 0x67, 0x67, 0x72, 0x42, 0x67, 0x45, 0x46, 0x42, 0x51, 0x63, 0x44, 0x42, 0x67, 0x59, 0x49, 0x4b, 0x77, 0x59, 0x42, 0x42, 0x51, 0x55, 0x48, 0x41, 0x77, 0x63, 0x47, 0x43, 0x43, 0x73, 0x47, 0x41, 0x51, 0x55, 0x46, 0x42, 0x77, 0x4d, 0x49, 0x42, 0x67, 0x67, 0x72, 0x42, 0x67, 0x45, 0x46, 0x42, 0x51, 0x63, 0x44, 0x43, 0x54, 0x41, 0x4e, 0x0a, 0x42, 0x67, 0x6b, 0x71, 0x68, 0x6b, 0x69, 0x47, 0x39, 0x77, 0x30, 0x42, 0x41, 0x51, 0x73, 0x46, 0x41, 0x41, 0x4f, 0x43, 0x41, 0x51, 0x45, 0x41, 0x46, 0x6d, 0x34, 0x37, 0x47, 0x55, 0x70, 0x50, 0x57, 0x35, 0x2b, 0x37, 0x69, 0x46, 0x74, 0x69, 0x6c, 0x6f, 0x6b, 0x35, 0x32, 0x49, 0x6f, 0x54, 0x57, 0x72, 0x74, 0x46, 0x67, 0x32, 0x79, 0x69, 0x36, 0x6b, 0x49, 0x32, 0x69, 0x52, 0x4e, 0x51, 0x0a, 0x4b, 0x75, 0x67, 0x48, 0x55, 0x49, 0x4f, 0x34, 0x4b, 0x53, 0x71, 0x4a, 0x56, 0x42, 0x50, 0x38, 0x61, 0x4b, 0x4f, 0x61, 0x54, 0x5a, 0x47, 0x45, 0x31, 0x4b, 0x4d, 0x68, 0x2f, 0x59, 0x6a, 0x68, 0x36, 0x71, 0x2f, 0x67, 0x50, 0x61, 0x6c, 0x67, 0x64, 0x2f, 0x38, 0x44, 0x6d, 0x72, 0x78, 0x53, 0x4a, 0x6d, 0x55, 0x78, 0x33, 0x62, 0x4e, 0x62, 0x38, 0x52, 0x59, 0x36, 0x70, 0x4b, 0x7a, 0x74, 0x0a, 0x5a, 0x64, 0x75, 0x53, 0x61, 0x53, 0x2b, 0x57, 0x55, 0x30, 0x59, 0x74, 0x2b, 0x6c, 0x47, 0x35, 0x76, 0x56, 0x67, 0x61, 0x70, 0x48, 0x45, 0x71, 0x36, 0x79, 0x71, 0x4c, 0x62, 0x65, 0x56, 0x78, 0x51, 0x4c, 0x75, 0x62, 0x54, 0x69, 0x6e, 0x4f, 0x66, 0x56, 0x56, 0x5a, 0x58, 0x79, 0x45, 0x43, 0x59, 0x47, 0x4d, 0x73, 0x59, 0x71, 0x65, 0x6e, 0x4a, 0x6a, 0x4e, 0x63, 0x62, 0x49, 0x5a, 0x4e, 0x0a, 0x79, 0x4d, 0x75, 0x72, 0x46, 0x63, 0x67, 0x30, 0x34, 0x36, 0x4f, 0x34, 0x59, 0x79, 0x68, 0x56, 0x79, 0x71, 0x53, 0x69, 0x74, 0x43, 0x59, 0x37, 0x68, 0x2f, 0x65, 0x71, 0x67, 0x6b, 0x50, 0x4a, 0x51, 0x30, 0x68, 0x6b, 0x70, 0x39, 0x45, 0x64, 0x51, 0x77, 0x62, 0x6e, 0x38, 0x56, 0x6c, 0x66, 0x78, 0x64, 0x42, 0x58, 0x77, 0x51, 0x34, 0x4e, 0x48, 0x4b, 0x30, 0x4a, 0x56, 0x46, 0x2f, 0x33, 0x0a, 0x71, 0x48, 0x61, 0x68, 0x4e, 0x48, 0x4f, 0x35, 0x64, 0x62, 0x4a, 0x5a, 0x57, 0x59, 0x41, 0x62, 0x42, 0x44, 0x70, 0x32, 0x51, 0x45, 0x53, 0x70, 0x76, 0x6f, 0x2b, 0x38, 0x33, 0x6c, 0x68, 0x34, 0x64, 0x6e, 0x58, 0x6a, 0x46, 0x58, 0x4d, 0x43, 0x48, 0x76, 0x52, 0x68, 0x35, 0x31, 0x79, 0x2f, 0x54, 0x71, 0x79, 0x42, 0x34, 0x56, 0x76, 0x72, 0x52, 0x4b, 0x49, 0x4b, 0x74, 0x54, 0x6f, 0x7a, 0x0a, 0x5a, 0x6a, 0x48, 0x59, 0x49, 0x63, 0x62, 0x6a, 0x76, 0x53, 0x58, 0x4d, 0x7a, 0x61, 0x44, 0x50, 0x6a, 0x50, 0x63, 0x5a, 0x47, 0x6a, 0x42, 0x4a, 0x6c, 0x47, 0x36, 0x43, 0x76, 0x44, 0x34, 0x4c, 0x6d, 0x59, 0x7a, 0x72, 0x6b, 0x48, 0x34, 0x31, 0x63, 0x7a, 0x72, 0x34, 0x57, 0x41, 0x3d, 0x3d, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x43, 0x45, 0x52, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a,])
                    });
                    return [4 /*yield*/, api.AddCa(in_rpc_hub_add_ca)];
                case 1:
                    out_rpc_hub_add_ca = _a.sent();
                    console.log(out_rpc_hub_add_ca);
                    console.log("End: Test_AddCa");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumCa', Enumerate CA(Certificate Authority) in the hub */
function Test_EnumCa() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_hub_enum_ca, out_rpc_hub_enum_ca;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumCa");
                    in_rpc_hub_enum_ca = new VPN.VpnRpcHubEnumCA({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.EnumCa(in_rpc_hub_enum_ca)];
                case 1:
                    out_rpc_hub_enum_ca = _a.sent();
                    console.log(out_rpc_hub_enum_ca);
                    console.log("End: Test_EnumCa");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/, out_rpc_hub_enum_ca];
            }
        });
    });
}
/** API test for 'GetCa', Get CA(Certificate Authority) setting from the hub */
function Test_GetCa(key) {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_hub_get_ca, out_rpc_hub_get_ca;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetCa");
                    in_rpc_hub_get_ca = new VPN.VpnRpcHubGetCA({
                        HubName_str: hub_name,
                        Key_u32: key
                    });
                    return [4 /*yield*/, api.GetCa(in_rpc_hub_get_ca)];
                case 1:
                    out_rpc_hub_get_ca = _a.sent();
                    console.log(out_rpc_hub_get_ca);
                    console.log("End: Test_GetCa");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'DeleteCa', Delete a CA(Certificate Authority) setting from the hub */
function Test_DeleteCa(key) {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_hub_delete_ca, out_rpc_hub_delete_ca;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_DeleteCa");
                    in_rpc_hub_delete_ca = new VPN.VpnRpcHubDeleteCA({
                        HubName_str: hub_name,
                        Key_u32: key
                    });
                    return [4 /*yield*/, api.DeleteCa(in_rpc_hub_delete_ca)];
                case 1:
                    out_rpc_hub_delete_ca = _a.sent();
                    console.log(out_rpc_hub_delete_ca);
                    console.log("End: Test_DeleteCa");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetLinkOnline', Make a link into on-line */
function Test_SetLinkOnline() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_link, out_rpc_link;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetLinkOnline");
                    in_rpc_link = new VPN.VpnRpcLink({
                        HubName_str: hub_name,
                        AccountName_utf: "linktest"
                    });
                    return [4 /*yield*/, api.SetLinkOnline(in_rpc_link)];
                case 1:
                    out_rpc_link = _a.sent();
                    console.log(out_rpc_link);
                    console.log("End: Test_SetLinkOnline");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetLinkOffline', Make a link into off-line */
function Test_SetLinkOffline() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_link, out_rpc_link;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetLinkOffline");
                    in_rpc_link = new VPN.VpnRpcLink({
                        HubName_str: hub_name,
                        AccountName_utf: "linktest"
                    });
                    return [4 /*yield*/, api.SetLinkOffline(in_rpc_link)];
                case 1:
                    out_rpc_link = _a.sent();
                    console.log(out_rpc_link);
                    console.log("End: Test_SetLinkOffline");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'DeleteLink', Delete a link */
function Test_DeleteLink() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_link, out_rpc_link;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_DeleteLink");
                    in_rpc_link = new VPN.VpnRpcLink({
                        HubName_str: hub_name,
                        AccountName_utf: "linktest2"
                    });
                    return [4 /*yield*/, api.DeleteLink(in_rpc_link)];
                case 1:
                    out_rpc_link = _a.sent();
                    console.log(out_rpc_link);
                    console.log("End: Test_DeleteLink");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'RenameLink', Rename link (cascade connection) */
function Test_RenameLink() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_rename_link, out_rpc_rename_link;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_RenameLink");
                    in_rpc_rename_link = new VPN.VpnRpcRenameLink({
                        HubName_str: hub_name,
                        OldAccountName_utf: "linktest",
                        NewAccountName_utf: "linktest2"
                    });
                    return [4 /*yield*/, api.RenameLink(in_rpc_rename_link)];
                case 1:
                    out_rpc_rename_link = _a.sent();
                    console.log(out_rpc_rename_link);
                    console.log("End: Test_RenameLink");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'CreateLink', Create a new link(cascade) */
function Test_CreateLink() {
    return __awaiter(this, void 0, void 0, function () {
        var _a, in_rpc_create_link, out_rpc_create_link;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    console.log("Begin: Test_CreateLink");
                    in_rpc_create_link = new VPN.VpnRpcCreateLink((_a = {
                            HubName_Ex_str: hub_name,
                            CheckServerCert_bool: false,
                            AccountName_utf: "linktest",
                            Hostname_str: "1.2.3.4",
                            Port_u32: 443,
                            ProxyType_u32: 0,
                            HubName_str: "ABC",
                            MaxConnection_u32: 16,
                            UseEncrypt_bool: true,
                            UseCompress_bool: false,
                            HalfConnection_bool: true,
                            AdditionalConnectionInterval_u32: 2,
                            ConnectionDisconnectSpan_u32: 24,
                            AuthType_u32: VPN.VpnRpcClientAuthType.PlainPassword,
                            Username_str: "181012",
                            PlainPassword_str: "microsoft",
                            HashedPassword_bin: new Uint8Array([]),
                            ClientX_bin: new Uint8Array([]),
                            ClientK_bin: new Uint8Array([])
                        },
                        _a["policy:DHCPFilter_bool"] = true,
                        _a["policy:DHCPNoServer_bool"] = true,
                        _a["policy:DHCPForce_bool"] = true,
                        _a.SecPol_CheckMac_bool = true,
                        _a.SecPol_CheckIP_bool = true,
                        _a["policy:ArpDhcpOnly_bool"] = true,
                        _a["policy:PrivacyFilter_bool"] = true,
                        _a["policy:NoServer_bool"] = true,
                        _a["policy:NoBroadcastLimiter_bool"] = true,
                        _a["policy:MaxMac_u32"] = 32,
                        _a["policy:MaxIP_u32"] = 64,
                        _a["policy:MaxUpload_u32"] = 960000,
                        _a["policy:MaxDownload_u32"] = 1280000,
                        _a["policy:RSandRAFilter_bool"] = true,
                        _a.SecPol_RAFilter_bool = true,
                        _a["policy:DHCPv6Filter_bool"] = true,
                        _a["policy:DHCPv6NoServer_bool"] = true,
                        _a.SecPol_CheckIPv6_bool = true,
                        _a["policy:NoServerV6_bool"] = true,
                        _a["policy:MaxIPv6_u32"] = 127,
                        _a["policy:FilterIPv4_bool"] = true,
                        _a["policy:FilterIPv6_bool"] = true,
                        _a["policy:FilterNonIP_bool"] = true,
                        _a["policy:NoIPv6DefaultRouterInRA_bool"] = true,
                        _a["policy:VLanId_u32"] = 123,
                        _a["policy:Ver3_bool"] = true,
                        _a));
                    return [4 /*yield*/, api.CreateLink(in_rpc_create_link)];
                case 1:
                    out_rpc_create_link = _b.sent();
                    console.log(out_rpc_create_link);
                    console.log("End: Test_CreateLink");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetLink', Get link configuration */
function Test_GetLink() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_create_link, out_rpc_create_link;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetLink");
                    in_rpc_create_link = new VPN.VpnRpcCreateLink({
                        HubName_Ex_str: hub_name,
                        AccountName_utf: "linktest"
                    });
                    return [4 /*yield*/, api.GetLink(in_rpc_create_link)];
                case 1:
                    out_rpc_create_link = _a.sent();
                    console.log(out_rpc_create_link);
                    console.log("End: Test_GetLink");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetLink', Set link configuration */
function Test_SetLink() {
    return __awaiter(this, void 0, void 0, function () {
        var _a, in_rpc_create_link, out_rpc_create_link;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    console.log("Begin: Test_SetLink");
                    in_rpc_create_link = new VPN.VpnRpcCreateLink((_a = {
                            HubName_Ex_str: hub_name,
                            CheckServerCert_bool: false,
                            AccountName_utf: "linktest",
                            Hostname_str: "1.2.3.4",
                            Port_u32: 443,
                            ProxyType_u32: 0,
                            HubName_str: "ABC",
                            MaxConnection_u32: 16,
                            UseEncrypt_bool: true,
                            UseCompress_bool: false,
                            HalfConnection_bool: true,
                            AdditionalConnectionInterval_u32: 2,
                            ConnectionDisconnectSpan_u32: 24,
                            AuthType_u32: VPN.VpnRpcClientAuthType.PlainPassword,
                            Username_str: "181012",
                            PlainPassword_str: "microsoft",
                            HashedPassword_bin: new Uint8Array([]),
                            ClientX_bin: new Uint8Array([]),
                            ClientK_bin: new Uint8Array([])
                        },
                        _a["policy:DHCPFilter_bool"] = true,
                        _a["policy:DHCPNoServer_bool"] = true,
                        _a["policy:DHCPForce_bool"] = true,
                        _a.SecPol_CheckMac_bool = true,
                        _a.SecPol_CheckIP_bool = true,
                        _a["policy:ArpDhcpOnly_bool"] = true,
                        _a["policy:PrivacyFilter_bool"] = true,
                        _a["policy:NoServer_bool"] = true,
                        _a["policy:NoBroadcastLimiter_bool"] = true,
                        _a["policy:MaxMac_u32"] = 32,
                        _a["policy:MaxIP_u32"] = 64,
                        _a["policy:MaxUpload_u32"] = 960000,
                        _a["policy:MaxDownload_u32"] = 1280000,
                        _a["policy:RSandRAFilter_bool"] = true,
                        _a.SecPol_RAFilter_bool = true,
                        _a["policy:DHCPv6Filter_bool"] = true,
                        _a["policy:DHCPv6NoServer_bool"] = true,
                        _a.SecPol_CheckIPv6_bool = true,
                        _a["policy:NoServerV6_bool"] = true,
                        _a["policy:MaxIPv6_u32"] = 127,
                        _a["policy:FilterIPv4_bool"] = true,
                        _a["policy:FilterIPv6_bool"] = true,
                        _a["policy:FilterNonIP_bool"] = true,
                        _a["policy:NoIPv6DefaultRouterInRA_bool"] = true,
                        _a["policy:VLanId_u32"] = 123,
                        _a["policy:Ver3_bool"] = true,
                        _a));
                    return [4 /*yield*/, api.SetLink(in_rpc_create_link)];
                case 1:
                    out_rpc_create_link = _b.sent();
                    console.log(out_rpc_create_link);
                    console.log("End: Test_SetLink");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumLink', Enumerate links */
function Test_EnumLink() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_enum_link, out_rpc_enum_link;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumLink");
                    in_rpc_enum_link = new VPN.VpnRpcEnumLink({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.EnumLink(in_rpc_enum_link)];
                case 1:
                    out_rpc_enum_link = _a.sent();
                    console.log(out_rpc_enum_link);
                    console.log("End: Test_EnumLink");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/, out_rpc_enum_link];
            }
        });
    });
}
/** API test for 'GetLinkStatus', Get link status */
function Test_GetLinkStatus(name) {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_link_status, out_rpc_link_status;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetLinkStatus");
                    in_rpc_link_status = new VPN.VpnRpcLinkStatus({
                        HubName_Ex_str: hub_name,
                        AccountName_utf: name
                    });
                    return [4 /*yield*/, api.GetLinkStatus(in_rpc_link_status)];
                case 1:
                    out_rpc_link_status = _a.sent();
                    console.log(out_rpc_link_status);
                    console.log("End: Test_GetLinkStatus");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'AddAccess', Add access list entry */
function Test_AddAccess() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_add_access_ipv4, out_rpc_add_access_ipv4, in_rpc_add_access_ipv6, out_rpc_add_access_ipv6;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_AddAccess");
                    in_rpc_add_access_ipv4 = new VPN.VpnRpcAddAccess({
                        HubName_str: hub_name,
                        AccessListSingle: [new VPN.VpnAccess({
                                Note_utf: "IPv4 Test",
                                Active_bool: true,
                                Priority_u32: 100,
                                Discard_bool: true,
                                IsIPv6_bool: false,
                                SrcIpAddress_ip: "192.168.0.0",
                                SrcSubnetMask_ip: "255.255.255.0",
                                DestIpAddress_ip: "10.0.0.0",
                                DestSubnetMask_ip: "255.255.0.0",
                                Protocol_u32: VPN.VpnIpProtocolNumber.TCP,
                                SrcPortStart_u32: 123,
                                SrcPortEnd_u32: 456,
                                DestPortStart_u32: 555,
                                DestPortEnd_u32: 666,
                                SrcUsername_str: "dnobori",
                                DestUsername_str: "nekosan",
                                CheckSrcMac_bool: true,
                                SrcMacAddress_bin: new Uint8Array([1, 2, 3, 0, 0, 0,]),
                                SrcMacMask_bin: new Uint8Array([255, 255, 255, 0, 0, 0,]),
                                CheckTcpState_bool: true,
                                Established_bool: true,
                                Delay_u32: 10,
                                Jitter_u32: 20,
                                Loss_u32: 30,
                                RedirectUrl_str: "aho"
                            }),]
                    });
                    return [4 /*yield*/, api.AddAccess(in_rpc_add_access_ipv4)];
                case 1:
                    out_rpc_add_access_ipv4 = _a.sent();
                    in_rpc_add_access_ipv6 = new VPN.VpnRpcAddAccess({
                        HubName_str: hub_name,
                        AccessListSingle: [new VPN.VpnAccess({
                                Note_utf: "IPv6 Test",
                                Active_bool: true,
                                Priority_u32: 100,
                                Discard_bool: true,
                                IsIPv6_bool: true,
                                SrcIpAddress6_bin: new Uint8Array([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]),
                                SrcSubnetMask6_bin: new Uint8Array([0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]),
                                Protocol_u32: VPN.VpnIpProtocolNumber.UDP,
                                SrcPortStart_u32: 123,
                                SrcPortEnd_u32: 456,
                                DestPortStart_u32: 555,
                                DestPortEnd_u32: 666,
                                SrcUsername_str: "dnobori",
                                DestUsername_str: "nekosan",
                                CheckSrcMac_bool: true,
                                SrcMacAddress_bin: new Uint8Array([1, 2, 3, 0, 0, 0,]),
                                SrcMacMask_bin: new Uint8Array([255, 255, 255, 0, 0, 0,]),
                                CheckTcpState_bool: true,
                                Established_bool: true,
                                Delay_u32: 10,
                                Jitter_u32: 20,
                                Loss_u32: 30,
                                RedirectUrl_str: "aho"
                            }),]
                    });
                    return [4 /*yield*/, api.AddAccess(in_rpc_add_access_ipv6)];
                case 2:
                    out_rpc_add_access_ipv6 = _a.sent();
                    console.log("End: Test_AddAccess");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'DeleteAccess', Delete access list entry */
function Test_DeleteAccess() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_delete_access, out_rpc_delete_access;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_DeleteAccess");
                    in_rpc_delete_access = new VPN.VpnRpcDeleteAccess({
                        HubName_str: hub_name,
                        Id_u32: 1
                    });
                    return [4 /*yield*/, api.DeleteAccess(in_rpc_delete_access)];
                case 1:
                    out_rpc_delete_access = _a.sent();
                    console.log(out_rpc_delete_access);
                    console.log("End: Test_DeleteAccess");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumAccess', Get access list */
function Test_EnumAccess() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_enum_access_list, out_rpc_enum_access_list;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumAccess");
                    in_rpc_enum_access_list = new VPN.VpnRpcEnumAccessList({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.EnumAccess(in_rpc_enum_access_list)];
                case 1:
                    out_rpc_enum_access_list = _a.sent();
                    console.log(out_rpc_enum_access_list);
                    console.log("End: Test_EnumAccess");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetAccessList', Set access list */
function Test_SetAccessList() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_enum_access_list, out_rpc_enum_access_list;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetAccessList");
                    in_rpc_enum_access_list = new VPN.VpnRpcEnumAccessList({
                        HubName_str: hub_name,
                        AccessList: [new VPN.VpnAccess({
                                Note_utf: "IPv4 Test 2",
                                Active_bool: true,
                                Priority_u32: 100,
                                Discard_bool: true,
                                IsIPv6_bool: false,
                                SrcIpAddress_ip: "192.168.0.0",
                                SrcSubnetMask_ip: "255.255.255.0",
                                DestIpAddress_ip: "10.0.0.0",
                                DestSubnetMask_ip: "255.255.0.0",
                                Protocol_u32: VPN.VpnIpProtocolNumber.TCP,
                                SrcPortStart_u32: 123,
                                SrcPortEnd_u32: 456,
                                DestPortStart_u32: 555,
                                DestPortEnd_u32: 666,
                                SrcUsername_str: "dnobori",
                                DestUsername_str: "nekosan",
                                CheckSrcMac_bool: true,
                                SrcMacAddress_bin: new Uint8Array([1, 2, 3, 0, 0, 0,]),
                                SrcMacMask_bin: new Uint8Array([255, 255, 255, 0, 0, 0,]),
                                CheckTcpState_bool: true,
                                Established_bool: true,
                                Delay_u32: 10,
                                Jitter_u32: 20,
                                Loss_u32: 30,
                                RedirectUrl_str: "aho"
                            }), new VPN.VpnAccess({
                                Note_utf: "IPv6 Test 2",
                                Active_bool: true,
                                Priority_u32: 100,
                                Discard_bool: true,
                                IsIPv6_bool: true,
                                SrcIpAddress6_bin: new Uint8Array([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]),
                                SrcSubnetMask6_bin: new Uint8Array([0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]),
                                Protocol_u32: VPN.VpnIpProtocolNumber.UDP,
                                SrcPortStart_u32: 123,
                                SrcPortEnd_u32: 456,
                                DestPortStart_u32: 555,
                                DestPortEnd_u32: 666,
                                SrcUsername_str: "dnobori",
                                DestUsername_str: "nekosan",
                                CheckSrcMac_bool: true,
                                SrcMacAddress_bin: new Uint8Array([1, 2, 3, 0, 0, 0,]),
                                SrcMacMask_bin: new Uint8Array([255, 255, 255, 0, 0, 0,]),
                                CheckTcpState_bool: true,
                                Established_bool: true,
                                Delay_u32: 10,
                                Jitter_u32: 20,
                                Loss_u32: 30,
                                RedirectUrl_str: "aho"
                            }),]
                    });
                    return [4 /*yield*/, api.SetAccessList(in_rpc_enum_access_list)];
                case 1:
                    out_rpc_enum_access_list = _a.sent();
                    console.log(out_rpc_enum_access_list);
                    console.log("End: Test_SetAccessList");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'CreateUser', Create a user */
function Test_CreateUser() {
    return __awaiter(this, void 0, void 0, function () {
        var _a, in_rpc_set_user, out_rpc_set_user;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    console.log("Begin: Test_CreateUser");
                    in_rpc_set_user = new VPN.VpnRpcSetUser((_a = {
                            HubName_str: hub_name,
                            Name_str: "test1",
                            Realname_utf: "Cat man",
                            Note_utf: "Hey!!!",
                            AuthType_u32: VPN.VpnRpcUserAuthType.Password,
                            Auth_Password_str: "microsoft",
                            UserX_bin: new Uint8Array([]),
                            Serial_bin: new Uint8Array([]),
                            CommonName_utf: "",
                            RadiusUsername_utf: "",
                            NtUsername_utf: "",
                            ExpireTime_dt: new Date(2019, 1, 1),
                            UsePolicy_bool: true
                        },
                        _a["policy:Access_bool"] = true,
                        _a["policy:DHCPFilter_bool"] = false,
                        _a["policy:DHCPNoServer_bool"] = true,
                        _a["policy:DHCPForce_bool"] = false,
                        _a["policy:NoBridge_bool"] = false,
                        _a["policy:NoRouting_bool"] = false,
                        _a["policy:CheckMac_bool"] = false,
                        _a["policy:CheckIP_bool"] = false,
                        _a["policy:ArpDhcpOnly_bool"] = false,
                        _a["policy:PrivacyFilter_bool"] = false,
                        _a["policy:NoServer_bool"] = false,
                        _a["policy:NoBroadcastLimiter_bool"] = false,
                        _a["policy:MonitorPort_bool"] = false,
                        _a["policy:MaxConnection_u32"] = 32,
                        _a["policy:TimeOut_u32"] = 15,
                        _a["policy:MaxMac_u32"] = 1000,
                        _a["policy:MaxIP_u32"] = 1000,
                        _a["policy:MaxUpload_u32"] = 1000000000,
                        _a["policy:MaxDownload_u32"] = 1000000000,
                        _a["policy:FixPassword_bool"] = false,
                        _a["policy:MultiLogins_u32"] = 1000,
                        _a["policy:NoQoS_bool"] = false,
                        _a["policy:RSandRAFilter_bool"] = false,
                        _a["policy:RAFilter_bool"] = false,
                        _a["policy:DHCPv6Filter_bool"] = false,
                        _a["policy:DHCPv6NoServer_bool"] = false,
                        _a["policy:NoRoutingV6_bool"] = false,
                        _a["policy:CheckIPv6_bool"] = false,
                        _a["policy:NoServerV6_bool"] = false,
                        _a["policy:MaxIPv6_u32"] = 1234,
                        _a["policy:NoSavePassword_bool"] = false,
                        _a["policy:AutoDisconnect_u32"] = 0,
                        _a["policy:FilterIPv4_bool"] = false,
                        _a["policy:FilterIPv6_bool"] = false,
                        _a["policy:FilterNonIP_bool"] = false,
                        _a["policy:NoIPv6DefaultRouterInRA_bool"] = false,
                        _a["policy:NoIPv6DefaultRouterInRAWhenIPv6_bool"] = false,
                        _a["policy:VLanId_u32"] = 0,
                        _a["policy:Ver3_bool"] = true,
                        _a));
                    return [4 /*yield*/, api.CreateUser(in_rpc_set_user)];
                case 1:
                    out_rpc_set_user = _b.sent();
                    console.log("End: Test_CreateUser");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetUser', Set user setting */
function Test_SetUser() {
    return __awaiter(this, void 0, void 0, function () {
        var _a, in_rpc_set_user, out_rpc_set_user;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    console.log("Begin: Test_SetUser");
                    in_rpc_set_user = new VPN.VpnRpcSetUser((_a = {
                            HubName_str: hub_name,
                            Name_str: "test1",
                            Realname_utf: "Cat man",
                            Note_utf: "Hey!!!",
                            GroupName_str: "group1",
                            AuthType_u32: VPN.VpnRpcUserAuthType.Anonymous,
                            Auth_Password_str: "",
                            UserX_bin: new Uint8Array([]),
                            Serial_bin: new Uint8Array([]),
                            CommonName_utf: "",
                            RadiusUsername_utf: "",
                            NtUsername_utf: "",
                            ExpireTime_dt: new Date(2019, 1, 1),
                            UsePolicy_bool: true
                        },
                        _a["policy:Access_bool"] = true,
                        _a["policy:DHCPFilter_bool"] = false,
                        _a["policy:DHCPNoServer_bool"] = true,
                        _a["policy:DHCPForce_bool"] = false,
                        _a["policy:NoBridge_bool"] = false,
                        _a["policy:NoRouting_bool"] = false,
                        _a["policy:CheckMac_bool"] = false,
                        _a["policy:CheckIP_bool"] = false,
                        _a["policy:ArpDhcpOnly_bool"] = false,
                        _a["policy:PrivacyFilter_bool"] = false,
                        _a["policy:NoServer_bool"] = false,
                        _a["policy:NoBroadcastLimiter_bool"] = false,
                        _a["policy:MonitorPort_bool"] = false,
                        _a["policy:MaxConnection_u32"] = 32,
                        _a["policy:TimeOut_u32"] = 15,
                        _a["policy:MaxMac_u32"] = 1000,
                        _a["policy:MaxIP_u32"] = 1000,
                        _a["policy:MaxUpload_u32"] = 1000000000,
                        _a["policy:MaxDownload_u32"] = 1000000000,
                        _a["policy:FixPassword_bool"] = false,
                        _a["policy:MultiLogins_u32"] = 1000,
                        _a["policy:NoQoS_bool"] = false,
                        _a["policy:RSandRAFilter_bool"] = false,
                        _a["policy:RAFilter_bool"] = false,
                        _a["policy:DHCPv6Filter_bool"] = false,
                        _a["policy:DHCPv6NoServer_bool"] = false,
                        _a["policy:NoRoutingV6_bool"] = false,
                        _a["policy:CheckIPv6_bool"] = false,
                        _a["policy:NoServerV6_bool"] = false,
                        _a["policy:MaxIPv6_u32"] = 1234,
                        _a["policy:NoSavePassword_bool"] = false,
                        _a["policy:AutoDisconnect_u32"] = 0,
                        _a["policy:FilterIPv4_bool"] = false,
                        _a["policy:FilterIPv6_bool"] = false,
                        _a["policy:FilterNonIP_bool"] = false,
                        _a["policy:NoIPv6DefaultRouterInRA_bool"] = false,
                        _a["policy:NoIPv6DefaultRouterInRAWhenIPv6_bool"] = false,
                        _a["policy:VLanId_u32"] = 0,
                        _a["policy:Ver3_bool"] = true,
                        _a));
                    return [4 /*yield*/, api.SetUser(in_rpc_set_user)];
                case 1:
                    out_rpc_set_user = _b.sent();
                    console.log("End: Test_SetUser");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetUser', Get user setting */
function Test_GetUser() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_set_user, out_rpc_set_user;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetUser");
                    in_rpc_set_user = new VPN.VpnRpcSetUser({
                        HubName_str: hub_name,
                        Name_str: "test1"
                    });
                    return [4 /*yield*/, api.GetUser(in_rpc_set_user)];
                case 1:
                    out_rpc_set_user = _a.sent();
                    console.log(out_rpc_set_user);
                    console.log("End: Test_GetUser");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'DeleteUser', Delete a user */
function Test_DeleteUser() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_delete_user, out_rpc_delete_user;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_DeleteUser");
                    in_rpc_delete_user = new VPN.VpnRpcDeleteUser({
                        HubName_str: hub_name,
                        Name_str: "test1"
                    });
                    return [4 /*yield*/, api.DeleteUser(in_rpc_delete_user)];
                case 1:
                    out_rpc_delete_user = _a.sent();
                    console.log("End: Test_DeleteUser");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumUser', Enumerate users */
function Test_EnumUser() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_enum_user, out_rpc_enum_user;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumUser");
                    in_rpc_enum_user = new VPN.VpnRpcEnumUser({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.EnumUser(in_rpc_enum_user)];
                case 1:
                    out_rpc_enum_user = _a.sent();
                    console.log(out_rpc_enum_user);
                    console.log("End: Test_EnumUser");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'CreateGroup', Create a group */
function Test_CreateGroup() {
    return __awaiter(this, void 0, void 0, function () {
        var _a, in_rpc_set_group, out_rpc_set_group;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    console.log("Begin: Test_CreateGroup");
                    in_rpc_set_group = new VPN.VpnRpcSetGroup((_a = {
                            HubName_str: hub_name,
                            Name_str: "group1",
                            Realname_utf: "Cat group",
                            Note_utf: "This is it! This is it!!",
                            UsePolicy_bool: true
                        },
                        _a["policy:Access_bool"] = true,
                        _a["policy:DHCPFilter_bool"] = false,
                        _a["policy:DHCPNoServer_bool"] = true,
                        _a["policy:DHCPForce_bool"] = false,
                        _a["policy:NoBridge_bool"] = false,
                        _a["policy:NoRouting_bool"] = false,
                        _a["policy:CheckMac_bool"] = false,
                        _a["policy:CheckIP_bool"] = false,
                        _a["policy:ArpDhcpOnly_bool"] = false,
                        _a["policy:PrivacyFilter_bool"] = false,
                        _a["policy:NoServer_bool"] = false,
                        _a["policy:NoBroadcastLimiter_bool"] = false,
                        _a["policy:MonitorPort_bool"] = false,
                        _a["policy:MaxConnection_u32"] = 32,
                        _a["policy:TimeOut_u32"] = 15,
                        _a["policy:MaxMac_u32"] = 1000,
                        _a["policy:MaxIP_u32"] = 1000,
                        _a["policy:MaxUpload_u32"] = 1000000000,
                        _a["policy:MaxDownload_u32"] = 1000000000,
                        _a["policy:FixPassword_bool"] = false,
                        _a["policy:MultiLogins_u32"] = 1000,
                        _a["policy:NoQoS_bool"] = false,
                        _a["policy:RSandRAFilter_bool"] = false,
                        _a["policy:RAFilter_bool"] = false,
                        _a["policy:DHCPv6Filter_bool"] = false,
                        _a["policy:DHCPv6NoServer_bool"] = false,
                        _a["policy:NoRoutingV6_bool"] = false,
                        _a["policy:CheckIPv6_bool"] = false,
                        _a["policy:NoServerV6_bool"] = false,
                        _a["policy:MaxIPv6_u32"] = 1234,
                        _a["policy:NoSavePassword_bool"] = false,
                        _a["policy:AutoDisconnect_u32"] = 0,
                        _a["policy:FilterIPv4_bool"] = false,
                        _a["policy:FilterIPv6_bool"] = false,
                        _a["policy:FilterNonIP_bool"] = false,
                        _a["policy:NoIPv6DefaultRouterInRA_bool"] = false,
                        _a["policy:NoIPv6DefaultRouterInRAWhenIPv6_bool"] = false,
                        _a["policy:VLanId_u32"] = 0,
                        _a["policy:Ver3_bool"] = true,
                        _a));
                    return [4 /*yield*/, api.CreateGroup(in_rpc_set_group)];
                case 1:
                    out_rpc_set_group = _b.sent();
                    console.log(out_rpc_set_group);
                    console.log("End: Test_CreateGroup");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetGroup', Set group setting */
function Test_SetGroup() {
    return __awaiter(this, void 0, void 0, function () {
        var _a, in_rpc_set_group, out_rpc_set_group;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    console.log("Begin: Test_SetGroup");
                    in_rpc_set_group = new VPN.VpnRpcSetGroup((_a = {
                            HubName_str: hub_name,
                            Name_str: "group1",
                            Realname_utf: "Cat group 2",
                            Note_utf: "This is it! This is it!! 2",
                            UsePolicy_bool: true
                        },
                        _a["policy:Access_bool"] = true,
                        _a["policy:DHCPFilter_bool"] = false,
                        _a["policy:DHCPNoServer_bool"] = true,
                        _a["policy:DHCPForce_bool"] = false,
                        _a["policy:NoBridge_bool"] = false,
                        _a["policy:NoRouting_bool"] = false,
                        _a["policy:CheckMac_bool"] = false,
                        _a["policy:CheckIP_bool"] = false,
                        _a["policy:ArpDhcpOnly_bool"] = false,
                        _a["policy:PrivacyFilter_bool"] = false,
                        _a["policy:NoServer_bool"] = false,
                        _a["policy:NoBroadcastLimiter_bool"] = false,
                        _a["policy:MonitorPort_bool"] = false,
                        _a["policy:MaxConnection_u32"] = 32,
                        _a["policy:TimeOut_u32"] = 15,
                        _a["policy:MaxMac_u32"] = 1000,
                        _a["policy:MaxIP_u32"] = 1000,
                        _a["policy:MaxUpload_u32"] = 1000000000,
                        _a["policy:MaxDownload_u32"] = 1000000000,
                        _a["policy:FixPassword_bool"] = false,
                        _a["policy:MultiLogins_u32"] = 1000,
                        _a["policy:NoQoS_bool"] = false,
                        _a["policy:RSandRAFilter_bool"] = false,
                        _a["policy:RAFilter_bool"] = false,
                        _a["policy:DHCPv6Filter_bool"] = false,
                        _a["policy:DHCPv6NoServer_bool"] = false,
                        _a["policy:NoRoutingV6_bool"] = false,
                        _a["policy:CheckIPv6_bool"] = false,
                        _a["policy:NoServerV6_bool"] = false,
                        _a["policy:MaxIPv6_u32"] = 1234,
                        _a["policy:NoSavePassword_bool"] = false,
                        _a["policy:AutoDisconnect_u32"] = 0,
                        _a["policy:FilterIPv4_bool"] = false,
                        _a["policy:FilterIPv6_bool"] = false,
                        _a["policy:FilterNonIP_bool"] = false,
                        _a["policy:NoIPv6DefaultRouterInRA_bool"] = false,
                        _a["policy:NoIPv6DefaultRouterInRAWhenIPv6_bool"] = false,
                        _a["policy:VLanId_u32"] = 0,
                        _a["policy:Ver3_bool"] = true,
                        _a));
                    return [4 /*yield*/, api.SetGroup(in_rpc_set_group)];
                case 1:
                    out_rpc_set_group = _b.sent();
                    console.log(out_rpc_set_group);
                    console.log("End: Test_SetGroup");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetGroup', Get group information */
function Test_GetGroup() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_set_group, out_rpc_set_group;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetGroup");
                    in_rpc_set_group = new VPN.VpnRpcSetGroup({
                        HubName_str: hub_name,
                        Name_str: "group1"
                    });
                    return [4 /*yield*/, api.GetGroup(in_rpc_set_group)];
                case 1:
                    out_rpc_set_group = _a.sent();
                    console.log(out_rpc_set_group);
                    console.log("End: Test_GetGroup");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'DeleteGroup', Delete a group */
function Test_DeleteGroup() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_delete_user, out_rpc_delete_user;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_DeleteGroup");
                    in_rpc_delete_user = new VPN.VpnRpcDeleteUser({
                        HubName_str: hub_name,
                        Name_str: "group1"
                    });
                    return [4 /*yield*/, api.DeleteGroup(in_rpc_delete_user)];
                case 1:
                    out_rpc_delete_user = _a.sent();
                    console.log(out_rpc_delete_user);
                    console.log("End: Test_DeleteGroup");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumGroup', Enumerate groups */
function Test_EnumGroup() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_enum_group, out_rpc_enum_group;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumGroup");
                    in_rpc_enum_group = new VPN.VpnRpcEnumGroup({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.EnumGroup(in_rpc_enum_group)];
                case 1:
                    out_rpc_enum_group = _a.sent();
                    console.log(out_rpc_enum_group);
                    console.log("End: Test_EnumGroup");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumSession', Enumerate sessions */
function Test_EnumSession() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_enum_session, out_rpc_enum_session;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumSession");
                    in_rpc_enum_session = new VPN.VpnRpcEnumSession({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.EnumSession(in_rpc_enum_session)];
                case 1:
                    out_rpc_enum_session = _a.sent();
                    console.log(out_rpc_enum_session);
                    console.log("End: Test_EnumSession");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/, out_rpc_enum_session];
            }
        });
    });
}
/** API test for 'GetSessionStatus', Get session status */
function Test_GetSessionStatus(session_name) {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_session_status, out_rpc_session_status;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetSessionStatus");
                    in_rpc_session_status = new VPN.VpnRpcSessionStatus({
                        HubName_str: hub_name,
                        Name_str: session_name
                    });
                    return [4 /*yield*/, api.GetSessionStatus(in_rpc_session_status)];
                case 1:
                    out_rpc_session_status = _a.sent();
                    console.log(out_rpc_session_status);
                    console.log("End: Test_GetSessionStatus");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'DeleteSession', Delete a session */
function Test_DeleteSession(session_id) {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_delete_session, out_rpc_delete_session;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_DeleteSession");
                    in_rpc_delete_session = new VPN.VpnRpcDeleteSession({
                        HubName_str: hub_name,
                        Name_str: session_id
                    });
                    return [4 /*yield*/, api.DeleteSession(in_rpc_delete_session)];
                case 1:
                    out_rpc_delete_session = _a.sent();
                    console.log(out_rpc_delete_session);
                    console.log("End: Test_DeleteSession");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumMacTable', Get MAC address table */
function Test_EnumMacTable() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_enum_mac_table, out_rpc_enum_mac_table;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumMacTable");
                    in_rpc_enum_mac_table = new VPN.VpnRpcEnumMacTable({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.EnumMacTable(in_rpc_enum_mac_table)];
                case 1:
                    out_rpc_enum_mac_table = _a.sent();
                    console.log(out_rpc_enum_mac_table);
                    console.log("End: Test_EnumMacTable");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/, out_rpc_enum_mac_table];
            }
        });
    });
}
/** API test for 'DeleteMacTable', Delete MAC address table entry */
function Test_DeleteMacTable(key32) {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_delete_table, out_rpc_delete_table;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_DeleteMacTable");
                    in_rpc_delete_table = new VPN.VpnRpcDeleteTable({
                        HubName_str: hub_name,
                        Key_u32: key32
                    });
                    return [4 /*yield*/, api.DeleteMacTable(in_rpc_delete_table)];
                case 1:
                    out_rpc_delete_table = _a.sent();
                    console.log("End: Test_DeleteMacTable");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumIpTable', Get IP address table */
function Test_EnumIpTable() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_enum_ip_table, out_rpc_enum_ip_table;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumIpTable");
                    in_rpc_enum_ip_table = new VPN.VpnRpcEnumIpTable({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.EnumIpTable(in_rpc_enum_ip_table)];
                case 1:
                    out_rpc_enum_ip_table = _a.sent();
                    console.log(out_rpc_enum_ip_table);
                    console.log("End: Test_EnumIpTable");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/, out_rpc_enum_ip_table];
            }
        });
    });
}
/** API test for 'DeleteIpTable', Delete IP address table entry */
function Test_DeleteIpTable(key32) {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_delete_table, out_rpc_delete_table;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_DeleteIpTable");
                    in_rpc_delete_table = new VPN.VpnRpcDeleteTable({
                        HubName_str: hub_name,
                        Key_u32: key32
                    });
                    return [4 /*yield*/, api.DeleteIpTable(in_rpc_delete_table)];
                case 1:
                    out_rpc_delete_table = _a.sent();
                    console.log(out_rpc_delete_table);
                    console.log("End: Test_DeleteIpTable");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetKeep', Set keep-alive function setting */
function Test_SetKeep() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_keep, out_rpc_keep;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetKeep");
                    in_rpc_keep = new VPN.VpnRpcKeep({
                        UseKeepConnect_bool: true,
                        KeepConnectHost_str: "www.softether.org",
                        KeepConnectPort_u32: 123,
                        KeepConnectProtocol_u32: VPN.VpnRpcKeepAliveProtocol.UDP,
                        KeepConnectInterval_u32: 1
                    });
                    return [4 /*yield*/, api.SetKeep(in_rpc_keep)];
                case 1:
                    out_rpc_keep = _a.sent();
                    console.log(out_rpc_keep);
                    console.log("End: Test_SetKeep");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetKeep', Get keep-alive function setting */
function Test_GetKeep() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_keep, out_rpc_keep;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetKeep");
                    in_rpc_keep = new VPN.VpnRpcKeep({});
                    return [4 /*yield*/, api.GetKeep(in_rpc_keep)];
                case 1:
                    out_rpc_keep = _a.sent();
                    console.log(out_rpc_keep);
                    console.log("End: Test_GetKeep");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnableSecureNAT', Enable SecureNAT function of the hub */
function Test_EnableSecureNAT() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_hub, out_rpc_hub;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnableSecureNAT");
                    in_rpc_hub = new VPN.VpnRpcHub({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.EnableSecureNAT(in_rpc_hub)];
                case 1:
                    out_rpc_hub = _a.sent();
                    console.log(out_rpc_hub);
                    console.log("End: Test_EnableSecureNAT");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'DisableSecureNAT', Disable the SecureNAT function of the hub */
function Test_DisableSecureNAT() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_hub, out_rpc_hub;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_DisableSecureNAT");
                    in_rpc_hub = new VPN.VpnRpcHub({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.DisableSecureNAT(in_rpc_hub)];
                case 1:
                    out_rpc_hub = _a.sent();
                    console.log(out_rpc_hub);
                    console.log("End: Test_DisableSecureNAT");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetSecureNATOption', Set SecureNAT options */
function Test_SetSecureNATOption() {
    return __awaiter(this, void 0, void 0, function () {
        var in_vh_option, out_vh_option;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetSecureNATOption");
                    in_vh_option = new VPN.VpnVhOption({
                        RpcHubName_str: hub_name,
                        MacAddress_bin: new Uint8Array([0x00, 0xAC, 0x00, 0x11, 0x22, 0x33,]),
                        Ip_ip: "10.0.0.254",
                        Mask_ip: "255.255.255.0",
                        UseNat_bool: true,
                        Mtu_u32: 1200,
                        NatTcpTimeout_u32: 100,
                        NatUdpTimeout_u32: 50,
                        UseDhcp_bool: true,
                        DhcpLeaseIPStart_ip: "10.0.0.101",
                        DhcpLeaseIPEnd_ip: "10.0.0.199",
                        DhcpSubnetMask_ip: "255.255.255.0",
                        DhcpExpireTimeSpan_u32: 3600,
                        DhcpGatewayAddress_ip: "10.0.0.254",
                        DhcpDnsServerAddress_ip: "10.0.0.254",
                        DhcpDnsServerAddress2_ip: "8.8.8.8",
                        DhcpDomainName_str: "lab.coe.ad.jp",
                        SaveLog_bool: true,
                        ApplyDhcpPushRoutes_bool: false,
                        DhcpPushRoutes_str: ""
                    });
                    return [4 /*yield*/, api.SetSecureNATOption(in_vh_option)];
                case 1:
                    out_vh_option = _a.sent();
                    console.log(out_vh_option);
                    console.log("End: Test_SetSecureNATOption");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetSecureNATOption', Get SecureNAT options */
function Test_GetSecureNATOption() {
    return __awaiter(this, void 0, void 0, function () {
        var in_vh_option, out_vh_option;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetSecureNATOption");
                    in_vh_option = new VPN.VpnVhOption({
                        RpcHubName_str: hub_name
                    });
                    return [4 /*yield*/, api.GetSecureNATOption(in_vh_option)];
                case 1:
                    out_vh_option = _a.sent();
                    console.log(out_vh_option);
                    console.log("End: Test_GetSecureNATOption");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumNAT', Enumerate NAT entries of the SecureNAT */
function Test_EnumNAT() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_enum_nat, out_rpc_enum_nat;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumNAT");
                    in_rpc_enum_nat = new VPN.VpnRpcEnumNat({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.EnumNAT(in_rpc_enum_nat)];
                case 1:
                    out_rpc_enum_nat = _a.sent();
                    console.log(out_rpc_enum_nat);
                    console.log("End: Test_EnumNAT");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumDHCP', Enumerate DHCP entries */
function Test_EnumDHCP() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_enum_dhcp, out_rpc_enum_dhcp;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumDHCP");
                    in_rpc_enum_dhcp = new VPN.VpnRpcEnumDhcp({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.EnumDHCP(in_rpc_enum_dhcp)];
                case 1:
                    out_rpc_enum_dhcp = _a.sent();
                    console.log(out_rpc_enum_dhcp);
                    console.log("End: Test_EnumDHCP");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetSecureNATStatus', Get status of the SecureNAT */
function Test_GetSecureNATStatus() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_nat_status, out_rpc_nat_status;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetSecureNATStatus");
                    in_rpc_nat_status = new VPN.VpnRpcNatStatus({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.GetSecureNATStatus(in_rpc_nat_status)];
                case 1:
                    out_rpc_nat_status = _a.sent();
                    console.log(out_rpc_nat_status);
                    console.log("End: Test_GetSecureNATStatus");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumEthernet', Enumerate Ethernet devices */
function Test_EnumEthernet() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_enum_eth;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumEthernet");
                    return [4 /*yield*/, api.EnumEthernet()];
                case 1:
                    out_rpc_enum_eth = _a.sent();
                    console.log(out_rpc_enum_eth);
                    console.log("End: Test_EnumEthernet");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'AddLocalBridge', Add a new local bridge */
function Test_AddLocalBridge() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_localbridge, out_rpc_localbridge;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_AddLocalBridge");
                    in_rpc_localbridge = new VPN.VpnRpcLocalBridge({
                        DeviceName_str: "Intel(R) Ethernet Connection (2) I219-V (ID=3632031273)",
                        HubNameLB_str: hub_name
                    });
                    return [4 /*yield*/, api.AddLocalBridge(in_rpc_localbridge)];
                case 1:
                    out_rpc_localbridge = _a.sent();
                    console.log(out_rpc_localbridge);
                    console.log("End: Test_AddLocalBridge");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'DeleteLocalBridge', Delete a local bridge */
function Test_DeleteLocalBridge() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_localbridge, out_rpc_localbridge;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_DeleteLocalBridge");
                    in_rpc_localbridge = new VPN.VpnRpcLocalBridge({
                        DeviceName_str: "Intel(R) Ethernet Connection (2) I219-V (ID=3632031273)",
                        HubNameLB_str: hub_name
                    });
                    return [4 /*yield*/, api.DeleteLocalBridge(in_rpc_localbridge)];
                case 1:
                    out_rpc_localbridge = _a.sent();
                    console.log(out_rpc_localbridge);
                    console.log("End: Test_DeleteLocalBridge");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumLocalBridge', Enumerate local bridges */
function Test_EnumLocalBridge() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_enum_localbridge;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumLocalBridge");
                    return [4 /*yield*/, api.EnumLocalBridge()];
                case 1:
                    out_rpc_enum_localbridge = _a.sent();
                    console.log(out_rpc_enum_localbridge);
                    console.log("End: Test_EnumLocalBridge");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetBridgeSupport', Get availability to localbridge function */
function Test_GetBridgeSupport() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_bridge_support;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetBridgeSupport");
                    return [4 /*yield*/, api.GetBridgeSupport()];
                case 1:
                    out_rpc_bridge_support = _a.sent();
                    console.log(out_rpc_bridge_support);
                    console.log("End: Test_GetBridgeSupport");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'RebootServer', Reboot server itself */
function Test_RebootServer() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_test, out_rpc_test;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_RebootServer");
                    in_rpc_test = new VPN.VpnRpcTest({});
                    return [4 /*yield*/, api.RebootServer(in_rpc_test)];
                case 1:
                    out_rpc_test = _a.sent();
                    console.log(out_rpc_test);
                    console.log("End: Test_RebootServer");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetCaps', Get capabilities */
function Test_GetCaps() {
    return __awaiter(this, void 0, void 0, function () {
        var out_capslist;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetCaps");
                    return [4 /*yield*/, api.GetCaps()];
                case 1:
                    out_capslist = _a.sent();
                    console.log(out_capslist);
                    console.log("End: Test_GetCaps");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetConfig', Get configuration file stream */
function Test_GetConfig() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_config;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetConfig");
                    return [4 /*yield*/, api.GetConfig()];
                case 1:
                    out_rpc_config = _a.sent();
                    console.log(out_rpc_config);
                    console.log("End: Test_GetConfig");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetConfig', Overwrite configuration file by specified data */
function Test_SetConfig() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_config, out_rpc_config;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetConfig");
                    in_rpc_config = new VPN.VpnRpcConfig({
                        FileData_bin: new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,])
                    });
                    return [4 /*yield*/, api.SetConfig(in_rpc_config)];
                case 1:
                    out_rpc_config = _a.sent();
                    console.log("End: Test_SetConfig");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetDefaultHubAdminOptions', Get default hub administration options */
function Test_GetDefaultHubAdminOptions() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_admin_option, out_rpc_admin_option;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetDefaultHubAdminOptions");
                    in_rpc_admin_option = new VPN.VpnRpcAdminOption({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.GetDefaultHubAdminOptions(in_rpc_admin_option)];
                case 1:
                    out_rpc_admin_option = _a.sent();
                    console.log(out_rpc_admin_option);
                    console.log("End: Test_GetDefaultHubAdminOptions");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetHubAdminOptions', Get hub administration options */
function Test_GetHubAdminOptions() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_admin_option, out_rpc_admin_option;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetHubAdminOptions");
                    in_rpc_admin_option = new VPN.VpnRpcAdminOption({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.GetHubAdminOptions(in_rpc_admin_option)];
                case 1:
                    out_rpc_admin_option = _a.sent();
                    console.log(out_rpc_admin_option);
                    console.log("End: Test_GetHubAdminOptions");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetHubAdminOptions', Set hub administration options */
function Test_SetHubAdminOptions() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_admin_option, out_rpc_admin_option;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetHubAdminOptions");
                    in_rpc_admin_option = new VPN.VpnRpcAdminOption({
                        HubName_str: hub_name,
                        AdminOptionList: [new VPN.VpnAdminOption({
                                Name_str: "no_securenat_enablenat",
                                Value_u32: 1
                            }),]
                    });
                    return [4 /*yield*/, api.SetHubAdminOptions(in_rpc_admin_option)];
                case 1:
                    out_rpc_admin_option = _a.sent();
                    console.log(out_rpc_admin_option);
                    console.log("End: Test_SetHubAdminOptions");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetHubExtOptions', Get hub extended options */
function Test_GetHubExtOptions() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_admin_option, out_rpc_admin_option;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetHubExtOptions");
                    in_rpc_admin_option = new VPN.VpnRpcAdminOption({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.GetHubExtOptions(in_rpc_admin_option)];
                case 1:
                    out_rpc_admin_option = _a.sent();
                    console.log(out_rpc_admin_option);
                    console.log("End: Test_GetHubExtOptions");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetHubExtOptions', Set hub extended options */
function Test_SetHubExtOptions() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_admin_option, out_rpc_admin_option;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetHubExtOptions");
                    in_rpc_admin_option = new VPN.VpnRpcAdminOption({
                        HubName_str: hub_name,
                        AdminOptionList: [new VPN.VpnAdminOption({
                                Name_str: "SecureNAT_RandomizeAssignIp",
                                Value_u32: 1
                            }),]
                    });
                    return [4 /*yield*/, api.SetHubExtOptions(in_rpc_admin_option)];
                case 1:
                    out_rpc_admin_option = _a.sent();
                    console.log(out_rpc_admin_option);
                    console.log("End: Test_SetHubExtOptions");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'AddL3Switch', Add a new virtual layer-3 switch */
function Test_AddL3Switch() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_l3sw, out_rpc_l3sw;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_AddL3Switch");
                    in_rpc_l3sw = new VPN.VpnRpcL3Sw({
                        Name_str: "L3SW1"
                    });
                    return [4 /*yield*/, api.AddL3Switch(in_rpc_l3sw)];
                case 1:
                    out_rpc_l3sw = _a.sent();
                    console.log(out_rpc_l3sw);
                    console.log("End: Test_AddL3Switch");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'DelL3Switch', Delete a virtual layer-3 switch */
function Test_DelL3Switch() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_l3sw, out_rpc_l3sw;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_DelL3Switch");
                    in_rpc_l3sw = new VPN.VpnRpcL3Sw({
                        Name_str: "L3SW1"
                    });
                    return [4 /*yield*/, api.DelL3Switch(in_rpc_l3sw)];
                case 1:
                    out_rpc_l3sw = _a.sent();
                    console.log(out_rpc_l3sw);
                    console.log("End: Test_DelL3Switch");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumL3Switch', Enumerate virtual layer-3 switches */
function Test_EnumL3Switch() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_enum_l3sw;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumL3Switch");
                    return [4 /*yield*/, api.EnumL3Switch()];
                case 1:
                    out_rpc_enum_l3sw = _a.sent();
                    console.log(out_rpc_enum_l3sw);
                    console.log("End: Test_EnumL3Switch");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'StartL3Switch', Start a virtual layer-3 switch */
function Test_StartL3Switch() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_l3sw, out_rpc_l3sw;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_StartL3Switch");
                    in_rpc_l3sw = new VPN.VpnRpcL3Sw({
                        Name_str: "L3SW1"
                    });
                    return [4 /*yield*/, api.StartL3Switch(in_rpc_l3sw)];
                case 1:
                    out_rpc_l3sw = _a.sent();
                    console.log(out_rpc_l3sw);
                    console.log("End: Test_StartL3Switch");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'StopL3Switch', Stop a virtual layer-3 switch */
function Test_StopL3Switch() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_l3sw, out_rpc_l3sw;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_StopL3Switch");
                    in_rpc_l3sw = new VPN.VpnRpcL3Sw({
                        Name_str: "L3SW1"
                    });
                    return [4 /*yield*/, api.StopL3Switch(in_rpc_l3sw)];
                case 1:
                    out_rpc_l3sw = _a.sent();
                    console.log(out_rpc_l3sw);
                    console.log("End: Test_StopL3Switch");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'AddL3If', Add new virtual interface on virtual L3 switch */
function Test_AddL3If() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_l3if, out_rpc_l3if;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_AddL3If");
                    in_rpc_l3if = new VPN.VpnRpcL3If({
                        Name_str: "L3SW1",
                        HubName_str: hub_name,
                        IpAddress_ip: "192.168.0.1",
                        SubnetMask_ip: "255.255.255.0"
                    });
                    return [4 /*yield*/, api.AddL3If(in_rpc_l3if)];
                case 1:
                    out_rpc_l3if = _a.sent();
                    console.log(out_rpc_l3if);
                    console.log("End: Test_AddL3If");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'DelL3If', Delete a virtual interface on virtual L3 switch */
function Test_DelL3If() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_l3if, out_rpc_l3if;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_DelL3If");
                    in_rpc_l3if = new VPN.VpnRpcL3If({
                        Name_str: "L3SW1",
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.DelL3If(in_rpc_l3if)];
                case 1:
                    out_rpc_l3if = _a.sent();
                    console.log(out_rpc_l3if);
                    console.log("End: Test_DelL3If");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumL3If', Enumerate virtual interfaces on virtual L3 switch */
function Test_EnumL3If() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_enum_l3if, out_rpc_enum_l3if;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumL3If");
                    in_rpc_enum_l3if = new VPN.VpnRpcEnumL3If({
                        Name_str: "L3SW1"
                    });
                    return [4 /*yield*/, api.EnumL3If(in_rpc_enum_l3if)];
                case 1:
                    out_rpc_enum_l3if = _a.sent();
                    console.log(out_rpc_enum_l3if);
                    console.log("End: Test_EnumL3If");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'AddL3Table', Add new routing table entry on virtual L3 switch */
function Test_AddL3Table() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_l3table, out_rpc_l3table;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_AddL3Table");
                    in_rpc_l3table = new VPN.VpnRpcL3Table({
                        Name_str: "L3SW1",
                        NetworkAddress_ip: "10.0.0.0",
                        SubnetMask_ip: "255.0.0.0",
                        GatewayAddress_ip: "192.168.7.1",
                        Metric_u32: 10
                    });
                    return [4 /*yield*/, api.AddL3Table(in_rpc_l3table)];
                case 1:
                    out_rpc_l3table = _a.sent();
                    console.log(out_rpc_l3table);
                    console.log("End: Test_AddL3Table");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'DelL3Table', Delete routing table entry on virtual L3 switch */
function Test_DelL3Table() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_l3table, out_rpc_l3table;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_DelL3Table");
                    in_rpc_l3table = new VPN.VpnRpcL3Table({
                        Name_str: "L3SW1",
                        NetworkAddress_ip: "10.0.0.0",
                        SubnetMask_ip: "255.0.0.0",
                        GatewayAddress_ip: "192.168.7.1",
                        Metric_u32: 10
                    });
                    return [4 /*yield*/, api.DelL3Table(in_rpc_l3table)];
                case 1:
                    out_rpc_l3table = _a.sent();
                    console.log(out_rpc_l3table);
                    console.log("End: Test_DelL3Table");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumL3Table', Get routing table on virtual L3 switch */
function Test_EnumL3Table() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_enum_l3table, out_rpc_enum_l3table;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumL3Table");
                    in_rpc_enum_l3table = new VPN.VpnRpcEnumL3Table({
                        Name_str: "L3SW1"
                    });
                    return [4 /*yield*/, api.EnumL3Table(in_rpc_enum_l3table)];
                case 1:
                    out_rpc_enum_l3table = _a.sent();
                    console.log(out_rpc_enum_l3table);
                    console.log("End: Test_EnumL3Table");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumCrl', Get CRL (Certificate Revocation List) index */
function Test_EnumCrl() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_enum_crl, out_rpc_enum_crl;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumCrl");
                    in_rpc_enum_crl = new VPN.VpnRpcEnumCrl({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.EnumCrl(in_rpc_enum_crl)];
                case 1:
                    out_rpc_enum_crl = _a.sent();
                    console.log(out_rpc_enum_crl);
                    console.log("End: Test_EnumCrl");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/, out_rpc_enum_crl];
            }
        });
    });
}
/** API test for 'AddCrl', Add new CRL (Certificate Revocation List) entry */
function Test_AddCrl() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_crl, out_rpc_crl;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_AddCrl");
                    in_rpc_crl = new VPN.VpnRpcCrl({
                        HubName_str: hub_name,
                        CommonName_utf: "CN",
                        Organization_utf: "Org",
                        Unit_utf: "ICSCOE",
                        Country_utf: "JP",
                        State_utf: "Ibaraki",
                        Local_utf: "Tsukuba",
                        Serial_bin: new Uint8Array([1, 2, 3, 4, 5,]),
                        DigestMD5_bin: new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,]),
                        DigestSHA1_bin: new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,])
                    });
                    return [4 /*yield*/, api.AddCrl(in_rpc_crl)];
                case 1:
                    out_rpc_crl = _a.sent();
                    console.log(out_rpc_crl);
                    console.log("End: Test_AddCrl");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'DelCrl', Delete CRL (Certificate Revocation List) entry */
function Test_DelCrl(key) {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_crl, out_rpc_crl;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_DelCrl");
                    in_rpc_crl = new VPN.VpnRpcCrl({
                        HubName_str: hub_name,
                        Key_u32: key
                    });
                    return [4 /*yield*/, api.DelCrl(in_rpc_crl)];
                case 1:
                    out_rpc_crl = _a.sent();
                    console.log(out_rpc_crl);
                    console.log("End: Test_DelCrl");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetCrl', Get CRL (Certificate Revocation List) entry */
function Test_GetCrl(key) {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_crl, out_rpc_crl;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetCrl");
                    in_rpc_crl = new VPN.VpnRpcCrl({
                        HubName_str: hub_name,
                        Key_u32: key
                    });
                    return [4 /*yield*/, api.GetCrl(in_rpc_crl)];
                case 1:
                    out_rpc_crl = _a.sent();
                    console.log(out_rpc_crl);
                    console.log("End: Test_GetCrl");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/, out_rpc_crl];
            }
        });
    });
}
/** API test for 'SetCrl', Set CRL (Certificate Revocation List) entry */
function Test_SetCrl(crl) {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_crl;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetCrl");
                    return [4 /*yield*/, api.SetCrl(crl)];
                case 1:
                    out_rpc_crl = _a.sent();
                    console.log(out_rpc_crl);
                    console.log("End: Test_SetCrl");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetAcList', Set access control list */
function Test_SetAcList() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_ac_list, out_rpc_ac_list;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetAcList");
                    in_rpc_ac_list = new VPN.VpnRpcAcList({
                        HubName_str: hub_name,
                        ACList: [new VPN.VpnAc({
                                Deny_bool: true,
                                IpAddress_ip: "192.168.0.0",
                                SubnetMask_ip: "255.255.0.0",
                                Masked_bool: true,
                                Priority_u32: 123
                            }), new VPN.VpnAc({
                                Deny_bool: false,
                                IpAddress_ip: "fe80::",
                                SubnetMask_ip: "8",
                                Masked_bool: true,
                                Priority_u32: 123
                            }),]
                    });
                    return [4 /*yield*/, api.SetAcList(in_rpc_ac_list)];
                case 1:
                    out_rpc_ac_list = _a.sent();
                    console.log(out_rpc_ac_list);
                    console.log("End: Test_SetAcList");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetAcList', Get access control list */
function Test_GetAcList() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_ac_list, out_rpc_ac_list;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetAcList");
                    in_rpc_ac_list = new VPN.VpnRpcAcList({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.GetAcList(in_rpc_ac_list)];
                case 1:
                    out_rpc_ac_list = _a.sent();
                    console.log(out_rpc_ac_list);
                    console.log("End: Test_GetAcList");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumLogFile', Enumerate log files */
function Test_EnumLogFile() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_enum_log_file;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumLogFile");
                    return [4 /*yield*/, api.EnumLogFile()];
                case 1:
                    out_rpc_enum_log_file = _a.sent();
                    console.log(out_rpc_enum_log_file);
                    console.log("End: Test_EnumLogFile");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/, out_rpc_enum_log_file];
            }
        });
    });
}
/** API test for 'ReadLogFile', Read a log file */
function Test_ReadLogFile(filename) {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_read_log_file, out_rpc_read_log_file;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_ReadLogFile");
                    in_rpc_read_log_file = new VPN.VpnRpcReadLogFile({
                        FilePath_str: filename
                    });
                    return [4 /*yield*/, api.ReadLogFile(in_rpc_read_log_file)];
                case 1:
                    out_rpc_read_log_file = _a.sent();
                    console.log(out_rpc_read_log_file);
                    console.log("End: Test_ReadLogFile");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetSysLog', Set syslog function setting */
function Test_SetSysLog(flag) {
    return __awaiter(this, void 0, void 0, function () {
        var in_syslog_setting, out_syslog_setting;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetSysLog");
                    in_syslog_setting = new VPN.VpnSyslogSetting({
                        SaveType_u32: flag ? VPN.VpnSyslogSaveType.ServerAndHubAllLog : VPN.VpnSyslogSaveType.None,
                        Hostname_str: "1.2.3.4",
                        Port_u32: 123
                    });
                    return [4 /*yield*/, api.SetSysLog(in_syslog_setting)];
                case 1:
                    out_syslog_setting = _a.sent();
                    console.log(out_syslog_setting);
                    console.log("End: Test_SetSysLog");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetSysLog', Get syslog function setting */
function Test_GetSysLog() {
    return __awaiter(this, void 0, void 0, function () {
        var in_syslog_setting, out_syslog_setting;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetSysLog");
                    in_syslog_setting = new VPN.VpnSyslogSetting({});
                    return [4 /*yield*/, api.GetSysLog(in_syslog_setting)];
                case 1:
                    out_syslog_setting = _a.sent();
                    console.log(out_syslog_setting);
                    console.log("End: Test_GetSysLog");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetHubMsg', Set message of today on hub */
function Test_SetHubMsg() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_msg, out_rpc_msg;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetHubMsg");
                    in_rpc_msg = new VPN.VpnRpcMsg({
                        HubName_str: hub_name,
                        Msg_bin: new Uint8Array([0x57, 0x6f, 0x72, 0x6b, 0x69, 0x6e, 0x67, 0x20, 0x4d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x41, 0x6c, 0x6c, 0x20, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73, 0x2c, 0x20, 0x55, 0x6e, 0x69, 0x74, 0x65, 0x21, 0x20, 0xe4, 0xb8, 0x87, 0xe5, 0x9b, 0xbd, 0xe3, 0x81, 0xae, 0xe5, 0x8a, 0xb4, 0xe5, 0x83, 0x8d, 0xe8, 0x80, 0x85, 0xe3, 0x82, 0x88, 0xe3, 0x80, 0x81, 0xe5, 0x9b, 0xa3, 0xe7, 0xb5, 0x90, 0xe3, 0x81, 0x9b, 0xe3, 0x82, 0x88, 0x21, 0x20, 0xd7, 0x92, 0xd7, 0x91, 0xd7, 0xa8, 0xd7, 0x99, 0xd7, 0x9d, 0x20, 0xd7, 0xa2, 0xd7, 0x95, 0xd7, 0x91, 0xd7, 0x93, 0xd7, 0x99, 0xd7, 0x9d, 0x20, 0xd7, 0xa9, 0xd7, 0x9c, 0x20, 0xd7, 0x9b, 0xd7, 0x9c, 0x20, 0xd7, 0x94, 0xd7, 0x9e, 0xd7, 0x93, 0xd7, 0x99, 0xd7, 0xa0, 0xd7, 0x95, 0xd7, 0xaa, 0x2c, 0x20, 0xd7, 0x94, 0xd7, 0xaa, 0xd7, 0x90, 0xd7, 0x97, 0xd7, 0x93, 0xd7, 0x95, 0x21,])
                    });
                    return [4 /*yield*/, api.SetHubMsg(in_rpc_msg)];
                case 1:
                    out_rpc_msg = _a.sent();
                    console.log(out_rpc_msg);
                    console.log("End: Test_SetHubMsg");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetHubMsg', Get message of today on hub */
function Test_GetHubMsg() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_msg, out_rpc_msg;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetHubMsg");
                    in_rpc_msg = new VPN.VpnRpcMsg({
                        HubName_str: hub_name
                    });
                    return [4 /*yield*/, api.GetHubMsg(in_rpc_msg)];
                case 1:
                    out_rpc_msg = _a.sent();
                    console.log(out_rpc_msg);
                    console.log("End: Test_GetHubMsg");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'Crash', Do Crash */
function Test_Crash() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_test, out_rpc_test;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_Crash");
                    in_rpc_test = new VPN.VpnRpcTest({});
                    return [4 /*yield*/, api.Crash(in_rpc_test)];
                case 1:
                    out_rpc_test = _a.sent();
                    console.log(out_rpc_test);
                    console.log("End: Test_Crash");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetAdminMsg', Get message for administrators */
function Test_GetAdminMsg() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_msg;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetAdminMsg");
                    return [4 /*yield*/, api.GetAdminMsg()];
                case 1:
                    out_rpc_msg = _a.sent();
                    console.log(out_rpc_msg);
                    console.log("End: Test_GetAdminMsg");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'Flush', Flush configuration file */
function Test_Flush() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_test, out_rpc_test;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_Flush");
                    in_rpc_test = new VPN.VpnRpcTest({});
                    return [4 /*yield*/, api.Flush(in_rpc_test)];
                case 1:
                    out_rpc_test = _a.sent();
                    console.log(out_rpc_test);
                    console.log("End: Test_Flush");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetIPsecServices', Set IPsec service configuration */
function Test_SetIPsecServices() {
    return __awaiter(this, void 0, void 0, function () {
        var in_ipsec_services, out_ipsec_services;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetIPsecServices");
                    in_ipsec_services = new VPN.VpnIPsecServices({
                        L2TP_Raw_bool: false,
                        L2TP_IPsec_bool: false,
                        EtherIP_IPsec_bool: false,
                        IPsec_Secret_str: "vpn",
                        L2TP_DefaultHub_str: "HUB_ABC"
                    });
                    return [4 /*yield*/, api.SetIPsecServices(in_ipsec_services)];
                case 1:
                    out_ipsec_services = _a.sent();
                    console.log(out_ipsec_services);
                    console.log("End: Test_SetIPsecServices");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetIPsecServices', Get IPsec service configuration */
function Test_GetIPsecServices() {
    return __awaiter(this, void 0, void 0, function () {
        var out_ipsec_services;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetIPsecServices");
                    return [4 /*yield*/, api.GetIPsecServices()];
                case 1:
                    out_ipsec_services = _a.sent();
                    console.log(out_ipsec_services);
                    console.log("End: Test_GetIPsecServices");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'AddEtherIpId', Add EtherIP ID setting */
function Test_AddEtherIpId() {
    return __awaiter(this, void 0, void 0, function () {
        var in_etherip_id, out_etherip_id;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_AddEtherIpId");
                    in_etherip_id = new VPN.VpnEtherIpId({
                        Id_str: "testid",
                        HubName_str: hub_name,
                        UserName_str: "nekosan",
                        Password_str: "torisan"
                    });
                    return [4 /*yield*/, api.AddEtherIpId(in_etherip_id)];
                case 1:
                    out_etherip_id = _a.sent();
                    console.log(out_etherip_id);
                    console.log("End: Test_AddEtherIpId");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetEtherIpId', Get EtherIP ID setting */
function Test_GetEtherIpId(id) {
    return __awaiter(this, void 0, void 0, function () {
        var in_etherip_id, out_etherip_id;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetEtherIpId");
                    in_etherip_id = new VPN.VpnEtherIpId({
                        Id_str: id
                    });
                    return [4 /*yield*/, api.GetEtherIpId(in_etherip_id)];
                case 1:
                    out_etherip_id = _a.sent();
                    console.log(out_etherip_id);
                    console.log("End: Test_GetEtherIpId");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'DeleteEtherIpId', Delete EtherIP ID setting */
function Test_DeleteEtherIpId(id) {
    return __awaiter(this, void 0, void 0, function () {
        var in_etherip_id, out_etherip_id;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_DeleteEtherIpId");
                    in_etherip_id = new VPN.VpnEtherIpId({
                        Id_str: id
                    });
                    return [4 /*yield*/, api.DeleteEtherIpId(in_etherip_id)];
                case 1:
                    out_etherip_id = _a.sent();
                    console.log(out_etherip_id);
                    console.log("End: Test_DeleteEtherIpId");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'EnumEtherIpId', Enumerate EtherIP ID settings */
function Test_EnumEtherIpId() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_enum_etherip_id;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_EnumEtherIpId");
                    return [4 /*yield*/, api.EnumEtherIpId()];
                case 1:
                    out_rpc_enum_etherip_id = _a.sent();
                    console.log(out_rpc_enum_etherip_id);
                    console.log("End: Test_EnumEtherIpId");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/, out_rpc_enum_etherip_id];
            }
        });
    });
}
/** API test for 'SetOpenVpnSstpConfig', Set configurations for OpenVPN and SSTP */
function Test_SetOpenVpnSstpConfig() {
    return __awaiter(this, void 0, void 0, function () {
        var in_openvpn_sstp_config, out_openvpn_sstp_config;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetOpenVpnSstpConfig");
                    in_openvpn_sstp_config = new VPN.VpnOpenVpnSstpConfig({
                        EnableOpenVPN_bool: true,
                        OpenVPNPortList_str: "1 2 3 4 5",
                        EnableSSTP_bool: true
                    });
                    return [4 /*yield*/, api.SetOpenVpnSstpConfig(in_openvpn_sstp_config)];
                case 1:
                    out_openvpn_sstp_config = _a.sent();
                    console.log(out_openvpn_sstp_config);
                    console.log("End: Test_SetOpenVpnSstpConfig");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetOpenVpnSstpConfig', Get configurations for OpenVPN and SSTP */
function Test_GetOpenVpnSstpConfig() {
    return __awaiter(this, void 0, void 0, function () {
        var out_openvpn_sstp_config;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetOpenVpnSstpConfig");
                    return [4 /*yield*/, api.GetOpenVpnSstpConfig()];
                case 1:
                    out_openvpn_sstp_config = _a.sent();
                    console.log(out_openvpn_sstp_config);
                    console.log("End: Test_GetOpenVpnSstpConfig");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetDDnsClientStatus', Get status of DDNS client */
function Test_GetDDnsClientStatus() {
    return __awaiter(this, void 0, void 0, function () {
        var out_ddns_client_status;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetDDnsClientStatus");
                    return [4 /*yield*/, api.GetDDnsClientStatus()];
                case 1:
                    out_ddns_client_status = _a.sent();
                    console.log(out_ddns_client_status);
                    console.log("End: Test_GetDDnsClientStatus");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'ChangeDDnsClientHostname', Change host-name for DDNS client */
function Test_ChangeDDnsClientHostname() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_test, out_rpc_test;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_ChangeDDnsClientHostname");
                    in_rpc_test = new VPN.VpnRpcTest({
                        StrValue_str: "nekotest" + Math.floor((Math.random() * (2100000000 - 1000000000)) + 1000000000)
                    });
                    return [4 /*yield*/, api.ChangeDDnsClientHostname(in_rpc_test)];
                case 1:
                    out_rpc_test = _a.sent();
                    console.log(out_rpc_test);
                    console.log("End: Test_ChangeDDnsClientHostname");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'RegenerateServerCert', Regenerate server certification */
function Test_RegenerateServerCert() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_test, out_rpc_test;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_RegenerateServerCert");
                    in_rpc_test = new VPN.VpnRpcTest({
                        StrValue_str: "abc.example.org"
                    });
                    return [4 /*yield*/, api.RegenerateServerCert(in_rpc_test)];
                case 1:
                    out_rpc_test = _a.sent();
                    console.log(out_rpc_test);
                    console.log("End: Test_RegenerateServerCert");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'MakeOpenVpnConfigFile', Generate OpenVPN configuration files */
function Test_MakeOpenVpnConfigFile() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_read_log_file;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_MakeOpenVpnConfigFile");
                    return [4 /*yield*/, api.MakeOpenVpnConfigFile()];
                case 1:
                    out_rpc_read_log_file = _a.sent();
                    console.log(out_rpc_read_log_file);
                    console.log("End: Test_MakeOpenVpnConfigFile");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetSpecialListener', Set special listener status */
function Test_SetSpecialListener() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_special_listener, out_rpc_special_listener;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetSpecialListener");
                    in_rpc_special_listener = new VPN.VpnRpcSpecialListener({
                        VpnOverDnsListener_bool: true,
                        VpnOverIcmpListener_bool: true
                    });
                    return [4 /*yield*/, api.SetSpecialListener(in_rpc_special_listener)];
                case 1:
                    out_rpc_special_listener = _a.sent();
                    console.log(out_rpc_special_listener);
                    console.log("End: Test_SetSpecialListener");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetSpecialListener', Get special listener status */
function Test_GetSpecialListener() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_special_listener;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetSpecialListener");
                    return [4 /*yield*/, api.GetSpecialListener()];
                case 1:
                    out_rpc_special_listener = _a.sent();
                    console.log(out_rpc_special_listener);
                    console.log("End: Test_GetSpecialListener");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetAzureStatus', Get Azure status */
function Test_GetAzureStatus() {
    return __awaiter(this, void 0, void 0, function () {
        var out_rpc_azure_status;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetAzureStatus");
                    return [4 /*yield*/, api.GetAzureStatus()];
                case 1:
                    out_rpc_azure_status = _a.sent();
                    console.log(out_rpc_azure_status);
                    console.log("End: Test_GetAzureStatus");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetAzureStatus', Set Azure status */
function Test_SetAzureStatus() {
    return __awaiter(this, void 0, void 0, function () {
        var in_rpc_azure_status, out_rpc_azure_status;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetAzureStatus");
                    in_rpc_azure_status = new VPN.VpnRpcAzureStatus({
                        IsEnabled_bool: true
                    });
                    return [4 /*yield*/, api.SetAzureStatus(in_rpc_azure_status)];
                case 1:
                    out_rpc_azure_status = _a.sent();
                    console.log(out_rpc_azure_status);
                    console.log("End: Test_SetAzureStatus");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetDDnsInternetSettng', Get DDNS proxy configuration */
function Test_GetDDnsInternetSettng() {
    return __awaiter(this, void 0, void 0, function () {
        var out_internet_setting;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetDDnsInternetSettng");
                    return [4 /*yield*/, api.GetDDnsInternetSettng()];
                case 1:
                    out_internet_setting = _a.sent();
                    console.log(out_internet_setting);
                    console.log("End: Test_GetDDnsInternetSettng");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetDDnsInternetSettng', Set DDNS proxy configuration */
function Test_SetDDnsInternetSettng() {
    return __awaiter(this, void 0, void 0, function () {
        var in_internet_setting, out_internet_setting;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetDDnsInternetSettng");
                    in_internet_setting = new VPN.VpnInternetSetting({
                        ProxyType_u32: VPN.VpnRpcProxyType.Direct,
                        ProxyHostName_str: "1.2.3.4",
                        ProxyPort_u32: 1234,
                        ProxyUsername_str: "neko",
                        ProxyPassword_str: "dog"
                    });
                    return [4 /*yield*/, api.SetDDnsInternetSettng(in_internet_setting)];
                case 1:
                    out_internet_setting = _a.sent();
                    console.log(out_internet_setting);
                    console.log("End: Test_SetDDnsInternetSettng");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'SetVgsConfig', Setting VPN Gate Server Configuration */
function Test_SetVgsConfig() {
    return __awaiter(this, void 0, void 0, function () {
        var in_vgs_config, out_vgs_config;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_SetVgsConfig");
                    in_vgs_config = new VPN.VpnVgsConfig({
                        IsEnabled_bool: false,
                        Message_utf: "Neko san!!!",
                        Owner_utf: "Go go go!!!",
                        Abuse_utf: "da.test@softether.co.jp",
                        NoLog_bool: false,
                        LogPermanent_bool: true,
                        EnableL2TP_bool: true
                    });
                    return [4 /*yield*/, api.SetVgsConfig(in_vgs_config)];
                case 1:
                    out_vgs_config = _a.sent();
                    console.log(out_vgs_config);
                    console.log("End: Test_SetVgsConfig");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
/** API test for 'GetVgsConfig', Get VPN Gate configuration */
function Test_GetVgsConfig() {
    return __awaiter(this, void 0, void 0, function () {
        var out_vgs_config;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Begin: Test_GetVgsConfig");
                    return [4 /*yield*/, api.GetVgsConfig()];
                case 1:
                    out_vgs_config = _a.sent();
                    console.log(out_vgs_config);
                    console.log("End: Test_GetVgsConfig");
                    console.log("-----");
                    console.log();
                    return [2 /*return*/];
            }
        });
    });
}
//# sourceMappingURL=sample.js.map
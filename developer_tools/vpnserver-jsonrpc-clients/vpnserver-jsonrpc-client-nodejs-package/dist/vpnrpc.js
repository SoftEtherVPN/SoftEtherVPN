"use strict";
// SoftEther VPN Server JSON-RPC Stub code for TypeScript
// 
// vpnrpc.ts
// Automatically generated at 2019-05-29 18:21:39 by vpnserver-jsonrpc-codegen
//
// Licensed under the Apache License 2.0
// Copyright (c) 2014-2019 SoftEther VPN Project
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
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
exports.__esModule = true;
// Trivial utility codes
var is_node_js = (typeof navigator === "undefined") || navigator.userAgent.indexOf("Node.js") !== -1 || navigator.userAgent.indexOf("jsdom") !== -1;
function is_null(obj) {
    return (typeof obj === "undefined") || (obj === null);
}
var debug_mode = false;
/** VPN Server RPC Stubs */
var VpnServerRpc = /** @class */ (function () {
    /**
     * Constructor of the VpnServerRpc class
     * @param vpnserver_hostname The hostname or IP address of the destination VPN Server. In the web browser you can specify null if you want to connect to the server itself.
     * @param vpnserver_port The port number of the destination VPN Server. In the web browser you can specify null if you want to connect to the server itself.
     * @param hubname The name of the Virtual Hub if you want to connect to the VPN Server as a Virtual Hub Admin Mode. Specify null if you want to connect to the VPN Server as the Entire VPN Server Admin Mode.
     * @param password Specify the administration password. This value is valid only if vpnserver_hostname is sepcified.
     * @param nodejs_https_client_reject_untrusted_server_cert In Node.js set this true to check the SSL server certificate on the destination VPN Server. Set this false to ignore the SSL server certification.
     */
    function VpnServerRpc(vpnserver_hostname, vpnserver_port, hubname, password, nodejs_https_client_reject_untrusted_server_cert) {
        var _this = this;
        // --- Stubs ---
        /** Test RPC function. Input any integer value to the IntValue_u32 field. Then the server will convert the integer to the string, and return the string in the StrValue_str field. */
        this.Test = function (in_param) {
            return _this.CallAsync("Test", in_param);
        };
        /** Get server information. This allows you to obtain the server information of the currently connected VPN Server or VPN Bridge. Included in the server information are the version number, build number and build information. You can also obtain information on the current server operation mode and the information of operating system that the server is operating on. */
        this.GetServerInfo = function () {
            return _this.CallAsync("GetServerInfo", new VpnRpcServerInfo());
        };
        /** Get Current Server Status. This allows you to obtain in real-time the current status of the currently connected VPN Server or VPN Bridge. You can get statistical information on data communication and the number of different kinds of objects that exist on the server. You can get information on how much memory is being used on the current computer by the OS. */
        this.GetServerStatus = function () {
            return _this.CallAsync("GetServerStatus", new VpnRpcServerStatus());
        };
        /** Create New TCP Listener. This allows you to create a new TCP Listener on the server. By creating the TCP Listener the server starts listening for a connection from clients at the specified TCP/IP port number. A TCP Listener that has been created can be deleted by the DeleteListener API. You can also get a list of TCP Listeners currently registered by using the EnumListener API. To execute this API, you must have VPN Server administrator privileges. */
        this.CreateListener = function (in_param) {
            return _this.CallAsync("CreateListener", in_param);
        };
        /** Get List of TCP Listeners. This allows you to get a list of TCP listeners registered on the current server. You can obtain information on whether the various TCP listeners have a status of operating or error. To call this API, you must have VPN Server administrator privileges. */
        this.EnumListener = function () {
            return _this.CallAsync("EnumListener", new VpnRpcListenerList());
        };
        /** Delete TCP Listener. This allows you to delete a TCP Listener that's registered on the server. When the TCP Listener is in a state of operation, the listener will automatically be deleted when its operation stops. You can also get a list of TCP Listeners currently registered by using the EnumListener API. To call this API, you must have VPN Server administrator privileges. */
        this.DeleteListener = function (in_param) {
            return _this.CallAsync("DeleteListener", in_param);
        };
        /** Enable / Disable TCP Listener. This starts or stops the operation of TCP Listeners registered on the current server. You can also get a list of TCP Listeners currently registered by using the EnumListener API. To call this API, you must have VPN Server administrator privileges. */
        this.EnableListener = function (in_param) {
            return _this.CallAsync("EnableListener", in_param);
        };
        /** Set VPN Server Administrator Password. This sets the VPN Server administrator password. You can specify the password as a parameter. To call this API, you must have VPN Server administrator privileges. */
        this.SetServerPassword = function (in_param) {
            return _this.CallAsync("SetServerPassword", in_param);
        };
        /** Set the VPN Server clustering configuration. Use this to set the VPN Server type as Standalone Server, Cluster Controller Server or Cluster Member Server. Standalone server means a VPN Server that does not belong to any cluster in its current state. When VPN Server is installed, by default it will be in standalone server mode. Unless you have particular plans to configure a cluster, we recommend the VPN Server be operated in standalone mode. A cluster controller is the central computer of all member servers of a cluster in the case where a clustering environment is made up of multiple VPN Servers. Multiple cluster members can be added to the cluster as required. A cluster requires one computer to serve this role. The other cluster member servers that are configured in the same cluster begin operation as a cluster member by connecting to the cluster controller. To call this API, you must have VPN Server administrator privileges. Also, when this API is executed, VPN Server will automatically restart. This API cannot be called on VPN Bridge. */
        this.SetFarmSetting = function (in_param) {
            return _this.CallAsync("SetFarmSetting", in_param);
        };
        /** Get Clustering Configuration of Current VPN Server. You can use this to acquire the clustering configuration of the current VPN Server. To call this API, you must have VPN Server administrator privileges. */
        this.GetFarmSetting = function () {
            return _this.CallAsync("GetFarmSetting", new VpnRpcFarm());
        };
        /** Get Cluster Member Information. When the VPN Server is operating as a cluster controller, you can get information on cluster member servers on that cluster by specifying the IDs of the member servers. You can get the following information about the specified cluster member server: Server Type, Time Connection has been Established, IP Address, Host Name, Points, Public Port List, Number of Operating Virtual Hubs, First Virtual Hub, Number of Sessions and Number of TCP Connections. This API cannot be invoked on VPN Bridge. */
        this.GetFarmInfo = function (in_param) {
            return _this.CallAsync("GetFarmInfo", in_param);
        };
        /** Get List of Cluster Members. Use this API when the VPN Server is operating as a cluster controller to get a list of the cluster member servers on the same cluster, including the cluster controller itself. For each member, the following information is also listed: Type, Connection Start, Host Name, Points, Number of Session, Number of TCP Connections, Number of Operating Virtual Hubs, Using Client Connection License and Using Bridge Connection License. This API cannot be invoked on VPN Bridge. */
        this.EnumFarmMember = function () {
            return _this.CallAsync("EnumFarmMember", new VpnRpcEnumFarm());
        };
        /** Get Connection Status to Cluster Controller. Use this API when the VPN Server is operating as a cluster controller to get the status of connection to the cluster controller. You can get the following information: Controller IP Address, Port Number, Connection Status, Connection Start Time, First Connection Established Time, Current Connection Established Time, Number of Connection Attempts, Number of Successful Connections, Number of Failed Connections. This API cannot be invoked on VPN Bridge. */
        this.GetFarmConnectionStatus = function () {
            return _this.CallAsync("GetFarmConnectionStatus", new VpnRpcFarmConnectionStatus());
        };
        /** Set SSL Certificate and Private Key of VPN Server. You can set the SSL certificate that the VPN Server provides to the connected client and the private key for that certificate. The certificate must be in X.509 format and the private key must be Base 64 encoded format. To call this API, you must have VPN Server administrator privileges. */
        this.SetServerCert = function (in_param) {
            return _this.CallAsync("SetServerCert", in_param);
        };
        /** Get SSL Certificate and Private Key of VPN Server. Use this to get the SSL certificate private key that the VPN Server provides to the connected client. To call this API, you must have VPN Server administrator privileges. */
        this.GetServerCert = function () {
            return _this.CallAsync("GetServerCert", new VpnRpcKeyPair());
        };
        /** Get the Encrypted Algorithm Used for VPN Communication. Use this API to get the current setting of the algorithm used for the electronic signature and encrypted for SSL connection to be used for communication between the VPN Server and the connected client and the list of algorithms that can be used on the VPN Server. */
        this.GetServerCipher = function () {
            return _this.CallAsync("GetServerCipher", new VpnRpcStr());
        };
        /** Set the Encrypted Algorithm Used for VPN Communication. Use this API to set the algorithm used for the electronic signature and encrypted for SSL connections to be used for communication between the VPN Server and the connected client. By specifying the algorithm name, the specified algorithm will be used later between the VPN Client and VPN Bridge connected to this server and the data will be encrypted. To call this API, you must have VPN Server administrator privileges. */
        this.SetServerCipher = function (in_param) {
            return _this.CallAsync("SetServerCipher", in_param);
        };
        /** Create New Virtual Hub. Use this to create a new Virtual Hub on the VPN Server. The created Virtual Hub will begin operation immediately. When the VPN Server is operating on a cluster, this API is only valid for the cluster controller. Also, the new Virtual Hub will operate as a dynamic Virtual Hub. You can change it to a static Virtual Hub by using the SetHub API. To get a list of Virtual Hubs that are already on the VPN Server, use the EnumHub API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Servers that are operating as a VPN Bridge or cluster member. */
        this.CreateHub = function (in_param) {
            return _this.CallAsync("CreateHub", in_param);
        };
        /** Set the Virtual Hub configuration. You can call this API to change the configuration of the specified Virtual Hub. You can set the Virtual Hub online or offline. You can set the maximum number of sessions that can be concurrently connected to the Virtual Hub that is currently being managed. You can set the Virtual Hub administrator password. You can set other parameters for the Virtual Hub. Before call this API, you need to obtain the latest state of the Virtual Hub by using the GetHub API. */
        this.SetHub = function (in_param) {
            return _this.CallAsync("SetHub", in_param);
        };
        /** Get the Virtual Hub configuration. You can call this API to get the current configuration of the specified Virtual Hub. To change the configuration of the Virtual Hub, call the SetHub API. */
        this.GetHub = function (in_param) {
            return _this.CallAsync("GetHub", in_param);
        };
        /** Get List of Virtual Hubs. Use this to get a list of existing Virtual Hubs on the VPN Server. For each Virtual Hub, you can get the following information: Virtual Hub Name, Status, Type, Number of Users, Number of Groups, Number of Sessions, Number of MAC Tables, Number of IP Tables, Number of Logins, Last Login, and Last Communication. Note that when connecting in Virtual Hub Admin Mode, if in the options of a Virtual Hub that you do not have administrator privileges for, the option Don't Enumerate this Virtual Hub for Anonymous Users is enabled then that Virtual Hub will not be enumerated. If you are connected in Server Admin Mode, then the list of all Virtual Hubs will be displayed. When connecting to and managing a non-cluster-controller cluster member of a clustering environment, only the Virtual Hub currently being hosted by that VPN Server will be displayed. When connecting to a cluster controller for administration purposes, all the Virtual Hubs will be displayed. */
        this.EnumHub = function () {
            return _this.CallAsync("EnumHub", new VpnRpcEnumHub());
        };
        /** Delete Virtual Hub. Use this to delete an existing Virtual Hub on the VPN Server. If you delete the Virtual Hub, all sessions that are currently connected to the Virtual Hub will be disconnected and new sessions will be unable to connect to the Virtual Hub. Also, this will also delete all the Hub settings, user objects, group objects, certificates and Cascade Connections. Once you delete the Virtual Hub, it cannot be recovered. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Servers that are operating as a VPN Bridge or cluster member. */
        this.DeleteHub = function (in_param) {
            return _this.CallAsync("DeleteHub", in_param);
        };
        /** Get Setting of RADIUS Server Used for User Authentication. Use this to get the current settings for the RADIUS server used when a user connects to the currently managed Virtual Hub using RADIUS Server Authentication Mode. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.GetHubRadius = function (in_param) {
            return _this.CallAsync("GetHubRadius", in_param);
        };
        /** Set RADIUS Server to use for User Authentication. To accept users to the currently managed Virtual Hub in RADIUS server authentication mode, you can specify an external RADIUS server that confirms the user name and password. (You can specify multiple hostname by splitting with comma or semicolon.) The RADIUS server must be set to receive requests from IP addresses of this VPN Server. Also, authentication by Password Authentication Protocol (PAP) must be enabled. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.SetHubRadius = function (in_param) {
            return _this.CallAsync("SetHubRadius", in_param);
        };
        /** Get List of TCP Connections Connecting to the VPN Server. Use this to get a list of TCP/IP connections that are currently connecting to the VPN Server. It does not display the TCP connections that have been established as VPN sessions. To get the list of TCP/IP connections that have been established as VPN sessions, you can use the EnumSession API. You can get the following: Connection Name, Connection Source, Connection Start and Type. To call this API, you must have VPN Server administrator privileges. */
        this.EnumConnection = function () {
            return _this.CallAsync("EnumConnection", new VpnRpcEnumConnection());
        };
        /** Disconnect TCP Connections Connecting to the VPN Server. Use this to forcefully disconnect specific TCP/IP connections that are connecting to the VPN Server. To call this API, you must have VPN Server administrator privileges. */
        this.DisconnectConnection = function (in_param) {
            return _this.CallAsync("DisconnectConnection", in_param);
        };
        /** Get Information of TCP Connections Connecting to the VPN Server. Use this to get detailed information of a specific TCP/IP connection that is connecting to the VPN Server. You can get the following information: Connection Name, Connection Type, Source Hostname, Source IP Address, Source Port Number (TCP), Connection Start, Server Product Name, Server Version, Server Build Number, Client Product Name, Client Version, and Client Build Number. To call this API, you must have VPN Server administrator privileges. */
        this.GetConnectionInfo = function (in_param) {
            return _this.CallAsync("GetConnectionInfo", in_param);
        };
        /** Switch Virtual Hub to Online or Offline. Use this to set the Virtual Hub to online or offline. A Virtual Hub with an offline status cannot receive VPN connections from clients. When you set the Virtual Hub offline, all sessions will be disconnected. A Virtual Hub with an offline status cannot receive VPN connections from clients. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.SetHubOnline = function (in_param) {
            return _this.CallAsync("SetHubOnline", in_param);
        };
        /** Get Current Status of Virtual Hub. Use this to get the current status of the Virtual Hub currently being managed. You can get the following information: Virtual Hub Type, Number of Sessions, Number of Each Type of Object, Number of Logins, Last Login, Last Communication, and Communication Statistical Data. */
        this.GetHubStatus = function (in_param) {
            return _this.CallAsync("GetHubStatus", in_param);
        };
        /** Set the logging configuration of the Virtual Hub. Use this to enable or disable a security log or packet logs of the Virtual Hub currently being managed, set the save contents of the packet log for each type of packet to be saved, and set the log file switch cycle for the security log or packet log that the currently managed Virtual Hub saves. There are the following packet types: TCP Connection Log, TCP Packet Log, DHCP Packet Log, UDP Packet Log, ICMP Packet Log, IP Packet Log, ARP Packet Log, and Ethernet Packet Log. To get the current setting, you can use the LogGet API. The log file switch cycle can be changed to switch in every second, every minute, every hour, every day, every month or not switch. To get the current setting, you can use the GetHubLog API. */
        this.SetHubLog = function (in_param) {
            return _this.CallAsync("SetHubLog", in_param);
        };
        /** Get the logging configuration of the Virtual Hub. Use this to get the configuration for a security log or packet logs of the Virtual Hub currently being managed, get the setting for save contents of the packet log for each type of packet to be saved, and get the log file switch cycle for the security log or packet log that the currently managed Virtual Hub saves. To set the current setting, you can use the SetHubLog API. */
        this.GetHubLog = function (in_param) {
            return _this.CallAsync("GetHubLog", in_param);
        };
        /** Add Trusted CA Certificate. Use this to add a new certificate to a list of CA certificates trusted by the currently managed Virtual Hub. The list of certificate authority certificates that are registered is used to verify certificates when a VPN Client is connected in signed certificate authentication mode. To get a list of the current certificates you can use the EnumCa API. The certificate you add must be saved in the X.509 file format. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
        this.AddCa = function (in_param) {
            return _this.CallAsync("AddCa", in_param);
        };
        /** Get List of Trusted CA Certificates. Here you can manage the certificate authority certificates that are trusted by this currently managed Virtual Hub. The list of certificate authority certificates that are registered is used to verify certificates when a VPN Client is connected in signed certificate authentication mode. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
        this.EnumCa = function (in_param) {
            return _this.CallAsync("EnumCa", in_param);
        };
        /** Get Trusted CA Certificate. Use this to get an existing certificate from the list of CA certificates trusted by the currently managed Virtual Hub and save it as a file in X.509 format. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
        this.GetCa = function (in_param) {
            return _this.CallAsync("GetCa", in_param);
        };
        /** Delete Trusted CA Certificate. Use this to delete an existing certificate from the list of CA certificates trusted by the currently managed Virtual Hub. To get a list of the current certificates you can use the EnumCa API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
        this.DeleteCa = function (in_param) {
            return _this.CallAsync("DeleteCa", in_param);
        };
        /** Create New Cascade Connection. Use this to create a new Cascade Connection on the currently managed Virtual Hub. By using a Cascade Connection, you can connect this Virtual Hub by Cascade Connection to another Virtual Hub that is operating on the same or a different computer. To create a Cascade Connection, you must specify the name of the Cascade Connection, destination server and destination Virtual Hub and user name. When a new Cascade Connection is created, the type of user authentication is initially set as Anonymous Authentication and the proxy server setting and the verification options of the server certificate is not set. To change these settings and other advanced settings after a Cascade Connection has been created, use the other APIs that include the name "Link". [Warning About Cascade Connections] By connecting using a Cascade Connection you can create a Layer 2 bridge between multiple Virtual Hubs but if the connection is incorrectly configured, a loopback Cascade Connection could inadvertently be created. When using a Cascade Connection function please design the network topology with care. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.CreateLink = function (in_param) {
            return _this.CallAsync("CreateLink", in_param);
        };
        /** Get the Cascade Connection Setting. Use this to get the Connection Setting of a Cascade Connection that is registered on the currently managed Virtual Hub. To change the Connection Setting contents of the Cascade Connection, use the APIs that include the name "Link" after creating the Cascade Connection. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.GetLink = function (in_param) {
            return _this.CallAsync("GetLink", in_param);
        };
        /** Change Existing Cascade Connection. Use this to alter the setting of an existing Cascade Connection on the currently managed Virtual Hub. */
        this.SetLink = function (in_param) {
            return _this.CallAsync("SetLink", in_param);
        };
        /** Get List of Cascade Connections. Use this to get a list of Cascade Connections that are registered on the currently managed Virtual Hub. By using a Cascade Connection, you can connect this Virtual Hub by Layer 2 Cascade Connection to another Virtual Hub that is operating on the same or a different computer. [Warning About Cascade Connections] By connecting using a Cascade Connection you can create a Layer 2 bridge between multiple Virtual Hubs but if the connection is incorrectly configured, a loopback Cascade Connection could inadvertently be created. When using a Cascade Connection function please design the network topology with care. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.EnumLink = function (in_param) {
            return _this.CallAsync("EnumLink", in_param);
        };
        /** Switch Cascade Connection to Online Status. When a Cascade Connection registered on the currently managed Virtual Hub is specified, use this to switch that Cascade Connection to online status. The Cascade Connection that is switched to online status begins the process of connecting to the destination VPN Server in accordance with the Connection Setting. The Cascade Connection that is switched to online status will establish normal connection to the VPN Server or continue to attempt connection until it is switched to offline status. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.SetLinkOnline = function (in_param) {
            return _this.CallAsync("SetLinkOnline", in_param);
        };
        /** Switch Cascade Connection to Offline Status. When a Cascade Connection registered on the currently managed Virtual Hub is specified, use this to switch that Cascade Connection to offline status. The Cascade Connection that is switched to offline will not connect to the VPN Server until next time it is switched to the online status using the SetLinkOnline API You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.SetLinkOffline = function (in_param) {
            return _this.CallAsync("SetLinkOffline", in_param);
        };
        /** Delete Cascade Connection Setting. Use this to delete a Cascade Connection that is registered on the currently managed Virtual Hub. If the specified Cascade Connection has a status of online, the connections will be automatically disconnected and then the Cascade Connection will be deleted. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.DeleteLink = function (in_param) {
            return _this.CallAsync("DeleteLink", in_param);
        };
        /** Change Name of Cascade Connection. When a Cascade Connection registered on the currently managed Virtual Hub is specified, use this to change the name of that Cascade Connection. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.RenameLink = function (in_param) {
            return _this.CallAsync("RenameLink", in_param);
        };
        /** Get Current Cascade Connection Status. When a Cascade Connection registered on the currently managed Virtual Hub is specified and that Cascade Connection is currently online, use this to get its connection status and other information. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.GetLinkStatus = function (in_param) {
            return _this.CallAsync("GetLinkStatus", in_param);
        };
        /** Add Access List Rule. Use this to add a new rule to the access list of the currently managed Virtual Hub. The access list is a set of packet file rules that are applied to packets that flow through the Virtual Hub. You can register multiple rules in an access list and you can also define an priority for each rule. All packets are checked for the conditions specified by the rules registered in the access list and based on the operation that is stipulated by the first matching rule, they either pass or are discarded. Packets that do not match any rule are implicitly allowed to pass. You can also use the access list to generate delays, jitters and packet losses. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
        this.AddAccess = function (in_param) {
            return _this.CallAsync("AddAccess", in_param);
        };
        /** Delete Rule from Access List. Use this to specify a packet filter rule registered on the access list of the currently managed Virtual Hub and delete it. To delete a rule, you must specify that rule's ID. You can display the ID by using the EnumAccess API. If you wish not to delete the rule but to only temporarily disable it, use the SetAccessList API to set the rule status to disable. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
        this.DeleteAccess = function (in_param) {
            return _this.CallAsync("DeleteAccess", in_param);
        };
        /** Get Access List Rule List. Use this to get a list of packet filter rules that are registered on access list of the currently managed Virtual Hub. The access list is a set of packet file rules that are applied to packets that flow through the Virtual Hub. You can register multiple rules in an access list and you can also define a priority for each rule. All packets are checked for the conditions specified by the rules registered in the access list and based on the operation that is stipulated by the first matching rule, they either pass or are discarded. Packets that do not match any rule are implicitly allowed to pass. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
        this.EnumAccess = function (in_param) {
            return _this.CallAsync("EnumAccess", in_param);
        };
        /** Replace all access lists on a single bulk API call. This API removes all existing access list rules on the Virtual Hub, and replace them by new access list rules specified by the parameter. */
        this.SetAccessList = function (in_param) {
            return _this.CallAsync("SetAccessList", in_param);
        };
        /** Create a user. Use this to create a new user in the security account database of the currently managed Virtual Hub. By creating a user, the VPN Client can connect to the Virtual Hub by using the authentication information of that user. Note that a user whose user name has been created as "*" (a single asterisk character) will automatically be registered as a RADIUS authentication user. For cases where there are users with "*" as the name, when a user, whose user name that has been provided when a client connected to a VPN Server does not match existing user names, is able to be authenticated by a RADIUS server or NT domain controller by inputting a user name and password, the authentication settings and security policy settings will follow the setting for the user "*". To change the user information of a user that has been created, use the SetUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
        this.CreateUser = function (in_param) {
            return _this.CallAsync("CreateUser", in_param);
        };
        /** Change User Settings. Use this to change user settings that is registered on the security account database of the currently managed Virtual Hub. The user settings that can be changed using this API are the three items that are specified when a new user is created using the CreateUser API: Group Name, Full Name, and Description. To get the list of currently registered users, use the EnumUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
        this.SetUser = function (in_param) {
            return _this.CallAsync("SetUser", in_param);
        };
        /** Get User Settings. Use this to get user settings information that is registered on the security account database of the currently managed Virtual Hub. The information that you can get using this API are User Name, Full Name, Group Name, Expiration Date, Security Policy, and Auth Type, as well as parameters that are specified as auth type attributes and the statistical data of that user. To get the list of currently registered users, use the EnumUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
        this.GetUser = function (in_param) {
            return _this.CallAsync("GetUser", in_param);
        };
        /** Delete a user. Use this to delete a user that is registered on the security account database of the currently managed Virtual Hub. By deleting the user, that user will no long be able to connect to the Virtual Hub. You can use the SetUser API to set the user's security policy to deny access instead of deleting a user, set the user to be temporarily denied from logging in. To get the list of currently registered users, use the EnumUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
        this.DeleteUser = function (in_param) {
            return _this.CallAsync("DeleteUser", in_param);
        };
        /** Get List of Users. Use this to get a list of users that are registered on the security account database of the currently managed Virtual Hub. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
        this.EnumUser = function (in_param) {
            return _this.CallAsync("EnumUser", in_param);
        };
        /** Create Group. Use this to create a new group in the security account database of the currently managed Virtual Hub. You can register multiple users in a group. To register users in a group use the SetUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
        this.CreateGroup = function (in_param) {
            return _this.CallAsync("CreateGroup", in_param);
        };
        /** Set group settings. Use this to set group settings that is registered on the security account database of the currently managed Virtual Hub. To get the list of currently registered groups, use the EnumGroup API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
        this.SetGroup = function (in_param) {
            return _this.CallAsync("SetGroup", in_param);
        };
        /** Get Group Setting (Sync mode). Use this to get the setting of a group that is registered on the security account database of the currently managed Virtual Hub. To get the list of currently registered groups, use the EnumGroup API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
        this.GetGroup = function (in_param) {
            return _this.CallAsync("GetGroup", in_param);
        };
        /** Delete User from Group. Use this to delete a specified user from the group that is registered on the security account database of the currently managed Virtual Hub. By deleting a user from the group, that user becomes unassigned. To get the list of currently registered groups, use the EnumGroup API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
        this.DeleteGroup = function (in_param) {
            return _this.CallAsync("DeleteGroup", in_param);
        };
        /** Get List of Groups. Use this to get a list of groups that are registered on the security account database of the currently managed Virtual Hub. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
        this.EnumGroup = function (in_param) {
            return _this.CallAsync("EnumGroup", in_param);
        };
        /** Get List of Connected VPN Sessions. Use this to get a list of the sessions connected to the Virtual Hub currently being managed. In the list of sessions, the following information will be obtained for each connection: Session Name, Session Site, User Name, Source Host Name, TCP Connection, Transfer Bytes and Transfer Packets. If the currently connected VPN Server is a cluster controller and the currently managed Virtual Hub is a static Virtual Hub, you can get an all-linked-together list of all sessions connected to that Virtual Hub on all cluster members. In all other cases, only the list of sessions that are actually connected to the currently managed VPN Server will be obtained. */
        this.EnumSession = function (in_param) {
            return _this.CallAsync("EnumSession", in_param);
        };
        /** Get Session Status. Use this to specify a session currently connected to the currently managed Virtual Hub and get the session information. The session status includes the following: source host name and user name, version information, time information, number of TCP connections, communication parameters, session key, statistical information on data transferred, and other client and server information. To get the list of currently connected sessions, use the EnumSession API. */
        this.GetSessionStatus = function (in_param) {
            return _this.CallAsync("GetSessionStatus", in_param);
        };
        /** Disconnect Session. Use this to specify a session currently connected to the currently managed Virtual Hub and forcefully disconnect that session using manager privileges. Note that when communication is disconnected by settings on the source client side and the automatically reconnect option is enabled, it is possible that the client will reconnect. To get the list of currently connected sessions, use the EnumSession API. */
        this.DeleteSession = function (in_param) {
            return _this.CallAsync("DeleteSession", in_param);
        };
        /** Get the MAC Address Table Database. Use this to get the MAC address table database that is held by the currently managed Virtual Hub. The MAC address table database is a table that the Virtual Hub requires to perform the action of switching Ethernet frames and the Virtual Hub decides the sorting destination session of each Ethernet frame based on the MAC address table database. The MAC address database is built by the Virtual Hub automatically analyzing the contents of the communication. */
        this.EnumMacTable = function (in_param) {
            return _this.CallAsync("EnumMacTable", in_param);
        };
        /** Delete MAC Address Table Entry. Use this API to operate the MAC address table database held by the currently managed Virtual Hub and delete a specified MAC address table entry from the database. To get the contents of the current MAC address table database use the EnumMacTable API. */
        this.DeleteMacTable = function (in_param) {
            return _this.CallAsync("DeleteMacTable", in_param);
        };
        /** Get the IP Address Table Database. Use this to get the IP address table database that is held by the currently managed Virtual Hub. The IP address table database is a table that is automatically generated by analyzing the contents of communication so that the Virtual Hub can always know which session is using which IP address and it is frequently used by the engine that applies the Virtual Hub security policy. By specifying the session name you can get the IP address table entry that has been associated with that session. */
        this.EnumIpTable = function (in_param) {
            return _this.CallAsync("EnumIpTable", in_param);
        };
        /** Delete IP Address Table Entry. Use this API to operate the IP address table database held by the currently managed Virtual Hub and delete a specified IP address table entry from the database. To get the contents of the current IP address table database use the EnumIpTable API. */
        this.DeleteIpTable = function (in_param) {
            return _this.CallAsync("DeleteIpTable", in_param);
        };
        /** Set the Keep Alive Internet Connection Function. Use this to set the destination host name etc. of the Keep Alive Internet Connection Function. For network connection environments where connections will automatically be disconnected where there are periods of no communication that are longer than a set period, by using the Keep Alive Internet Connection Function, it is possible to keep alive the Internet connection by sending packets to a nominated server on the Internet at set intervals. When using this API, you can specify the following: Host Name, Port Number, Packet Send Interval, and Protocol. Packets sent to keep alive the Internet connection will have random content and personal information that could identify a computer or user is not sent. You can use the SetKeep API to enable/disable the Keep Alive Internet Connection Function. To execute this API on a VPN Server or VPN Bridge, you must have administrator privileges. */
        this.SetKeep = function (in_param) {
            return _this.CallAsync("SetKeep", in_param);
        };
        /** Get the Keep Alive Internet Connection Function. Use this to get the current setting contents of the Keep Alive Internet Connection Function. In addition to the destination's Host Name, Port Number, Packet Send Interval and Protocol, you can obtain the current enabled/disabled status of the Keep Alive Internet Connection Function. */
        this.GetKeep = function (in_param) {
            return _this.CallAsync("GetKeep", in_param);
        };
        /** Enable the Virtual NAT and DHCP Server Function (SecureNAT Function). Use this to enable the Virtual NAT and DHCP Server function (SecureNAT Function) on the currently managed Virtual Hub and begin its operation. Before executing this API, you must first check the setting contents of the current Virtual NAT function and DHCP Server function using the SetSecureNATOption API and GetSecureNATOption API. By enabling the SecureNAT function, you can virtually operate a NAT router (IP masquerade) and the DHCP Server function on a virtual network on the Virtual Hub. [Warning about SecureNAT Function] The SecureNAT function is recommended only for system administrators and people with a detailed knowledge of networks. If you use the SecureNAT function correctly, it is possible to achieve a safe form of remote access via a VPN. However when used in the wrong way, it can put the entire network in danger. Anyone who does not have a thorough knowledge of networks and anyone who does not have the network administrator's permission must not enable the SecureNAT function. For a detailed explanation of the SecureNAT function, please refer to the VPN Server's manual and online documentation. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.EnableSecureNAT = function (in_param) {
            return _this.CallAsync("EnableSecureNAT", in_param);
        };
        /** Disable the Virtual NAT and DHCP Server Function (SecureNAT Function). Use this to disable the Virtual NAT and DHCP Server function (SecureNAT Function) on the currently managed Virtual Hub. By executing this API the Virtual NAT function immediately stops operating and the Virtual DHCP Server function deletes the DHCP lease database and stops the service. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.DisableSecureNAT = function (in_param) {
            return _this.CallAsync("DisableSecureNAT", in_param);
        };
        /** Change Settings of SecureNAT Function. Use this to change and save the virtual host network interface settings, virtual NAT function settings and virtual DHCP server settings of the Virtual NAT and DHCP Server function (SecureNAT function) on the currently managed Virtual Hub. The SecureNAT function holds one virtual network adapter on the L2 segment inside the Virtual Hub and it has been assigned a MAC address and an IP address. By doing this, another host connected to the same L2 segment is able to communicate with the SecureNAT virtual host as if it is an actual IP host existing on the network. [Warning about SecureNAT Function] The SecureNAT function is recommended only for system administrators and people with a detailed knowledge of networks. If you use the SecureNAT function correctly, it is possible to achieve a safe form of remote access via a VPN. However when used in the wrong way, it can put the entire network in danger. Anyone who does not have a thorough knowledge of networks and anyone who does not have the network administrators permission must not enable the SecureNAT function. For a detailed explanation of the SecureNAT function, please refer to the VPN Server's manual and online documentation. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.SetSecureNATOption = function (in_param) {
            return _this.CallAsync("SetSecureNATOption", in_param);
        };
        /** Get Settings of SecureNAT Function. This API get the registered settings for the SecureNAT function which is set by the SetSecureNATOption API. */
        this.GetSecureNATOption = function (in_param) {
            return _this.CallAsync("GetSecureNATOption", in_param);
        };
        /** Get Virtual NAT Function Session Table of SecureNAT Function. Use this to get the table of TCP and UDP sessions currently communicating via the Virtual NAT (NAT table) in cases when the Virtual NAT function is operating on the currently managed Virtual Hub. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.EnumNAT = function (in_param) {
            return _this.CallAsync("EnumNAT", in_param);
        };
        /** Get Virtual DHCP Server Function Lease Table of SecureNAT Function. Use this to get the lease table of IP addresses, held by the Virtual DHCP Server, that are assigned to clients in cases when the Virtual NAT function is operating on the currently managed Virtual Hub. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.EnumDHCP = function (in_param) {
            return _this.CallAsync("EnumDHCP", in_param);
        };
        /** Get the Operating Status of the Virtual NAT and DHCP Server Function (SecureNAT Function). Use this to get the operating status of the Virtual NAT and DHCP Server function (SecureNAT Function) when it is operating on the currently managed Virtual Hub. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.GetSecureNATStatus = function (in_param) {
            return _this.CallAsync("GetSecureNATStatus", in_param);
        };
        /** Get List of Network Adapters Usable as Local Bridge. Use this to get a list of Ethernet devices (network adapters) that can be used as a bridge destination device as part of a Local Bridge connection. If possible, network connection name is displayed. You can use a device displayed here by using the AddLocalBridge API. To call this API, you must have VPN Server administrator privileges. */
        this.EnumEthernet = function () {
            return _this.CallAsync("EnumEthernet", new VpnRpcEnumEth());
        };
        /** Create Local Bridge Connection. Use this to create a new Local Bridge connection on the VPN Server. By using a Local Bridge, you can configure a Layer 2 bridge connection between a Virtual Hub operating on this VPN server and a physical Ethernet Device (Network Adapter). You can create a tap device (virtual network interface) on the system and connect a bridge between Virtual Hubs (the tap device is only supported by Linux versions). It is possible to establish a bridge to an operating network adapter of your choice for the bridge destination Ethernet device (network adapter), but in high load environments, we recommend you prepare a network adapter dedicated to serve as a bridge. To call this API, you must have VPN Server administrator privileges. */
        this.AddLocalBridge = function (in_param) {
            return _this.CallAsync("AddLocalBridge", in_param);
        };
        /** Delete Local Bridge Connection. Use this to delete an existing Local Bridge connection. To get a list of current Local Bridge connections use the EnumLocalBridge API. To call this API, you must have VPN Server administrator privileges. */
        this.DeleteLocalBridge = function (in_param) {
            return _this.CallAsync("DeleteLocalBridge", in_param);
        };
        /** Get List of Local Bridge Connection. Use this to get a list of the currently defined Local Bridge connections. You can get the Local Bridge connection Virtual Hub name and the bridge destination Ethernet device (network adapter) name or tap device name, as well as the operating status. */
        this.EnumLocalBridge = function () {
            return _this.CallAsync("EnumLocalBridge", new VpnRpcEnumLocalBridge());
        };
        /** Get whether the localbridge function is supported on the current system. */
        this.GetBridgeSupport = function () {
            return _this.CallAsync("GetBridgeSupport", new VpnRpcBridgeSupport());
        };
        /** Reboot VPN Server Service. Use this to restart the VPN Server service. When you restart the VPN Server, all currently connected sessions and TCP connections will be disconnected and no new connections will be accepted until the restart process has completed. By using this API, only the VPN Server service program will be restarted and the physical computer that VPN Server is operating on does not restart. This management session will also be disconnected, so you will need to reconnect to continue management. Also, by specifying the "IntValue" parameter to "1", the contents of the configuration file (.config) held by the current VPN Server will be initialized. To call this API, you must have VPN Server administrator privileges. */
        this.RebootServer = function (in_param) {
            return _this.CallAsync("RebootServer", in_param);
        };
        /** Get List of Server Functions / Capability. Use this get a list of functions and capability of the VPN Server currently connected and being managed. The function and capability of VPN Servers are different depending on the operating VPN server's edition and version. Using this API, you can find out the capability of the target VPN Server and report it. */
        this.GetCaps = function () {
            return _this.CallAsync("GetCaps", new VpnCapslist());
        };
        /** Get the current configuration of the VPN Server. Use this to get a text file (.config file) that contains the current configuration contents of the VPN server. You can get the status on the VPN Server at the instant this API is executed. You can edit the configuration file by using a regular text editor. To write an edited configuration to the VPN Server, use the SetConfig API. To call this API, you must have VPN Server administrator privileges. */
        this.GetConfig = function () {
            return _this.CallAsync("GetConfig", new VpnRpcConfig());
        };
        /** Write Configuration File to VPN Server. Use this to write the configuration file to the VPN Server. By executing this API, the contents of the specified configuration file will be applied to the VPN Server and the VPN Server program will automatically restart and upon restart, operate according to the new configuration contents. Because it is difficult for an administrator to write all the contents of a configuration file, we recommend you use the GetConfig API to get the current contents of the VPN Server configuration and save it to file. You can then edit these contents in a regular text editor and then use the SetConfig API to rewrite the contents to the VPN Server. This API is for people with a detailed knowledge of the VPN Server and if an incorrectly configured configuration file is written to the VPN Server, it not only could cause errors, it could also result in the lost of the current setting data. Take special care when carrying out this action. To call this API, you must have VPN Server administrator privileges. */
        this.SetConfig = function (in_param) {
            return _this.CallAsync("SetConfig", in_param);
        };
        /** Get Virtual Hub Administration Option default values. */
        this.GetDefaultHubAdminOptions = function (in_param) {
            return _this.CallAsync("GetDefaultHubAdminOptions", in_param);
        };
        /** Get List of Virtual Hub Administration Options. Use this to get a list of Virtual Hub administration options that are set on the currently managed Virtual Hub. The purpose of the Virtual Hub administration options is for the VPN Server Administrator to set limits for the setting ranges when the administration of the Virtual Hub is to be trusted to each Virtual Hub administrator. Only an administrator with administration privileges for this entire VPN Server is able to add, edit and delete the Virtual Hub administration options. The Virtual Hub administrators are unable to make changes to the administration options, however they are able to view them. There is an exception however. If allow_hub_admin_change_option is set to "1", even Virtual Hub administrators are able to edit the administration options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member. */
        this.GetHubAdminOptions = function (in_param) {
            return _this.CallAsync("GetHubAdminOptions", in_param);
        };
        /** Set Values of Virtual Hub Administration Options. Use this to change the values of Virtual Hub administration options that are set on the currently managed Virtual Hub. The purpose of the Virtual Hub administration options is for the VPN Server Administrator to set limits for the setting ranges when the administration of the Virtual Hub is to be trusted to each Virtual Hub administrator. Only an administrator with administration privileges for this entire VPN Server is able to add, edit and delete the Virtual Hub administration options. The Virtual Hub administrators are unable to make changes to the administration options, however they are able to view them. There is an exception however. If allow_hub_admin_change_option is set to "1", even Virtual Hub administrators are able to edit the administration options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member. */
        this.SetHubAdminOptions = function (in_param) {
            return _this.CallAsync("SetHubAdminOptions", in_param);
        };
        /** Get List of Virtual Hub Extended Options. Use this to get a Virtual Hub Extended Options List that is set on the currently managed Virtual Hub. Virtual Hub Extended Option enables you to configure more detail settings of the Virtual Hub. By default, both VPN Server's global administrators and individual Virtual Hub's administrators can modify the Virtual Hub Extended Options. However, if the deny_hub_admin_change_ext_option is set to 1 on the Virtual Hub Admin Options, the individual Virtual Hub's administrators cannot modify the Virtual Hub Extended Options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member. */
        this.GetHubExtOptions = function (in_param) {
            return _this.CallAsync("GetHubExtOptions", in_param);
        };
        /** Set a Value of Virtual Hub Extended Options. Use this to set a value in the Virtual Hub Extended Options List that is set on the currently managed Virtual Hub. Virtual Hub Extended Option enables you to configure more detail settings of the Virtual Hub. By default, both VPN Server's global administrators and individual Virtual Hub's administrators can modify the Virtual Hub Extended Options. However, if the deny_hub_admin_change_ext_option is set to 1 on the Virtual Hub Admin Options, the individual Virtual Hub's administrators cannot modify the Virtual Hub Extended Options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member. */
        this.SetHubExtOptions = function (in_param) {
            return _this.CallAsync("SetHubExtOptions", in_param);
        };
        /** Define New Virtual Layer 3 Switch. Use this to define a new Virtual Layer 3 Switch on the VPN Server. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. [Explanation on Virtual Layer 3 Switch Function] You can define Virtual Layer 3 Switches between multiple Virtual Hubs operating on this VPN Server and configure routing between different IP networks. [Caution about the Virtual Layer 3 Switch Function] The Virtual Layer 3 Switch functions are provided for network administrators and other people who know a lot about networks and IP routing. If you are using the regular VPN functions, you do not need to use the Virtual Layer 3 Switch functions. If the Virtual Layer 3 Switch functions are to be used, the person who configures them must have sufficient knowledge of IP routing and be perfectly capable of not impacting the network. */
        this.AddL3Switch = function (in_param) {
            return _this.CallAsync("AddL3Switch", in_param);
        };
        /** Delete Virtual Layer 3 Switch. Use this to delete an existing Virtual Layer 3 Switch that is defined on the VPN Server. When the specified Virtual Layer 3 Switch is operating, it will be automatically deleted after operation stops. To get a list of existing Virtual Layer 3 Switches, use the EnumL3Switch API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. */
        this.DelL3Switch = function (in_param) {
            return _this.CallAsync("DelL3Switch", in_param);
        };
        /** Get List of Virtual Layer 3 Switches. Use this to define a new Virtual Layer 3 Switch on the VPN Server. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. [Explanation on Virtual Layer 3 Switch Function] You can define Virtual Layer 3 Switches between multiple Virtual Hubs operating on this VPN Server and configure routing between different IP networks. [Caution about the Virtual Layer 3 Switch Function] The Virtual Layer 3 Switch functions are provided for network administrators and other people who know a lot about networks and IP routing. If you are using the regular VPN functions, you do not need to use the Virtual Layer 3 Switch functions. If the Virtual Layer 3 Switch functions are to be used, the person who configures them must have sufficient knowledge of IP routing and be perfectly capable of not impacting the network. */
        this.EnumL3Switch = function () {
            return _this.CallAsync("EnumL3Switch", new VpnRpcEnumL3Sw());
        };
        /** Start Virtual Layer 3 Switch Operation. Use this to start the operation of an existing Virtual Layer 3 Switch defined on the VPN Server whose operation is currently stopped. To get a list of existing Virtual Layer 3 Switches, use the EnumL3Switch API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. [Explanation on Virtual Layer 3 Switch Function] You can define Virtual Layer 3 Switches between multiple Virtual Hubs operating on this VPN Server and configure routing between different IP networks. [Caution about the Virtual Layer 3 Switch Function] The Virtual Layer 3 Switch functions are provided for network administrators and other people who know a lot about networks and IP routing. If you are using the regular VPN functions, you do not need to use the Virtual Layer 3 Switch functions. If the Virtual Layer 3 Switch functions are to be used, the person who configures them must have sufficient knowledge of IP routing and be perfectly capable of not impacting the network. */
        this.StartL3Switch = function (in_param) {
            return _this.CallAsync("StartL3Switch", in_param);
        };
        /** Stop Virtual Layer 3 Switch Operation. Use this to stop the operation of an existing Virtual Layer 3 Switch defined on the VPN Server whose operation is currently operating. To get a list of existing Virtual Layer 3 Switches, use the EnumL3Switch API. To call this API, you must have VPN Server administrator privileges. */
        this.StopL3Switch = function (in_param) {
            return _this.CallAsync("StopL3Switch", in_param);
        };
        /** Add Virtual Interface to Virtual Layer 3 Switch. Use this to add to a specified Virtual Layer 3 Switch, a virtual interface that connects to a Virtual Hub operating on the same VPN Server. You can define multiple virtual interfaces and routing tables for a single Virtual Layer 3 Switch. A virtual interface is associated to a virtual Hub and operates as a single IP host on the Virtual Hub when that Virtual Hub is operating. When multiple virtual interfaces that respectively belong to a different IP network of a different Virtual Hub are defined, IP routing will be automatically performed between these interfaces. You must define the IP network space that the virtual interface belongs to and the IP address of the interface itself. Also, you must specify the name of the Virtual Hub that the interface will connect to. You can specify a Virtual Hub that currently doesn't exist for the Virtual Hub name. The virtual interface must have one IP address in the Virtual Hub. You also must specify the subnet mask of an IP network that the IP address belongs to. Routing via the Virtual Layer 3 Switches of IP spaces of multiple virtual Hubs operates based on the IP address is specified here. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API. */
        this.AddL3If = function (in_param) {
            return _this.CallAsync("AddL3If", in_param);
        };
        /** Delete Virtual Interface of Virtual Layer 3 Switch. Use this to delete a virtual interface already defined in the specified Virtual Layer 3 Switch. You can get a list of the virtual interfaces currently defined, by using the EnumL3If API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API. */
        this.DelL3If = function (in_param) {
            return _this.CallAsync("DelL3If", in_param);
        };
        /** Get List of Interfaces Registered on the Virtual Layer 3 Switch. Use this to get a list of virtual interfaces when virtual interfaces have been defined on a specified Virtual Layer 3 Switch. You can define multiple virtual interfaces and routing tables for a single Virtual Layer 3 Switch. A virtual interface is associated to a virtual Hub and operates as a single IP host on the Virtual Hub when that Virtual Hub is operating. When multiple virtual interfaces that respectively belong to a different IP network of a different Virtual Hub are defined, IP routing will be automatically performed between these interfaces. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. */
        this.EnumL3If = function (in_param) {
            return _this.CallAsync("EnumL3If", in_param);
        };
        /** Add Routing Table Entry for Virtual Layer 3 Switch. Here you can add a new routing table entry to the routing table of the specified Virtual Layer 3 Switch. If the destination IP address of the IP packet does not belong to any IP network that belongs to a virtual interface, the IP routing engine of the Virtual Layer 3 Switch will reference the routing table and execute routing. You must specify the contents of the routing table entry to be added to the Virtual Layer 3 Switch. You must specify any IP address that belongs to the same IP network in the virtual interface of this Virtual Layer 3 Switch as the gateway address. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API. */
        this.AddL3Table = function (in_param) {
            return _this.CallAsync("AddL3Table", in_param);
        };
        /** Delete Routing Table Entry of Virtual Layer 3 Switch. Use this to delete a routing table entry that is defined in the specified Virtual Layer 3 Switch. You can get a list of the already defined routing table entries by using the EnumL3Table API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API. */
        this.DelL3Table = function (in_param) {
            return _this.CallAsync("DelL3Table", in_param);
        };
        /** Get List of Routing Tables of Virtual Layer 3 Switch. Use this to get a list of routing tables when routing tables have been defined on a specified Virtual Layer 3 Switch. If the destination IP address of the IP packet does not belong to any IP network that belongs to a virtual interface, the IP routing engine of the Virtual Layer 3 Switch will reference this routing table and execute routing. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. */
        this.EnumL3Table = function (in_param) {
            return _this.CallAsync("EnumL3Table", in_param);
        };
        /** Get List of Certificates Revocation List. Use this to get a Certificates Revocation List that is set on the currently managed Virtual Hub. By registering certificates in the Certificates Revocation List, the clients who provide these certificates will be unable to connect to this Virtual Hub using certificate authentication mode. Normally with this function, in cases where the security of a private key has been compromised or where a person holding a certificate has been stripped of their privileges, by registering that certificate as invalid on the Virtual Hub, it is possible to deny user authentication when that certificate is used by a client to connect to the Virtual Hub. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.EnumCrl = function (in_param) {
            return _this.CallAsync("EnumCrl", in_param);
        };
        /** Add a Revoked Certificate. Use this to add a new revoked certificate definition in the Certificate Revocation List that is set on the currently managed Virtual Hub. Specify the contents to be registered in the Certificate Revocation List by using the parameters of this API. When a user connects to a Virtual Hub in certificate authentication mode and that certificate matches 1 or more of the contents registered in the certificates revocation list, the user is denied connection. A certificate that matches all the conditions that are defined by the parameters specified by this API will be judged as invalid. The items that can be set are as follows: Name (CN), Organization (O), Organization Unit (OU), Country (C), State (ST), Locale (L), Serial Number (hexadecimal), MD5 Digest Value (hexadecimal, 128 bit), and SHA-1 Digest Value (hexadecimal, 160 bit). For the specification of a digest value (hash value) a certificate is optionally specified depending on the circumstances. Normally when a MD5 or SHA-1 digest value is input, it is not necessary to input the other items. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.AddCrl = function (in_param) {
            return _this.CallAsync("AddCrl", in_param);
        };
        /** Delete a Revoked Certificate. Use this to specify and delete a revoked certificate definition from the certificate revocation list that is set on the currently managed Virtual Hub. To get the list of currently registered revoked certificate definitions, use the EnumCrl API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.DelCrl = function (in_param) {
            return _this.CallAsync("DelCrl", in_param);
        };
        /** Get a Revoked Certificate. Use this to specify and get the contents of a revoked certificate definition from the Certificates Revocation List that is set on the currently managed Virtual Hub. To get the list of currently registered revoked certificate definitions, use the EnumCrl API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.GetCrl = function (in_param) {
            return _this.CallAsync("GetCrl", in_param);
        };
        /** Change Existing CRL (Certificate Revocation List) Entry. Use this to alter an existing revoked certificate definition in the Certificate Revocation List that is set on the currently managed Virtual Hub. Specify the contents to be registered in the Certificate Revocation List by using the parameters of this API. When a user connects to a Virtual Hub in certificate authentication mode and that certificate matches 1 or more of the contents registered in the certificates revocation list, the user is denied connection. A certificate that matches all the conditions that are defined by the parameters specified by this API will be judged as invalid. The items that can be set are as follows: Name (CN), Organization (O), Organization Unit (OU), Country (C), State (ST), Locale (L), Serial Number (hexadecimal), MD5 Digest Value (hexadecimal, 128 bit), and SHA-1 Digest Value (hexadecimal, 160 bit). For the specification of a digest value (hash value) a certificate is optionally specified depending on the circumstances. Normally when a MD5 or SHA-1 digest value is input, it is not necessary to input the other items. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.SetCrl = function (in_param) {
            return _this.CallAsync("SetCrl", in_param);
        };
        /** Add Rule to Source IP Address Limit List. Use this to add a new rule to the Source IP Address Limit List that is set on the currently managed Virtual Hub. The items set here will be used to decide whether to allow or deny connection from a VPN Client when this client attempts connection to the Virtual Hub. You can specify a client IP address, or IP address or mask to match the rule as the contents of the rule item. By specifying an IP address only, there will only be one specified computer that will match the rule, but by specifying an IP net mask address or subnet mask address, all the computers in the range of that subnet will match the rule. You can specify the priority for the rule. You can specify an integer of 1 or greater for the priority and the smaller the number, the higher the priority. To get a list of the currently registered Source IP Address Limit List, use the GetAcList API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.SetAcList = function (in_param) {
            return _this.CallAsync("SetAcList", in_param);
        };
        /** Get List of Rule Items of Source IP Address Limit List. Use this to get a list of Source IP Address Limit List rules that is set on the currently managed Virtual Hub. You can allow or deny VPN connections to this Virtual Hub according to the client computer's source IP address. You can define multiple rules and set a priority for each rule. The search proceeds from the rule with the highest order or priority and based on the action of the rule that the IP address first matches, the connection from the client is either allowed or denied. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.GetAcList = function (in_param) {
            return _this.CallAsync("GetAcList", in_param);
        };
        /** Get List of Log Files. Use this to display a list of log files outputted by the VPN Server that have been saved on the VPN Server computer. By specifying a log file file name displayed here and calling it using the ReadLogFile API you can download the contents of the log file. If you are connected to the VPN Server in server admin mode, you can display or download the packet logs and security logs of all Virtual Hubs and the server log of the VPN Server. When connected in Virtual Hub Admin Mode, you are able to view or download only the packet log and security log of the Virtual Hub that is the target of management. */
        this.EnumLogFile = function () {
            return _this.CallAsync("EnumLogFile", new VpnRpcEnumLogFile());
        };
        /** Download a part of Log File. Use this to download the log file that is saved on the VPN Server computer. To download the log file first get the list of log files using the EnumLogFile API and then download the log file using the ReadLogFile API. If you are connected to the VPN Server in server admin mode, you can display or download the packet logs and security logs of all Virtual Hubs and the server log of the VPN Server. When connected in Virtual Hub Admin Mode, you are able to view or download only the packet log and security log of the Virtual Hub that is the target of management. */
        this.ReadLogFile = function (in_param) {
            return _this.CallAsync("ReadLogFile", in_param);
        };
        /** Set syslog Send Function. Use this to set the usage of syslog send function and which syslog server to use. */
        this.SetSysLog = function (in_param) {
            return _this.CallAsync("SetSysLog", in_param);
        };
        /** Get syslog Send Function. This allows you to get the current setting contents of the syslog send function. You can get the usage setting of the syslog function and the host name and port number of the syslog server to use. */
        this.GetSysLog = function (in_param) {
            return _this.CallAsync("GetSysLog", in_param);
        };
        /** Set Today's Message of Virtual Hub. The message will be displayed on VPN Client UI when a user will establish a connection to the Virtual Hub. */
        this.SetHubMsg = function (in_param) {
            return _this.CallAsync("SetHubMsg", in_param);
        };
        /** Get Today's Message of Virtual Hub. The message will be displayed on VPN Client UI when a user will establish a connection to the Virtual Hub. */
        this.GetHubMsg = function (in_param) {
            return _this.CallAsync("GetHubMsg", in_param);
        };
        /** Raise a vital error on the VPN Server / Bridge to terminate the process forcefully. This API will raise a fatal error (memory access violation) on the VPN Server / Bridge running process in order to crash the process. As the result, VPN Server / Bridge will be terminated and restarted if it is running as a service mode. If the VPN Server is running as a user mode, the process will not automatically restarted. This API is for a situation when the VPN Server / Bridge is under a non-recoverable error or the process is in an infinite loop. This API will disconnect all VPN Sessions on the VPN Server / Bridge. All unsaved settings in the memory of VPN Server / Bridge will be lost. Before run this API, call the Flush API to try to save volatile data to the configuration file. To execute this API, you must have VPN Server / VPN Bridge administrator privileges. */
        this.Crash = function (in_param) {
            return _this.CallAsync("Crash", in_param);
        };
        /** Get the message for administrators. */
        this.GetAdminMsg = function () {
            return _this.CallAsync("GetAdminMsg", new VpnRpcMsg());
        };
        /** Save All Volatile Data of VPN Server / Bridge to the Configuration File. The number of configuration file bytes will be returned as the "IntValue" parameter. Normally, the VPN Server / VPN Bridge retains the volatile configuration data in memory. It is flushed to the disk as vpn_server.config or vpn_bridge.config periodically. The period is 300 seconds (5 minutes) by default. (The period can be altered by modifying the AutoSaveConfigSpan item in the configuration file.) The data will be saved on the timing of shutting down normally of the VPN Server / Bridge. Execute the Flush API to make the VPN Server / Bridge save the settings to the file immediately. The setting data will be stored on the disk drive of the server computer. Use the Flush API in a situation that you do not have an enough time to shut down the server process normally. To call this API, you must have VPN Server administrator privileges. To execute this API, you must have VPN Server / VPN Bridge administrator privileges. */
        this.Flush = function (in_param) {
            return _this.CallAsync("Flush", in_param);
        };
        /** Enable or Disable IPsec VPN Server Function. Enable or Disable IPsec VPN Server Function on the VPN Server. If you enable this function, Virtual Hubs on the VPN Server will be able to accept Remote-Access VPN connections from L2TP-compatible PCs, Mac OS X and Smartphones, and also can accept EtherIP Site-to-Site VPN Connection. VPN Connections from Smartphones suchlike iPhone, iPad and Android, and also from native VPN Clients on Mac OS X and Windows can be accepted. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.SetIPsecServices = function (in_param) {
            return _this.CallAsync("SetIPsecServices", in_param);
        };
        /** Get the Current IPsec VPN Server Settings. Get and view the current IPsec VPN Server settings on the VPN Server. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.GetIPsecServices = function () {
            return _this.CallAsync("GetIPsecServices", new VpnIPsecServices());
        };
        /** Add New EtherIP / L2TPv3 over IPsec Client Setting to Accept EthreIP / L2TPv3 Client Devices. Add a new setting entry to enable the EtherIP / L2TPv3 over IPsec Server Function to accept client devices. In order to accept connections from routers by the EtherIP / L2TPv3 over IPsec Server Function, you have to define the relation table between an IPsec Phase 1 string which is presented by client devices of EtherIP / L2TPv3 over IPsec compatible router, and the designation of the destination Virtual Hub. After you add a definition entry by AddEtherIpId API, the defined connection setting to the Virtual Hub will be applied on the login-attepting session from an EtherIP / L2TPv3 over IPsec client device. The username and password in an entry must be registered on the Virtual Hub. An EtherIP / L2TPv3 client will be regarded as it connected the Virtual HUB with the identification of the above user information. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.AddEtherIpId = function (in_param) {
            return _this.CallAsync("AddEtherIpId", in_param);
        };
        /** Get the Current List of EtherIP / L2TPv3 Client Device Entry Definitions. This API gets and shows the list of entries to accept VPN clients by EtherIP / L2TPv3 over IPsec Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.GetEtherIpId = function (in_param) {
            return _this.CallAsync("GetEtherIpId", in_param);
        };
        /** Delete an EtherIP / L2TPv3 over IPsec Client Setting. This API deletes an entry to accept VPN clients by EtherIP / L2TPv3 over IPsec Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.DeleteEtherIpId = function (in_param) {
            return _this.CallAsync("DeleteEtherIpId", in_param);
        };
        /** Get the Current List of EtherIP / L2TPv3 Client Device Entry Definitions. This API gets and shows the list of entries to accept VPN clients by EtherIP / L2TPv3 over IPsec Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.EnumEtherIpId = function () {
            return _this.CallAsync("EnumEtherIpId", new VpnRpcEnumEtherIpId());
        };
        /** Set Settings for OpenVPN Clone Server Function. The VPN Server has the clone functions of OpenVPN software products by OpenVPN Technologies, Inc. Any OpenVPN Clients can connect to this VPN Server. The manner to specify a username to connect to the Virtual Hub, and the selection rule of default Hub by using this clone server functions are same to the IPsec Server functions. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.SetOpenVpnSstpConfig = function (in_param) {
            return _this.CallAsync("SetOpenVpnSstpConfig", in_param);
        };
        /** Get the Current Settings of OpenVPN Clone Server Function. Get and show the current settings of OpenVPN Clone Server Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.GetOpenVpnSstpConfig = function () {
            return _this.CallAsync("GetOpenVpnSstpConfig", new VpnOpenVpnSstpConfig());
        };
        /** Show the Current Status of Dynamic DNS Function. Get and show the current status of the Dynamic DNS function. The Dynamic DNS assigns a unique and permanent DNS hostname for this VPN Server. You can use that hostname to specify this VPN Server on the settings for VPN Client and VPN Bridge. You need not to register and keep a domain name. Also, if your ISP assignes you a dynamic (not-fixed) IP address, the corresponding IP address of your Dynamic DNS hostname will be automatically changed. It enables you to keep running the VPN Server by using only a dynamic IP address. Therefore, you need not any longer to keep static global IP addresses with expenses monthly costs. [Caution] To disable the Dynamic DNS Function, modify the configuration file of VPN Server. The "declare root" directive has the "declare DDnsClient" directive. In this directive, you can switch "bool Disable" from false to true, and reboot the VPN Server, then the Dynamic DNS Function will be disabled. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. */
        this.GetDDnsClientStatus = function () {
            return _this.CallAsync("GetDDnsClientStatus", new VpnDDnsClientStatus());
        };
        /** Set the Dynamic DNS Hostname. You must specify the new hostname on the StrValue_str field. You can use this API to change the hostname assigned by the Dynamic DNS function. The currently assigned hostname can be showen by the GetDDnsClientStatus API. The Dynamic DNS assigns a unique and permanent DNS hostname for this VPN Server. You can use that hostname to specify this VPN Server on the settings for VPN Client and VPN Bridge. You need not to register and keep a domain name. Also, if your ISP assignes you a dynamic (not-fixed) IP address, the corresponding IP address of your Dynamic DNS hostname will be automatically changed. It enables you to keep running the VPN Server by using only a dynamic IP address. Therefore, you need not any longer to keep static global IP addresses with expenses monthly costs. [Caution] To disable the Dynamic DNS Function, modify the configuration file of VPN Server. The "declare root" directive has the "declare DDnsClient" directive. In this directive, you can switch "bool Disable" from false to true, and reboot the VPN Server, then the Dynamic DNS Function will be disabled. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. */
        this.ChangeDDnsClientHostname = function (in_param) {
            return _this.CallAsync("ChangeDDnsClientHostname", in_param);
        };
        /** Generate New Self-Signed Certificate with Specified CN (Common Name) and Register on VPN Server. You can specify the new CN (common name) value on the StrValue_str field. You can use this API to replace the current certificate on the VPN Server to a new self-signed certificate which has the CN (Common Name) value in the fields. This API is convenient if you are planning to use Microsoft SSTP VPN Clone Server Function. Because of the value of CN (Common Name) on the SSL certificate of VPN Server must match to the hostname specified on the SSTP VPN client. This API will delete the existing SSL certificate of the VPN Server. It is recommended to backup the current SSL certificate and private key by using the GetServerCert API beforehand. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.RegenerateServerCert = function (in_param) {
            return _this.CallAsync("RegenerateServerCert", in_param);
        };
        /** Generate a Sample Setting File for OpenVPN Client. Originally, the OpenVPN Client requires a user to write a very difficult configuration file manually. This API helps you to make a useful configuration sample. What you need to generate the configuration file for the OpenVPN Client is to run this API. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.MakeOpenVpnConfigFile = function () {
            return _this.CallAsync("MakeOpenVpnConfigFile", new VpnRpcReadLogFile());
        };
        /** Enable / Disable the VPN over ICMP / VPN over DNS Server Function. You can establish a VPN only with ICMP or DNS packets even if there is a firewall or routers which blocks TCP/IP communications. You have to enable the following functions beforehand. Warning: Use this function for emergency only. It is helpful when a firewall or router is misconfigured to blocks TCP/IP, but either ICMP or DNS is not blocked. It is not for long-term stable using. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. */
        this.SetSpecialListener = function (in_param) {
            return _this.CallAsync("SetSpecialListener", in_param);
        };
        /** Get Current Setting of the VPN over ICMP / VPN over DNS Function. Get and show the current VPN over ICMP / VPN over DNS Function status. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. */
        this.GetSpecialListener = function () {
            return _this.CallAsync("GetSpecialListener", new VpnRpcSpecialListener());
        };
        /** Show the current status of VPN Azure function. Get and show the current status of the VPN Azure function. VPN Azure makes it easier to establish a VPN Session from your home PC to your office PC. While a VPN connection is established, you can access to any other servers on the private network of your company. You don't need a global IP address on the office PC (VPN Server). It can work behind firewalls or NATs. No network administrator's configuration required. You can use the built-in SSTP-VPN Client of Windows in your home PC. VPN Azure is a cloud VPN service operated by SoftEther Corporation. VPN Azure is free of charge and available to anyone. Visit http://www.vpnazure.net/ to see details and how-to-use instructions. The VPN Azure hostname is same to the hostname of the Dynamic DNS setting, but altering the domain suffix to "vpnazure.net". To change the hostname use the ChangeDDnsClientHostname API. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.GetAzureStatus = function () {
            return _this.CallAsync("GetAzureStatus", new VpnRpcAzureStatus());
        };
        /** Enable / Disable VPN Azure Function. Enable or disable the VPN Azure function. VPN Azure makes it easier to establish a VPN Session from your home PC to your office PC. While a VPN connection is established, you can access to any other servers on the private network of your company. You don't need a global IP address on the office PC (VPN Server). It can work behind firewalls or NATs. No network administrator's configuration required. You can use the built-in SSTP-VPN Client of Windows in your home PC. VPN Azure is a cloud VPN service operated by SoftEther Corporation. VPN Azure is free of charge and available to anyone. Visit http://www.vpnazure.net/ to see details and how-to-use instructions. The VPN Azure hostname is same to the hostname of the Dynamic DNS setting, but altering the domain suffix to "vpnazure.net". To change the hostname use the ChangeDDnsClientHostname API. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
        this.SetAzureStatus = function (in_param) {
            return _this.CallAsync("SetAzureStatus", in_param);
        };
        /** Get the Proxy Settings for Connecting to the DDNS server. */
        this.GetDDnsInternetSettng = function () {
            return _this.CallAsync("GetDDnsInternetSettng", new VpnInternetSetting());
        };
        /** Set the Proxy Settings for Connecting to the DDNS server. */
        this.SetDDnsInternetSettng = function (in_param) {
            return _this.CallAsync("SetDDnsInternetSettng", in_param);
        };
        /** Set the VPN Gate Server Configuration. This API is valid for Win32 binary distribution of the Stable Edition of SoftEther VPN Server. */
        this.SetVgsConfig = function (in_param) {
            return _this.CallAsync("SetVgsConfig", in_param);
        };
        /** Get the VPN Gate Server Configuration. This API is valid for Win32 binary distribution of the Stable Edition of SoftEther VPN Server. */
        this.GetVgsConfig = function () {
            return _this.CallAsync("GetVgsConfig", new VpnVgsConfig());
        };
        var headers = {};
        var send_credentials = false;
        nodejs_https_client_reject_untrusted_server_cert = is_null(nodejs_https_client_reject_untrusted_server_cert) ? false : nodejs_https_client_reject_untrusted_server_cert;
        if (is_null(vpnserver_hostname)) {
            this.rpc_url = "/api/";
            send_credentials = true;
        }
        else {
            if (is_null(vpnserver_port))
                vpnserver_port = 443;
            this.rpc_url = "https://" + vpnserver_hostname + ":" + vpnserver_port + "/api/";
            headers["X-VPNADMIN-HUBNAME"] = is_null(hubname) ? "" : hubname;
            headers["X-VPNADMIN-PASSWORD"] = is_null(password) ? "" : password;
        }
        if (is_null(nodejs_https_client_reject_untrusted_server_cert))
            nodejs_https_client_reject_untrusted_server_cert = false;
        this.rpc_client = new JsonRpcClient(this.rpc_url, headers, send_credentials, nodejs_https_client_reject_untrusted_server_cert);
    }
    /** Determine if this JavaScript environment is on the Node.js or not. */
    VpnServerRpc.IsNodeJS = function () {
        return is_node_js;
    };
    /** Set the debug mode flag */
    VpnServerRpc.SetDebugMode = function (flag) {
        debug_mode = flag;
    };
    // -- Utility functions --
    /** Call a RPC procedure */
    VpnServerRpc.prototype.CallAsync = function (method_name, request) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.rpc_client.CallAsync(method_name, request)];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, response];
                }
            });
        });
    };
    return VpnServerRpc;
}());
exports.VpnServerRpc = VpnServerRpc;
// --- Types ---
/** IP Protocol Numbers */
var VpnIpProtocolNumber;
(function (VpnIpProtocolNumber) {
    /** ICMP for IPv4 */
    VpnIpProtocolNumber[VpnIpProtocolNumber["ICMPv4"] = 1] = "ICMPv4";
    /** TCP */
    VpnIpProtocolNumber[VpnIpProtocolNumber["TCP"] = 6] = "TCP";
    /** UDP */
    VpnIpProtocolNumber[VpnIpProtocolNumber["UDP"] = 17] = "UDP";
    /** ICMP for IPv6 */
    VpnIpProtocolNumber[VpnIpProtocolNumber["ICMPv6"] = 58] = "ICMPv6";
})(VpnIpProtocolNumber = exports.VpnIpProtocolNumber || (exports.VpnIpProtocolNumber = {}));
/** The body of the Access list */
var VpnAccess = /** @class */ (function () {
    /** Constructor for the 'VpnAccess' class: The body of the Access list */
    function VpnAccess(init) {
        /** ID */
        this.Id_u32 = 0;
        /** Specify a description (note) for this rule */
        this.Note_utf = "";
        /** Enabled flag (true: enabled, false: disabled) */
        this.Active_bool = false;
        /** Specify an integer of 1 or higher to indicate the priority of the rule. Higher priority is given to rules with the lower priority values. */
        this.Priority_u32 = 0;
        /** The flag if the rule is DISCARD operation or PASS operation. When a packet matches this rule condition, this operation is decided. When the operation of the rule is PASS, the packet is allowed to pass, otherwise the packet will be discarded. */
        this.Discard_bool = false;
        /** The flag if the rule is for IPv6. Specify false for IPv4, or specify true for IPv6. */
        this.IsIPv6_bool = false;
        /** Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a source IPv4 address as a rule condition. You must also specify the SrcSubnetMask_ip field. */
        this.SrcIpAddress_ip = "";
        /** Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a source IPv4 subnet mask as a rule condition. "0.0.0.0" means all hosts. "255.255.255.255" means one single host. */
        this.SrcSubnetMask_ip = "";
        /** Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a destination IPv4 address as a rule condition. You must also specify the DestSubnetMask_ip field. */
        this.DestIpAddress_ip = "";
        /** Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a destination IPv4 subnet mask as a rule condition. "0.0.0.0" means all hosts. "255.255.255.255" means one single host. */
        this.DestSubnetMask_ip = "";
        /** Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a source IPv6 address as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 address in binary form. You must also specify the SrcSubnetMask6_bin field. */
        this.SrcIpAddress6_bin = new Uint8Array([]);
        /** Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a source IPv6 subnet mask as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 subnet mask in binary form. */
        this.SrcSubnetMask6_bin = new Uint8Array([]);
        /** Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a destination IPv6 address as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 address in binary form. You must also specify the DestSubnetMask6_bin field. */
        this.DestIpAddress6_bin = new Uint8Array([]);
        /** Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a destination IPv6 subnet mask as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 subnet mask in binary form. */
        this.DestSubnetMask6_bin = new Uint8Array([]);
        /** The IP protocol number */
        this.Protocol_u32 = 0;
        /** The Start Value of the Source Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the source port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers. */
        this.SrcPortStart_u32 = 0;
        /** The End Value of the Source Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the source port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers. */
        this.SrcPortEnd_u32 = 0;
        /** The Start Value of the Destination Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the destination port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers. */
        this.DestPortStart_u32 = 0;
        /** The End Value of the Destination Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the destination port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers. */
        this.DestPortEnd_u32 = 0;
        /** Source user name. You can apply this rule to only the packets sent by a user session of a user name that has been specified as a rule condition. In this case, specify the user name. */
        this.SrcUsername_str = "";
        /** Destination user name. You can apply this rule to only the packets received by a user session of a user name that has been specified as a rule condition. In this case, specify the user name. */
        this.DestUsername_str = "";
        /** Specify true if you want to check the source MAC address. */
        this.CheckSrcMac_bool = false;
        /** Source MAC address (6 bytes), valid only if CheckSrcMac_bool == true. */
        this.SrcMacAddress_bin = new Uint8Array([]);
        /** Source MAC address mask (6 bytes), valid only if CheckSrcMac_bool == true. */
        this.SrcMacMask_bin = new Uint8Array([]);
        /** Specify true if you want to check the destination MAC address. */
        this.CheckDstMac_bool = false;
        /** Destination MAC address (6 bytes), valid only if CheckSrcMac_bool == true. */
        this.DstMacAddress_bin = new Uint8Array([]);
        /** Destination MAC address mask (6 bytes), valid only if CheckSrcMac_bool == true. */
        this.DstMacMask_bin = new Uint8Array([]);
        /** Specify true if you want to check the state of the TCP connection. */
        this.CheckTcpState_bool = false;
        /** Valid only if CheckTcpState_bool == true. Set this field true to match only TCP-established packets. Set this field false to match only TCP-non established packets. */
        this.Established_bool = false;
        /** Set this value to generate delays when packets is passing. Specify the delay period in milliseconds. Specify 0 means no delays to generate. The delays must be 10000 milliseconds at most. */
        this.Delay_u32 = 0;
        /** Set this value to generate jitters when packets is passing. Specify the ratio of fluctuation of jitters within 0% to 100% range. Specify 0 means no jitters to generate. */
        this.Jitter_u32 = 0;
        /** Set this value to generate packet losses when packets is passing. Specify the ratio of packet losses within 0% to 100% range. Specify 0 means no packet losses to generate. */
        this.Loss_u32 = 0;
        /** The specified URL will be mandatory replied to the client as a response for TCP connecting request packets which matches the conditions of this access list entry via this Virtual Hub. To use this setting, you can enforce the web browser of the VPN Client computer to show the specified web site when that web browser tries to access the specific IP address. */
        this.RedirectUrl_str = "";
        Object.assign(this, init);
    }
    return VpnAccess;
}());
exports.VpnAccess = VpnAccess;
/** Add an item to Access List */
var VpnRpcAddAccess = /** @class */ (function () {
    /** Constructor for the 'VpnRpcAddAccess' class: Add an item to Access List */
    function VpnRpcAddAccess(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** Access list (Must be a single item) */
        this.AccessListSingle = [];
        Object.assign(this, init);
    }
    return VpnRpcAddAccess;
}());
exports.VpnRpcAddAccess = VpnRpcAddAccess;
/** Add CA to HUB */
var VpnRpcHubAddCA = /** @class */ (function () {
    /** Constructor for the 'VpnRpcHubAddCA' class: Add CA to HUB */
    function VpnRpcHubAddCA(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** The body of the X.509 certificate */
        this.Cert_bin = new Uint8Array([]);
        Object.assign(this, init);
    }
    return VpnRpcHubAddCA;
}());
exports.VpnRpcHubAddCA = VpnRpcHubAddCA;
/** CRL entry */
var VpnRpcCrl = /** @class */ (function () {
    /** Constructor for the 'VpnRpcCrl' class: CRL entry */
    function VpnRpcCrl(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** Key ID */
        this.Key_u32 = 0;
        /** CN, optional */
        this.CommonName_utf = "";
        /** O, optional */
        this.Organization_utf = "";
        /** OU, optional */
        this.Unit_utf = "";
        /** C, optional */
        this.Country_utf = "";
        /** ST, optional */
        this.State_utf = "";
        /** L, optional */
        this.Local_utf = "";
        /** Serial, optional */
        this.Serial_bin = new Uint8Array([]);
        /** MD5 Digest, optional */
        this.DigestMD5_bin = new Uint8Array([]);
        /** SHA1 Digest, optional */
        this.DigestSHA1_bin = new Uint8Array([]);
        Object.assign(this, init);
    }
    return VpnRpcCrl;
}());
exports.VpnRpcCrl = VpnRpcCrl;
/** EtherIP key list entry */
var VpnEtherIpId = /** @class */ (function () {
    /** Constructor for the 'VpnEtherIpId' class: EtherIP key list entry */
    function VpnEtherIpId(init) {
        /** Specify an ISAKMP Phase 1 ID. The ID must be exactly same as a ID in the configuration of the EtherIP / L2TPv3 Client. You can specify IP address as well as characters as ID, if the EtherIP Client uses IP address as Phase 1 ID. If you specify '*' (asterisk), it will be a wildcard to match any clients which doesn't match other explicit rules. */
        this.Id_str = "";
        /** Specify the name of the Virtual Hub to connect. */
        this.HubName_str = "";
        /** Specify the username to login to the destination Virtual Hub. */
        this.UserName_str = "";
        /** Specify the password to login to the destination Virtual Hub. */
        this.Password_str = "";
        Object.assign(this, init);
    }
    return VpnEtherIpId;
}());
exports.VpnEtherIpId = VpnEtherIpId;
/** Layer-3 virtual interface */
var VpnRpcL3If = /** @class */ (function () {
    /** Constructor for the 'VpnRpcL3If' class: Layer-3 virtual interface */
    function VpnRpcL3If(init) {
        /** L3 switch name */
        this.Name_str = "";
        /** Virtual HUB name */
        this.HubName_str = "";
        /** IP address */
        this.IpAddress_ip = "";
        /** Subnet mask */
        this.SubnetMask_ip = "";
        Object.assign(this, init);
    }
    return VpnRpcL3If;
}());
exports.VpnRpcL3If = VpnRpcL3If;
/** Layer-3 switch */
var VpnRpcL3Sw = /** @class */ (function () {
    /** Constructor for the 'VpnRpcL3Sw' class: Layer-3 switch */
    function VpnRpcL3Sw(init) {
        /** Layer-3 Switch name */
        this.Name_str = "";
        Object.assign(this, init);
    }
    return VpnRpcL3Sw;
}());
exports.VpnRpcL3Sw = VpnRpcL3Sw;
/** Routing table */
var VpnRpcL3Table = /** @class */ (function () {
    /** Constructor for the 'VpnRpcL3Table' class: Routing table */
    function VpnRpcL3Table(init) {
        /** L3 switch name */
        this.Name_str = "";
        /** Network address */
        this.NetworkAddress_ip = "";
        /** Subnet mask */
        this.SubnetMask_ip = "";
        /** Gateway address */
        this.GatewayAddress_ip = "";
        /** Metric */
        this.Metric_u32 = 0;
        Object.assign(this, init);
    }
    return VpnRpcL3Table;
}());
exports.VpnRpcL3Table = VpnRpcL3Table;
/** Generic parameter to contain u32, u64, ascii_string and unicode string */
var VpnRpcTest = /** @class */ (function () {
    /** Constructor for the 'VpnRpcTest' class: Generic parameter to contain u32, u64, ascii_string and unicode string */
    function VpnRpcTest(init) {
        /** A 32-bit integer field */
        this.IntValue_u32 = 0;
        /** A 64-bit integer field */
        this.Int64Value_u64 = 0;
        /** An Ascii string field */
        this.StrValue_str = "";
        /** An UTF-8 string field */
        this.UniStrValue_utf = "";
        Object.assign(this, init);
    }
    return VpnRpcTest;
}());
exports.VpnRpcTest = VpnRpcTest;
/** Local Bridge list item */
var VpnRpcLocalBridge = /** @class */ (function () {
    /** Constructor for the 'VpnRpcLocalBridge' class: Local Bridge list item */
    function VpnRpcLocalBridge(init) {
        /** Physical Ethernet device name */
        this.DeviceName_str = "";
        /** The Virtual Hub name */
        this.HubNameLB_str = "";
        /** Online flag */
        this.Online_bool = false;
        /** Running flag */
        this.Active_bool = false;
        /** Specify true if you are using a tap device rather than a network adapter for the bridge destination (only supported for Linux versions). */
        this.TapMode_bool = false;
        Object.assign(this, init);
    }
    return VpnRpcLocalBridge;
}());
exports.VpnRpcLocalBridge = VpnRpcLocalBridge;
/** Create, configure, and get the group */
var VpnRpcSetGroup = /** @class */ (function () {
    /** Constructor for the 'VpnRpcSetGroup' class: Create, configure, and get the group */
    function VpnRpcSetGroup(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** The group name */
        this.Name_str = "";
        /** Optional real name (full name) of the group, allow using any Unicode characters */
        this.Realname_utf = "";
        /** Optional, specify a description of the group */
        this.Note_utf = "";
        /** Number of broadcast packets (Recv) */
        this["Recv.BroadcastBytes_u64"] = 0;
        /** Broadcast bytes (Recv) */
        this["Recv.BroadcastCount_u64"] = 0;
        /** Unicast count (Recv) */
        this["Recv.UnicastBytes_u64"] = 0;
        /** Unicast bytes (Recv) */
        this["Recv.UnicastCount_u64"] = 0;
        /** Number of broadcast packets (Send) */
        this["Send.BroadcastBytes_u64"] = 0;
        /** Broadcast bytes (Send) */
        this["Send.BroadcastCount_u64"] = 0;
        /** Unicast bytes (Send) */
        this["Send.UnicastBytes_u64"] = 0;
        /** Unicast bytes (Send) */
        this["Send.UnicastCount_u64"] = 0;
        /** The flag whether to use security policy */
        this.UsePolicy_bool = false;
        /** Security policy: Allow Access. The users, which this policy value is true, have permission to make VPN connection to VPN Server. */
        this["policy:Access_bool"] = false;
        /** Security policy: Filter DHCP Packets (IPv4). All IPv4 DHCP packets in sessions defined this policy will be filtered. */
        this["policy:DHCPFilter_bool"] = false;
        /** Security policy: Disallow DHCP Server Operation (IPv4). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv4 addresses to DHCP clients. */
        this["policy:DHCPNoServer_bool"] = false;
        /** Security policy: Enforce DHCP Allocated IP Addresses (IPv4). Computers in sessions that have this policy setting will only be able to use IPv4 addresses allocated by a DHCP server on the virtual network side. */
        this["policy:DHCPForce_bool"] = false;
        /** Security policy: Deny Bridge Operation. Bridge-mode connections are denied for user sessions that have this policy setting. Even in cases when the Ethernet Bridge is configured in the client side, communication will not be possible. */
        this["policy:NoBridge_bool"] = false;
        /** Security policy: Deny Routing Operation (IPv4). IPv4 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible. */
        this["policy:NoRouting_bool"] = false;
        /** Security policy: Deny MAC Addresses Duplication. The use of duplicating MAC addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting. */
        this["policy:CheckMac_bool"] = false;
        /** Security policy: Deny IP Address Duplication (IPv4). The use of duplicating IPv4 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting. */
        this["policy:CheckIP_bool"] = false;
        /** Security policy: Deny Non-ARP / Non-DHCP / Non-ICMPv6 broadcasts. The sending or receiving of broadcast packets that are not ARP protocol, DHCP protocol, nor ICMPv6 on the virtual network will not be allowed for sessions with this policy setting. */
        this["policy:ArpDhcpOnly_bool"] = false;
        /** Security policy: Privacy Filter Mode. All direct communication between sessions with the privacy filter mode policy setting will be filtered. */
        this["policy:PrivacyFilter_bool"] = false;
        /** Security policy: Deny Operation as TCP/IP Server (IPv4). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv4. */
        this["policy:NoServer_bool"] = false;
        /** Security policy: Unlimited Number of Broadcasts. If a computer of a session with this policy setting sends broadcast packets of a number unusually larger than what would be considered normal on the virtual network, there will be no automatic limiting. */
        this["policy:NoBroadcastLimiter_bool"] = false;
        /** Security policy: Allow Monitoring Mode. Users with this policy setting will be granted to connect to the Virtual Hub in Monitoring Mode. Sessions in Monitoring Mode are able to monitor (tap) all packets flowing through the Virtual Hub. */
        this["policy:MonitorPort_bool"] = false;
        /** Security policy: Maximum Number of TCP Connections. For sessions with this policy setting, this sets the maximum number of physical TCP connections consists in a physical VPN session. */
        this["policy:MaxConnection_u32"] = 0;
        /** Security policy: Time-out Period. For sessions with this policy setting, this sets, in seconds, the time-out period to wait before disconnecting a session when communication trouble occurs between the VPN Client / VPN Server. */
        this["policy:TimeOut_u32"] = 0;
        /** Security policy: Maximum Number of MAC Addresses. For sessions with this policy setting, this limits the number of MAC addresses per session. */
        this["policy:MaxMac_u32"] = 0;
        /** Security policy: Maximum Number of IP Addresses (IPv4). For sessions with this policy setting, this specifies the number of IPv4 addresses that can be registered for a single session. */
        this["policy:MaxIP_u32"] = 0;
        /** Security policy: Upload Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the inwards direction from outside to inside the Virtual Hub. */
        this["policy:MaxUpload_u32"] = 0;
        /** Security policy: Download Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the outwards direction from inside the Virtual Hub to outside the Virtual Hub. */
        this["policy:MaxDownload_u32"] = 0;
        /** Security policy: Deny Changing Password. The users which use password authentication with this policy setting are not allowed to change their own password from the VPN Client Manager or similar. */
        this["policy:FixPassword_bool"] = false;
        /** Security policy: Maximum Number of Multiple Logins. Users with this policy setting are unable to have more than this number of concurrent logins. Bridge Mode sessions are not subjects to this policy. */
        this["policy:MultiLogins_u32"] = 0;
        /** Security policy: Deny VoIP / QoS Function. Users with this security policy are unable to use VoIP / QoS functions in VPN connection sessions. */
        this["policy:NoQoS_bool"] = false;
        /** Security policy: Filter RS / RA Packets (IPv6). All ICMPv6 packets which the message-type is 133 (Router Solicitation) or 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, an IPv6 client will be unable to use IPv6 address prefix auto detection and IPv6 default gateway auto detection. */
        this["policy:RSandRAFilter_bool"] = false;
        /** Security policy: Filter RA Packets (IPv6). All ICMPv6 packets which the message-type is 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, a malicious users will be unable to spread illegal IPv6 prefix or default gateway advertisements on the network. */
        this["policy:RAFilter_bool"] = false;
        /** Security policy: Filter DHCP Packets (IPv6). All IPv6 DHCP packets in sessions defined this policy will be filtered. */
        this["policy:DHCPv6Filter_bool"] = false;
        /** Security policy: Disallow DHCP Server Operation (IPv6). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv6 addresses to DHCP clients. */
        this["policy:DHCPv6NoServer_bool"] = false;
        /** Security policy: Deny Routing Operation (IPv6). IPv6 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible. */
        this["policy:NoRoutingV6_bool"] = false;
        /** Security policy: Deny IP Address Duplication (IPv6). The use of duplicating IPv6 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting. */
        this["policy:CheckIPv6_bool"] = false;
        /** Security policy: Deny Operation as TCP/IP Server (IPv6). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv6. */
        this["policy:NoServerV6_bool"] = false;
        /** Security policy: Maximum Number of IP Addresses (IPv6). For sessions with this policy setting, this specifies the number of IPv6 addresses that can be registered for a single session. */
        this["policy:MaxIPv6_u32"] = 0;
        /** Security policy: Disallow Password Save in VPN Client. For users with this policy setting, when the user is using *standard* password authentication, the user will be unable to save the password in VPN Client. The user will be required to input passwords for every time to connect a VPN. This will improve the security. If this policy is enabled, VPN Client Version 2.0 will be denied to access. */
        this["policy:NoSavePassword_bool"] = false;
        /** Security policy: VPN Client Automatic Disconnect. For users with this policy setting, a user's VPN session will be disconnected automatically after the specific period will elapse. In this case no automatic re-connection will be performed. This can prevent a lot of inactive VPN Sessions. If this policy is enabled, VPN Client Version 2.0 will be denied to access. */
        this["policy:AutoDisconnect_u32"] = 0;
        /** Security policy: Filter All IPv4 Packets. All IPv4 and ARP packets in sessions defined this policy will be filtered. */
        this["policy:FilterIPv4_bool"] = false;
        /** Security policy: Filter All IPv6 Packets. All IPv6 packets in sessions defined this policy will be filtered. */
        this["policy:FilterIPv6_bool"] = false;
        /** Security policy: Filter All Non-IP Packets. All non-IP packets in sessions defined this policy will be filtered. "Non-IP packet" mean a packet which is not IPv4, ARP nor IPv6. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. */
        this["policy:FilterNonIP_bool"] = false;
        /** Security policy: No Default-Router on IPv6 RA. In all VPN Sessions defines this policy, any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router. */
        this["policy:NoIPv6DefaultRouterInRA_bool"] = false;
        /** Security policy: No Default-Router on IPv6 RA (physical IPv6). In all VPN Sessions defines this policy (only when the physical communication protocol between VPN Client / VPN Bridge and VPN Server is IPv6), any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router. */
        this["policy:NoIPv6DefaultRouterInRAWhenIPv6_bool"] = false;
        /** Security policy: VLAN ID (IEEE802.1Q). You can specify the VLAN ID on the security policy. All VPN Sessions defines this policy, all Ethernet packets toward the Virtual Hub from the user will be inserted a VLAN tag (IEEE 802.1Q) with the VLAN ID. The user can also receive only packets with a VLAN tag which has the same VLAN ID. (Receiving process removes the VLAN tag automatically.) Any Ethernet packets with any other VLAN IDs or non-VLAN packets will not be received. All VPN Sessions without this policy definition can send / receive any kinds of Ethernet packets regardless of VLAN tags, and VLAN tags are not inserted or removed automatically. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. Therefore, tagged-VLAN packets are not subjects for IPv4 / IPv6 security policies, access lists nor other IPv4 / IPv6 specific deep processing. */
        this["policy:VLanId_u32"] = 0;
        /** Security policy: Whether version 3.0 (must be true) */
        this["policy:Ver3_bool"] = false;
        Object.assign(this, init);
    }
    return VpnRpcSetGroup;
}());
exports.VpnRpcSetGroup = VpnRpcSetGroup;
/** Hub types */
var VpnRpcHubType;
(function (VpnRpcHubType) {
    /** Stand-alone HUB */
    VpnRpcHubType[VpnRpcHubType["Standalone"] = 0] = "Standalone";
    /** Static HUB */
    VpnRpcHubType[VpnRpcHubType["FarmStatic"] = 1] = "FarmStatic";
    /** Dynamic HUB */
    VpnRpcHubType[VpnRpcHubType["FarmDynamic"] = 2] = "FarmDynamic";
})(VpnRpcHubType = exports.VpnRpcHubType || (exports.VpnRpcHubType = {}));
/** Create a HUB */
var VpnRpcCreateHub = /** @class */ (function () {
    /** Constructor for the 'VpnRpcCreateHub' class: Create a HUB */
    function VpnRpcCreateHub(init) {
        /** Specify the name of the Virtual Hub to create / update. */
        this.HubName_str = "";
        /** Specify an administrator password when the administrator password is going to be set for the Virtual Hub. On the update, leave it to empty string if you don't want to change the password. */
        this.AdminPasswordPlainText_str = "";
        /** Online flag */
        this.Online_bool = false;
        /** Maximum number of VPN sessions */
        this.MaxSession_u32 = 0;
        /** No Enum flag. By enabling this option, the VPN Client user will be unable to enumerate this Virtual Hub even if they send a Virtual Hub enumeration request to the VPN Server. */
        this.NoEnum_bool = false;
        /** Type of the Virtual Hub (Valid only for Clustered VPN Servers) */
        this.HubType_u32 = 0;
        Object.assign(this, init);
    }
    return VpnRpcCreateHub;
}());
exports.VpnRpcCreateHub = VpnRpcCreateHub;
var VpnRpcClientAuthType;
(function (VpnRpcClientAuthType) {
    /** Anonymous authentication */
    VpnRpcClientAuthType[VpnRpcClientAuthType["Anonymous"] = 0] = "Anonymous";
    /** SHA-0 hashed password authentication */
    VpnRpcClientAuthType[VpnRpcClientAuthType["SHA0_Hashed_Password"] = 1] = "SHA0_Hashed_Password";
    /** Plain password authentication */
    VpnRpcClientAuthType[VpnRpcClientAuthType["PlainPassword"] = 2] = "PlainPassword";
    /** Certificate authentication */
    VpnRpcClientAuthType[VpnRpcClientAuthType["Cert"] = 3] = "Cert";
})(VpnRpcClientAuthType = exports.VpnRpcClientAuthType || (exports.VpnRpcClientAuthType = {}));
/** Create and set of link */
var VpnRpcCreateLink = /** @class */ (function () {
    /** Constructor for the 'VpnRpcCreateLink' class: Create and set of link */
    function VpnRpcCreateLink(init) {
        /** The Virtual Hub name */
        this.HubName_Ex_str = "";
        /** Online flag */
        this.Online_bool = false;
        /** The flag to enable validation for the server certificate */
        this.CheckServerCert_bool = false;
        /** The body of server X.509 certificate to compare. Valid only if the CheckServerCert_bool flag is true. */
        this.ServerCert_bin = new Uint8Array([]);
        /** Client Option Parameters: Specify the name of the Cascade Connection */
        this.AccountName_utf = "";
        /** Client Option Parameters: Specify the hostname of the destination VPN Server. You can also specify by IP address. */
        this.Hostname_str = "";
        /** Client Option Parameters: Specify the port number of the destination VPN Server. */
        this.Port_u32 = 0;
        /** Client Option Parameters: The type of the proxy server */
        this.ProxyType_u32 = 0;
        /** Client Option Parameters: The hostname or IP address of the proxy server name */
        this.ProxyName_str = "";
        /** Client Option Parameters: The port number of the proxy server */
        this.ProxyPort_u32 = 0;
        /** Client Option Parameters: The username to connect to the proxy server */
        this.ProxyUsername_str = "";
        /** Client Option Parameters: The password to connect to the proxy server */
        this.ProxyPassword_str = "";
        /** Client Option Parameters: The Virtual Hub on the destination VPN Server */
        this.HubName_str = "";
        /** Client Option Parameters: Number of TCP Connections to Use in VPN Communication */
        this.MaxConnection_u32 = 0;
        /** Client Option Parameters: The flag to enable the encryption on the communication */
        this.UseEncrypt_bool = false;
        /** Client Option Parameters: Enable / Disable Data Compression when Communicating by Cascade Connection */
        this.UseCompress_bool = false;
        /** Client Option Parameters: Specify true when enabling half duplex mode. When using two or more TCP connections for VPN communication, it is possible to use Half Duplex Mode. By enabling half duplex mode it is possible to automatically fix data transmission direction as half and half for each TCP connection. In the case where a VPN using 8 TCP connections is established, for example, when half-duplex is enabled, communication can be fixes so that 4 TCP connections are dedicated to the upload direction and the other 4 connections are dedicated to the download direction. */
        this.HalfConnection_bool = false;
        /** Client Option Parameters: Connection attempt interval when additional connection will be established */
        this.AdditionalConnectionInterval_u32 = 0;
        /** Client Option Parameters: Connection Life of Each TCP Connection (0 for no keep-alive) */
        this.ConnectionDisconnectSpan_u32 = 0;
        /** Client Option Parameters: Disable QoS Control Function if the value is true */
        this.DisableQoS_bool = false;
        /** Client Option Parameters: Do not use TLS 1.x of the value is true */
        this.NoTls1_bool = false;
        /** Client Option Parameters: Do not use UDP acceleration mode if the value is true */
        this.NoUdpAcceleration_bool = false;
        /** Authentication type */
        this.AuthType_u32 = 0;
        /** User name */
        this.Username_str = "";
        /** SHA-0 Hashed password. Valid only if ClientAuth_AuthType_u32 == SHA0_Hashed_Password (1). The SHA-0 hashed password must be caluclated by the SHA0(UpperCase(username_ascii_string) + password_ascii_string). */
        this.HashedPassword_bin = new Uint8Array([]);
        /** Plaintext Password. Valid only if ClientAuth_AuthType_u32 == PlainPassword (2). */
        this.PlainPassword_str = "";
        /** Client certificate. Valid only if ClientAuth_AuthType_u32 == Cert (3). */
        this.ClientX_bin = new Uint8Array([]);
        /** Client private key of the certificate. Valid only if ClientAuth_AuthType_u32 == Cert (3). */
        this.ClientK_bin = new Uint8Array([]);
        /** Security policy: Filter DHCP Packets (IPv4). All IPv4 DHCP packets in sessions defined this policy will be filtered. */
        this["policy:DHCPFilter_bool"] = false;
        /** Security policy: Disallow DHCP Server Operation (IPv4). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv4 addresses to DHCP clients. */
        this["policy:DHCPNoServer_bool"] = false;
        /** Security policy: Enforce DHCP Allocated IP Addresses (IPv4). Computers in sessions that have this policy setting will only be able to use IPv4 addresses allocated by a DHCP server on the virtual network side. */
        this["policy:DHCPForce_bool"] = false;
        /** Security policy: Prohibit the duplicate MAC address */
        this.SecPol_CheckMac_bool = false;
        /** Security policy: Prohibit a duplicate IP address (IPv4) */
        this.SecPol_CheckIP_bool = false;
        /** Security policy: Deny Non-ARP / Non-DHCP / Non-ICMPv6 broadcasts. The sending or receiving of broadcast packets that are not ARP protocol, DHCP protocol, nor ICMPv6 on the virtual network will not be allowed for sessions with this policy setting. */
        this["policy:ArpDhcpOnly_bool"] = false;
        /** Security policy: Privacy Filter Mode. All direct communication between sessions with the privacy filter mode policy setting will be filtered. */
        this["policy:PrivacyFilter_bool"] = false;
        /** Security policy: Deny Operation as TCP/IP Server (IPv4). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv4. */
        this["policy:NoServer_bool"] = false;
        /** Security policy: Unlimited Number of Broadcasts. If a computer of a session with this policy setting sends broadcast packets of a number unusually larger than what would be considered normal on the virtual network, there will be no automatic limiting. */
        this["policy:NoBroadcastLimiter_bool"] = false;
        /** Security policy: Maximum Number of MAC Addresses. For sessions with this policy setting, this limits the number of MAC addresses per session. */
        this["policy:MaxMac_u32"] = 0;
        /** Security policy: Maximum Number of IP Addresses (IPv4). For sessions with this policy setting, this specifies the number of IPv4 addresses that can be registered for a single session. */
        this["policy:MaxIP_u32"] = 0;
        /** Security policy: Upload Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the inwards direction from outside to inside the Virtual Hub. */
        this["policy:MaxUpload_u32"] = 0;
        /** Security policy: Download Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the outwards direction from inside the Virtual Hub to outside the Virtual Hub. */
        this["policy:MaxDownload_u32"] = 0;
        /** Security policy: Filter RS / RA Packets (IPv6). All ICMPv6 packets which the message-type is 133 (Router Solicitation) or 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, an IPv6 client will be unable to use IPv6 address prefix auto detection and IPv6 default gateway auto detection. */
        this["policy:RSandRAFilter_bool"] = false;
        /** Security policy: Filter the router advertisement packet (IPv6) */
        this.SecPol_RAFilter_bool = false;
        /** Security policy: Filter DHCP Packets (IPv6). All IPv6 DHCP packets in sessions defined this policy will be filtered. */
        this["policy:DHCPv6Filter_bool"] = false;
        /** Security policy: Disallow DHCP Server Operation (IPv6). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv6 addresses to DHCP clients. */
        this["policy:DHCPv6NoServer_bool"] = false;
        /** Security policy: Prohibit the duplicate IP address (IPv6) */
        this.SecPol_CheckIPv6_bool = false;
        /** Security policy: Deny Operation as TCP/IP Server (IPv6). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv6. */
        this["policy:NoServerV6_bool"] = false;
        /** Security policy: Maximum Number of IP Addresses (IPv6). For sessions with this policy setting, this specifies the number of IPv6 addresses that can be registered for a single session. */
        this["policy:MaxIPv6_u32"] = 0;
        /** Security policy: Filter All IPv4 Packets. All IPv4 and ARP packets in sessions defined this policy will be filtered. */
        this["policy:FilterIPv4_bool"] = false;
        /** Security policy: Filter All IPv6 Packets. All IPv6 packets in sessions defined this policy will be filtered. */
        this["policy:FilterIPv6_bool"] = false;
        /** Security policy: Filter All Non-IP Packets. All non-IP packets in sessions defined this policy will be filtered. "Non-IP packet" mean a packet which is not IPv4, ARP nor IPv6. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. */
        this["policy:FilterNonIP_bool"] = false;
        /** Security policy: No Default-Router on IPv6 RA. In all VPN Sessions defines this policy, any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router. */
        this["policy:NoIPv6DefaultRouterInRA_bool"] = false;
        /** Security policy: VLAN ID (IEEE802.1Q). You can specify the VLAN ID on the security policy. All VPN Sessions defines this policy, all Ethernet packets toward the Virtual Hub from the user will be inserted a VLAN tag (IEEE 802.1Q) with the VLAN ID. The user can also receive only packets with a VLAN tag which has the same VLAN ID. (Receiving process removes the VLAN tag automatically.) Any Ethernet packets with any other VLAN IDs or non-VLAN packets will not be received. All VPN Sessions without this policy definition can send / receive any kinds of Ethernet packets regardless of VLAN tags, and VLAN tags are not inserted or removed automatically. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. Therefore, tagged-VLAN packets are not subjects for IPv4 / IPv6 security policies, access lists nor other IPv4 / IPv6 specific deep processing. */
        this["policy:VLanId_u32"] = 0;
        /** Security policy: Whether version 3.0 (must be true) */
        this["policy:Ver3_bool"] = false;
        Object.assign(this, init);
    }
    return VpnRpcCreateLink;
}());
exports.VpnRpcCreateLink = VpnRpcCreateLink;
/** Listener */
var VpnRpcListener = /** @class */ (function () {
    /** Constructor for the 'VpnRpcListener' class: Listener */
    function VpnRpcListener(init) {
        /** Port number (Range: 1 - 65535) */
        this.Port_u32 = 0;
        /** Active state */
        this.Enable_bool = false;
        Object.assign(this, init);
    }
    return VpnRpcListener;
}());
exports.VpnRpcListener = VpnRpcListener;
/** User authentication type (server side) */
var VpnRpcUserAuthType;
(function (VpnRpcUserAuthType) {
    /** Anonymous authentication */
    VpnRpcUserAuthType[VpnRpcUserAuthType["Anonymous"] = 0] = "Anonymous";
    /** Password authentication */
    VpnRpcUserAuthType[VpnRpcUserAuthType["Password"] = 1] = "Password";
    /** User certificate authentication */
    VpnRpcUserAuthType[VpnRpcUserAuthType["UserCert"] = 2] = "UserCert";
    /** Root certificate which is issued by trusted Certificate Authority */
    VpnRpcUserAuthType[VpnRpcUserAuthType["RootCert"] = 3] = "RootCert";
    /** Radius authentication */
    VpnRpcUserAuthType[VpnRpcUserAuthType["Radius"] = 4] = "Radius";
    /** Windows NT authentication */
    VpnRpcUserAuthType[VpnRpcUserAuthType["NTDomain"] = 5] = "NTDomain";
})(VpnRpcUserAuthType = exports.VpnRpcUserAuthType || (exports.VpnRpcUserAuthType = {}));
/** Create, configure, and get the user */
var VpnRpcSetUser = /** @class */ (function () {
    /** Constructor for the 'VpnRpcSetUser' class: Create, configure, and get the user */
    function VpnRpcSetUser(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** Specify the user name of the user */
        this.Name_str = "";
        /** Assigned group name for the user */
        this.GroupName_str = "";
        /** Optional real name (full name) of the user, allow using any Unicode characters */
        this.Realname_utf = "";
        /** Optional User Description */
        this.Note_utf = "";
        /** Creation date and time */
        this.CreatedTime_dt = new Date();
        /** Last modified date and time */
        this.UpdatedTime_dt = new Date();
        /** Expiration date and time */
        this.ExpireTime_dt = new Date();
        /** Authentication method of the user */
        this.AuthType_u32 = 0;
        /** User password, valid only if AuthType_u32 == Password(1). Valid only to create or set operations. */
        this.Auth_Password_str = "";
        /** User certificate, valid only if AuthType_u32 == UserCert(2). */
        this.UserX_bin = new Uint8Array([]);
        /** Certificate Serial Number, optional, valid only if AuthType_u32 == RootCert(3). */
        this.Serial_bin = new Uint8Array([]);
        /** Certificate Common Name, optional, valid only if AuthType_u32 == RootCert(3). */
        this.CommonName_utf = "";
        /** Username in RADIUS server, optional, valid only if AuthType_u32 == Radius(4). */
        this.RadiusUsername_utf = "";
        /** Username in NT Domain server, optional, valid only if AuthType_u32 == NT(5). */
        this.NtUsername_utf = "";
        /** Number of total logins of the user */
        this.NumLogin_u32 = 0;
        /** Number of broadcast packets (Recv) */
        this["Recv.BroadcastBytes_u64"] = 0;
        /** Broadcast bytes (Recv) */
        this["Recv.BroadcastCount_u64"] = 0;
        /** Unicast count (Recv) */
        this["Recv.UnicastBytes_u64"] = 0;
        /** Unicast bytes (Recv) */
        this["Recv.UnicastCount_u64"] = 0;
        /** Number of broadcast packets (Send) */
        this["Send.BroadcastBytes_u64"] = 0;
        /** Broadcast bytes (Send) */
        this["Send.BroadcastCount_u64"] = 0;
        /** Unicast bytes (Send) */
        this["Send.UnicastBytes_u64"] = 0;
        /** Unicast bytes (Send) */
        this["Send.UnicastCount_u64"] = 0;
        /** The flag whether to use security policy */
        this.UsePolicy_bool = false;
        /** Security policy: Allow Access. The users, which this policy value is true, have permission to make VPN connection to VPN Server. */
        this["policy:Access_bool"] = false;
        /** Security policy: Filter DHCP Packets (IPv4). All IPv4 DHCP packets in sessions defined this policy will be filtered. */
        this["policy:DHCPFilter_bool"] = false;
        /** Security policy: Disallow DHCP Server Operation (IPv4). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv4 addresses to DHCP clients. */
        this["policy:DHCPNoServer_bool"] = false;
        /** Security policy: Enforce DHCP Allocated IP Addresses (IPv4). Computers in sessions that have this policy setting will only be able to use IPv4 addresses allocated by a DHCP server on the virtual network side. */
        this["policy:DHCPForce_bool"] = false;
        /** Security policy: Deny Bridge Operation. Bridge-mode connections are denied for user sessions that have this policy setting. Even in cases when the Ethernet Bridge is configured in the client side, communication will not be possible. */
        this["policy:NoBridge_bool"] = false;
        /** Security policy: Deny Routing Operation (IPv4). IPv4 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible. */
        this["policy:NoRouting_bool"] = false;
        /** Security policy: Deny MAC Addresses Duplication. The use of duplicating MAC addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting. */
        this["policy:CheckMac_bool"] = false;
        /** Security policy: Deny IP Address Duplication (IPv4). The use of duplicating IPv4 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting. */
        this["policy:CheckIP_bool"] = false;
        /** Security policy: Deny Non-ARP / Non-DHCP / Non-ICMPv6 broadcasts. The sending or receiving of broadcast packets that are not ARP protocol, DHCP protocol, nor ICMPv6 on the virtual network will not be allowed for sessions with this policy setting. */
        this["policy:ArpDhcpOnly_bool"] = false;
        /** Security policy: Privacy Filter Mode. All direct communication between sessions with the privacy filter mode policy setting will be filtered. */
        this["policy:PrivacyFilter_bool"] = false;
        /** Security policy: Deny Operation as TCP/IP Server (IPv4). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv4. */
        this["policy:NoServer_bool"] = false;
        /** Security policy: Unlimited Number of Broadcasts. If a computer of a session with this policy setting sends broadcast packets of a number unusually larger than what would be considered normal on the virtual network, there will be no automatic limiting. */
        this["policy:NoBroadcastLimiter_bool"] = false;
        /** Security policy: Allow Monitoring Mode. Users with this policy setting will be granted to connect to the Virtual Hub in Monitoring Mode. Sessions in Monitoring Mode are able to monitor (tap) all packets flowing through the Virtual Hub. */
        this["policy:MonitorPort_bool"] = false;
        /** Security policy: Maximum Number of TCP Connections. For sessions with this policy setting, this sets the maximum number of physical TCP connections consists in a physical VPN session. */
        this["policy:MaxConnection_u32"] = 0;
        /** Security policy: Time-out Period. For sessions with this policy setting, this sets, in seconds, the time-out period to wait before disconnecting a session when communication trouble occurs between the VPN Client / VPN Server. */
        this["policy:TimeOut_u32"] = 0;
        /** Security policy: Maximum Number of MAC Addresses. For sessions with this policy setting, this limits the number of MAC addresses per session. */
        this["policy:MaxMac_u32"] = 0;
        /** Security policy: Maximum Number of IP Addresses (IPv4). For sessions with this policy setting, this specifies the number of IPv4 addresses that can be registered for a single session. */
        this["policy:MaxIP_u32"] = 0;
        /** Security policy: Upload Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the inwards direction from outside to inside the Virtual Hub. */
        this["policy:MaxUpload_u32"] = 0;
        /** Security policy: Download Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the outwards direction from inside the Virtual Hub to outside the Virtual Hub. */
        this["policy:MaxDownload_u32"] = 0;
        /** Security policy: Deny Changing Password. The users which use password authentication with this policy setting are not allowed to change their own password from the VPN Client Manager or similar. */
        this["policy:FixPassword_bool"] = false;
        /** Security policy: Maximum Number of Multiple Logins. Users with this policy setting are unable to have more than this number of concurrent logins. Bridge Mode sessions are not subjects to this policy. */
        this["policy:MultiLogins_u32"] = 0;
        /** Security policy: Deny VoIP / QoS Function. Users with this security policy are unable to use VoIP / QoS functions in VPN connection sessions. */
        this["policy:NoQoS_bool"] = false;
        /** Security policy: Filter RS / RA Packets (IPv6). All ICMPv6 packets which the message-type is 133 (Router Solicitation) or 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, an IPv6 client will be unable to use IPv6 address prefix auto detection and IPv6 default gateway auto detection. */
        this["policy:RSandRAFilter_bool"] = false;
        /** Security policy: Filter RA Packets (IPv6). All ICMPv6 packets which the message-type is 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, a malicious users will be unable to spread illegal IPv6 prefix or default gateway advertisements on the network. */
        this["policy:RAFilter_bool"] = false;
        /** Security policy: Filter DHCP Packets (IPv6). All IPv6 DHCP packets in sessions defined this policy will be filtered. */
        this["policy:DHCPv6Filter_bool"] = false;
        /** Security policy: Disallow DHCP Server Operation (IPv6). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv6 addresses to DHCP clients. */
        this["policy:DHCPv6NoServer_bool"] = false;
        /** Security policy: Deny Routing Operation (IPv6). IPv6 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible. */
        this["policy:NoRoutingV6_bool"] = false;
        /** Security policy: Deny IP Address Duplication (IPv6). The use of duplicating IPv6 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting. */
        this["policy:CheckIPv6_bool"] = false;
        /** Security policy: Deny Operation as TCP/IP Server (IPv6). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv6. */
        this["policy:NoServerV6_bool"] = false;
        /** Security policy: Maximum Number of IP Addresses (IPv6). For sessions with this policy setting, this specifies the number of IPv6 addresses that can be registered for a single session. */
        this["policy:MaxIPv6_u32"] = 0;
        /** Security policy: Disallow Password Save in VPN Client. For users with this policy setting, when the user is using *standard* password authentication, the user will be unable to save the password in VPN Client. The user will be required to input passwords for every time to connect a VPN. This will improve the security. If this policy is enabled, VPN Client Version 2.0 will be denied to access. */
        this["policy:NoSavePassword_bool"] = false;
        /** Security policy: VPN Client Automatic Disconnect. For users with this policy setting, a user's VPN session will be disconnected automatically after the specific period will elapse. In this case no automatic re-connection will be performed. This can prevent a lot of inactive VPN Sessions. If this policy is enabled, VPN Client Version 2.0 will be denied to access. */
        this["policy:AutoDisconnect_u32"] = 0;
        /** Security policy: Filter All IPv4 Packets. All IPv4 and ARP packets in sessions defined this policy will be filtered. */
        this["policy:FilterIPv4_bool"] = false;
        /** Security policy: Filter All IPv6 Packets. All IPv6 packets in sessions defined this policy will be filtered. */
        this["policy:FilterIPv6_bool"] = false;
        /** Security policy: Filter All Non-IP Packets. All non-IP packets in sessions defined this policy will be filtered. "Non-IP packet" mean a packet which is not IPv4, ARP nor IPv6. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. */
        this["policy:FilterNonIP_bool"] = false;
        /** Security policy: No Default-Router on IPv6 RA. In all VPN Sessions defines this policy, any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router. */
        this["policy:NoIPv6DefaultRouterInRA_bool"] = false;
        /** Security policy: No Default-Router on IPv6 RA (physical IPv6). In all VPN Sessions defines this policy (only when the physical communication protocol between VPN Client / VPN Bridge and VPN Server is IPv6), any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router. */
        this["policy:NoIPv6DefaultRouterInRAWhenIPv6_bool"] = false;
        /** Security policy: VLAN ID (IEEE802.1Q). You can specify the VLAN ID on the security policy. All VPN Sessions defines this policy, all Ethernet packets toward the Virtual Hub from the user will be inserted a VLAN tag (IEEE 802.1Q) with the VLAN ID. The user can also receive only packets with a VLAN tag which has the same VLAN ID. (Receiving process removes the VLAN tag automatically.) Any Ethernet packets with any other VLAN IDs or non-VLAN packets will not be received. All VPN Sessions without this policy definition can send / receive any kinds of Ethernet packets regardless of VLAN tags, and VLAN tags are not inserted or removed automatically. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. Therefore, tagged-VLAN packets are not subjects for IPv4 / IPv6 security policies, access lists nor other IPv4 / IPv6 specific deep processing. */
        this["policy:VLanId_u32"] = 0;
        /** Security policy: Whether version 3.0 (must be true) */
        this["policy:Ver3_bool"] = false;
        Object.assign(this, init);
    }
    return VpnRpcSetUser;
}());
exports.VpnRpcSetUser = VpnRpcSetUser;
/** Delete the access list */
var VpnRpcDeleteAccess = /** @class */ (function () {
    /** Constructor for the 'VpnRpcDeleteAccess' class: Delete the access list */
    function VpnRpcDeleteAccess(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** ID */
        this.Id_u32 = 0;
        Object.assign(this, init);
    }
    return VpnRpcDeleteAccess;
}());
exports.VpnRpcDeleteAccess = VpnRpcDeleteAccess;
/** Delete the CA of HUB */
var VpnRpcHubDeleteCA = /** @class */ (function () {
    /** Constructor for the 'VpnRpcHubDeleteCA' class: Delete the CA of HUB */
    function VpnRpcHubDeleteCA(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** Certificate key id to be deleted */
        this.Key_u32 = 0;
        Object.assign(this, init);
    }
    return VpnRpcHubDeleteCA;
}());
exports.VpnRpcHubDeleteCA = VpnRpcHubDeleteCA;
/** Deleting a user or group */
var VpnRpcDeleteUser = /** @class */ (function () {
    /** Constructor for the 'VpnRpcDeleteUser' class: Deleting a user or group */
    function VpnRpcDeleteUser(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** User or group name */
        this.Name_str = "";
        Object.assign(this, init);
    }
    return VpnRpcDeleteUser;
}());
exports.VpnRpcDeleteUser = VpnRpcDeleteUser;
/** Delete the HUB */
var VpnRpcDeleteHub = /** @class */ (function () {
    /** Constructor for the 'VpnRpcDeleteHub' class: Delete the HUB */
    function VpnRpcDeleteHub(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        Object.assign(this, init);
    }
    return VpnRpcDeleteHub;
}());
exports.VpnRpcDeleteHub = VpnRpcDeleteHub;
/** Delete the table */
var VpnRpcDeleteTable = /** @class */ (function () {
    /** Constructor for the 'VpnRpcDeleteTable' class: Delete the table */
    function VpnRpcDeleteTable(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** Key ID */
        this.Key_u32 = 0;
        Object.assign(this, init);
    }
    return VpnRpcDeleteTable;
}());
exports.VpnRpcDeleteTable = VpnRpcDeleteTable;
/** Specify the Link */
var VpnRpcLink = /** @class */ (function () {
    /** Constructor for the 'VpnRpcLink' class: Specify the Link */
    function VpnRpcLink(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** The name of the cascade connection */
        this.AccountName_utf = "";
        Object.assign(this, init);
    }
    return VpnRpcLink;
}());
exports.VpnRpcLink = VpnRpcLink;
/** Disconnect the session */
var VpnRpcDeleteSession = /** @class */ (function () {
    /** Constructor for the 'VpnRpcDeleteSession' class: Disconnect the session */
    function VpnRpcDeleteSession(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** Session name */
        this.Name_str = "";
        Object.assign(this, init);
    }
    return VpnRpcDeleteSession;
}());
exports.VpnRpcDeleteSession = VpnRpcDeleteSession;
/** Specify the HUB */
var VpnRpcHub = /** @class */ (function () {
    /** Constructor for the 'VpnRpcHub' class: Specify the HUB */
    function VpnRpcHub(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        Object.assign(this, init);
    }
    return VpnRpcHub;
}());
exports.VpnRpcHub = VpnRpcHub;
/** Disconnect a connection */
var VpnRpcDisconnectConnection = /** @class */ (function () {
    /** Constructor for the 'VpnRpcDisconnectConnection' class: Disconnect a connection */
    function VpnRpcDisconnectConnection(init) {
        /** Connection name */
        this.Name_str = "";
        Object.assign(this, init);
    }
    return VpnRpcDisconnectConnection;
}());
exports.VpnRpcDisconnectConnection = VpnRpcDisconnectConnection;
/** Enumeration of the access list */
var VpnRpcEnumAccessList = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumAccessList' class: Enumeration of the access list */
    function VpnRpcEnumAccessList(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** Access list */
        this.AccessList = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumAccessList;
}());
exports.VpnRpcEnumAccessList = VpnRpcEnumAccessList;
/** CA enumeration items of HUB */
var VpnRpcHubEnumCAItem = /** @class */ (function () {
    /** Constructor for the 'VpnRpcHubEnumCAItem' class: CA enumeration items of HUB */
    function VpnRpcHubEnumCAItem(init) {
        /** The key id of the item */
        this.Key_u32 = 0;
        /** Subject */
        this.SubjectName_utf = "";
        /** Issuer */
        this.IssuerName_utf = "";
        /** Expiration date */
        this.Expires_dt = new Date();
        Object.assign(this, init);
    }
    return VpnRpcHubEnumCAItem;
}());
exports.VpnRpcHubEnumCAItem = VpnRpcHubEnumCAItem;
/** CA enumeration of HUB */
var VpnRpcHubEnumCA = /** @class */ (function () {
    /** Constructor for the 'VpnRpcHubEnumCA' class: CA enumeration of HUB */
    function VpnRpcHubEnumCA(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** The list of CA */
        this.CAList = [];
        Object.assign(this, init);
    }
    return VpnRpcHubEnumCA;
}());
exports.VpnRpcHubEnumCA = VpnRpcHubEnumCA;
/** Type of connection */
var VpnRpcConnectionType;
(function (VpnRpcConnectionType) {
    /** VPN Client */
    VpnRpcConnectionType[VpnRpcConnectionType["Client"] = 0] = "Client";
    /** During initialization */
    VpnRpcConnectionType[VpnRpcConnectionType["Init"] = 1] = "Init";
    /** Login connection */
    VpnRpcConnectionType[VpnRpcConnectionType["Login"] = 2] = "Login";
    /** Additional connection */
    VpnRpcConnectionType[VpnRpcConnectionType["Additional"] = 3] = "Additional";
    /** RPC for server farm */
    VpnRpcConnectionType[VpnRpcConnectionType["FarmRpc"] = 4] = "FarmRpc";
    /** RPC for Management */
    VpnRpcConnectionType[VpnRpcConnectionType["AdminRpc"] = 5] = "AdminRpc";
    /** HUB enumeration */
    VpnRpcConnectionType[VpnRpcConnectionType["EnumHub"] = 6] = "EnumHub";
    /** Password change */
    VpnRpcConnectionType[VpnRpcConnectionType["Password"] = 7] = "Password";
    /** SSTP */
    VpnRpcConnectionType[VpnRpcConnectionType["SSTP"] = 8] = "SSTP";
    /** OpenVPN */
    VpnRpcConnectionType[VpnRpcConnectionType["OpenVPN"] = 9] = "OpenVPN";
})(VpnRpcConnectionType = exports.VpnRpcConnectionType || (exports.VpnRpcConnectionType = {}));
/** Connection enumeration items */
var VpnRpcEnumConnectionItem = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumConnectionItem' class: Connection enumeration items */
    function VpnRpcEnumConnectionItem(init) {
        /** Connection name */
        this.Name_str = "";
        /** Host name */
        this.Hostname_str = "";
        /** IP address */
        this.Ip_ip = "";
        /** Port number */
        this.Port_u32 = 0;
        /** Connected time */
        this.ConnectedTime_dt = new Date();
        /** Connection type */
        this.Type_u32 = 0;
        Object.assign(this, init);
    }
    return VpnRpcEnumConnectionItem;
}());
exports.VpnRpcEnumConnectionItem = VpnRpcEnumConnectionItem;
/** Connection enumeration */
var VpnRpcEnumConnection = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumConnection' class: Connection enumeration */
    function VpnRpcEnumConnection(init) {
        /** Number of connections */
        this.NumConnection_u32 = 0;
        /** Connection list */
        this.ConnectionList = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumConnection;
}());
exports.VpnRpcEnumConnection = VpnRpcEnumConnection;
/** Enum CRL Item */
var VpnRpcEnumCrlItem = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumCrlItem' class: Enum CRL Item */
    function VpnRpcEnumCrlItem(init) {
        /** Key ID */
        this.Key_u32 = 0;
        /** The contents of the CRL item */
        this.CrlInfo_utf = "";
        Object.assign(this, init);
    }
    return VpnRpcEnumCrlItem;
}());
exports.VpnRpcEnumCrlItem = VpnRpcEnumCrlItem;
/** Enum CRL */
var VpnRpcEnumCrl = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumCrl' class: Enum CRL */
    function VpnRpcEnumCrl(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** CRL list */
        this.CRLList = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumCrl;
}());
exports.VpnRpcEnumCrl = VpnRpcEnumCrl;
/** RPC_ENUM_DHCP_ITEM */
var VpnRpcEnumDhcpItem = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumDhcpItem' class: RPC_ENUM_DHCP_ITEM */
    function VpnRpcEnumDhcpItem(init) {
        /** ID */
        this.Id_u32 = 0;
        /** Lease time */
        this.LeasedTime_dt = new Date();
        /** Expiration date */
        this.ExpireTime_dt = new Date();
        /** MAC address */
        this.MacAddress_bin = new Uint8Array([]);
        /** IP address */
        this.IpAddress_ip = "";
        /** Subnet mask */
        this.Mask_u32 = 0;
        /** Host name */
        this.Hostname_str = "";
        Object.assign(this, init);
    }
    return VpnRpcEnumDhcpItem;
}());
exports.VpnRpcEnumDhcpItem = VpnRpcEnumDhcpItem;
/** RPC_ENUM_DHCP */
var VpnRpcEnumDhcp = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumDhcp' class: RPC_ENUM_DHCP */
    function VpnRpcEnumDhcp(init) {
        /** Virtual Hub Name */
        this.HubName_str = "";
        /** DHCP Item */
        this.DhcpTable = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumDhcp;
}());
exports.VpnRpcEnumDhcp = VpnRpcEnumDhcp;
/** EtherIP setting list */
var VpnRpcEnumEtherIpId = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumEtherIpId' class: EtherIP setting list */
    function VpnRpcEnumEtherIpId(init) {
        /** Setting list */
        this.Settings = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumEtherIpId;
}());
exports.VpnRpcEnumEtherIpId = VpnRpcEnumEtherIpId;
/** Ethernet Network Adapters list item */
var VpnRpcEnumEthItem = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumEthItem' class: Ethernet Network Adapters list item */
    function VpnRpcEnumEthItem(init) {
        /** Device name */
        this.DeviceName_str = "";
        /** Network connection name (description) */
        this.NetworkConnectionName_utf = "";
        Object.assign(this, init);
    }
    return VpnRpcEnumEthItem;
}());
exports.VpnRpcEnumEthItem = VpnRpcEnumEthItem;
/** Ethernet Network Adapters list */
var VpnRpcEnumEth = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumEth' class: Ethernet Network Adapters list */
    function VpnRpcEnumEth(init) {
        /** Ethernet Network Adapters list */
        this.EthList = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumEth;
}());
exports.VpnRpcEnumEth = VpnRpcEnumEth;
/** Server farm members enumeration items */
var VpnRpcEnumFarmItem = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumFarmItem' class: Server farm members enumeration items */
    function VpnRpcEnumFarmItem(init) {
        /** ID */
        this.Id_u32 = 0;
        /** Controller */
        this.Controller_bool = false;
        /** Connection time */
        this.ConnectedTime_dt = new Date();
        /** IP address */
        this.Ip_ip = "";
        /** Host name */
        this.Hostname_str = "";
        /** Point */
        this.Point_u32 = 0;
        /** Number of sessions */
        this.NumSessions_u32 = 0;
        /** Number of TCP connections */
        this.NumTcpConnections_u32 = 0;
        /** Number of HUBs */
        this.NumHubs_u32 = 0;
        /** Number of assigned client licenses */
        this.AssignedClientLicense_u32 = 0;
        /** Number of assigned bridge licenses */
        this.AssignedBridgeLicense_u32 = 0;
        Object.assign(this, init);
    }
    return VpnRpcEnumFarmItem;
}());
exports.VpnRpcEnumFarmItem = VpnRpcEnumFarmItem;
/** Server farm member enumeration */
var VpnRpcEnumFarm = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumFarm' class: Server farm member enumeration */
    function VpnRpcEnumFarm(init) {
        /** Number of Cluster Members */
        this.NumFarm_u32 = 0;
        /** Cluster Members list */
        this.FarmMemberList = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumFarm;
}());
exports.VpnRpcEnumFarm = VpnRpcEnumFarm;
/** Enumeration items in the group */
var VpnRpcEnumGroupItem = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumGroupItem' class: Enumeration items in the group */
    function VpnRpcEnumGroupItem(init) {
        /** User name */
        this.Name_str = "";
        /** Real name */
        this.Realname_utf = "";
        /** Note */
        this.Note_utf = "";
        /** Number of users */
        this.NumUsers_u32 = 0;
        /** Access denied */
        this.DenyAccess_bool = false;
        Object.assign(this, init);
    }
    return VpnRpcEnumGroupItem;
}());
exports.VpnRpcEnumGroupItem = VpnRpcEnumGroupItem;
/** Group enumeration */
var VpnRpcEnumGroup = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumGroup' class: Group enumeration */
    function VpnRpcEnumGroup(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** Group list */
        this.GroupList = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumGroup;
}());
exports.VpnRpcEnumGroup = VpnRpcEnumGroup;
/** Enumeration items of HUB */
var VpnRpcEnumHubItem = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumHubItem' class: Enumeration items of HUB */
    function VpnRpcEnumHubItem(init) {
        /** The name of the Virtual Hub */
        this.HubName_str = "";
        /** Online state */
        this.Online_bool = false;
        /** Type of HUB (Valid only for Clustered VPN Servers) */
        this.HubType_u32 = 0;
        /** Number of users */
        this.NumUsers_u32 = 0;
        /** Number of registered groups */
        this.NumGroups_u32 = 0;
        /** Number of registered sessions */
        this.NumSessions_u32 = 0;
        /** Number of current MAC table entries */
        this.NumMacTables_u32 = 0;
        /** Number of current IP table entries */
        this.NumIpTables_u32 = 0;
        /** Last communication date and time */
        this.LastCommTime_dt = new Date();
        /** Last login date and time */
        this.LastLoginTime_dt = new Date();
        /** Creation date and time */
        this.CreatedTime_dt = new Date();
        /** Number of accumulated logins */
        this.NumLogin_u32 = 0;
        /** Whether the traffic information is provided */
        this.IsTrafficFilled_bool = false;
        /** Number of broadcast packets (Recv) */
        this["Ex.Recv.BroadcastBytes_u64"] = 0;
        /** Broadcast bytes (Recv) */
        this["Ex.Recv.BroadcastCount_u64"] = 0;
        /** Unicast count (Recv) */
        this["Ex.Recv.UnicastBytes_u64"] = 0;
        /** Unicast bytes (Recv) */
        this["Ex.Recv.UnicastCount_u64"] = 0;
        /** Number of broadcast packets (Send) */
        this["Ex.Send.BroadcastBytes_u64"] = 0;
        /** Broadcast bytes (Send) */
        this["Ex.Send.BroadcastCount_u64"] = 0;
        /** Unicast bytes (Send) */
        this["Ex.Send.UnicastBytes_u64"] = 0;
        /** Unicast bytes (Send) */
        this["Ex.Send.UnicastCount_u64"] = 0;
        Object.assign(this, init);
    }
    return VpnRpcEnumHubItem;
}());
exports.VpnRpcEnumHubItem = VpnRpcEnumHubItem;
/** Enumeration of HUB */
var VpnRpcEnumHub = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumHub' class: Enumeration of HUB */
    function VpnRpcEnumHub(init) {
        /** Number of Virtual Hubs */
        this.NumHub_u32 = 0;
        /** Virtual Hubs */
        this.HubList = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumHub;
}());
exports.VpnRpcEnumHub = VpnRpcEnumHub;
/** Enumeration items of IP table */
var VpnRpcEnumIpTableItem = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumIpTableItem' class: Enumeration items of IP table */
    function VpnRpcEnumIpTableItem(init) {
        /** Key ID */
        this.Key_u32 = 0;
        /** Session name */
        this.SessionName_str = "";
        /** IP address */
        this.IpAddress_ip = "";
        /** Assigned by the DHCP */
        this.DhcpAllocated_bool = false;
        /** Creation date and time */
        this.CreatedTime_dt = new Date();
        /** Updating date */
        this.UpdatedTime_dt = new Date();
        /** Remote items */
        this.RemoteItem_bool = false;
        /** Remote host name */
        this.RemoteHostname_str = "";
        Object.assign(this, init);
    }
    return VpnRpcEnumIpTableItem;
}());
exports.VpnRpcEnumIpTableItem = VpnRpcEnumIpTableItem;
/** Enumeration of IP table */
var VpnRpcEnumIpTable = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumIpTable' class: Enumeration of IP table */
    function VpnRpcEnumIpTable(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** MAC table */
        this.IpTable = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumIpTable;
}());
exports.VpnRpcEnumIpTable = VpnRpcEnumIpTable;
/** Layer-3 interface enumeration */
var VpnRpcEnumL3If = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumL3If' class: Layer-3 interface enumeration */
    function VpnRpcEnumL3If(init) {
        /** Layer-3 switch name */
        this.Name_str = "";
        /** Layer-3 interface list */
        this.L3IFList = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumL3If;
}());
exports.VpnRpcEnumL3If = VpnRpcEnumL3If;
/** Layer-3 switch enumeration item */
var VpnRpcEnumL3SwItem = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumL3SwItem' class: Layer-3 switch enumeration item */
    function VpnRpcEnumL3SwItem(init) {
        /** Name of the layer-3 switch */
        this.Name_str = "";
        /** Number of layer-3 switch virtual interfaces */
        this.NumInterfaces_u32 = 0;
        /** Number of routing tables */
        this.NumTables_u32 = 0;
        /** Activated flag */
        this.Active_bool = false;
        /** Online flag */
        this.Online_bool = false;
        Object.assign(this, init);
    }
    return VpnRpcEnumL3SwItem;
}());
exports.VpnRpcEnumL3SwItem = VpnRpcEnumL3SwItem;
/** Layer-3 switch enumeration */
var VpnRpcEnumL3Sw = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumL3Sw' class: Layer-3 switch enumeration */
    function VpnRpcEnumL3Sw(init) {
        /** Layer-3 switch list */
        this.L3SWList = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumL3Sw;
}());
exports.VpnRpcEnumL3Sw = VpnRpcEnumL3Sw;
/** Routing table enumeration */
var VpnRpcEnumL3Table = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumL3Table' class: Routing table enumeration */
    function VpnRpcEnumL3Table(init) {
        /** L3 switch name */
        this.Name_str = "";
        /** Routing table item list */
        this.L3Table = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumL3Table;
}());
exports.VpnRpcEnumL3Table = VpnRpcEnumL3Table;
/** Cascade Connection Enumeration */
var VpnRpcEnumLinkItem = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumLinkItem' class: Cascade Connection Enumeration */
    function VpnRpcEnumLinkItem(init) {
        /** The name of cascade connection */
        this.AccountName_utf = "";
        /** Online flag */
        this.Online_bool = false;
        /** The flag indicates whether the cascade connection is established */
        this.Connected_bool = false;
        /** The error last occurred if the cascade connection is in the fail state */
        this.LastError_u32 = 0;
        /** Connection completion time */
        this.ConnectedTime_dt = new Date();
        /** Host name of the destination VPN server */
        this.Hostname_str = "";
        /** The Virtual Hub name */
        this.TargetHubName_str = "";
        Object.assign(this, init);
    }
    return VpnRpcEnumLinkItem;
}());
exports.VpnRpcEnumLinkItem = VpnRpcEnumLinkItem;
/** Enumeration of the link */
var VpnRpcEnumLink = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumLink' class: Enumeration of the link */
    function VpnRpcEnumLink(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** Number of cascade connections */
        this.NumLink_u32 = 0;
        /** The list of cascade connections */
        this.LinkList = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumLink;
}());
exports.VpnRpcEnumLink = VpnRpcEnumLink;
/** List of listeners item */
var VpnRpcListenerListItem = /** @class */ (function () {
    /** Constructor for the 'VpnRpcListenerListItem' class: List of listeners item */
    function VpnRpcListenerListItem(init) {
        /** TCP port number (range: 1 - 65535) */
        this.Ports_u32 = 0;
        /** Active state */
        this.Enables_bool = false;
        /** The flag to indicate if the error occurred on the listener port */
        this.Errors_bool = false;
        Object.assign(this, init);
    }
    return VpnRpcListenerListItem;
}());
exports.VpnRpcListenerListItem = VpnRpcListenerListItem;
/** List of listeners */
var VpnRpcListenerList = /** @class */ (function () {
    /** Constructor for the 'VpnRpcListenerList' class: List of listeners */
    function VpnRpcListenerList(init) {
        /** List of listener items */
        this.ListenerList = [];
        Object.assign(this, init);
    }
    return VpnRpcListenerList;
}());
exports.VpnRpcListenerList = VpnRpcListenerList;
/** Local Bridge enumeration */
var VpnRpcEnumLocalBridge = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumLocalBridge' class: Local Bridge enumeration */
    function VpnRpcEnumLocalBridge(init) {
        /** Local Bridge list */
        this.LocalBridgeList = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumLocalBridge;
}());
exports.VpnRpcEnumLocalBridge = VpnRpcEnumLocalBridge;
/** Log file enumeration */
var VpnRpcEnumLogFileItem = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumLogFileItem' class: Log file enumeration */
    function VpnRpcEnumLogFileItem(init) {
        /** Server name */
        this.ServerName_str = "";
        /** File path */
        this.FilePath_str = "";
        /** File size */
        this.FileSize_u32 = 0;
        /** Last write date */
        this.UpdatedTime_dt = new Date();
        Object.assign(this, init);
    }
    return VpnRpcEnumLogFileItem;
}());
exports.VpnRpcEnumLogFileItem = VpnRpcEnumLogFileItem;
/** Log file enumeration */
var VpnRpcEnumLogFile = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumLogFile' class: Log file enumeration */
    function VpnRpcEnumLogFile(init) {
        /** Log file list */
        this.LogFiles = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumLogFile;
}());
exports.VpnRpcEnumLogFile = VpnRpcEnumLogFile;
/** Enumeration items of the MAC table */
var VpnRpcEnumMacTableItem = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumMacTableItem' class: Enumeration items of the MAC table */
    function VpnRpcEnumMacTableItem(init) {
        /** Key ID */
        this.Key_u32 = 0;
        /** Session name */
        this.SessionName_str = "";
        /** MAC address */
        this.MacAddress_bin = new Uint8Array([]);
        /** Creation date and time */
        this.CreatedTime_dt = new Date();
        /** Updating date */
        this.UpdatedTime_dt = new Date();
        /** Remote items */
        this.RemoteItem_bool = false;
        /** Remote host name */
        this.RemoteHostname_str = "";
        /** VLAN ID */
        this.VlanId_u32 = 0;
        Object.assign(this, init);
    }
    return VpnRpcEnumMacTableItem;
}());
exports.VpnRpcEnumMacTableItem = VpnRpcEnumMacTableItem;
/** Enumeration of the MAC table */
var VpnRpcEnumMacTable = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumMacTable' class: Enumeration of the MAC table */
    function VpnRpcEnumMacTable(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** MAC table */
        this.MacTable = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumMacTable;
}());
exports.VpnRpcEnumMacTable = VpnRpcEnumMacTable;
/** NAT Entry Protocol Number */
var VpnRpcNatProtocol;
(function (VpnRpcNatProtocol) {
    /** TCP */
    VpnRpcNatProtocol[VpnRpcNatProtocol["TCP"] = 0] = "TCP";
    /** UDP */
    VpnRpcNatProtocol[VpnRpcNatProtocol["UDP"] = 1] = "UDP";
    /** DNS */
    VpnRpcNatProtocol[VpnRpcNatProtocol["DNS"] = 2] = "DNS";
    /** ICMP */
    VpnRpcNatProtocol[VpnRpcNatProtocol["ICMP"] = 3] = "ICMP";
})(VpnRpcNatProtocol = exports.VpnRpcNatProtocol || (exports.VpnRpcNatProtocol = {}));
/** State of NAT session (TCP) */
var VpnRpcNatTcpState;
(function (VpnRpcNatTcpState) {
    /** Connecting */
    VpnRpcNatTcpState[VpnRpcNatTcpState["Connecting"] = 0] = "Connecting";
    /** Send the RST (Connection failure or disconnected) */
    VpnRpcNatTcpState[VpnRpcNatTcpState["SendReset"] = 1] = "SendReset";
    /** Connection complete */
    VpnRpcNatTcpState[VpnRpcNatTcpState["Connected"] = 2] = "Connected";
    /** Connection established */
    VpnRpcNatTcpState[VpnRpcNatTcpState["Established"] = 3] = "Established";
    /** Wait for socket disconnection */
    VpnRpcNatTcpState[VpnRpcNatTcpState["WaitDisconnect"] = 4] = "WaitDisconnect";
})(VpnRpcNatTcpState = exports.VpnRpcNatTcpState || (exports.VpnRpcNatTcpState = {}));
/** VpnRpcEnumNat List Item */
var VpnRpcEnumNatItem = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumNatItem' class: VpnRpcEnumNat List Item */
    function VpnRpcEnumNatItem(init) {
        /** ID */
        this.Id_u32 = 0;
        /** Protocol */
        this.Protocol_u32 = 0;
        /** Source IP address */
        this.SrcIp_ip = "";
        /** Source host name */
        this.SrcHost_str = "";
        /** Source port number */
        this.SrcPort_u32 = 0;
        /** Destination IP address */
        this.DestIp_ip = "";
        /** Destination host name */
        this.DestHost_str = "";
        /** Destination port number */
        this.DestPort_u32 = 0;
        /** Connection time */
        this.CreatedTime_dt = new Date();
        /** Last communication time */
        this.LastCommTime_dt = new Date();
        /** Transmission size */
        this.SendSize_u64 = 0;
        /** Receive size */
        this.RecvSize_u64 = 0;
        /** TCP state */
        this.TcpStatus_u32 = 0;
        Object.assign(this, init);
    }
    return VpnRpcEnumNatItem;
}());
exports.VpnRpcEnumNatItem = VpnRpcEnumNatItem;
/** RPC_ENUM_NAT */
var VpnRpcEnumNat = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumNat' class: RPC_ENUM_NAT */
    function VpnRpcEnumNat(init) {
        /** Virtual Hub Name */
        this.HubName_str = "";
        /** NAT item */
        this.NatTable = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumNat;
}());
exports.VpnRpcEnumNat = VpnRpcEnumNat;
/** Enumeration item of VPN session */
var VpnRpcEnumSessionItem = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumSessionItem' class: Enumeration item of VPN session */
    function VpnRpcEnumSessionItem(init) {
        /** Session name */
        this.Name_str = "";
        /** Remote session */
        this.RemoteSession_bool = false;
        /** Remote server name */
        this.RemoteHostname_str = "";
        /** User name */
        this.Username_str = "";
        /** IP address */
        this.ClientIP_ip = "";
        /** Host name */
        this.Hostname_str = "";
        /** Maximum number of underlying TCP connections */
        this.MaxNumTcp_u32 = 0;
        /** Number of current underlying TCP connections */
        this.CurrentNumTcp_u32 = 0;
        /** Packet size transmitted */
        this.PacketSize_u64 = 0;
        /** Number of packets transmitted */
        this.PacketNum_u64 = 0;
        /** Is a Cascade VPN session */
        this.LinkMode_bool = false;
        /** Is a SecureNAT VPN session */
        this.SecureNATMode_bool = false;
        /** Is the VPN session for Local Bridge */
        this.BridgeMode_bool = false;
        /** Is a Layer-3 Switch VPN session */
        this.Layer3Mode_bool = false;
        /** Is in Bridge Mode */
        this.Client_BridgeMode_bool = false;
        /** Is in Monitor Mode */
        this.Client_MonitorMode_bool = false;
        /** VLAN ID */
        this.VLanId_u32 = 0;
        /** Unique ID of the VPN Session */
        this.UniqueId_bin = new Uint8Array([]);
        /** Creation date and time */
        this.CreatedTime_dt = new Date();
        /** Last communication date and time */
        this.LastCommTime_dt = new Date();
        Object.assign(this, init);
    }
    return VpnRpcEnumSessionItem;
}());
exports.VpnRpcEnumSessionItem = VpnRpcEnumSessionItem;
/** Enumerate VPN sessions */
var VpnRpcEnumSession = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumSession' class: Enumerate VPN sessions */
    function VpnRpcEnumSession(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** VPN sessions list */
        this.SessionList = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumSession;
}());
exports.VpnRpcEnumSession = VpnRpcEnumSession;
/** Enumeration item of user */
var VpnRpcEnumUserItem = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumUserItem' class: Enumeration item of user */
    function VpnRpcEnumUserItem(init) {
        /** User name */
        this.Name_str = "";
        /** Group name */
        this.GroupName_str = "";
        /** Real name */
        this.Realname_utf = "";
        /** Note */
        this.Note_utf = "";
        /** Authentication method */
        this.AuthType_u32 = 0;
        /** Number of logins */
        this.NumLogin_u32 = 0;
        /** Last login date and time */
        this.LastLoginTime_dt = new Date();
        /** Access denied */
        this.DenyAccess_bool = false;
        /** Flag of whether the traffic variable is set */
        this.IsTrafficFilled_bool = false;
        /** Flag of whether expiration date variable is set */
        this.IsExpiresFilled_bool = false;
        /** Expiration date */
        this.Expires_dt = new Date();
        /** Number of broadcast packets (Recv) */
        this["Ex.Recv.BroadcastBytes_u64"] = 0;
        /** Broadcast bytes (Recv) */
        this["Ex.Recv.BroadcastCount_u64"] = 0;
        /** Unicast count (Recv) */
        this["Ex.Recv.UnicastBytes_u64"] = 0;
        /** Unicast bytes (Recv) */
        this["Ex.Recv.UnicastCount_u64"] = 0;
        /** Number of broadcast packets (Send) */
        this["Ex.Send.BroadcastBytes_u64"] = 0;
        /** Broadcast bytes (Send) */
        this["Ex.Send.BroadcastCount_u64"] = 0;
        /** Unicast bytes (Send) */
        this["Ex.Send.UnicastBytes_u64"] = 0;
        /** Unicast bytes (Send) */
        this["Ex.Send.UnicastCount_u64"] = 0;
        Object.assign(this, init);
    }
    return VpnRpcEnumUserItem;
}());
exports.VpnRpcEnumUserItem = VpnRpcEnumUserItem;
/** Enumeration of user */
var VpnRpcEnumUser = /** @class */ (function () {
    /** Constructor for the 'VpnRpcEnumUser' class: Enumeration of user */
    function VpnRpcEnumUser(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** User list */
        this.UserList = [];
        Object.assign(this, init);
    }
    return VpnRpcEnumUser;
}());
exports.VpnRpcEnumUser = VpnRpcEnumUser;
/** Source IP Address Limit List Item */
var VpnAc = /** @class */ (function () {
    /** Constructor for the 'VpnAc' class: Source IP Address Limit List Item */
    function VpnAc(init) {
        /** ID */
        this.Id_u32 = 0;
        /** Priority */
        this.Priority_u32 = 0;
        /** Deny access */
        this.Deny_bool = false;
        /** Set true if you want to specify the SubnetMask_ip item. */
        this.Masked_bool = false;
        /** IP address */
        this.IpAddress_ip = "";
        /** Subnet mask, valid only if Masked_bool == true */
        this.SubnetMask_ip = "";
        Object.assign(this, init);
    }
    return VpnAc;
}());
exports.VpnAc = VpnAc;
/** Source IP Address Limit List */
var VpnRpcAcList = /** @class */ (function () {
    /** Constructor for the 'VpnRpcAcList' class: Source IP Address Limit List */
    function VpnRpcAcList(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** Source IP Address Limit List */
        this.ACList = [];
        Object.assign(this, init);
    }
    return VpnRpcAcList;
}());
exports.VpnRpcAcList = VpnRpcAcList;
/** Message */
var VpnRpcMsg = /** @class */ (function () {
    /** Constructor for the 'VpnRpcMsg' class: Message */
    function VpnRpcMsg(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** Message (Unicode strings acceptable) */
        this.Msg_bin = new Uint8Array([]);
        Object.assign(this, init);
    }
    return VpnRpcMsg;
}());
exports.VpnRpcMsg = VpnRpcMsg;
/** Get / Set the Azure state */
var VpnRpcAzureStatus = /** @class */ (function () {
    /** Constructor for the 'VpnRpcAzureStatus' class: Get / Set the Azure state */
    function VpnRpcAzureStatus(init) {
        /** Whether VPN Azure Function is Enabled */
        this.IsEnabled_bool = false;
        /** Whether connection to VPN Azure Cloud Server is established */
        this.IsConnected_bool = false;
        Object.assign(this, init);
    }
    return VpnRpcAzureStatus;
}());
exports.VpnRpcAzureStatus = VpnRpcAzureStatus;
/** Local Bridge support information */
var VpnRpcBridgeSupport = /** @class */ (function () {
    /** Constructor for the 'VpnRpcBridgeSupport' class: Local Bridge support information */
    function VpnRpcBridgeSupport(init) {
        /** Whether the OS supports the Local Bridge function */
        this.IsBridgeSupportedOs_bool = false;
        /** Whether WinPcap is necessary to install */
        this.IsWinPcapNeeded_bool = false;
        Object.assign(this, init);
    }
    return VpnRpcBridgeSupport;
}());
exports.VpnRpcBridgeSupport = VpnRpcBridgeSupport;
/** Get the CA of HUB */
var VpnRpcHubGetCA = /** @class */ (function () {
    /** Constructor for the 'VpnRpcHubGetCA' class: Get the CA of HUB */
    function VpnRpcHubGetCA(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** The key id of the certificate */
        this.Key_u32 = 0;
        /** The body of the X.509 certificate */
        this.Cert_bin = new Uint8Array([]);
        Object.assign(this, init);
    }
    return VpnRpcHubGetCA;
}());
exports.VpnRpcHubGetCA = VpnRpcHubGetCA;
/** Caps item of the VPN Server */
var VpnCaps = /** @class */ (function () {
    /** Constructor for the 'VpnCaps' class: Caps item of the VPN Server */
    function VpnCaps(init) {
        /** Name */
        this.CapsName_str = "";
        /** Value */
        this.CapsValue_u32 = 0;
        /** Descrption */
        this.CapsDescrption_utf = "";
        Object.assign(this, init);
    }
    return VpnCaps;
}());
exports.VpnCaps = VpnCaps;
/** Caps list of the VPN Server */
var VpnCapslist = /** @class */ (function () {
    /** Constructor for the 'VpnCapslist' class: Caps list of the VPN Server */
    function VpnCapslist(init) {
        /** Caps list of the VPN Server */
        this.CapsList = [];
        Object.assign(this, init);
    }
    return VpnCapslist;
}());
exports.VpnCapslist = VpnCapslist;
/** Config operation */
var VpnRpcConfig = /** @class */ (function () {
    /** Constructor for the 'VpnRpcConfig' class: Config operation */
    function VpnRpcConfig(init) {
        /** File name (valid only for returning from the server) */
        this.FileName_str = "";
        /** File data */
        this.FileData_bin = new Uint8Array([]);
        Object.assign(this, init);
    }
    return VpnRpcConfig;
}());
exports.VpnRpcConfig = VpnRpcConfig;
/** Connection information */
var VpnRpcConnectionInfo = /** @class */ (function () {
    /** Constructor for the 'VpnRpcConnectionInfo' class: Connection information */
    function VpnRpcConnectionInfo(init) {
        /** Connection name */
        this.Name_str = "";
        /** Type */
        this.Type_u32 = 0;
        /** Host name */
        this.Hostname_str = "";
        /** IP address */
        this.Ip_ip = "";
        /** Port number */
        this.Port_u32 = 0;
        /** Connected time */
        this.ConnectedTime_dt = new Date();
        /** Server string */
        this.ServerStr_str = "";
        /** Server version */
        this.ServerVer_u32 = 0;
        /** Server build number */
        this.ServerBuild_u32 = 0;
        /** Client string */
        this.ClientStr_str = "";
        /** Client version */
        this.ClientVer_u32 = 0;
        /** Client build number */
        this.ClientBuild_u32 = 0;
        Object.assign(this, init);
    }
    return VpnRpcConnectionInfo;
}());
exports.VpnRpcConnectionInfo = VpnRpcConnectionInfo;
/** Proxy type */
var VpnRpcProxyType;
(function (VpnRpcProxyType) {
    /** Direct TCP connection */
    VpnRpcProxyType[VpnRpcProxyType["Direct"] = 0] = "Direct";
    /** Connection via HTTP proxy server */
    VpnRpcProxyType[VpnRpcProxyType["HTTP"] = 1] = "HTTP";
    /** Connection via SOCKS proxy server */
    VpnRpcProxyType[VpnRpcProxyType["SOCKS"] = 2] = "SOCKS";
})(VpnRpcProxyType = exports.VpnRpcProxyType || (exports.VpnRpcProxyType = {}));
/** The current status of the DDNS */
var VpnDDnsClientStatus = /** @class */ (function () {
    /** Constructor for the 'VpnDDnsClientStatus' class: The current status of the DDNS */
    function VpnDDnsClientStatus(init) {
        /** Last error code (IPv4) */
        this.Err_IPv4_u32 = 0;
        /** Last error string (IPv4) */
        this.ErrStr_IPv4_utf = "";
        /** Last error code (IPv6) */
        this.Err_IPv6_u32 = 0;
        /** Last error string (IPv6) */
        this.ErrStr_IPv6_utf = "";
        /** Current DDNS host name */
        this.CurrentHostName_str = "";
        /** Current FQDN of the DDNS hostname */
        this.CurrentFqdn_str = "";
        /** DDNS suffix */
        this.DnsSuffix_str = "";
        /** Current IPv4 address of the VPN Server */
        this.CurrentIPv4_str = "";
        /** Current IPv6 address of the VPN Server */
        this.CurrentIPv6_str = "";
        Object.assign(this, init);
    }
    return VpnDDnsClientStatus;
}());
exports.VpnDDnsClientStatus = VpnDDnsClientStatus;
/** Internet connection settings */
var VpnInternetSetting = /** @class */ (function () {
    /** Constructor for the 'VpnInternetSetting' class: Internet connection settings */
    function VpnInternetSetting(init) {
        /** Type of proxy server */
        this.ProxyType_u32 = 0;
        /** Proxy server host name */
        this.ProxyHostName_str = "";
        /** Proxy server port number */
        this.ProxyPort_u32 = 0;
        /** Proxy server user name */
        this.ProxyUsername_str = "";
        /** Proxy server password */
        this.ProxyPassword_str = "";
        Object.assign(this, init);
    }
    return VpnInternetSetting;
}());
exports.VpnInternetSetting = VpnInternetSetting;
/** Administration options */
var VpnAdminOption = /** @class */ (function () {
    /** Constructor for the 'VpnAdminOption' class: Administration options */
    function VpnAdminOption(init) {
        /** Name */
        this.Name_str = "";
        /** Data */
        this.Value_u32 = 0;
        /** Descrption */
        this.Descrption_utf = "";
        Object.assign(this, init);
    }
    return VpnAdminOption;
}());
exports.VpnAdminOption = VpnAdminOption;
/** Administration options list */
var VpnRpcAdminOption = /** @class */ (function () {
    /** Constructor for the 'VpnRpcAdminOption' class: Administration options list */
    function VpnRpcAdminOption(init) {
        /** Virtual HUB name */
        this.HubName_str = "";
        /** List data */
        this.AdminOptionList = [];
        Object.assign(this, init);
    }
    return VpnRpcAdminOption;
}());
exports.VpnRpcAdminOption = VpnRpcAdminOption;
/** Connection state to the controller */
var VpnRpcFarmConnectionStatus = /** @class */ (function () {
    /** Constructor for the 'VpnRpcFarmConnectionStatus' class: Connection state to the controller */
    function VpnRpcFarmConnectionStatus(init) {
        /** IP address */
        this.Ip_ip = "";
        /** Port number */
        this.Port_u32 = 0;
        /** Online state */
        this.Online_bool = false;
        /** Last error code */
        this.LastError_u32 = 0;
        /** Connection start time */
        this.StartedTime_dt = new Date();
        /** First connection time */
        this.FirstConnectedTime_dt = new Date();
        /** Connection time of this time */
        this.CurrentConnectedTime_dt = new Date();
        /** Number of retries */
        this.NumTry_u32 = 0;
        /** Number of connection count */
        this.NumConnected_u32 = 0;
        /** Connection failure count */
        this.NumFailed_u32 = 0;
        Object.assign(this, init);
    }
    return VpnRpcFarmConnectionStatus;
}());
exports.VpnRpcFarmConnectionStatus = VpnRpcFarmConnectionStatus;
/** HUB item of each farm member */
var VpnRpcFarmHub = /** @class */ (function () {
    /** Constructor for the 'VpnRpcFarmHub' class: HUB item of each farm member */
    function VpnRpcFarmHub(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** Dynamic HUB */
        this.DynamicHub_bool = false;
        Object.assign(this, init);
    }
    return VpnRpcFarmHub;
}());
exports.VpnRpcFarmHub = VpnRpcFarmHub;
/** Server farm member information acquisition */
var VpnRpcFarmInfo = /** @class */ (function () {
    /** Constructor for the 'VpnRpcFarmInfo' class: Server farm member information acquisition */
    function VpnRpcFarmInfo(init) {
        /** ID */
        this.Id_u32 = 0;
        /** The flag if the server is Cluster Controller (false: Cluster Member servers) */
        this.Controller_bool = false;
        /** Connection Established Time */
        this.ConnectedTime_dt = new Date();
        /** IP address */
        this.Ip_ip = "";
        /** Host name */
        this.Hostname_str = "";
        /** Point */
        this.Point_u32 = 0;
        /** Number of Public Ports */
        this.NumPort_u32 = 0;
        /** Public Ports */
        this.Ports_u32 = [];
        /** Server certificate */
        this.ServerCert_bin = new Uint8Array([]);
        /** Number of farm HUB */
        this.NumFarmHub_u32 = 0;
        /** The hosted Virtual Hub list */
        this.HubsList = [];
        /** Number of hosted VPN sessions */
        this.NumSessions_u32 = 0;
        /** Number of TCP connections */
        this.NumTcpConnections_u32 = 0;
        /** Performance Standard Ratio */
        this.Weight_u32 = 0;
        Object.assign(this, init);
    }
    return VpnRpcFarmInfo;
}());
exports.VpnRpcFarmInfo = VpnRpcFarmInfo;
/** Server farm configuration */
var VpnRpcFarm = /** @class */ (function () {
    /** Constructor for the 'VpnRpcFarm' class: Server farm configuration */
    function VpnRpcFarm(init) {
        /** Type of server */
        this.ServerType_u32 = 0;
        /** Valid only for Cluster Member servers. Number of the Ports_u32 element. */
        this.NumPort_u32 = 0;
        /** Valid only for Cluster Member servers. Specify the list of public port numbers on this server. The list must have at least one public port number set, and it is also possible to set multiple public port numbers. */
        this.Ports_u32 = [];
        /** Valid only for Cluster Member servers. Specify the public IP address of this server. If you wish to leave public IP address unspecified, specify the empty string. When a public IP address is not specified, the IP address of the network interface used when connecting to the cluster controller will be automatically used. */
        this.PublicIp_ip = "";
        /** Valid only for Cluster Member servers. Specify the host name or IP address of the destination cluster controller. */
        this.ControllerName_str = "";
        /** Valid only for Cluster Member servers. Specify the TCP port number of the destination cluster controller. */
        this.ControllerPort_u32 = 0;
        /** Valid only for Cluster Member servers. Specify the password required to connect to the destination controller. It needs to be the same as an administrator password on the destination controller. */
        this.MemberPasswordPlaintext_str = "";
        /** This sets a value for the performance standard ratio of this VPN Server. This is the standard value for when load balancing is performed in the cluster. For example, making only one machine 200 while the other members have a status of 100, will regulate that machine to receive twice as many connections as the other members. Specify 1 or higher for the value. If this parameter is left unspecified, 100 will be used. */
        this.Weight_u32 = 0;
        /** Valid only for Cluster Controller server. By specifying true, the VPN Server will operate only as a controller on the cluster and it will always distribute general VPN Client connections to members other than itself. This function is used in high-load environments. */
        this.ControllerOnly_bool = false;
        Object.assign(this, init);
    }
    return VpnRpcFarm;
}());
exports.VpnRpcFarm = VpnRpcFarm;
/** Log switch type */
var VpnRpcLogSwitchType;
(function (VpnRpcLogSwitchType) {
    /** No switching */
    VpnRpcLogSwitchType[VpnRpcLogSwitchType["No"] = 0] = "No";
    /** Secondly basis */
    VpnRpcLogSwitchType[VpnRpcLogSwitchType["Second"] = 1] = "Second";
    /** Minutely basis */
    VpnRpcLogSwitchType[VpnRpcLogSwitchType["Minute"] = 2] = "Minute";
    /** Hourly basis */
    VpnRpcLogSwitchType[VpnRpcLogSwitchType["Hour"] = 3] = "Hour";
    /** Daily basis */
    VpnRpcLogSwitchType[VpnRpcLogSwitchType["Day"] = 4] = "Day";
    /** Monthly basis */
    VpnRpcLogSwitchType[VpnRpcLogSwitchType["Month"] = 5] = "Month";
})(VpnRpcLogSwitchType = exports.VpnRpcLogSwitchType || (exports.VpnRpcLogSwitchType = {}));
/** Packet log settings */
var VpnRpcPacketLogSetting;
(function (VpnRpcPacketLogSetting) {
    /** Not save */
    VpnRpcPacketLogSetting[VpnRpcPacketLogSetting["None"] = 0] = "None";
    /** Only header */
    VpnRpcPacketLogSetting[VpnRpcPacketLogSetting["Header"] = 1] = "Header";
    /** All payloads */
    VpnRpcPacketLogSetting[VpnRpcPacketLogSetting["All"] = 2] = "All";
})(VpnRpcPacketLogSetting = exports.VpnRpcPacketLogSetting || (exports.VpnRpcPacketLogSetting = {}));
/** Packet log settings array index */
var VpnRpcPacketLogSettingIndex;
(function (VpnRpcPacketLogSettingIndex) {
    /** TCP connection log */
    VpnRpcPacketLogSettingIndex[VpnRpcPacketLogSettingIndex["TcpConnection"] = 0] = "TcpConnection";
    /** TCP packet log */
    VpnRpcPacketLogSettingIndex[VpnRpcPacketLogSettingIndex["TcpAll"] = 1] = "TcpAll";
    /** DHCP Log */
    VpnRpcPacketLogSettingIndex[VpnRpcPacketLogSettingIndex["Dhcp"] = 2] = "Dhcp";
    /** UDP log */
    VpnRpcPacketLogSettingIndex[VpnRpcPacketLogSettingIndex["Udp"] = 3] = "Udp";
    /** ICMP log */
    VpnRpcPacketLogSettingIndex[VpnRpcPacketLogSettingIndex["Icmp"] = 4] = "Icmp";
    /** IP log */
    VpnRpcPacketLogSettingIndex[VpnRpcPacketLogSettingIndex["Ip"] = 5] = "Ip";
    /** ARP log */
    VpnRpcPacketLogSettingIndex[VpnRpcPacketLogSettingIndex["Arp"] = 6] = "Arp";
    /** Ethernet log */
    VpnRpcPacketLogSettingIndex[VpnRpcPacketLogSettingIndex["Ethernet"] = 7] = "Ethernet";
})(VpnRpcPacketLogSettingIndex = exports.VpnRpcPacketLogSettingIndex || (exports.VpnRpcPacketLogSettingIndex = {}));
/** HUB log settings */
var VpnRpcHubLog = /** @class */ (function () {
    /** Constructor for the 'VpnRpcHubLog' class: HUB log settings */
    function VpnRpcHubLog(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** The flag to enable / disable saving the security log */
        this.SaveSecurityLog_bool = false;
        /** The log filename switching setting of the security log */
        this.SecurityLogSwitchType_u32 = 0;
        /** The flag to enable / disable saving the security log */
        this.SavePacketLog_bool = false;
        /** The log filename switching settings of the packet logs */
        this.PacketLogSwitchType_u32 = 0;
        /** Specify the save contents of the packet logs (uint * 16 array). The index numbers: TcpConnection = 0, TcpAll = 1, DHCP = 2, UDP = 3, ICMP = 4, IP = 5, ARP = 6, Ethernet = 7. */
        this.PacketLogConfig_u32 = [];
        Object.assign(this, init);
    }
    return VpnRpcHubLog;
}());
exports.VpnRpcHubLog = VpnRpcHubLog;
/** RADIUS server options */
var VpnRpcRadius = /** @class */ (function () {
    /** Constructor for the 'VpnRpcRadius' class: RADIUS server options */
    function VpnRpcRadius(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** RADIUS server name */
        this.RadiusServerName_str = "";
        /** RADIUS port number */
        this.RadiusPort_u32 = 0;
        /** Secret key */
        this.RadiusSecret_str = "";
        /** Radius retry interval */
        this.RadiusRetryInterval_u32 = 0;
        Object.assign(this, init);
    }
    return VpnRpcRadius;
}());
exports.VpnRpcRadius = VpnRpcRadius;
/** Get the state HUB */
var VpnRpcHubStatus = /** @class */ (function () {
    /** Constructor for the 'VpnRpcHubStatus' class: Get the state HUB */
    function VpnRpcHubStatus(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** Online */
        this.Online_bool = false;
        /** Type of HUB */
        this.HubType_u32 = 0;
        /** Number of sessions */
        this.NumSessions_u32 = 0;
        /** Number of sessions (client mode) */
        this.NumSessionsClient_u32 = 0;
        /** Number of sessions (bridge mode) */
        this.NumSessionsBridge_u32 = 0;
        /** Number of Access list entries */
        this.NumAccessLists_u32 = 0;
        /** Number of users */
        this.NumUsers_u32 = 0;
        /** Number of groups */
        this.NumGroups_u32 = 0;
        /** Number of MAC table entries */
        this.NumMacTables_u32 = 0;
        /** Number of IP table entries */
        this.NumIpTables_u32 = 0;
        /** Number of broadcast packets (Recv) */
        this["Recv.BroadcastBytes_u64"] = 0;
        /** Broadcast bytes (Recv) */
        this["Recv.BroadcastCount_u64"] = 0;
        /** Unicast count (Recv) */
        this["Recv.UnicastBytes_u64"] = 0;
        /** Unicast bytes (Recv) */
        this["Recv.UnicastCount_u64"] = 0;
        /** Number of broadcast packets (Send) */
        this["Send.BroadcastBytes_u64"] = 0;
        /** Broadcast bytes (Send) */
        this["Send.BroadcastCount_u64"] = 0;
        /** Unicast bytes (Send) */
        this["Send.UnicastBytes_u64"] = 0;
        /** Unicast bytes (Send) */
        this["Send.UnicastCount_u64"] = 0;
        /** Whether SecureNAT is enabled */
        this.SecureNATEnabled_bool = false;
        /** Last communication date and time */
        this.LastCommTime_dt = new Date();
        /** Last login date and time */
        this.LastLoginTime_dt = new Date();
        /** Creation date and time */
        this.CreatedTime_dt = new Date();
        /** Number of logins */
        this.NumLogin_u32 = 0;
        Object.assign(this, init);
    }
    return VpnRpcHubStatus;
}());
exports.VpnRpcHubStatus = VpnRpcHubStatus;
/** List of services provided by IPsec server */
var VpnIPsecServices = /** @class */ (function () {
    /** Constructor for the 'VpnIPsecServices' class: List of services provided by IPsec server */
    function VpnIPsecServices(init) {
        /** Enable or Disable the L2TP Server Function (Raw L2TP with No Encryptions). To accept special VPN clients, enable this option. */
        this.L2TP_Raw_bool = false;
        /** Enable or Disable the L2TP over IPsec Server Function. To accept VPN connections from iPhone, iPad, Android, Windows or Mac OS X, enable this option. */
        this.L2TP_IPsec_bool = false;
        /** Enable or Disable the EtherIP / L2TPv3 over IPsec Server Function (for site-to-site VPN Server function). Router Products which are compatible with EtherIP over IPsec can connect to Virtual Hubs on the VPN Server and establish Layer-2 (Ethernet) Bridging. */
        this.EtherIP_IPsec_bool = false;
        /** Specify the IPsec Pre-Shared Key. An IPsec Pre-Shared Key is also called as "PSK" or "secret". Specify it equal or less than 8 letters, and distribute it to every users who will connect to the VPN Server. Please note: Google Android 4.0 has a bug which a Pre-Shared Key with 10 or more letters causes a unexpected behavior. For that reason, the letters of a Pre-Shared Key should be 9 or less characters. */
        this.IPsec_Secret_str = "";
        /** Specify the default Virtual HUB in a case of omitting the name of HUB on the Username. Users should specify their username such as "Username@Target Virtual HUB Name" to connect this L2TP Server. If the designation of the Virtual Hub is omitted, the above HUB will be used as the target. */
        this.L2TP_DefaultHub_str = "";
        Object.assign(this, init);
    }
    return VpnIPsecServices;
}());
exports.VpnIPsecServices = VpnIPsecServices;
/** Keep alive protocol */
var VpnRpcKeepAliveProtocol;
(function (VpnRpcKeepAliveProtocol) {
    /** TCP */
    VpnRpcKeepAliveProtocol[VpnRpcKeepAliveProtocol["TCP"] = 0] = "TCP";
    /** UDP */
    VpnRpcKeepAliveProtocol[VpnRpcKeepAliveProtocol["UDP"] = 1] = "UDP";
})(VpnRpcKeepAliveProtocol = exports.VpnRpcKeepAliveProtocol || (exports.VpnRpcKeepAliveProtocol = {}));
/** Keep Alive settings */
var VpnRpcKeep = /** @class */ (function () {
    /** Constructor for the 'VpnRpcKeep' class: Keep Alive settings */
    function VpnRpcKeep(init) {
        /** The flag to enable keep-alive to the Internet */
        this.UseKeepConnect_bool = false;
        /** Specify the host name or IP address of the destination */
        this.KeepConnectHost_str = "";
        /** Specify the port number of the destination */
        this.KeepConnectPort_u32 = 0;
        /** Protocol type */
        this.KeepConnectProtocol_u32 = 0;
        /** Interval Between Packets Sends (Seconds) */
        this.KeepConnectInterval_u32 = 0;
        Object.assign(this, init);
    }
    return VpnRpcKeep;
}());
exports.VpnRpcKeep = VpnRpcKeep;
/** State of the client session */
var VpnRpcClientSessionStatus;
(function (VpnRpcClientSessionStatus) {
    /** Connecting */
    VpnRpcClientSessionStatus[VpnRpcClientSessionStatus["Connecting"] = 0] = "Connecting";
    /** Negotiating */
    VpnRpcClientSessionStatus[VpnRpcClientSessionStatus["Negotiation"] = 1] = "Negotiation";
    /** During user authentication */
    VpnRpcClientSessionStatus[VpnRpcClientSessionStatus["Auth"] = 2] = "Auth";
    /** Connection complete */
    VpnRpcClientSessionStatus[VpnRpcClientSessionStatus["Established"] = 3] = "Established";
    /** Wait to retry */
    VpnRpcClientSessionStatus[VpnRpcClientSessionStatus["Retry"] = 4] = "Retry";
    /** Idle state */
    VpnRpcClientSessionStatus[VpnRpcClientSessionStatus["Idle"] = 5] = "Idle";
})(VpnRpcClientSessionStatus = exports.VpnRpcClientSessionStatus || (exports.VpnRpcClientSessionStatus = {}));
/** Get the link state */
var VpnRpcLinkStatus = /** @class */ (function () {
    /** Constructor for the 'VpnRpcLinkStatus' class: Get the link state */
    function VpnRpcLinkStatus(init) {
        /** The Virtual Hub name */
        this.HubName_Ex_str = "";
        /** The name of the cascade connection */
        this.AccountName_utf = "";
        /** The flag whether the cascade connection is enabled */
        this.Active_bool = false;
        /** The flag whether the cascade connection is established */
        this.Connected_bool = false;
        /** The session status */
        this.SessionStatus_u32 = 0;
        /** The destination VPN server name */
        this.ServerName_str = "";
        /** The port number of the server */
        this.ServerPort_u32 = 0;
        /** Server product name */
        this.ServerProductName_str = "";
        /** Server product version */
        this.ServerProductVer_u32 = 0;
        /** Server product build number */
        this.ServerProductBuild_u32 = 0;
        /** Server's X.509 certificate */
        this.ServerX_bin = new Uint8Array([]);
        /** Client certificate */
        this.ClientX_bin = new Uint8Array([]);
        /** Connection start time */
        this.StartTime_dt = new Date();
        /** Connection completion time of the first connection */
        this.FirstConnectionEstablisiedTime_dt = new Date();
        /** Connection completion time of this connection */
        this.CurrentConnectionEstablishTime_dt = new Date();
        /** Number of connections have been established so far */
        this.NumConnectionsEatablished_u32 = 0;
        /** Half-connection */
        this.HalfConnection_bool = false;
        /** VoIP / QoS */
        this.QoS_bool = false;
        /** Maximum number of the underlying TCP connections */
        this.MaxTcpConnections_u32 = 0;
        /** Number of current underlying TCP connections */
        this.NumTcpConnections_u32 = 0;
        /** Number of underlying inbound TCP connections */
        this.NumTcpConnectionsUpload_u32 = 0;
        /** Number of underlying outbound TCP connections */
        this.NumTcpConnectionsDownload_u32 = 0;
        /** Use of encryption */
        this.UseEncrypt_bool = false;
        /** Cipher algorithm name */
        this.CipherName_str = "";
        /** Use of compression */
        this.UseCompress_bool = false;
        /** The flag whether this is a R-UDP session */
        this.IsRUDPSession_bool = false;
        /** Underlying physical communication protocol */
        this.UnderlayProtocol_str = "";
        /** The UDP acceleration is enabled */
        this.IsUdpAccelerationEnabled_bool = false;
        /** The UDP acceleration is being actually used */
        this.IsUsingUdpAcceleration_bool = false;
        /** Session name */
        this.SessionName_str = "";
        /** Connection name */
        this.ConnectionName_str = "";
        /** Session key */
        this.SessionKey_bin = new Uint8Array([]);
        /** Total transmitted data size */
        this.TotalSendSize_u64 = 0;
        /** Total received data size */
        this.TotalRecvSize_u64 = 0;
        /** Total transmitted data size (no compression) */
        this.TotalSendSizeReal_u64 = 0;
        /** Total received data size (no compression) */
        this.TotalRecvSizeReal_u64 = 0;
        /** The flag whether the VPN session is Bridge Mode */
        this.IsBridgeMode_bool = false;
        /** The flag whether the VPN session is Monitor mode */
        this.IsMonitorMode_bool = false;
        /** VLAN ID */
        this.VLanId_u32 = 0;
        Object.assign(this, init);
    }
    return VpnRpcLinkStatus;
}());
exports.VpnRpcLinkStatus = VpnRpcLinkStatus;
/** Setting of SSTP and OpenVPN */
var VpnOpenVpnSstpConfig = /** @class */ (function () {
    /** Constructor for the 'VpnOpenVpnSstpConfig' class: Setting of SSTP and OpenVPN */
    function VpnOpenVpnSstpConfig(init) {
        /** Specify true to enable the OpenVPN Clone Server Function. Specify false to disable. */
        this.EnableOpenVPN_bool = false;
        /** Specify UDP ports to listen for OpenVPN. Multiple UDP ports can be specified with splitting by space or comma letters, for example: "1194, 2001, 2010, 2012". The default port for OpenVPN is UDP 1194. You can specify any other UDP ports. */
        this.OpenVPNPortList_str = "";
        /** pecify true to enable the Microsoft SSTP VPN Clone Server Function. Specify false to disable. */
        this.EnableSSTP_bool = false;
        Object.assign(this, init);
    }
    return VpnOpenVpnSstpConfig;
}());
exports.VpnOpenVpnSstpConfig = VpnOpenVpnSstpConfig;
/** Virtual host option */
var VpnVhOption = /** @class */ (function () {
    /** Constructor for the 'VpnVhOption' class: Virtual host option */
    function VpnVhOption(init) {
        /** Target Virtual HUB name */
        this.RpcHubName_str = "";
        /** MAC address */
        this.MacAddress_bin = new Uint8Array([]);
        /** IP address */
        this.Ip_ip = "";
        /** Subnet mask */
        this.Mask_ip = "";
        /** Use flag of the Virtual NAT function */
        this.UseNat_bool = false;
        /** MTU value (Standard: 1500) */
        this.Mtu_u32 = 0;
        /** NAT TCP timeout in seconds */
        this.NatTcpTimeout_u32 = 0;
        /** NAT UDP timeout in seconds */
        this.NatUdpTimeout_u32 = 0;
        /** Using flag of DHCP function */
        this.UseDhcp_bool = false;
        /** Specify the start point of the address band to be distributed to the client. (Example: 192.168.30.10) */
        this.DhcpLeaseIPStart_ip = "";
        /** Specify the end point of the address band to be distributed to the client. (Example: 192.168.30.200) */
        this.DhcpLeaseIPEnd_ip = "";
        /** Specify the subnet mask to be specified for the client. (Example: 255.255.255.0) */
        this.DhcpSubnetMask_ip = "";
        /** Specify the expiration date in second units for leasing an IP address to a client. */
        this.DhcpExpireTimeSpan_u32 = 0;
        /** Specify the IP address of the default gateway to be notified to the client. You can specify a SecureNAT Virtual Host IP address for this when the SecureNAT Function's Virtual NAT Function has been enabled and is being used also. If you specify 0 or none, then the client will not be notified of the default gateway. */
        this.DhcpGatewayAddress_ip = "";
        /** Specify the IP address of the primary DNS Server to be notified to the client. You can specify a SecureNAT Virtual Host IP address for this when the SecureNAT Function's Virtual NAT Function has been enabled and is being used also. If you specify empty, then the client will not be notified of the DNS Server address. */
        this.DhcpDnsServerAddress_ip = "";
        /** Specify the IP address of the secondary DNS Server to be notified to the client. You can specify a SecureNAT Virtual Host IP address for this when the SecureNAT Function's Virtual NAT Function has been enabled and is being used also. If you specify empty, then the client will not be notified of the DNS Server address. */
        this.DhcpDnsServerAddress2_ip = "";
        /** Specify the domain name to be notified to the client. If you specify none, then the client will not be notified of the domain name. */
        this.DhcpDomainName_str = "";
        /** Specify whether or not to save the Virtual DHCP Server operation in the Virtual Hub security log. Specify true to save it. This value is interlinked with the Virtual NAT Function log save setting. */
        this.SaveLog_bool = false;
        /** The flag to enable the DhcpPushRoutes_str field. */
        this.ApplyDhcpPushRoutes_bool = false;
        /** Specify the static routing table to push. Example: "192.168.5.0/255.255.255.0/192.168.4.254, 10.0.0.0/255.0.0.0/192.168.4.253" Split multiple entries (maximum: 64 entries) by comma or space characters. Each entry must be specified in the "IP network address/subnet mask/gateway IP address" format. This Virtual DHCP Server can push the classless static routes (RFC 3442) with DHCP reply messages to VPN clients. Whether or not a VPN client can recognize the classless static routes (RFC 3442) depends on the target VPN client software. SoftEther VPN Client and OpenVPN Client are supporting the classless static routes. On L2TP/IPsec and MS-SSTP protocols, the compatibility depends on the implementation of the client software. You can realize the split tunneling if you clear the default gateway field on the Virtual DHCP Server options. On the client side, L2TP/IPsec and MS-SSTP clients need to be configured not to set up the default gateway for the split tunneling usage. You can also push the classless static routes (RFC 3442) by your existing external DHCP server. In that case, disable the Virtual DHCP Server function on SecureNAT, and you need not to set up the classless routes on this API. See the RFC 3442 to understand the classless routes. */
        this.DhcpPushRoutes_str = "";
        Object.assign(this, init);
    }
    return VpnVhOption;
}());
exports.VpnVhOption = VpnVhOption;
/** RPC_NAT_STATUS */
var VpnRpcNatStatus = /** @class */ (function () {
    /** Constructor for the 'VpnRpcNatStatus' class: RPC_NAT_STATUS */
    function VpnRpcNatStatus(init) {
        /** Virtual Hub Name */
        this.HubName_str = "";
        /** Number of TCP sessions */
        this.NumTcpSessions_u32 = 0;
        /** Ntmber of UDP sessions */
        this.NumUdpSessions_u32 = 0;
        /** Nymber of ICMP sessions */
        this.NumIcmpSessions_u32 = 0;
        /** Number of DNS sessions */
        this.NumDnsSessions_u32 = 0;
        /** Number of DHCP clients */
        this.NumDhcpClients_u32 = 0;
        /** Whether the NAT is operating in the Kernel Mode */
        this.IsKernelMode_bool = false;
        /** Whether the NAT is operating in the Raw IP Mode */
        this.IsRawIpMode_bool = false;
        Object.assign(this, init);
    }
    return VpnRpcNatStatus;
}());
exports.VpnRpcNatStatus = VpnRpcNatStatus;
/** Key pair */
var VpnRpcKeyPair = /** @class */ (function () {
    /** Constructor for the 'VpnRpcKeyPair' class: Key pair */
    function VpnRpcKeyPair(init) {
        /** The body of the certificate */
        this.Cert_bin = new Uint8Array([]);
        /** The body of the private key */
        this.Key_bin = new Uint8Array([]);
        Object.assign(this, init);
    }
    return VpnRpcKeyPair;
}());
exports.VpnRpcKeyPair = VpnRpcKeyPair;
/** Single string value */
var VpnRpcStr = /** @class */ (function () {
    /** Constructor for the 'VpnRpcStr' class: Single string value */
    function VpnRpcStr(init) {
        /** A string value */
        this.String_str = "";
        Object.assign(this, init);
    }
    return VpnRpcStr;
}());
exports.VpnRpcStr = VpnRpcStr;
/** Type of VPN Server */
var VpnRpcServerType;
(function (VpnRpcServerType) {
    /** Stand-alone server */
    VpnRpcServerType[VpnRpcServerType["Standalone"] = 0] = "Standalone";
    /** Farm controller server */
    VpnRpcServerType[VpnRpcServerType["FarmController"] = 1] = "FarmController";
    /** Farm member server */
    VpnRpcServerType[VpnRpcServerType["FarmMember"] = 2] = "FarmMember";
})(VpnRpcServerType = exports.VpnRpcServerType || (exports.VpnRpcServerType = {}));
/** Operating system type */
var VpnRpcOsType;
(function (VpnRpcOsType) {
    /** Windows 95 */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_95"] = 1100] = "WINDOWS_95";
    /** Windows 98 */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_98"] = 1200] = "WINDOWS_98";
    /** Windows Me */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_ME"] = 1300] = "WINDOWS_ME";
    /** Windows (unknown) */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_UNKNOWN"] = 1400] = "WINDOWS_UNKNOWN";
    /** Windows NT 4.0 Workstation */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_NT_4_WORKSTATION"] = 2100] = "WINDOWS_NT_4_WORKSTATION";
    /** Windows NT 4.0 Server */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_NT_4_SERVER"] = 2110] = "WINDOWS_NT_4_SERVER";
    /** Windows NT 4.0 Server, Enterprise Edition */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_NT_4_SERVER_ENTERPRISE"] = 2111] = "WINDOWS_NT_4_SERVER_ENTERPRISE";
    /** Windows NT 4.0 Terminal Server */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_NT_4_TERMINAL_SERVER"] = 2112] = "WINDOWS_NT_4_TERMINAL_SERVER";
    /** BackOffice Server 4.5 */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_NT_4_BACKOFFICE"] = 2113] = "WINDOWS_NT_4_BACKOFFICE";
    /** Small Business Server 4.5 */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_NT_4_SMS"] = 2114] = "WINDOWS_NT_4_SMS";
    /** Windows 2000 Professional */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_2000_PROFESSIONAL"] = 2200] = "WINDOWS_2000_PROFESSIONAL";
    /** Windows 2000 Server */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_2000_SERVER"] = 2211] = "WINDOWS_2000_SERVER";
    /** Windows 2000 Advanced Server */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_2000_ADVANCED_SERVER"] = 2212] = "WINDOWS_2000_ADVANCED_SERVER";
    /** Windows 2000 Datacenter Server */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_2000_DATACENTER_SERVER"] = 2213] = "WINDOWS_2000_DATACENTER_SERVER";
    /** BackOffice Server 2000 */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_2000_BACKOFFICE"] = 2214] = "WINDOWS_2000_BACKOFFICE";
    /** Small Business Server 2000 */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_2000_SBS"] = 2215] = "WINDOWS_2000_SBS";
    /** Windows XP Home Edition */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_XP_HOME"] = 2300] = "WINDOWS_XP_HOME";
    /** Windows XP Professional */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_XP_PROFESSIONAL"] = 2301] = "WINDOWS_XP_PROFESSIONAL";
    /** Windows Server 2003 Web Edition */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_2003_WEB"] = 2410] = "WINDOWS_2003_WEB";
    /** Windows Server 2003 Standard Edition */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_2003_STANDARD"] = 2411] = "WINDOWS_2003_STANDARD";
    /** Windows Server 2003 Enterprise Edition */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_2003_ENTERPRISE"] = 2412] = "WINDOWS_2003_ENTERPRISE";
    /** Windows Server 2003 DataCenter Edition */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_2003_DATACENTER"] = 2413] = "WINDOWS_2003_DATACENTER";
    /** BackOffice Server 2003 */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_2003_BACKOFFICE"] = 2414] = "WINDOWS_2003_BACKOFFICE";
    /** Small Business Server 2003 */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_2003_SBS"] = 2415] = "WINDOWS_2003_SBS";
    /** Windows Vista */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_LONGHORN_PROFESSIONAL"] = 2500] = "WINDOWS_LONGHORN_PROFESSIONAL";
    /** Windows Server 2008 */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_LONGHORN_SERVER"] = 2510] = "WINDOWS_LONGHORN_SERVER";
    /** Windows 7 */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_7"] = 2600] = "WINDOWS_7";
    /** Windows Server 2008 R2 */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_SERVER_2008_R2"] = 2610] = "WINDOWS_SERVER_2008_R2";
    /** Windows 8 */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_8"] = 2700] = "WINDOWS_8";
    /** Windows Server 2012 */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_SERVER_8"] = 2710] = "WINDOWS_SERVER_8";
    /** Windows 8.1 */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_81"] = 2701] = "WINDOWS_81";
    /** Windows Server 2012 R2 */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_SERVER_81"] = 2711] = "WINDOWS_SERVER_81";
    /** Windows 10 */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_10"] = 2702] = "WINDOWS_10";
    /** Windows Server 10 */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_SERVER_10"] = 2712] = "WINDOWS_SERVER_10";
    /** Windows 11 or later */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_11"] = 2800] = "WINDOWS_11";
    /** Windows Server 11 or later */
    VpnRpcOsType[VpnRpcOsType["WINDOWS_SERVER_11"] = 2810] = "WINDOWS_SERVER_11";
    /** Unknown UNIX */
    VpnRpcOsType[VpnRpcOsType["UNIX_UNKNOWN"] = 3000] = "UNIX_UNKNOWN";
    /** Linux */
    VpnRpcOsType[VpnRpcOsType["LINUX"] = 3100] = "LINUX";
    /** Solaris */
    VpnRpcOsType[VpnRpcOsType["SOLARIS"] = 3200] = "SOLARIS";
    /** Cygwin */
    VpnRpcOsType[VpnRpcOsType["CYGWIN"] = 3300] = "CYGWIN";
    /** BSD */
    VpnRpcOsType[VpnRpcOsType["BSD"] = 3400] = "BSD";
    /** MacOS X */
    VpnRpcOsType[VpnRpcOsType["MACOS_X"] = 3500] = "MACOS_X";
})(VpnRpcOsType = exports.VpnRpcOsType || (exports.VpnRpcOsType = {}));
/** VPN Server Information */
var VpnRpcServerInfo = /** @class */ (function () {
    /** Constructor for the 'VpnRpcServerInfo' class: VPN Server Information */
    function VpnRpcServerInfo(init) {
        /** Server product name */
        this.ServerProductName_str = "";
        /** Server version string */
        this.ServerVersionString_str = "";
        /** Server build information string */
        this.ServerBuildInfoString_str = "";
        /** Server version integer value */
        this.ServerVerInt_u32 = 0;
        /** Server build number integer value */
        this.ServerBuildInt_u32 = 0;
        /** Server host name */
        this.ServerHostName_str = "";
        /** Type of server */
        this.ServerType_u32 = 0;
        /** Build date and time of the server */
        this.ServerBuildDate_dt = new Date();
        /** Family name */
        this.ServerFamilyName_str = "";
        /** OS type */
        this.OsType_u32 = 0;
        /** Service pack number */
        this.OsServicePack_u32 = 0;
        /** OS system name */
        this.OsSystemName_str = "";
        /** OS product name */
        this.OsProductName_str = "";
        /** OS vendor name */
        this.OsVendorName_str = "";
        /** OS version */
        this.OsVersion_str = "";
        /** Kernel name */
        this.KernelName_str = "";
        /** Kernel version */
        this.KernelVersion_str = "";
        Object.assign(this, init);
    }
    return VpnRpcServerInfo;
}());
exports.VpnRpcServerInfo = VpnRpcServerInfo;
/** Server status */
var VpnRpcServerStatus = /** @class */ (function () {
    /** Constructor for the 'VpnRpcServerStatus' class: Server status */
    function VpnRpcServerStatus(init) {
        /** Type of server */
        this.ServerType_u32 = 0;
        /** Total number of TCP connections */
        this.NumTcpConnections_u32 = 0;
        /** Number of Local TCP connections */
        this.NumTcpConnectionsLocal_u32 = 0;
        /** Number of remote TCP connections */
        this.NumTcpConnectionsRemote_u32 = 0;
        /** Total number of HUBs */
        this.NumHubTotal_u32 = 0;
        /** Nymber of stand-alone HUB */
        this.NumHubStandalone_u32 = 0;
        /** Number of static HUBs */
        this.NumHubStatic_u32 = 0;
        /** Number of Dynamic HUBs */
        this.NumHubDynamic_u32 = 0;
        /** Total number of sessions */
        this.NumSessionsTotal_u32 = 0;
        /** Number of local VPN sessions */
        this.NumSessionsLocal_u32 = 0;
        /** The number of remote sessions */
        this.NumSessionsRemote_u32 = 0;
        /** Number of MAC table entries (total sum of all Virtual Hubs) */
        this.NumMacTables_u32 = 0;
        /** Number of IP table entries (total sum of all Virtual Hubs) */
        this.NumIpTables_u32 = 0;
        /** Number of users (total sum of all Virtual Hubs) */
        this.NumUsers_u32 = 0;
        /** Number of groups (total sum of all Virtual Hubs) */
        this.NumGroups_u32 = 0;
        /** Number of assigned bridge licenses (Useful to make a commercial version) */
        this.AssignedBridgeLicenses_u32 = 0;
        /** Number of assigned client licenses (Useful to make a commercial version) */
        this.AssignedClientLicenses_u32 = 0;
        /** Number of Assigned bridge license (cluster-wide), useful to make a commercial version */
        this.AssignedBridgeLicensesTotal_u32 = 0;
        /** Number of assigned client licenses (cluster-wide), useful to make a commercial version */
        this.AssignedClientLicensesTotal_u32 = 0;
        /** Number of broadcast packets (Recv) */
        this["Recv.BroadcastBytes_u64"] = 0;
        /** Broadcast bytes (Recv) */
        this["Recv.BroadcastCount_u64"] = 0;
        /** Unicast count (Recv) */
        this["Recv.UnicastBytes_u64"] = 0;
        /** Unicast bytes (Recv) */
        this["Recv.UnicastCount_u64"] = 0;
        /** Number of broadcast packets (Send) */
        this["Send.BroadcastBytes_u64"] = 0;
        /** Broadcast bytes (Send) */
        this["Send.BroadcastCount_u64"] = 0;
        /** Unicast bytes (Send) */
        this["Send.UnicastBytes_u64"] = 0;
        /** Unicast bytes (Send) */
        this["Send.UnicastCount_u64"] = 0;
        /** Current time */
        this.CurrentTime_dt = new Date();
        /** 64 bit High-Precision Logical System Clock */
        this.CurrentTick_u64 = 0;
        /** VPN Server Start-up time */
        this.StartTime_dt = new Date();
        /** Memory information: Total Memory */
        this.TotalMemory_u64 = 0;
        /** Memory information: Used Memory */
        this.UsedMemory_u64 = 0;
        /** Memory information: Free Memory */
        this.FreeMemory_u64 = 0;
        /** Memory information: Total Phys */
        this.TotalPhys_u64 = 0;
        /** Memory information: Used Phys */
        this.UsedPhys_u64 = 0;
        /** Memory information: Free Phys */
        this.FreePhys_u64 = 0;
        Object.assign(this, init);
    }
    return VpnRpcServerStatus;
}());
exports.VpnRpcServerStatus = VpnRpcServerStatus;
/** VPN Session status */
var VpnRpcSessionStatus = /** @class */ (function () {
    /** Constructor for the 'VpnRpcSessionStatus' class: VPN Session status */
    function VpnRpcSessionStatus(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** VPN session name */
        this.Name_str = "";
        /** User name */
        this.Username_str = "";
        /** Real user name which was used for the authentication */
        this.RealUsername_str = "";
        /** Group name */
        this.GroupName_str = "";
        /** Is Cascade Session */
        this.LinkMode_bool = false;
        /** Client IP address */
        this.Client_Ip_Address_ip = "";
        /** Client host name */
        this.SessionStatus_ClientHostName_str = "";
        /** Operation flag */
        this.Active_bool = false;
        /** Connected flag */
        this.Connected_bool = false;
        /** State of the client session */
        this.SessionStatus_u32 = 0;
        /** Server name */
        this.ServerName_str = "";
        /** Port number of the server */
        this.ServerPort_u32 = 0;
        /** Server product name */
        this.ServerProductName_str = "";
        /** Server product version */
        this.ServerProductVer_u32 = 0;
        /** Server product build number */
        this.ServerProductBuild_u32 = 0;
        /** Connection start time */
        this.StartTime_dt = new Date();
        /** Connection completion time of the first connection */
        this.FirstConnectionEstablisiedTime_dt = new Date();
        /** Connection completion time of this connection */
        this.CurrentConnectionEstablishTime_dt = new Date();
        /** Number of connections have been established so far */
        this.NumConnectionsEatablished_u32 = 0;
        /** Half-connection */
        this.HalfConnection_bool = false;
        /** VoIP / QoS */
        this.QoS_bool = false;
        /** Maximum number of the underlying TCP connections */
        this.MaxTcpConnections_u32 = 0;
        /** Number of current underlying TCP connections */
        this.NumTcpConnections_u32 = 0;
        /** Number of inbound underlying connections */
        this.NumTcpConnectionsUpload_u32 = 0;
        /** Number of outbound underlying connections */
        this.NumTcpConnectionsDownload_u32 = 0;
        /** Use of encryption */
        this.UseEncrypt_bool = false;
        /** Cipher algorithm name */
        this.CipherName_str = "";
        /** Use of compression */
        this.UseCompress_bool = false;
        /** Is R-UDP session */
        this.IsRUDPSession_bool = false;
        /** Physical underlying communication protocol */
        this.UnderlayProtocol_str = "";
        /** The UDP acceleration is enabled */
        this.IsUdpAccelerationEnabled_bool = false;
        /** Using the UDP acceleration function */
        this.IsUsingUdpAcceleration_bool = false;
        /** VPN session name */
        this.SessionName_str = "";
        /** Connection name */
        this.ConnectionName_str = "";
        /** Session key */
        this.SessionKey_bin = new Uint8Array([]);
        /** Total transmitted data size */
        this.TotalSendSize_u64 = 0;
        /** Total received data size */
        this.TotalRecvSize_u64 = 0;
        /** Total transmitted data size (no compression) */
        this.TotalSendSizeReal_u64 = 0;
        /** Total received data size (no compression) */
        this.TotalRecvSizeReal_u64 = 0;
        /** Is Bridge Mode */
        this.IsBridgeMode_bool = false;
        /** Is Monitor mode */
        this.IsMonitorMode_bool = false;
        /** VLAN ID */
        this.VLanId_u32 = 0;
        /** Client product name */
        this.ClientProductName_str = "";
        /** Client version */
        this.ClientProductVer_u32 = 0;
        /** Client build number */
        this.ClientProductBuild_u32 = 0;
        /** Client OS name */
        this.ClientOsName_str = "";
        /** Client OS version */
        this.ClientOsVer_str = "";
        /** Client OS Product ID */
        this.ClientOsProductId_str = "";
        /** Client host name */
        this.ClientHostname_str = "";
        /** Unique ID */
        this.UniqueId_bin = new Uint8Array([]);
        Object.assign(this, init);
    }
    return VpnRpcSessionStatus;
}());
exports.VpnRpcSessionStatus = VpnRpcSessionStatus;
/** Set the special listener */
var VpnRpcSpecialListener = /** @class */ (function () {
    /** Constructor for the 'VpnRpcSpecialListener' class: Set the special listener */
    function VpnRpcSpecialListener(init) {
        /** The flag to activate the VPN over ICMP server function */
        this.VpnOverIcmpListener_bool = false;
        /** The flag to activate the VPN over DNS function */
        this.VpnOverDnsListener_bool = false;
        Object.assign(this, init);
    }
    return VpnRpcSpecialListener;
}());
exports.VpnRpcSpecialListener = VpnRpcSpecialListener;
/** Syslog configuration */
var VpnSyslogSaveType;
(function (VpnSyslogSaveType) {
    /** Do not use syslog */
    VpnSyslogSaveType[VpnSyslogSaveType["None"] = 0] = "None";
    /** Only server log */
    VpnSyslogSaveType[VpnSyslogSaveType["ServerLog"] = 1] = "ServerLog";
    /** Server and Virtual HUB security log */
    VpnSyslogSaveType[VpnSyslogSaveType["ServerAndHubSecurityLog"] = 2] = "ServerAndHubSecurityLog";
    /** Server, Virtual HUB security, and packet log */
    VpnSyslogSaveType[VpnSyslogSaveType["ServerAndHubAllLog"] = 3] = "ServerAndHubAllLog";
})(VpnSyslogSaveType = exports.VpnSyslogSaveType || (exports.VpnSyslogSaveType = {}));
/** Syslog configuration */
var VpnSyslogSetting = /** @class */ (function () {
    /** Constructor for the 'VpnSyslogSetting' class: Syslog configuration */
    function VpnSyslogSetting(init) {
        /** The behavior of the syslog function */
        this.SaveType_u32 = 0;
        /** Specify the host name or IP address of the syslog server */
        this.Hostname_str = "";
        /** Specify the port number of the syslog server */
        this.Port_u32 = 0;
        Object.assign(this, init);
    }
    return VpnSyslogSetting;
}());
exports.VpnSyslogSetting = VpnSyslogSetting;
/** VPN Gate Server Config */
var VpnVgsConfig = /** @class */ (function () {
    /** Constructor for the 'VpnVgsConfig' class: VPN Gate Server Config */
    function VpnVgsConfig(init) {
        /** Active flag */
        this.IsEnabled_bool = false;
        /** Message */
        this.Message_utf = "";
        /** Owner name */
        this.Owner_utf = "";
        /** Abuse email */
        this.Abuse_utf = "";
        /** Log save flag */
        this.NoLog_bool = false;
        /** Save log permanently */
        this.LogPermanent_bool = false;
        /** Enable the L2TP VPN function */
        this.EnableL2TP_bool = false;
        Object.assign(this, init);
    }
    return VpnVgsConfig;
}());
exports.VpnVgsConfig = VpnVgsConfig;
/** Read a Log file */
var VpnRpcReadLogFile = /** @class */ (function () {
    /** Constructor for the 'VpnRpcReadLogFile' class: Read a Log file */
    function VpnRpcReadLogFile(init) {
        /** Server name */
        this.ServerName_str = "";
        /** File Path */
        this.FilePath_str = "";
        /** Offset to download. You have to call the ReadLogFile API multiple times to download the entire log file with requesting a part of the file by specifying the Offset_u32 field. */
        this.Offset_u32 = 0;
        /** Received buffer */
        this.Buffer_bin = new Uint8Array([]);
        Object.assign(this, init);
    }
    return VpnRpcReadLogFile;
}());
exports.VpnRpcReadLogFile = VpnRpcReadLogFile;
/** Rename link */
var VpnRpcRenameLink = /** @class */ (function () {
    /** Constructor for the 'VpnRpcRenameLink' class: Rename link */
    function VpnRpcRenameLink(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** The old name of the cascade connection */
        this.OldAccountName_utf = "";
        /** The new name of the cascade connection */
        this.NewAccountName_utf = "";
        Object.assign(this, init);
    }
    return VpnRpcRenameLink;
}());
exports.VpnRpcRenameLink = VpnRpcRenameLink;
/** Online or offline the HUB */
var VpnRpcSetHubOnline = /** @class */ (function () {
    /** Constructor for the 'VpnRpcSetHubOnline' class: Online or offline the HUB */
    function VpnRpcSetHubOnline(init) {
        /** The Virtual Hub name */
        this.HubName_str = "";
        /** Online / offline flag */
        this.Online_bool = false;
        Object.assign(this, init);
    }
    return VpnRpcSetHubOnline;
}());
exports.VpnRpcSetHubOnline = VpnRpcSetHubOnline;
/** Set Password */
var VpnRpcSetPassword = /** @class */ (function () {
    /** Constructor for the 'VpnRpcSetPassword' class: Set Password */
    function VpnRpcSetPassword(init) {
        /** The plaintext password */
        this.PlainTextPassword_str = "";
        Object.assign(this, init);
    }
    return VpnRpcSetPassword;
}());
exports.VpnRpcSetPassword = VpnRpcSetPassword;
// --- Utility codes ---
/** JSON-RPC request class. See https://www.jsonrpc.org/specification */
var JsonRpcRequest = /** @class */ (function () {
    function JsonRpcRequest(method, param, id) {
        if (method === void 0) { method = ""; }
        if (param === void 0) { param = null; }
        if (id === void 0) { id = ""; }
        this.jsonrpc = "2.0";
        this.method = method;
        this.params = param;
        this.id = id;
    }
    return JsonRpcRequest;
}());
exports.JsonRpcRequest = JsonRpcRequest;
/** JSON-RPC error class. See https://www.jsonrpc.org/specification */
var JsonRpcError = /** @class */ (function () {
    function JsonRpcError(code, message, data) {
        if (code === void 0) { code = 0; }
        if (message === void 0) { message = ""; }
        if (data === void 0) { data = null; }
        this.code = code;
        this.message = message;
        this.data = data;
    }
    return JsonRpcError;
}());
exports.JsonRpcError = JsonRpcError;
/** JSON-RPC response class with generics */
var JsonRpcResponse = /** @class */ (function () {
    function JsonRpcResponse() {
        this.jsonrpc = "2.0";
        this.result = null;
        this.error = null;
        this.id = "";
    }
    return JsonRpcResponse;
}());
exports.JsonRpcResponse = JsonRpcResponse;
/** JSON-RPC client class. See https://www.jsonrpc.org/specification */
var JsonRpcClient = /** @class */ (function () {
    /**
     * JSON-RPC client class constructor
     * @param url The URL
     * @param headers Additional HTTP headers
     * @param send_credential Set true to use the same credential with the browsing web site. Valid only if the code is running on the web browser.
     */
    function JsonRpcClient(url, headers, send_credential, nodejs_https_client_reject_untrusted_server_cert) {
        this.BaseUrl = url;
        this.headers = headers;
        this.client = new HttpClient();
        this.client.SendCredential = send_credential;
        this.client.NodeJS_HTTPS_Client_Reject_Unauthorized = nodejs_https_client_reject_untrusted_server_cert;
    }
    /** A utility function to convert any object to JSON string */
    JsonRpcClient.ObjectToJson = function (obj) {
        return JSON.stringify(obj, function (key, value) {
            if (key.endsWith("_bin")) {
                return Util_Base64_Encode(value);
            }
            return value;
        }, 4);
    };
    /** A utility function to convert JSON string to object */
    JsonRpcClient.JsonToObject = function (str) {
        return JSON.parse(str, function (key, value) {
            if (key.endsWith("_bin")) {
                return Util_Base64_Decode(value);
            }
            else if (key.endsWith("_dt")) {
                return new Date(value);
            }
            return value;
        });
    };
    /**
     * Call a single RPC call (without error check). You can wait for the response with Promise<string> or await statement.
     * @param method_name The name of RPC method
     * @param param The parameters
     */
    JsonRpcClient.prototype.CallInternalAsync = function (method_name, param) {
        return __awaiter(this, void 0, void 0, function () {
            var id, req, req_string, http_response, ret_string;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        id = "1";
                        req = new JsonRpcRequest(method_name, param, id);
                        req_string = JsonRpcClient.ObjectToJson(req);
                        if (debug_mode) {
                            console.log("--- RPC Request Body ---");
                            console.log(req_string);
                            console.log("------------------------");
                        }
                        return [4 /*yield*/, this.client.PostAsync(this.BaseUrl, this.headers, req_string, "application/json")];
                    case 1:
                        http_response = _a.sent();
                        ret_string = http_response.Body;
                        if (debug_mode) {
                            console.log("--- RPC Response Body ---");
                            console.log(ret_string);
                            console.log("-------------------------");
                        }
                        return [2 /*return*/, ret_string];
                }
            });
        });
    };
    /**
     * Call a single RPC call (with error check). You can wait for the response with Promise<TResult> or await statement. In the case of error, it will be thrown.
     * @param method_name The name of RPC method
     * @param param The parameters
     */
    JsonRpcClient.prototype.CallAsync = function (method_name, param) {
        return __awaiter(this, void 0, void 0, function () {
            var ret_string, ret;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.CallInternalAsync(method_name, param)];
                    case 1:
                        ret_string = _a.sent();
                        ret = JSON.parse(ret_string);
                        if (is_null(ret.error) === false) {
                            throw new JsonRpcException(ret.error);
                        }
                        return [2 /*return*/, ret.result];
                }
            });
        });
    };
    return JsonRpcClient;
}());
exports.JsonRpcClient = JsonRpcClient;
/** JSON-RPC exception class */
var JsonRpcException = /** @class */ (function (_super) {
    __extends(JsonRpcException, _super);
    function JsonRpcException(error) {
        var _this = _super.call(this, "Code=" + error.code + ", Message=" + error.message) || this;
        _this.Error = error;
        return _this;
    }
    return JsonRpcException;
}(Error));
exports.JsonRpcException = JsonRpcException;
/** HTTP client exception class */
var HttpClientException = /** @class */ (function (_super) {
    __extends(HttpClientException, _super);
    function HttpClientException(message) {
        return _super.call(this, message) || this;
    }
    return HttpClientException;
}(Error));
exports.HttpClientException = HttpClientException;
/** HTTP client response class */
var HttpClientResponse = /** @class */ (function () {
    function HttpClientResponse() {
        this.Body = "";
    }
    return HttpClientResponse;
}());
exports.HttpClientResponse = HttpClientResponse;
/** An HTTP client which can be used in both web browsers and Node.js */
var HttpClient = /** @class */ (function () {
    function HttpClient() {
        this.TimeoutMsecs = 60 * 5 * 1000;
        this.SendCredential = true;
        this.NodeJS_HTTPS_Client_Reject_Unauthorized = false;
    }
    /** Post method. In web browsers this function will process the request by itself. In Node.js this function will call PostAsync_NodeJS() instead. */
    HttpClient.prototype.PostAsync = function (url, headers, req_body, req_media_type) {
        return __awaiter(this, void 0, void 0, function () {
            var fetch_header_list, _i, _a, name_1, fetch_init, fetch_response, ret, _b;
            return __generator(this, function (_c) {
                switch (_c.label) {
                    case 0:
                        if (is_node_js) {
                            return [2 /*return*/, this.PostAsync_NodeJS(url, headers, req_body, req_media_type)];
                        }
                        fetch_header_list = new Headers();
                        for (_i = 0, _a = Object.keys(headers); _i < _a.length; _i++) {
                            name_1 = _a[_i];
                            fetch_header_list.append(name_1, headers[name_1]);
                        }
                        fetch_init = {
                            mode: "cors",
                            headers: fetch_header_list,
                            credentials: (this.SendCredential ? "include" : "omit"),
                            method: "POST",
                            cache: "no-cache",
                            keepalive: true,
                            redirect: "follow",
                            body: req_body
                        };
                        return [4 /*yield*/, fetch(url, fetch_init)];
                    case 1:
                        fetch_response = _c.sent();
                        if (fetch_response.ok === false) {
                            throw new HttpClientException("HTTP Error: " + fetch_response.status + " " + fetch_response.statusText);
                        }
                        ret = new HttpClientResponse();
                        _b = ret;
                        return [4 /*yield*/, fetch_response.text()];
                    case 2:
                        _b.Body = _c.sent();
                        return [2 /*return*/, ret];
                }
            });
        });
    };
    /** Post method for Node.js. */
    HttpClient.prototype.PostAsync_NodeJS = function (url, headers, req_body, req_media_type) {
        var https = require("https");
        var keepAliveAgent = new https.Agent({ keepAlive: true });
        var urlparse = require("url");
        var urlobj = urlparse.parse(url);
        if (is_null(urlobj.host))
            throw new Error("URL is invalid.");
        var options = {
            host: urlobj.hostname,
            port: urlobj.port,
            path: urlobj.path,
            rejectUnauthorized: this.NodeJS_HTTPS_Client_Reject_Unauthorized,
            method: "POST",
            timeout: this.TimeoutMsecs,
            agent: keepAliveAgent
        };
        return new Promise(function (resolve, reject) {
            var req = https.request(options, function (res) {
                if (res.statusCode !== 200) {
                    reject(new HttpClientException("HTTP Error: " + res.statusCode + " " + res.statusMessage));
                }
                var recv_str = "";
                res.on("data", function (body) {
                    recv_str += body;
                });
                res.on("end", function () {
                    var ret = new HttpClientResponse();
                    ret.Body = recv_str;
                    resolve(ret);
                });
            }).on("error", function (err) {
                throw err;
            });
            for (var _i = 0, _a = Object.keys(headers); _i < _a.length; _i++) {
                var name_2 = _a[_i];
                req.setHeader(name_2, !is_null(headers[name_2]) ? headers[name_2] : "");
            }
            req.setHeader("Content-Type", req_media_type);
            req.setHeader("Content-Length", Buffer.byteLength(req_body));
            req.write(req_body);
            req.end();
        });
    };
    return HttpClient;
}());
exports.HttpClient = HttpClient;
//////// BEGIN: Base64 encode / decode utility functions from https://github.com/beatgammit/base64-js
// The MIT License(MIT)
// Copyright(c) 2014
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
//     in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in
//     all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//     FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//     OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
var lookup = [];
var revLookup = [];
var code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
for (var i = 0, len = code.length; i < len; ++i) {
    lookup[i] = code[i];
    revLookup[code.charCodeAt(i)] = i;
}
// Support decoding URL-safe base64 strings, as Node.js does.
// See: https://en.wikipedia.org/wiki/Base64#URL_applications
revLookup["-".charCodeAt(0)] = 62;
revLookup["_".charCodeAt(0)] = 63;
function getLens(b64) {
    var len = b64.length;
    if (len % 4 > 0) {
        throw new Error("Invalid string. Length must be a multiple of 4");
    }
    // Trim off extra bytes after placeholder bytes are found
    // See: https://github.com/beatgammit/base64-js/issues/42
    var validLen = b64.indexOf("=");
    if (validLen === -1)
        validLen = len;
    var placeHoldersLen = validLen === len
        ? 0
        : 4 - (validLen % 4);
    return [validLen, placeHoldersLen];
}
// base64 is 4/3 + up to two characters of the original data
function byteLength(b64) {
    var lens = getLens(b64);
    var validLen = lens[0];
    var placeHoldersLen = lens[1];
    return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen;
}
function _byteLength(b64, validLen, placeHoldersLen) {
    return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen;
}
function Util_Base64_Decode(b64) {
    var tmp;
    var lens = getLens(b64);
    var validLen = lens[0];
    var placeHoldersLen = lens[1];
    var arr = new Uint8Array(_byteLength(b64, validLen, placeHoldersLen));
    var curByte = 0;
    // if there are placeholders, only get up to the last complete 4 chars
    var len = placeHoldersLen > 0
        ? validLen - 4
        : validLen;
    for (var i = 0; i < len; i += 4) {
        tmp =
            (revLookup[b64.charCodeAt(i)] << 18) |
                (revLookup[b64.charCodeAt(i + 1)] << 12) |
                (revLookup[b64.charCodeAt(i + 2)] << 6) |
                revLookup[b64.charCodeAt(i + 3)];
        arr[curByte++] = (tmp >> 16) & 0xFF;
        arr[curByte++] = (tmp >> 8) & 0xFF;
        arr[curByte++] = tmp & 0xFF;
    }
    if (placeHoldersLen === 2) {
        tmp =
            (revLookup[b64.charCodeAt(i)] << 2) |
                (revLookup[b64.charCodeAt(i + 1)] >> 4);
        arr[curByte++] = tmp & 0xFF;
    }
    if (placeHoldersLen === 1) {
        tmp =
            (revLookup[b64.charCodeAt(i)] << 10) |
                (revLookup[b64.charCodeAt(i + 1)] << 4) |
                (revLookup[b64.charCodeAt(i + 2)] >> 2);
        arr[curByte++] = (tmp >> 8) & 0xFF;
        arr[curByte++] = tmp & 0xFF;
    }
    return arr;
}
exports.Util_Base64_Decode = Util_Base64_Decode;
function tripletToBase64(num) {
    return lookup[num >> 18 & 0x3F] +
        lookup[num >> 12 & 0x3F] +
        lookup[num >> 6 & 0x3F] +
        lookup[num & 0x3F];
}
function encodeChunk(uint8, start, end) {
    var tmp;
    var output = [];
    for (var i = start; i < end; i += 3) {
        tmp =
            ((uint8[i] << 16) & 0xFF0000) +
                ((uint8[i + 1] << 8) & 0xFF00) +
                (uint8[i + 2] & 0xFF);
        output.push(tripletToBase64(tmp));
    }
    return output.join("");
}
function Util_Base64_Encode(uint8) {
    var tmp;
    var len = uint8.length;
    var extraBytes = len % 3; // if we have 1 byte left, pad 2 bytes
    var parts = [];
    var maxChunkLength = 16383; // must be multiple of 3
    // go through the array every three bytes, we'll deal with trailing stuff later
    for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
        parts.push(encodeChunk(uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)));
    }
    // pad the end with zeros, but make sure to not forget the extra bytes
    if (extraBytes === 1) {
        tmp = uint8[len - 1];
        parts.push(lookup[tmp >> 2] +
            lookup[(tmp << 4) & 0x3F] +
            "==");
    }
    else if (extraBytes === 2) {
        tmp = (uint8[len - 2] << 8) + uint8[len - 1];
        parts.push(lookup[tmp >> 10] +
            lookup[(tmp >> 4) & 0x3F] +
            lookup[(tmp << 2) & 0x3F] +
            "=");
    }
    return parts.join("");
}
exports.Util_Base64_Encode = Util_Base64_Encode;
//////// END: Base64 encode / decode utility functions from https://github.com/beatgammit/base64-js
//# sourceMappingURL=vpnrpc.js.map
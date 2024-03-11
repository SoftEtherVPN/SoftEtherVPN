// SoftEther VPN Server JSON-RPC Stub code for C#
// 
// VPNServerRpc.cs - SoftEther VPN Server's JSON-RPC Stubs
//
// Automatically generated at __TIMESTAMP__ by vpnserver-jsonrpc-codegen
//
// Licensed under the Apache License 2.0
// Copyright (c) 2014-__YEAR__ SoftEther VPN Project

using System.Threading.Tasks;
using SoftEther.JsonRpc;

namespace SoftEther.VPNServerRpc
{
    /// <summary>
    /// VPN Server RPC Stubs
    /// </summary>
    public class VpnServerRpc
    {
        JsonRpcClient rpc_client;

        /// <summary>
        /// Constructor of the VpnServerRpc class
        /// </summary>
        /// <param name="vpnserver_host">The hostname or IP address of the destination VPN Server. In the web browser you can specify null if you want to connect to the server itself.</param>
        /// <param name="vpnserver_port">The port number of the destination VPN Server. In the web browser you can specify null if you want to connect to the server itself.</param>
        /// <param name="admin_password">Specify the administration password. This value is valid only if vpnserver_hostname is sepcified.</param>
        /// <param name="hub_name">The name of the Virtual Hub if you want to connect to the VPN Server as a Virtual Hub Admin Mode. Specify null if you want to connect to the VPN Server as the Entire VPN Server Admin Mode.</param>
        public VpnServerRpc(string vpnserver_host, int vpnserver_port, string admin_password, string hub_name = null)
        {
            rpc_client = new JsonRpcClient($"https://{vpnserver_host}:{vpnserver_port}/api/", null);

            rpc_client.HttpHeaders.Add("X-VPNADMIN-HUBNAME", string.IsNullOrEmpty(hub_name) ? "" : hub_name);
            rpc_client.HttpHeaders.Add("X-VPNADMIN-PASSWORD", admin_password);
        }

        /// <summary>
        /// Call a RPC procedure
        /// </summary>
        public async Task<T> CallAsync<T>(string method_name, T request)
        {
            T response = await rpc_client.CallAsync<T>(method_name, request);

            return response;
        }

        /// <summary>
        /// Test RPC function (Async mode). Input any integer value to the IntValue_u32 field. Then the server will convert the integer to the string, and return the string in the StrValue_str field.
        /// </summary>
        public async Task<VpnRpcTest> TestAsync(VpnRpcTest t) => await CallAsync<VpnRpcTest>("Test", t);

        /// <summary>
        /// Test RPC function (Sync mode). Input any integer value to the IntValue_u32 field. Then the server will convert the integer to the string, and return the string in the StrValue_str field.
        /// </summary>
        public VpnRpcTest Test(VpnRpcTest t) => TestAsync(t).Result;

        /// <summary>
        /// Get server information (Async mode). This allows you to obtain the server information of the currently connected VPN Server or VPN Bridge. Included in the server information are the version number, build number and build information. You can also obtain information on the current server operation mode and the information of operating system that the server is operating on.
        /// </summary>
        public async Task<VpnRpcServerInfo> GetServerInfoAsync() => await CallAsync<VpnRpcServerInfo>("GetServerInfo", new VpnRpcServerInfo());

        /// <summary>
        /// Get server information (Sync mode). This allows you to obtain the server information of the currently connected VPN Server or VPN Bridge. Included in the server information are the version number, build number and build information. You can also obtain information on the current server operation mode and the information of operating system that the server is operating on.
        /// </summary>
        public VpnRpcServerInfo GetServerInfo() => GetServerInfoAsync().Result;

        /// <summary>
        /// Get Current Server Status (Async mode). This allows you to obtain in real-time the current status of the currently connected VPN Server or VPN Bridge. You can get statistical information on data communication and the number of different kinds of objects that exist on the server. You can get information on how much memory is being used on the current computer by the OS.
        /// </summary>
        public async Task<VpnRpcServerStatus> GetServerStatusAsync() => await CallAsync<VpnRpcServerStatus>("GetServerStatus", new VpnRpcServerStatus());

        /// <summary>
        /// Get Current Server Status (Sync mode). This allows you to obtain in real-time the current status of the currently connected VPN Server or VPN Bridge. You can get statistical information on data communication and the number of different kinds of objects that exist on the server. You can get information on how much memory is being used on the current computer by the OS.
        /// </summary>
        public VpnRpcServerStatus GetServerStatus() => GetServerStatusAsync().Result;

        /// <summary>
        /// Create New TCP Listener (Async mode). This allows you to create a new TCP Listener on the server. By creating the TCP Listener the server starts listening for a connection from clients at the specified TCP/IP port number. A TCP Listener that has been created can be deleted by the DeleteListener API. You can also get a list of TCP Listeners currently registered by using the EnumListener API. To execute this API, you must have VPN Server administrator privileges.
        /// </summary>
        public async Task<VpnRpcListener> CreateListenerAsync(VpnRpcListener t) => await CallAsync<VpnRpcListener>("CreateListener", t);

        /// <summary>
        /// Create New TCP Listener (Sync mode). This allows you to create a new TCP Listener on the server. By creating the TCP Listener the server starts listening for a connection from clients at the specified TCP/IP port number. A TCP Listener that has been created can be deleted by the DeleteListener API. You can also get a list of TCP Listeners currently registered by using the EnumListener API. To execute this API, you must have VPN Server administrator privileges.
        /// </summary>
        public VpnRpcListener CreateListener(VpnRpcListener t) => CreateListenerAsync(t).Result;

        /// <summary>
        /// Get List of TCP Listeners (Async mode). This allows you to get a list of TCP listeners registered on the current server. You can obtain information on whether the various TCP listeners have a status of operating or error. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public async Task<VpnRpcListenerList> EnumListenerAsync() => await CallAsync<VpnRpcListenerList>("EnumListener", new VpnRpcListenerList());

        /// <summary>
        /// Get List of TCP Listeners (Async mode). This allows you to get a list of TCP listeners registered on the current server. You can obtain information on whether the various TCP listeners have a status of operating or error. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public VpnRpcListenerList EnumListener() => EnumListenerAsync().Result;

        /// <summary>
        /// Delete TCP Listener (Async mode). This allows you to delete a TCP Listener that's registered on the server. When the TCP Listener is in a state of operation, the listener will automatically be deleted when its operation stops. You can also get a list of TCP Listeners currently registered by using the EnumListener API. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public async Task<VpnRpcListener> DeleteListenerAsync(VpnRpcListener t) => await CallAsync<VpnRpcListener>("DeleteListener", t);

        /// <summary>
        /// Delete TCP Listener (Async mode). This allows you to delete a TCP Listener that's registered on the server. When the TCP Listener is in a state of operation, the listener will automatically be deleted when its operation stops. You can also get a list of TCP Listeners currently registered by using the EnumListener API. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public VpnRpcListener DeleteListener(VpnRpcListener t) => DeleteListenerAsync(t).Result;

        /// <summary>
        /// Enable / Disable TCP Listener (Async mode). This starts or stops the operation of TCP Listeners registered on the current server. You can also get a list of TCP Listeners currently registered by using the EnumListener API. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public async Task<VpnRpcListener> EnableListenerAsync(VpnRpcListener t) => await CallAsync<VpnRpcListener>("EnableListener", t);

        /// <summary>
        /// Enable / Disable TCP Listener (Async mode). This starts or stops the operation of TCP Listeners registered on the current server. You can also get a list of TCP Listeners currently registered by using the EnumListener API. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public VpnRpcListener EnableListener(VpnRpcListener t) => EnableListenerAsync(t).Result;

        /// <summary>
        /// Set VPN Server Administrator Password (Async mode). This sets the VPN Server administrator password. You can specify the password as a parameter. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public async Task<VpnRpcSetPassword> SetServerPasswordAsync(VpnRpcSetPassword t) => await CallAsync<VpnRpcSetPassword>("SetServerPassword", t);

        /// <summary>
        /// Set VPN Server Administrator Password (Async mode). This sets the VPN Server administrator password. You can specify the password as a parameter. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public VpnRpcSetPassword SetServerPassword(VpnRpcSetPassword t) => SetServerPasswordAsync(t).Result;

        /// <summary>
        /// Set the VPN Server clustering configuration (Async mode). Use this to set the VPN Server type as Standalone Server, Cluster Controller Server or Cluster Member Server. Standalone server means a VPN Server that does not belong to any cluster in its current state. When VPN Server is installed, by default it will be in standalone server mode. Unless you have particular plans to configure a cluster, we recommend the VPN Server be operated in standalone mode. A cluster controller is the central computer of all member servers of a cluster in the case where a clustering environment is made up of multiple VPN Servers. Multiple cluster members can be added to the cluster as required. A cluster requires one computer to serve this role. The other cluster member servers that are configured in the same cluster begin operation as a cluster member by connecting to the cluster controller. To call this API, you must have VPN Server administrator privileges. Also, when this API is executed, VPN Server will automatically restart. This API cannot be called on VPN Bridge.
        /// </summary>
        public async Task<VpnRpcFarm> SetFarmSettingAsync(VpnRpcFarm t) => await CallAsync<VpnRpcFarm>("SetFarmSetting", t);

        /// <summary>
        /// Set the VPN Server clustering configuration (Async mode). Use this to set the VPN Server type as Standalone Server, Cluster Controller Server or Cluster Member Server. Standalone server means a VPN Server that does not belong to any cluster in its current state. When VPN Server is installed, by default it will be in standalone server mode. Unless you have particular plans to configure a cluster, we recommend the VPN Server be operated in standalone mode. A cluster controller is the central computer of all member servers of a cluster in the case where a clustering environment is made up of multiple VPN Servers. Multiple cluster members can be added to the cluster as required. A cluster requires one computer to serve this role. The other cluster member servers that are configured in the same cluster begin operation as a cluster member by connecting to the cluster controller. To call this API, you must have VPN Server administrator privileges. Also, when this API is executed, VPN Server will automatically restart. This API cannot be called on VPN Bridge.
        /// </summary>
        public VpnRpcFarm SetFarmSetting(VpnRpcFarm t) => SetFarmSettingAsync(t).Result;

        /// <summary>
        /// Get Clustering Configuration of Current VPN Server (Async mode). You can use this to acquire the clustering configuration of the current VPN Server. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public async Task<VpnRpcFarm> GetFarmSettingAsync() => await CallAsync<VpnRpcFarm>("GetFarmSetting", new VpnRpcFarm());

        /// <summary>
        /// Get Clustering Configuration of Current VPN Server (Async mode). You can use this to acquire the clustering configuration of the current VPN Server. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public VpnRpcFarm GetFarmSetting() => GetFarmSettingAsync().Result;

        /// <summary>
        /// Get Cluster Member Information (Async mode). When the VPN Server is operating as a cluster controller, you can get information on cluster member servers on that cluster by specifying the IDs of the member servers. You can get the following information about the specified cluster member server: Server Type, Time Connection has been Established, IP Address, Host Name, Points, Public Port List, Number of Operating Virtual Hubs, First Virtual Hub, Number of Sessions and Number of TCP Connections. This API cannot be invoked on VPN Bridge.
        /// </summary>
        public async Task<VpnRpcFarmInfo> GetFarmInfoAsync(VpnRpcFarmInfo t) => await CallAsync<VpnRpcFarmInfo>("GetFarmInfo", t);

        /// <summary>
        /// Get Cluster Member Information (Async mode). When the VPN Server is operating as a cluster controller, you can get information on cluster member servers on that cluster by specifying the IDs of the member servers. You can get the following information about the specified cluster member server: Server Type, Time Connection has been Established, IP Address, Host Name, Points, Public Port List, Number of Operating Virtual Hubs, First Virtual Hub, Number of Sessions and Number of TCP Connections. This API cannot be invoked on VPN Bridge.
        /// </summary>
        public VpnRpcFarmInfo GetFarmInfo(VpnRpcFarmInfo t) => GetFarmInfoAsync(t).Result;

        /// <summary>
        /// Get List of Cluster Members (Async mode). Use this API when the VPN Server is operating as a cluster controller to get a list of the cluster member servers on the same cluster, including the cluster controller itself. For each member, the following information is also listed: Type, Connection Start, Host Name, Points, Number of Session, Number of TCP Connections, Number of Operating Virtual Hubs, Using Client Connection License and Using Bridge Connection License. This API cannot be invoked on VPN Bridge.
        /// </summary>
        public async Task<VpnRpcEnumFarm> EnumFarmMemberAsync() => await CallAsync<VpnRpcEnumFarm>("EnumFarmMember", new VpnRpcEnumFarm());

        /// <summary>
        /// Get List of Cluster Members (Async mode). Use this API when the VPN Server is operating as a cluster controller to get a list of the cluster member servers on the same cluster, including the cluster controller itself. For each member, the following information is also listed: Type, Connection Start, Host Name, Points, Number of Session, Number of TCP Connections, Number of Operating Virtual Hubs, Using Client Connection License and Using Bridge Connection License. This API cannot be invoked on VPN Bridge.
        /// </summary>
        public VpnRpcEnumFarm EnumFarmMember() => EnumFarmMemberAsync().Result;

        /// <summary>
        /// Get Connection Status to Cluster Controller (Async mode). Use this API when the VPN Server is operating as a cluster controller to get the status of connection to the cluster controller. You can get the following information: Controller IP Address, Port Number, Connection Status, Connection Start Time, First Connection Established Time, Current Connection Established Time, Number of Connection Attempts, Number of Successful Connections, Number of Failed Connections. This API cannot be invoked on VPN Bridge.
        /// </summary>
        public async Task<VpnRpcFarmConnectionStatus> GetFarmConnectionStatusAsync() => await CallAsync<VpnRpcFarmConnectionStatus>("GetFarmConnectionStatus", new VpnRpcFarmConnectionStatus());

        /// <summary>
        /// Get Connection Status to Cluster Controller (Sync mode). Use this API when the VPN Server is operating as a cluster controller to get the status of connection to the cluster controller. You can get the following information: Controller IP Address, Port Number, Connection Status, Connection Start Time, First Connection Established Time, Current Connection Established Time, Number of Connection Attempts, Number of Successful Connections, Number of Failed Connections. This API cannot be invoked on VPN Bridge.
        /// </summary>
        public VpnRpcFarmConnectionStatus GetFarmConnectionStatus() => GetFarmConnectionStatusAsync().Result;

        /// <summary>
        /// Set SSL Certificate and Private Key of VPN Server (Async mode). You can set the SSL certificate that the VPN Server provides to the connected client and the private key for that certificate. The certificate must be in X.509 format and the private key must be Base 64 encoded format. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public async Task<VpnRpcKeyPair> SetServerCertAsync(VpnRpcKeyPair t) => await CallAsync<VpnRpcKeyPair>("SetServerCert", t);

        /// <summary>
        /// Set SSL Certificate and Private Key of VPN Server (Sync mode). You can set the SSL certificate that the VPN Server provides to the connected client and the private key for that certificate. The certificate must be in X.509 format and the private key must be Base 64 encoded format. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public VpnRpcKeyPair SetServerCert(VpnRpcKeyPair t) => SetServerCertAsync(t).Result;

        /// <summary>
        /// Get SSL Certificate and Private Key of VPN Server (Async mode). Use this to get the SSL certificate private key that the VPN Server provides to the connected client. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public async Task<VpnRpcKeyPair> GetServerCertAsync() => await CallAsync<VpnRpcKeyPair>("GetServerCert", new VpnRpcKeyPair());

        /// <summary>
        /// Get SSL Certificate and Private Key of VPN Server (Async mode). Use this to get the SSL certificate private key that the VPN Server provides to the connected client. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public VpnRpcKeyPair GetServerCert() => GetServerCertAsync().Result;

        /// <summary>
        /// Get the Encrypted Algorithm Used for VPN Communication (Async mode). Use this API to get the current setting of the algorithm used for the electronic signature and encrypted for SSL connection to be used for communication between the VPN Server and the connected client and the list of algorithms that can be used on the VPN Server.
        /// </summary>
        public async Task<VpnRpcStr> GetServerCipherAsync() => await CallAsync<VpnRpcStr>("GetServerCipher", new VpnRpcStr());

        /// <summary>
        /// Get the Encrypted Algorithm Used for VPN Communication (Async mode). Use this API to get the current setting of the algorithm used for the electronic signature and encrypted for SSL connection to be used for communication between the VPN Server and the connected client and the list of algorithms that can be used on the VPN Server.
        /// </summary>
        public VpnRpcStr GetServerCipher() => GetServerCipherAsync().Result;

        /// <summary>
        /// Set the Encrypted Algorithm Used for VPN Communication (Async mode). Use this API to set the algorithm used for the electronic signature and encrypted for SSL connections to be used for communication between the VPN Server and the connected client. By specifying the algorithm name, the specified algorithm will be used later between the VPN Client and VPN Bridge connected to this server and the data will be encrypted. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public async Task<VpnRpcStr> SetServerCipherAsync(VpnRpcStr t) => await CallAsync<VpnRpcStr>("SetServerCipher", t);

        /// <summary>
        /// Set the Encrypted Algorithm Used for VPN Communication (Async mode). Use this API to set the algorithm used for the electronic signature and encrypted for SSL connections to be used for communication between the VPN Server and the connected client. By specifying the algorithm name, the specified algorithm will be used later between the VPN Client and VPN Bridge connected to this server and the data will be encrypted. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public VpnRpcStr SetServerCipher(VpnRpcStr t) => SetServerCipherAsync(t).Result;

        /// <summary>
        /// Create New Virtual Hub (Async mode). Use this to create a new Virtual Hub on the VPN Server. The created Virtual Hub will begin operation immediately. When the VPN Server is operating on a cluster, this API is only valid for the cluster controller. Also, the new Virtual Hub will operate as a dynamic Virtual Hub. You can change it to a static Virtual Hub by using the SetHub API. To get a list of Virtual Hubs that are already on the VPN Server, use the EnumHub API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Servers that are operating as a VPN Bridge or cluster member.
        /// </summary>
        public async Task<VpnRpcCreateHub> CreateHubAsync(VpnRpcCreateHub input_param) => await CallAsync<VpnRpcCreateHub>("CreateHub", input_param);

        /// <summary>
        /// Create New Virtual Hub (Async mode). Use this to create a new Virtual Hub on the VPN Server. The created Virtual Hub will begin operation immediately. When the VPN Server is operating on a cluster, this API is only valid for the cluster controller. Also, the new Virtual Hub will operate as a dynamic Virtual Hub. You can change it to a static Virtual Hub by using the SetHub API. To get a list of Virtual Hubs that are already on the VPN Server, use the EnumHub API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Servers that are operating as a VPN Bridge or cluster member.
        /// </summary>
        public VpnRpcCreateHub CreateHub(VpnRpcCreateHub input_param) => CreateHubAsync(input_param).Result;

        /// <summary>
        /// Set the Virtual Hub configuration (Async mode). You can call this API to change the configuration of the specified Virtual Hub. You can set the Virtual Hub online or offline. You can set the maximum number of sessions that can be concurrently connected to the Virtual Hub that is currently being managed. You can set the Virtual Hub administrator password. You can set other parameters for the Virtual Hub. Before call this API, you need to obtain the latest state of the Virtual Hub by using the GetHub API.
        /// </summary>
        public async Task<VpnRpcCreateHub> SetHubAsync(VpnRpcCreateHub input_param) => await CallAsync<VpnRpcCreateHub>("SetHub", input_param);

        /// <summary>
        /// Set the Virtual Hub configuration (Async mode). You can call this API to change the configuration of the specified Virtual Hub. You can set the Virtual Hub online or offline. You can set the maximum number of sessions that can be concurrently connected to the Virtual Hub that is currently being managed. You can set the Virtual Hub administrator password. You can set other parameters for the Virtual Hub. Before call this API, you need to obtain the latest state of the Virtual Hub by using the GetHub API.
        /// </summary>
        public VpnRpcCreateHub SetHub(VpnRpcCreateHub input_param) => SetHubAsync(input_param).Result;

        /// <summary>
        /// Get the Virtual Hub configuration (Async mode). You can call this API to get the current configuration of the specified Virtual Hub. To change the configuration of the Virtual Hub, call the SetHub API.
        /// </summary>
        public async Task<VpnRpcCreateHub> GetHubAsync(VpnRpcCreateHub input_param) => await CallAsync<VpnRpcCreateHub>("GetHub", input_param);

        /// <summary>
        /// Get the Virtual Hub configuration (Async mode). You can call this API to get the current configuration of the specified Virtual Hub. To change the configuration of the Virtual Hub, call the SetHub API.
        /// </summary>
        public VpnRpcCreateHub GetHub(VpnRpcCreateHub input_param) => GetHubAsync(input_param).Result;

        /// <summary>
        /// Get List of Virtual Hubs (Async mode). Use this to get a list of existing Virtual Hubs on the VPN Server. For each Virtual Hub, you can get the following information: Virtual Hub Name, Status, Type, Number of Users, Number of Groups, Number of Sessions, Number of MAC Tables, Number of IP Tables, Number of Logins, Last Login, and Last Communication. Note that when connecting in Virtual Hub Admin Mode, if in the options of a Virtual Hub that you do not have administrator privileges for, the option Don't Enumerate this Virtual Hub for Anonymous Users is enabled then that Virtual Hub will not be enumerated. If you are connected in Server Admin Mode, then the list of all Virtual Hubs will be displayed. When connecting to and managing a non-cluster-controller cluster member of a clustering environment, only the Virtual Hub currently being hosted by that VPN Server will be displayed. When connecting to a cluster controller for administration purposes, all the Virtual Hubs will be displayed.
        /// </summary>
        public async Task<VpnRpcEnumHub> EnumHubAsync() => await CallAsync<VpnRpcEnumHub>("EnumHub", new VpnRpcEnumHub());

        /// <summary>
        /// Get List of Virtual Hubs (Async mode). Use this to get a list of existing Virtual Hubs on the VPN Server. For each Virtual Hub, you can get the following information: Virtual Hub Name, Status, Type, Number of Users, Number of Groups, Number of Sessions, Number of MAC Tables, Number of IP Tables, Number of Logins, Last Login, and Last Communication. Note that when connecting in Virtual Hub Admin Mode, if in the options of a Virtual Hub that you do not have administrator privileges for, the option Don't Enumerate this Virtual Hub for Anonymous Users is enabled then that Virtual Hub will not be enumerated. If you are connected in Server Admin Mode, then the list of all Virtual Hubs will be displayed. When connecting to and managing a non-cluster-controller cluster member of a clustering environment, only the Virtual Hub currently being hosted by that VPN Server will be displayed. When connecting to a cluster controller for administration purposes, all the Virtual Hubs will be displayed.
        /// </summary>
        public VpnRpcEnumHub EnumHub() => EnumHubAsync().Result;

        /// <summary>
        /// Delete Virtual Hub (Async mode). Use this to delete an existing Virtual Hub on the VPN Server. If you delete the Virtual Hub, all sessions that are currently connected to the Virtual Hub will be disconnected and new sessions will be unable to connect to the Virtual Hub. Also, this will also delete all the Hub settings, user objects, group objects, certificates and Cascade Connections. Once you delete the Virtual Hub, it cannot be recovered. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Servers that are operating as a VPN Bridge or cluster member.
        /// </summary>
        public async Task<VpnRpcDeleteHub> DeleteHubAsync(VpnRpcDeleteHub input_param) => await CallAsync<VpnRpcDeleteHub>("DeleteHub", input_param);

        /// <summary>
        /// Delete Virtual Hub (Async mode). Use this to delete an existing Virtual Hub on the VPN Server. If you delete the Virtual Hub, all sessions that are currently connected to the Virtual Hub will be disconnected and new sessions will be unable to connect to the Virtual Hub. Also, this will also delete all the Hub settings, user objects, group objects, certificates and Cascade Connections. Once you delete the Virtual Hub, it cannot be recovered. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Servers that are operating as a VPN Bridge or cluster member.
        /// </summary>
        public VpnRpcDeleteHub DeleteHub(VpnRpcDeleteHub input_param) => DeleteHubAsync(input_param).Result;

        /// <summary>
        /// Get Setting of RADIUS Server Used for User Authentication (Async mode). Use this to get the current settings for the RADIUS server used when a user connects to the currently managed Virtual Hub using RADIUS Server Authentication Mode. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcRadius> GetHubRadiusAsync(VpnRpcRadius input_param) => await CallAsync<VpnRpcRadius>("GetHubRadius", input_param);

        /// <summary>
        /// Get Setting of RADIUS Server Used for User Authentication (Async mode). Use this to get the current settings for the RADIUS server used when a user connects to the currently managed Virtual Hub using RADIUS Server Authentication Mode. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcRadius GetHubRadius(VpnRpcRadius input_param) => GetHubRadiusAsync(input_param).Result;

        /// <summary>
        /// Set RADIUS Server to use for User Authentication (Async mode). To accept users to the currently managed Virtual Hub in RADIUS server authentication mode, you can specify an external RADIUS server that confirms the user name and password. (You can specify multiple hostname by splitting with comma or semicolon.) The RADIUS server must be set to receive requests from IP addresses of this VPN Server. Also, authentication by Password Authentication Protocol (PAP) must be enabled. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcRadius> SetHubRadiusAsync(VpnRpcRadius input_param) => await CallAsync<VpnRpcRadius>("SetHubRadius", input_param);

        /// <summary>
        /// Set RADIUS Server to use for User Authentication (Async mode). To accept users to the currently managed Virtual Hub in RADIUS server authentication mode, you can specify an external RADIUS server that confirms the user name and password. (You can specify multiple hostname by splitting with comma or semicolon.) The RADIUS server must be set to receive requests from IP addresses of this VPN Server. Also, authentication by Password Authentication Protocol (PAP) must be enabled. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcRadius SetHubRadius(VpnRpcRadius input_param) => SetHubRadiusAsync(input_param).Result;

        /// <summary>
        /// Get List of TCP Connections Connecting to the VPN Server (Async mode). Use this to get a list of TCP/IP connections that are currently connecting to the VPN Server. It does not display the TCP connections that have been established as VPN sessions. To get the list of TCP/IP connections that have been established as VPN sessions, you can use the EnumSession API. You can get the following: Connection Name, Connection Source, Connection Start and Type. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public async Task<VpnRpcEnumConnection> EnumConnectionAsync() => await CallAsync<VpnRpcEnumConnection>("EnumConnection", new VpnRpcEnumConnection());

        /// <summary>
        /// Get List of TCP Connections Connecting to the VPN Server (Async mode). Use this to get a list of TCP/IP connections that are currently connecting to the VPN Server. It does not display the TCP connections that have been established as VPN sessions. To get the list of TCP/IP connections that have been established as VPN sessions, you can use the EnumSession API. You can get the following: Connection Name, Connection Source, Connection Start and Type. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public VpnRpcEnumConnection EnumConnection() => EnumConnectionAsync().Result;

        /// <summary>
        /// Disconnect TCP Connections Connecting to the VPN Server (Async mode). Use this to forcefully disconnect specific TCP/IP connections that are connecting to the VPN Server. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public async Task<VpnRpcDisconnectConnection> DisconnectConnectionAsync(VpnRpcDisconnectConnection input_param) => await CallAsync<VpnRpcDisconnectConnection>("DisconnectConnection", input_param);

        /// <summary>
        /// Disconnect TCP Connections Connecting to the VPN Server (Async mode). Use this to forcefully disconnect specific TCP/IP connections that are connecting to the VPN Server. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public VpnRpcDisconnectConnection DisconnectConnection(VpnRpcDisconnectConnection input_param) => DisconnectConnectionAsync(input_param).Result;

        /// <summary>
        /// Get Information of TCP Connections Connecting to the VPN Server (Async mode). Use this to get detailed information of a specific TCP/IP connection that is connecting to the VPN Server. You can get the following information: Connection Name, Connection Type, Source Hostname, Source IP Address, Source Port Number (TCP), Connection Start, Server Product Name, Server Version, Server Build Number, Client Product Name, Client Version, and Client Build Number. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public async Task<VpnRpcConnectionInfo> GetConnectionInfoAsync(VpnRpcConnectionInfo input_param) => await CallAsync<VpnRpcConnectionInfo>("GetConnectionInfo", input_param);

        /// <summary>
        /// Get Information of TCP Connections Connecting to the VPN Server (Async mode). Use this to get detailed information of a specific TCP/IP connection that is connecting to the VPN Server. You can get the following information: Connection Name, Connection Type, Source Hostname, Source IP Address, Source Port Number (TCP), Connection Start, Server Product Name, Server Version, Server Build Number, Client Product Name, Client Version, and Client Build Number. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public VpnRpcConnectionInfo GetConnectionInfo(VpnRpcConnectionInfo input_param) => GetConnectionInfoAsync(input_param).Result;

        /// <summary>
        /// Switch Virtual Hub to Online or Offline (Async mode). Use this to set the Virtual Hub to online or offline. A Virtual Hub with an offline status cannot receive VPN connections from clients. When you set the Virtual Hub offline, all sessions will be disconnected. A Virtual Hub with an offline status cannot receive VPN connections from clients. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcSetHubOnline> SetHubOnlineAsync(VpnRpcSetHubOnline input_param) => await CallAsync<VpnRpcSetHubOnline>("SetHubOnline", input_param);

        /// <summary>
        /// Switch Virtual Hub to Online or Offline (Async mode). Use this to set the Virtual Hub to online or offline. A Virtual Hub with an offline status cannot receive VPN connections from clients. When you set the Virtual Hub offline, all sessions will be disconnected. A Virtual Hub with an offline status cannot receive VPN connections from clients. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcSetHubOnline SetHubOnline(VpnRpcSetHubOnline input_param) => SetHubOnlineAsync(input_param).Result;

        /// <summary>
        /// Get Current Status of Virtual Hub (Async mode). Use this to get the current status of the Virtual Hub currently being managed. You can get the following information: Virtual Hub Type, Number of Sessions, Number of Each Type of Object, Number of Logins, Last Login, Last Communication, and Communication Statistical Data.
        /// </summary>
        public async Task<VpnRpcHubStatus> GetHubStatusAsync(VpnRpcHubStatus input_param) => await CallAsync<VpnRpcHubStatus>("GetHubStatus", input_param);

        /// <summary>
        /// Get Current Status of Virtual Hub (Async mode). Use this to get the current status of the Virtual Hub currently being managed. You can get the following information: Virtual Hub Type, Number of Sessions, Number of Each Type of Object, Number of Logins, Last Login, Last Communication, and Communication Statistical Data.
        /// </summary>
        public VpnRpcHubStatus GetHubStatus(VpnRpcHubStatus input_param) => GetHubStatusAsync(input_param).Result;

        /// <summary>
        /// Set the logging configuration of the Virtual Hub (Async mode). Use this to enable or disable a security log or packet logs of the Virtual Hub currently being managed, set the save contents of the packet log for each type of packet to be saved, and set the log file switch cycle for the security log or packet log that the currently managed Virtual Hub saves. There are the following packet types: TCP Connection Log, TCP Packet Log, DHCP Packet Log, UDP Packet Log, ICMP Packet Log, IP Packet Log, ARP Packet Log, and Ethernet Packet Log. To get the current setting, you can use the LogGet API. The log file switch cycle can be changed to switch in every second, every minute, every hour, every day, every month or not switch. To get the current setting, you can use the GetHubLog API.
        /// </summary>
        public async Task<VpnRpcHubLog> SetHubLogAsync(VpnRpcHubLog input_param) => await CallAsync<VpnRpcHubLog>("SetHubLog", input_param);

        /// <summary>
        /// Set the logging configuration of the Virtual Hub (Async mode). Use this to enable or disable a security log or packet logs of the Virtual Hub currently being managed, set the save contents of the packet log for each type of packet to be saved, and set the log file switch cycle for the security log or packet log that the currently managed Virtual Hub saves. There are the following packet types: TCP Connection Log, TCP Packet Log, DHCP Packet Log, UDP Packet Log, ICMP Packet Log, IP Packet Log, ARP Packet Log, and Ethernet Packet Log. To get the current setting, you can use the LogGet API. The log file switch cycle can be changed to switch in every second, every minute, every hour, every day, every month or not switch. To get the current setting, you can use the GetHubLog API.
        /// </summary>
        public VpnRpcHubLog SetHubLog(VpnRpcHubLog input_param) => SetHubLogAsync(input_param).Result;

        /// <summary>
        /// Get the logging configuration of the Virtual Hub (Async mode). Use this to get the configuration for a security log or packet logs of the Virtual Hub currently being managed, get the setting for save contents of the packet log for each type of packet to be saved, and get the log file switch cycle for the security log or packet log that the currently managed Virtual Hub saves. To set the current setting, you can use the SetHubLog API.
        /// </summary>
        public async Task<VpnRpcHubLog> GetHubLogAsync(VpnRpcHubLog input_param) => await CallAsync<VpnRpcHubLog>("GetHubLog", input_param);

        /// <summary>
        /// Get the logging configuration of the Virtual Hub (Async mode). Use this to get the configuration for a security log or packet logs of the Virtual Hub currently being managed, get the setting for save contents of the packet log for each type of packet to be saved, and get the log file switch cycle for the security log or packet log that the currently managed Virtual Hub saves. To set the current setting, you can use the SetHubLog API.
        /// </summary>
        public VpnRpcHubLog GetHubLog(VpnRpcHubLog input_param) => GetHubLogAsync(input_param).Result;

        /// <summary>
        /// Add Trusted CA Certificate (Async mode). Use this to add a new certificate to a list of CA certificates trusted by the currently managed Virtual Hub. The list of certificate authority certificates that are registered is used to verify certificates when a VPN Client is connected in signed certificate authentication mode. To get a list of the current certificates you can use the EnumCa API. The certificate you add must be saved in the X.509 file format. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public async Task<VpnRpcHubAddCA> AddCaAsync(VpnRpcHubAddCA input_param) => await CallAsync<VpnRpcHubAddCA>("AddCa", input_param);

        /// <summary>
        /// Add Trusted CA Certificate (Async mode). Use this to add a new certificate to a list of CA certificates trusted by the currently managed Virtual Hub. The list of certificate authority certificates that are registered is used to verify certificates when a VPN Client is connected in signed certificate authentication mode. To get a list of the current certificates you can use the EnumCa API. The certificate you add must be saved in the X.509 file format. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public VpnRpcHubAddCA AddCa(VpnRpcHubAddCA input_param) => AddCaAsync(input_param).Result;

        /// <summary>
        /// Get List of Trusted CA Certificates (Async mode). Here you can manage the certificate authority certificates that are trusted by this currently managed Virtual Hub. The list of certificate authority certificates that are registered is used to verify certificates when a VPN Client is connected in signed certificate authentication mode. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public async Task<VpnRpcHubEnumCA> EnumCaAsync(VpnRpcHubEnumCA input_param) => await CallAsync<VpnRpcHubEnumCA>("EnumCa", input_param);

        /// <summary>
        /// Get List of Trusted CA Certificates (Async mode). Here you can manage the certificate authority certificates that are trusted by this currently managed Virtual Hub. The list of certificate authority certificates that are registered is used to verify certificates when a VPN Client is connected in signed certificate authentication mode. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public VpnRpcHubEnumCA EnumCa(VpnRpcHubEnumCA input_param) => EnumCaAsync(input_param).Result;

        /// <summary>
        /// Get Trusted CA Certificate (Async mode). Use this to get an existing certificate from the list of CA certificates trusted by the currently managed Virtual Hub and save it as a file in X.509 format. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public async Task<VpnRpcHubGetCA> GetCaAsync(VpnRpcHubGetCA input_param) => await CallAsync<VpnRpcHubGetCA>("GetCa", input_param);

        /// <summary>
        /// Get Trusted CA Certificate (Async mode). Use this to get an existing certificate from the list of CA certificates trusted by the currently managed Virtual Hub and save it as a file in X.509 format. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public VpnRpcHubGetCA GetCa(VpnRpcHubGetCA input_param) => GetCaAsync(input_param).Result;

        /// <summary>
        /// Delete Trusted CA Certificate (Async mode). Use this to delete an existing certificate from the list of CA certificates trusted by the currently managed Virtual Hub. To get a list of the current certificates you can use the EnumCa API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public async Task<VpnRpcHubDeleteCA> DeleteCaAsync(VpnRpcHubDeleteCA input_param) => await CallAsync<VpnRpcHubDeleteCA>("DeleteCa", input_param);

        /// <summary>
        /// Delete Trusted CA Certificate (Async mode). Use this to delete an existing certificate from the list of CA certificates trusted by the currently managed Virtual Hub. To get a list of the current certificates you can use the EnumCa API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public VpnRpcHubDeleteCA DeleteCa(VpnRpcHubDeleteCA input_param) => DeleteCaAsync(input_param).Result;

        /// <summary>
        /// Create New Cascade Connection (Async mode). Use this to create a new Cascade Connection on the currently managed Virtual Hub. By using a Cascade Connection, you can connect this Virtual Hub by Cascade Connection to another Virtual Hub that is operating on the same or a different computer. To create a Cascade Connection, you must specify the name of the Cascade Connection, destination server and destination Virtual Hub and user name. When a new Cascade Connection is created, the type of user authentication is initially set as Anonymous Authentication and the proxy server setting and the verification options of the server certificate is not set. To change these settings and other advanced settings after a Cascade Connection has been created, use the other APIs that include the name "Link". [Warning About Cascade Connections] By connecting using a Cascade Connection you can create a Layer 2 bridge between multiple Virtual Hubs but if the connection is incorrectly configured, a loopback Cascade Connection could inadvertently be created. When using a Cascade Connection function please design the network topology with care. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcCreateLink> CreateLinkAsync(VpnRpcCreateLink input_param) => await CallAsync<VpnRpcCreateLink>("CreateLink", input_param);

        /// <summary>
        /// Create New Cascade Connection (Async mode). Use this to create a new Cascade Connection on the currently managed Virtual Hub. By using a Cascade Connection, you can connect this Virtual Hub by Cascade Connection to another Virtual Hub that is operating on the same or a different computer. To create a Cascade Connection, you must specify the name of the Cascade Connection, destination server and destination Virtual Hub and user name. When a new Cascade Connection is created, the type of user authentication is initially set as Anonymous Authentication and the proxy server setting and the verification options of the server certificate is not set. To change these settings and other advanced settings after a Cascade Connection has been created, use the other APIs that include the name "Link". [Warning About Cascade Connections] By connecting using a Cascade Connection you can create a Layer 2 bridge between multiple Virtual Hubs but if the connection is incorrectly configured, a loopback Cascade Connection could inadvertently be created. When using a Cascade Connection function please design the network topology with care. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcCreateLink CreateLink(VpnRpcCreateLink input_param) => CreateLinkAsync(input_param).Result;

        /// <summary>
        /// Get the Cascade Connection Setting (Async mode). Use this to get the Connection Setting of a Cascade Connection that is registered on the currently managed Virtual Hub. To change the Connection Setting contents of the Cascade Connection, use the APIs that include the name "Link" after creating the Cascade Connection. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcCreateLink> GetLinkAsync(VpnRpcCreateLink input_param) => await CallAsync<VpnRpcCreateLink>("GetLink", input_param);

        /// <summary>
        /// Get the Cascade Connection Setting (Async mode). Use this to get the Connection Setting of a Cascade Connection that is registered on the currently managed Virtual Hub. To change the Connection Setting contents of the Cascade Connection, use the APIs that include the name "Link" after creating the Cascade Connection. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcCreateLink GetLink(VpnRpcCreateLink input_param) => GetLinkAsync(input_param).Result;

        /// <summary>
        /// Change Existing Cascade Connection (Async mode). Use this to alter the setting of an existing Cascade Connection on the currently managed Virtual Hub.
        /// </summary>
        public async Task<VpnRpcCreateLink> SetLinkAsync(VpnRpcCreateLink input_param) => await CallAsync<VpnRpcCreateLink>("SetLink", input_param);

        /// <summary>
        /// Change Existing Cascade Connection (Async mode). Use this to alter the setting of an existing Cascade Connection on the currently managed Virtual Hub.
        /// </summary>
        public VpnRpcCreateLink SetLink(VpnRpcCreateLink input_param) => SetLinkAsync(input_param).Result;

        /// <summary>
        /// Get List of Cascade Connections (Async mode). Use this to get a list of Cascade Connections that are registered on the currently managed Virtual Hub. By using a Cascade Connection, you can connect this Virtual Hub by Layer 2 Cascade Connection to another Virtual Hub that is operating on the same or a different computer. [Warning About Cascade Connections] By connecting using a Cascade Connection you can create a Layer 2 bridge between multiple Virtual Hubs but if the connection is incorrectly configured, a loopback Cascade Connection could inadvertently be created. When using a Cascade Connection function please design the network topology with care. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcEnumLink> EnumLinkAsync(VpnRpcEnumLink input_param) => await CallAsync<VpnRpcEnumLink>("EnumLink", input_param);

        /// <summary>
        /// Get List of Cascade Connections (Async mode). Use this to get a list of Cascade Connections that are registered on the currently managed Virtual Hub. By using a Cascade Connection, you can connect this Virtual Hub by Layer 2 Cascade Connection to another Virtual Hub that is operating on the same or a different computer. [Warning About Cascade Connections] By connecting using a Cascade Connection you can create a Layer 2 bridge between multiple Virtual Hubs but if the connection is incorrectly configured, a loopback Cascade Connection could inadvertently be created. When using a Cascade Connection function please design the network topology with care. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcEnumLink EnumLink(VpnRpcEnumLink input_param) => EnumLinkAsync(input_param).Result;

        /// <summary>
        /// Switch Cascade Connection to Online Status (Async mode). When a Cascade Connection registered on the currently managed Virtual Hub is specified, use this to switch that Cascade Connection to online status. The Cascade Connection that is switched to online status begins the process of connecting to the destination VPN Server in accordance with the Connection Setting. The Cascade Connection that is switched to online status will establish normal connection to the VPN Server or continue to attempt connection until it is switched to offline status. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcLink> SetLinkOnlineAsync(VpnRpcLink input_param) => await CallAsync<VpnRpcLink>("SetLinkOnline", input_param);

        /// <summary>
        /// Switch Cascade Connection to Online Status (Async mode). When a Cascade Connection registered on the currently managed Virtual Hub is specified, use this to switch that Cascade Connection to online status. The Cascade Connection that is switched to online status begins the process of connecting to the destination VPN Server in accordance with the Connection Setting. The Cascade Connection that is switched to online status will establish normal connection to the VPN Server or continue to attempt connection until it is switched to offline status. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcLink SetLinkOnline(VpnRpcLink input_param) => SetLinkOnlineAsync(input_param).Result;

        /// <summary>
        /// Switch Cascade Connection to Offline Status (Async mode). When a Cascade Connection registered on the currently managed Virtual Hub is specified, use this to switch that Cascade Connection to offline status. The Cascade Connection that is switched to offline will not connect to the VPN Server until next time it is switched to the online status using the SetLinkOnline API You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcLink> SetLinkOfflineAsync(VpnRpcLink input_param) => await CallAsync<VpnRpcLink>("SetLinkOffline", input_param);

        /// <summary>
        /// Switch Cascade Connection to Offline Status (Async mode). When a Cascade Connection registered on the currently managed Virtual Hub is specified, use this to switch that Cascade Connection to offline status. The Cascade Connection that is switched to offline will not connect to the VPN Server until next time it is switched to the online status using the SetLinkOnline API You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcLink SetLinkOffline(VpnRpcLink input_param) => SetLinkOfflineAsync(input_param).Result;

        /// <summary>
        /// Delete Cascade Connection Setting (Async mode). Use this to delete a Cascade Connection that is registered on the currently managed Virtual Hub. If the specified Cascade Connection has a status of online, the connections will be automatically disconnected and then the Cascade Connection will be deleted. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcLink> DeleteLinkAsync(VpnRpcLink input_param) => await CallAsync<VpnRpcLink>("DeleteLink", input_param);

        /// <summary>
        /// Delete Cascade Connection Setting (Async mode). Use this to delete a Cascade Connection that is registered on the currently managed Virtual Hub. If the specified Cascade Connection has a status of online, the connections will be automatically disconnected and then the Cascade Connection will be deleted. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcLink DeleteLink(VpnRpcLink input_param) => DeleteLinkAsync(input_param).Result;

        /// <summary>
        /// Change Name of Cascade Connection (Async mode). When a Cascade Connection registered on the currently managed Virtual Hub is specified, use this to change the name of that Cascade Connection. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcRenameLink> RenameLinkAsync(VpnRpcRenameLink input_param) => await CallAsync<VpnRpcRenameLink>("RenameLink", input_param);

        /// <summary>
        /// Change Name of Cascade Connection (Async mode). When a Cascade Connection registered on the currently managed Virtual Hub is specified, use this to change the name of that Cascade Connection. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcRenameLink RenameLink(VpnRpcRenameLink input_param) => RenameLinkAsync(input_param).Result;

        /// <summary>
        /// Get Current Cascade Connection Status (Async mode). When a Cascade Connection registered on the currently managed Virtual Hub is specified and that Cascade Connection is currently online, use this to get its connection status and other information. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcLinkStatus> GetLinkStatusAsync(VpnRpcLinkStatus input_param) => await CallAsync<VpnRpcLinkStatus>("GetLinkStatus", input_param);

        /// <summary>
        /// Get Current Cascade Connection Status (Async mode). When a Cascade Connection registered on the currently managed Virtual Hub is specified and that Cascade Connection is currently online, use this to get its connection status and other information. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcLinkStatus GetLinkStatus(VpnRpcLinkStatus input_param) => GetLinkStatusAsync(input_param).Result;

        /// <summary>
        /// Add Access List Rule (Async mode). Use this to add a new rule to the access list of the currently managed Virtual Hub. The access list is a set of packet file rules that are applied to packets that flow through the Virtual Hub. You can register multiple rules in an access list and you can also define an priority for each rule. All packets are checked for the conditions specified by the rules registered in the access list and based on the operation that is stipulated by the first matching rule, they either pass or are discarded. Packets that do not match any rule are implicitly allowed to pass. You can also use the access list to generate delays, jitters and packet losses. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public async Task<VpnRpcAddAccess> AddAccessAsync(VpnRpcAddAccess input_param) => await CallAsync<VpnRpcAddAccess>("AddAccess", input_param);

        /// <summary>
        /// Add Access List Rule (Async mode). Use this to add a new rule to the access list of the currently managed Virtual Hub. The access list is a set of packet file rules that are applied to packets that flow through the Virtual Hub. You can register multiple rules in an access list and you can also define an priority for each rule. All packets are checked for the conditions specified by the rules registered in the access list and based on the operation that is stipulated by the first matching rule, they either pass or are discarded. Packets that do not match any rule are implicitly allowed to pass. You can also use the access list to generate delays, jitters and packet losses. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public VpnRpcAddAccess AddAccess(VpnRpcAddAccess input_param) => AddAccessAsync(input_param).Result;

        /// <summary>
        /// Delete Rule from Access List (Async mode). Use this to specify a packet filter rule registered on the access list of the currently managed Virtual Hub and delete it. To delete a rule, you must specify that rule's ID. You can display the ID by using the EnumAccess API. If you wish not to delete the rule but to only temporarily disable it, use the SetAccessList API to set the rule status to disable. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public async Task<VpnRpcDeleteAccess> DeleteAccessAsync(VpnRpcDeleteAccess input_param) => await CallAsync<VpnRpcDeleteAccess>("DeleteAccess", input_param);

        /// <summary>
        /// Delete Rule from Access List (Async mode). Use this to specify a packet filter rule registered on the access list of the currently managed Virtual Hub and delete it. To delete a rule, you must specify that rule's ID. You can display the ID by using the EnumAccess API. If you wish not to delete the rule but to only temporarily disable it, use the SetAccessList API to set the rule status to disable. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public VpnRpcDeleteAccess DeleteAccess(VpnRpcDeleteAccess input_param) => DeleteAccessAsync(input_param).Result;

        /// <summary>
        /// Get Access List Rule List (Async mode). Use this to get a list of packet filter rules that are registered on access list of the currently managed Virtual Hub. The access list is a set of packet file rules that are applied to packets that flow through the Virtual Hub. You can register multiple rules in an access list and you can also define a priority for each rule. All packets are checked for the conditions specified by the rules registered in the access list and based on the operation that is stipulated by the first matching rule, they either pass or are discarded. Packets that do not match any rule are implicitly allowed to pass. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public async Task<VpnRpcEnumAccessList> EnumAccessAsync(VpnRpcEnumAccessList input_param) => await CallAsync<VpnRpcEnumAccessList>("EnumAccess", input_param);

        /// <summary>
        /// Get Access List Rule List (Async mode). Use this to get a list of packet filter rules that are registered on access list of the currently managed Virtual Hub. The access list is a set of packet file rules that are applied to packets that flow through the Virtual Hub. You can register multiple rules in an access list and you can also define a priority for each rule. All packets are checked for the conditions specified by the rules registered in the access list and based on the operation that is stipulated by the first matching rule, they either pass or are discarded. Packets that do not match any rule are implicitly allowed to pass. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public VpnRpcEnumAccessList EnumAccess(VpnRpcEnumAccessList input_param) => EnumAccessAsync(input_param).Result;

        /// <summary>
        /// Replace all access lists on a single bulk API call (Async mode). This API removes all existing access list rules on the Virtual Hub, and replace them by new access list rules specified by the parameter.
        /// </summary>
        public async Task<VpnRpcEnumAccessList> SetAccessListAsync(VpnRpcEnumAccessList input_param) => await CallAsync<VpnRpcEnumAccessList>("SetAccessList", input_param);

        /// <summary>
        /// Replace all access lists on a single bulk API call (Async mode). This API removes all existing access list rules on the Virtual Hub, and replace them by new access list rules specified by the parameter.
        /// </summary>
        public VpnRpcEnumAccessList SetAccessList(VpnRpcEnumAccessList input_param) => SetAccessListAsync(input_param).Result;

        /// <summary>
        /// Create a user (Async mode). Use this to create a new user in the security account database of the currently managed Virtual Hub. By creating a user, the VPN Client can connect to the Virtual Hub by using the authentication information of that user. Note that a user whose user name has been created as "*" (a single asterisk character) will automatically be registered as a RADIUS authentication user. For cases where there are users with "*" as the name, when a user, whose user name that has been provided when a client connected to a VPN Server does not match existing user names, is able to be authenticated by a RADIUS server or NT domain controller by inputting a user name and password, the authentication settings and security policy settings will follow the setting for the user "*". To change the user information of a user that has been created, use the SetUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public async Task<VpnRpcSetUser> CreateUserAsync(VpnRpcSetUser input_param) => await CallAsync<VpnRpcSetUser>("CreateUser", input_param);

        /// <summary>
        /// Create a user (Async mode). Use this to create a new user in the security account database of the currently managed Virtual Hub. By creating a user, the VPN Client can connect to the Virtual Hub by using the authentication information of that user. Note that a user whose user name has been created as "*" (a single asterisk character) will automatically be registered as a RADIUS authentication user. For cases where there are users with "*" as the name, when a user, whose user name that has been provided when a client connected to a VPN Server does not match existing user names, is able to be authenticated by a RADIUS server or NT domain controller by inputting a user name and password, the authentication settings and security policy settings will follow the setting for the user "*". To change the user information of a user that has been created, use the SetUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public VpnRpcSetUser CreateUser(VpnRpcSetUser input_param) => CreateUserAsync(input_param).Result;

        /// <summary>
        /// Change User Settings (Async mode). Use this to change user settings that is registered on the security account database of the currently managed Virtual Hub. The user settings that can be changed using this API are the three items that are specified when a new user is created using the CreateUser API: Group Name, Full Name, and Description. To get the list of currently registered users, use the EnumUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public async Task<VpnRpcSetUser> SetUserAsync(VpnRpcSetUser input_param) => await CallAsync<VpnRpcSetUser>("SetUser", input_param);

        /// <summary>
        /// Change User Settings (Async mode). Use this to change user settings that is registered on the security account database of the currently managed Virtual Hub. The user settings that can be changed using this API are the three items that are specified when a new user is created using the CreateUser API: Group Name, Full Name, and Description. To get the list of currently registered users, use the EnumUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public VpnRpcSetUser SetUser(VpnRpcSetUser input_param) => SetUserAsync(input_param).Result;

        /// <summary>
        /// Get User Settings (Async mode). Use this to get user settings information that is registered on the security account database of the currently managed Virtual Hub. The information that you can get using this API are User Name, Full Name, Group Name, Expiration Date, Security Policy, and Auth Type, as well as parameters that are specified as auth type attributes and the statistical data of that user. To get the list of currently registered users, use the EnumUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public async Task<VpnRpcSetUser> GetUserAsync(VpnRpcSetUser input_param) => await CallAsync<VpnRpcSetUser>("GetUser", input_param);

        /// <summary>
        /// Get User Settings (Async mode). Use this to get user settings information that is registered on the security account database of the currently managed Virtual Hub. The information that you can get using this API are User Name, Full Name, Group Name, Expiration Date, Security Policy, and Auth Type, as well as parameters that are specified as auth type attributes and the statistical data of that user. To get the list of currently registered users, use the EnumUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public VpnRpcSetUser GetUser(VpnRpcSetUser input_param) => GetUserAsync(input_param).Result;

        /// <summary>
        /// Delete a user (Async mode). Use this to delete a user that is registered on the security account database of the currently managed Virtual Hub. By deleting the user, that user will no long be able to connect to the Virtual Hub. You can use the SetUser API to set the user's security policy to deny access instead of deleting a user, set the user to be temporarily denied from logging in. To get the list of currently registered users, use the EnumUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public async Task<VpnRpcDeleteUser> DeleteUserAsync(VpnRpcDeleteUser input_param) => await CallAsync<VpnRpcDeleteUser>("DeleteUser", input_param);

        /// <summary>
        /// Delete a user (Sync mode). Use this to delete a user that is registered on the security account database of the currently managed Virtual Hub. By deleting the user, that user will no long be able to connect to the Virtual Hub. You can use the SetUser API to set the user's security policy to deny access instead of deleting a user, set the user to be temporarily denied from logging in. To get the list of currently registered users, use the EnumUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public VpnRpcDeleteUser DeleteUser(VpnRpcDeleteUser input_param) => DeleteUserAsync(input_param).Result;

        /// <summary>
        /// Get List of Users (Async mode). Use this to get a list of users that are registered on the security account database of the currently managed Virtual Hub. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public async Task<VpnRpcEnumUser> EnumUserAsync(VpnRpcEnumUser input_param) => await CallAsync<VpnRpcEnumUser>("EnumUser", input_param);

        /// <summary>
        /// Get List of Users (Async mode). Use this to get a list of users that are registered on the security account database of the currently managed Virtual Hub. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public VpnRpcEnumUser EnumUser(VpnRpcEnumUser input_param) => EnumUserAsync(input_param).Result;

        /// <summary>
        /// Create Group (Async mode). Use this to create a new group in the security account database of the currently managed Virtual Hub. You can register multiple users in a group. To register users in a group use the SetUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public async Task<VpnRpcSetGroup> CreateGroupAsync(VpnRpcSetGroup input_param) => await CallAsync<VpnRpcSetGroup>("CreateGroup", input_param);

        /// <summary>
        /// Create Group (Async mode). Use this to create a new group in the security account database of the currently managed Virtual Hub. You can register multiple users in a group. To register users in a group use the SetUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public VpnRpcSetGroup CreateGroup(VpnRpcSetGroup input_param) => CreateGroupAsync(input_param).Result;

        /// <summary>
        /// Set group settings (Async mode). Use this to set group settings that is registered on the security account database of the currently managed Virtual Hub. To get the list of currently registered groups, use the EnumGroup API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public async Task<VpnRpcSetGroup> SetGroupAsync(VpnRpcSetGroup input_param) => await CallAsync<VpnRpcSetGroup>("SetGroup", input_param);

        /// <summary>
        /// Set group settings (Async mode). Use this to set group settings that is registered on the security account database of the currently managed Virtual Hub. To get the list of currently registered groups, use the EnumGroup API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public VpnRpcSetGroup SetGroup(VpnRpcSetGroup input_param) => SetGroupAsync(input_param).Result;

        /// <summary>
        /// Get Group Setting (Sync mode). Use this to get the setting of a group that is registered on the security account database of the currently managed Virtual Hub. To get the list of currently registered groups, use the EnumGroup API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public async Task<VpnRpcSetGroup> GetGroupAsync(VpnRpcSetGroup input_param) => await CallAsync<VpnRpcSetGroup>("GetGroup", input_param);

        /// <summary>
        /// Get Group Setting (Sync mode). Use this to get the setting of a group that is registered on the security account database of the currently managed Virtual Hub. To get the list of currently registered groups, use the EnumGroup API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public VpnRpcSetGroup GetGroup(VpnRpcSetGroup input_param) => GetGroupAsync(input_param).Result;

        /// <summary>
        /// Delete User from Group (Async mode). Use this to delete a specified user from the group that is registered on the security account database of the currently managed Virtual Hub. By deleting a user from the group, that user becomes unassigned. To get the list of currently registered groups, use the EnumGroup API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public async Task<VpnRpcDeleteUser> DeleteGroupAsync(VpnRpcDeleteUser input_param) => await CallAsync<VpnRpcDeleteUser>("DeleteGroup", input_param);

        /// <summary>
        /// Delete User from Group (Async mode). Use this to delete a specified user from the group that is registered on the security account database of the currently managed Virtual Hub. By deleting a user from the group, that user becomes unassigned. To get the list of currently registered groups, use the EnumGroup API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public VpnRpcDeleteUser DeleteGroup(VpnRpcDeleteUser input_param) => DeleteGroupAsync(input_param).Result;

        /// <summary>
        /// Get List of Groups (Async mode). Use this to get a list of groups that are registered on the security account database of the currently managed Virtual Hub. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public async Task<VpnRpcEnumGroup> EnumGroupAsync(VpnRpcEnumGroup input_param) => await CallAsync<VpnRpcEnumGroup>("EnumGroup", input_param);

        /// <summary>
        /// Get List of Groups (Async mode). Use this to get a list of groups that are registered on the security account database of the currently managed Virtual Hub. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.
        /// </summary>
        public VpnRpcEnumGroup EnumGroup(VpnRpcEnumGroup input_param) => EnumGroupAsync(input_param).Result;

        /// <summary>
        /// Get List of Connected VPN Sessions (Async mode). Use this to get a list of the sessions connected to the Virtual Hub currently being managed. In the list of sessions, the following information will be obtained for each connection: Session Name, Session Site, User Name, Source Host Name, TCP Connection, Transfer Bytes and Transfer Packets. If the currently connected VPN Server is a cluster controller and the currently managed Virtual Hub is a static Virtual Hub, you can get an all-linked-together list of all sessions connected to that Virtual Hub on all cluster members. In all other cases, only the list of sessions that are actually connected to the currently managed VPN Server will be obtained.
        /// </summary>
        public async Task<VpnRpcEnumSession> EnumSessionAsync(VpnRpcEnumSession input_param) => await CallAsync<VpnRpcEnumSession>("EnumSession", input_param);

        /// <summary>
        /// Get List of Connected VPN Sessions (Async mode). Use this to get a list of the sessions connected to the Virtual Hub currently being managed. In the list of sessions, the following information will be obtained for each connection: Session Name, Session Site, User Name, Source Host Name, TCP Connection, Transfer Bytes and Transfer Packets. If the currently connected VPN Server is a cluster controller and the currently managed Virtual Hub is a static Virtual Hub, you can get an all-linked-together list of all sessions connected to that Virtual Hub on all cluster members. In all other cases, only the list of sessions that are actually connected to the currently managed VPN Server will be obtained.
        /// </summary>
        public VpnRpcEnumSession EnumSession(VpnRpcEnumSession input_param) => EnumSessionAsync(input_param).Result;

        /// <summary>
        /// Get Session Status (Async mode). Use this to specify a session currently connected to the currently managed Virtual Hub and get the session information. The session status includes the following: source host name and user name, version information, time information, number of TCP connections, communication parameters, session key, statistical information on data transferred, and other client and server information. To get the list of currently connected sessions, use the EnumSession API.
        /// </summary>
        public async Task<VpnRpcSessionStatus> GetSessionStatusAsync(VpnRpcSessionStatus input_param) => await CallAsync<VpnRpcSessionStatus>("GetSessionStatus", input_param);

        /// <summary>
        /// Get Session Status (Async mode). Use this to specify a session currently connected to the currently managed Virtual Hub and get the session information. The session status includes the following: source host name and user name, version information, time information, number of TCP connections, communication parameters, session key, statistical information on data transferred, and other client and server information. To get the list of currently connected sessions, use the EnumSession API.
        /// </summary>
        public VpnRpcSessionStatus GetSessionStatus(VpnRpcSessionStatus input_param) => GetSessionStatusAsync(input_param).Result;

        /// <summary>
        /// Disconnect Session (Async mode). Use this to specify a session currently connected to the currently managed Virtual Hub and forcefully disconnect that session using manager privileges. Note that when communication is disconnected by settings on the source client side and the automatically reconnect option is enabled, it is possible that the client will reconnect. To get the list of currently connected sessions, use the EnumSession API.
        /// </summary>
        public async Task<VpnRpcDeleteSession> DeleteSessionAsync(VpnRpcDeleteSession input_param) => await CallAsync<VpnRpcDeleteSession>("DeleteSession", input_param);

        /// <summary>
        /// Disconnect Session (Async mode). Use this to specify a session currently connected to the currently managed Virtual Hub and forcefully disconnect that session using manager privileges. Note that when communication is disconnected by settings on the source client side and the automatically reconnect option is enabled, it is possible that the client will reconnect. To get the list of currently connected sessions, use the EnumSession API.
        /// </summary>
        public VpnRpcDeleteSession DeleteSession(VpnRpcDeleteSession input_param) => DeleteSessionAsync(input_param).Result;

        /// <summary>
        /// Get the MAC Address Table Database (Async mode). Use this to get the MAC address table database that is held by the currently managed Virtual Hub. The MAC address table database is a table that the Virtual Hub requires to perform the action of switching Ethernet frames and the Virtual Hub decides the sorting destination session of each Ethernet frame based on the MAC address table database. The MAC address database is built by the Virtual Hub automatically analyzing the contents of the communication.
        /// </summary>
        public async Task<VpnRpcEnumMacTable> EnumMacTableAsync(VpnRpcEnumMacTable input_param) => await CallAsync<VpnRpcEnumMacTable>("EnumMacTable", input_param);

        /// <summary>
        /// Get the MAC Address Table Database (Async mode). Use this to get the MAC address table database that is held by the currently managed Virtual Hub. The MAC address table database is a table that the Virtual Hub requires to perform the action of switching Ethernet frames and the Virtual Hub decides the sorting destination session of each Ethernet frame based on the MAC address table database. The MAC address database is built by the Virtual Hub automatically analyzing the contents of the communication.
        /// </summary>
        public VpnRpcEnumMacTable EnumMacTable(VpnRpcEnumMacTable input_param) => EnumMacTableAsync(input_param).Result;

        /// <summary>
        /// Delete MAC Address Table Entry (Async mode). Use this API to operate the MAC address table database held by the currently managed Virtual Hub and delete a specified MAC address table entry from the database. To get the contents of the current MAC address table database use the EnumMacTable API.
        /// </summary>
        public async Task<VpnRpcDeleteTable> DeleteMacTableAsync(VpnRpcDeleteTable input_param) => await CallAsync<VpnRpcDeleteTable>("DeleteMacTable", input_param);

        /// <summary>
        /// Delete MAC Address Table Entry (Async mode). Use this API to operate the MAC address table database held by the currently managed Virtual Hub and delete a specified MAC address table entry from the database. To get the contents of the current MAC address table database use the EnumMacTable API.
        /// </summary>
        public VpnRpcDeleteTable DeleteMacTable(VpnRpcDeleteTable input_param) => DeleteMacTableAsync(input_param).Result;

        /// <summary>
        /// Get the IP Address Table Database (Async mode). Use this to get the IP address table database that is held by the currently managed Virtual Hub. The IP address table database is a table that is automatically generated by analyzing the contents of communication so that the Virtual Hub can always know which session is using which IP address and it is frequently used by the engine that applies the Virtual Hub security policy. By specifying the session name you can get the IP address table entry that has been associated with that session.
        /// </summary>
        public async Task<VpnRpcEnumIpTable> EnumIpTableAsync(VpnRpcEnumIpTable input_param) => await CallAsync<VpnRpcEnumIpTable>("EnumIpTable", input_param);

        /// <summary>
        /// Get the IP Address Table Database (Async mode). Use this to get the IP address table database that is held by the currently managed Virtual Hub. The IP address table database is a table that is automatically generated by analyzing the contents of communication so that the Virtual Hub can always know which session is using which IP address and it is frequently used by the engine that applies the Virtual Hub security policy. By specifying the session name you can get the IP address table entry that has been associated with that session.
        /// </summary>
        public VpnRpcEnumIpTable EnumIpTable(VpnRpcEnumIpTable input_param) => EnumIpTableAsync(input_param).Result;

        /// <summary>
        /// Delete IP Address Table Entry (Async mode). Use this API to operate the IP address table database held by the currently managed Virtual Hub and delete a specified IP address table entry from the database. To get the contents of the current IP address table database use the EnumIpTable API.
        /// </summary>
        public async Task<VpnRpcDeleteTable> DeleteIpTableAsync(VpnRpcDeleteTable input_param) => await CallAsync<VpnRpcDeleteTable>("DeleteIpTable", input_param);

        /// <summary>
        /// Delete IP Address Table Entry (Async mode). Use this API to operate the IP address table database held by the currently managed Virtual Hub and delete a specified IP address table entry from the database. To get the contents of the current IP address table database use the EnumIpTable API.
        /// </summary>
        public VpnRpcDeleteTable DeleteIpTable(VpnRpcDeleteTable input_param) => DeleteIpTableAsync(input_param).Result;

        /// <summary>
        /// Set the Keep Alive Internet Connection Function (Async mode). Use this to set the destination host name etc. of the Keep Alive Internet Connection Function. For network connection environments where connections will automatically be disconnected where there are periods of no communication that are longer than a set period, by using the Keep Alive Internet Connection Function, it is possible to keep alive the Internet connection by sending packets to a nominated server on the Internet at set intervals. When using this API, you can specify the following: Host Name, Port Number, Packet Send Interval, and Protocol. Packets sent to keep alive the Internet connection will have random content and personal information that could identify a computer or user is not sent. You can use the SetKeep API to enable/disable the Keep Alive Internet Connection Function. To execute this API on a VPN Server or VPN Bridge, you must have administrator privileges.
        /// </summary>
        public async Task<VpnRpcKeep> SetKeepAsync(VpnRpcKeep input_param) => await CallAsync<VpnRpcKeep>("SetKeep", input_param);

        /// <summary>
        /// Set the Keep Alive Internet Connection Function (Async mode). Use this to set the destination host name etc. of the Keep Alive Internet Connection Function. For network connection environments where connections will automatically be disconnected where there are periods of no communication that are longer than a set period, by using the Keep Alive Internet Connection Function, it is possible to keep alive the Internet connection by sending packets to a nominated server on the Internet at set intervals. When using this API, you can specify the following: Host Name, Port Number, Packet Send Interval, and Protocol. Packets sent to keep alive the Internet connection will have random content and personal information that could identify a computer or user is not sent. You can use the SetKeep API to enable/disable the Keep Alive Internet Connection Function. To execute this API on a VPN Server or VPN Bridge, you must have administrator privileges.
        /// </summary>
        public VpnRpcKeep SetKeep(VpnRpcKeep input_param) => SetKeepAsync(input_param).Result;

        /// <summary>
        /// Get the Keep Alive Internet Connection Function (Async mode). Use this to get the current setting contents of the Keep Alive Internet Connection Function. In addition to the destination's Host Name, Port Number, Packet Send Interval and Protocol, you can obtain the current enabled/disabled status of the Keep Alive Internet Connection Function.
        /// </summary>
        public async Task<VpnRpcKeep> GetKeepAsync(VpnRpcKeep input_param) => await CallAsync<VpnRpcKeep>("GetKeep", input_param);

        /// <summary>
        /// Get the Keep Alive Internet Connection Function (Async mode). Use this to get the current setting contents of the Keep Alive Internet Connection Function. In addition to the destination's Host Name, Port Number, Packet Send Interval and Protocol, you can obtain the current enabled/disabled status of the Keep Alive Internet Connection Function.
        /// </summary>
        public VpnRpcKeep GetKeep(VpnRpcKeep input_param) => GetKeepAsync(input_param).Result;

        /// <summary>
        /// Enable the Virtual NAT and DHCP Server Function (SecureNAT Function) (Async mode). Use this to enable the Virtual NAT and DHCP Server function (SecureNAT Function) on the currently managed Virtual Hub and begin its operation. Before executing this API, you must first check the setting contents of the current Virtual NAT function and DHCP Server function using the SetSecureNATOption API and GetSecureNATOption API. By enabling the SecureNAT function, you can virtually operate a NAT router (IP masquerade) and the DHCP Server function on a virtual network on the Virtual Hub. [Warning about SecureNAT Function] The SecureNAT function is recommended only for system administrators and people with a detailed knowledge of networks. If you use the SecureNAT function correctly, it is possible to achieve a safe form of remote access via a VPN. However when used in the wrong way, it can put the entire network in danger. Anyone who does not have a thorough knowledge of networks and anyone who does not have the network administrator's permission must not enable the SecureNAT function. For a detailed explanation of the SecureNAT function, please refer to the VPN Server's manual and online documentation. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcHub> EnableSecureNATAsync(VpnRpcHub input_param) => await CallAsync<VpnRpcHub>("EnableSecureNAT", input_param);

        /// <summary>
        /// Enable the Virtual NAT and DHCP Server Function (SecureNAT Function) (Async mode). Use this to enable the Virtual NAT and DHCP Server function (SecureNAT Function) on the currently managed Virtual Hub and begin its operation. Before executing this API, you must first check the setting contents of the current Virtual NAT function and DHCP Server function using the SetSecureNATOption API and GetSecureNATOption API. By enabling the SecureNAT function, you can virtually operate a NAT router (IP masquerade) and the DHCP Server function on a virtual network on the Virtual Hub. [Warning about SecureNAT Function] The SecureNAT function is recommended only for system administrators and people with a detailed knowledge of networks. If you use the SecureNAT function correctly, it is possible to achieve a safe form of remote access via a VPN. However when used in the wrong way, it can put the entire network in danger. Anyone who does not have a thorough knowledge of networks and anyone who does not have the network administrator's permission must not enable the SecureNAT function. For a detailed explanation of the SecureNAT function, please refer to the VPN Server's manual and online documentation. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcHub EnableSecureNAT(VpnRpcHub input_param) => EnableSecureNATAsync(input_param).Result;

        /// <summary>
        /// Disable the Virtual NAT and DHCP Server Function (SecureNAT Function) (Async mode). Use this to disable the Virtual NAT and DHCP Server function (SecureNAT Function) on the currently managed Virtual Hub. By executing this API the Virtual NAT function immediately stops operating and the Virtual DHCP Server function deletes the DHCP lease database and stops the service. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcHub> DisableSecureNATAsync(VpnRpcHub input_param) => await CallAsync<VpnRpcHub>("DisableSecureNAT", input_param);

        /// <summary>
        /// Disable the Virtual NAT and DHCP Server Function (SecureNAT Function) (Async mode). Use this to disable the Virtual NAT and DHCP Server function (SecureNAT Function) on the currently managed Virtual Hub. By executing this API the Virtual NAT function immediately stops operating and the Virtual DHCP Server function deletes the DHCP lease database and stops the service. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcHub DisableSecureNAT(VpnRpcHub input_param) => DisableSecureNATAsync(input_param).Result;

        /// <summary>
        /// Change Settings of SecureNAT Function (Async mode). Use this to change and save the virtual host network interface settings, virtual NAT function settings and virtual DHCP server settings of the Virtual NAT and DHCP Server function (SecureNAT function) on the currently managed Virtual Hub. The SecureNAT function holds one virtual network adapter on the L2 segment inside the Virtual Hub and it has been assigned a MAC address and an IP address. By doing this, another host connected to the same L2 segment is able to communicate with the SecureNAT virtual host as if it is an actual IP host existing on the network. [Warning about SecureNAT Function] The SecureNAT function is recommended only for system administrators and people with a detailed knowledge of networks. If you use the SecureNAT function correctly, it is possible to achieve a safe form of remote access via a VPN. However when used in the wrong way, it can put the entire network in danger. Anyone who does not have a thorough knowledge of networks and anyone who does not have the network administrators permission must not enable the SecureNAT function. For a detailed explanation of the SecureNAT function, please refer to the VPN Server's manual and online documentation. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnVhOption> SetSecureNATOptionAsync(VpnVhOption input_param) => await CallAsync<VpnVhOption>("SetSecureNATOption", input_param);

        /// <summary>
        /// Change Settings of SecureNAT Function (Async mode). Use this to change and save the virtual host network interface settings, virtual NAT function settings and virtual DHCP server settings of the Virtual NAT and DHCP Server function (SecureNAT function) on the currently managed Virtual Hub. The SecureNAT function holds one virtual network adapter on the L2 segment inside the Virtual Hub and it has been assigned a MAC address and an IP address. By doing this, another host connected to the same L2 segment is able to communicate with the SecureNAT virtual host as if it is an actual IP host existing on the network. [Warning about SecureNAT Function] The SecureNAT function is recommended only for system administrators and people with a detailed knowledge of networks. If you use the SecureNAT function correctly, it is possible to achieve a safe form of remote access via a VPN. However when used in the wrong way, it can put the entire network in danger. Anyone who does not have a thorough knowledge of networks and anyone who does not have the network administrators permission must not enable the SecureNAT function. For a detailed explanation of the SecureNAT function, please refer to the VPN Server's manual and online documentation. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnVhOption SetSecureNATOption(VpnVhOption input_param) => SetSecureNATOptionAsync(input_param).Result;

        /// <summary>
        /// Get Settings of SecureNAT Function (Async mode). This API get the registered settings for the SecureNAT function which is set by the SetSecureNATOption API.
        /// </summary>
        public async Task<VpnVhOption> GetSecureNATOptionAsync(VpnVhOption input_param) => await CallAsync<VpnVhOption>("GetSecureNATOption", input_param);

        /// <summary>
        /// Get Settings of SecureNAT Function (Async mode). This API get the registered settings for the SecureNAT function which is set by the SetSecureNATOption API.
        /// </summary>
        public VpnVhOption GetSecureNATOption(VpnVhOption input_param) => GetSecureNATOptionAsync(input_param).Result;

        /// <summary>
        /// Get Virtual NAT Function Session Table of SecureNAT Function (Async mode). Use this to get the table of TCP and UDP sessions currently communicating via the Virtual NAT (NAT table) in cases when the Virtual NAT function is operating on the currently managed Virtual Hub. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcEnumNat> EnumNATAsync(VpnRpcEnumNat input_param) => await CallAsync<VpnRpcEnumNat>("EnumNAT", input_param);

        /// <summary>
        /// Get Virtual NAT Function Session Table of SecureNAT Function (Async mode). Use this to get the table of TCP and UDP sessions currently communicating via the Virtual NAT (NAT table) in cases when the Virtual NAT function is operating on the currently managed Virtual Hub. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcEnumNat EnumNAT(VpnRpcEnumNat input_param) => EnumNATAsync(input_param).Result;

        /// <summary>
        /// Get Virtual DHCP Server Function Lease Table of SecureNAT Function (Async mode). Use this to get the lease table of IP addresses, held by the Virtual DHCP Server, that are assigned to clients in cases when the Virtual NAT function is operating on the currently managed Virtual Hub. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcEnumDhcp> EnumDHCPAsync(VpnRpcEnumDhcp input_param) => await CallAsync<VpnRpcEnumDhcp>("EnumDHCP", input_param);

        /// <summary>
        /// Get Virtual DHCP Server Function Lease Table of SecureNAT Function (Async mode). Use this to get the lease table of IP addresses, held by the Virtual DHCP Server, that are assigned to clients in cases when the Virtual NAT function is operating on the currently managed Virtual Hub. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcEnumDhcp EnumDHCP(VpnRpcEnumDhcp input_param) => EnumDHCPAsync(input_param).Result;

        /// <summary>
        /// Get the Operating Status of the Virtual NAT and DHCP Server Function (SecureNAT Function) (Async mode). Use this to get the operating status of the Virtual NAT and DHCP Server function (SecureNAT Function) when it is operating on the currently managed Virtual Hub. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcNatStatus> GetSecureNATStatusAsync(VpnRpcNatStatus input_param) => await CallAsync<VpnRpcNatStatus>("GetSecureNATStatus", input_param);

        /// <summary>
        /// Get the Operating Status of the Virtual NAT and DHCP Server Function (SecureNAT Function) (Async mode). Use this to get the operating status of the Virtual NAT and DHCP Server function (SecureNAT Function) when it is operating on the currently managed Virtual Hub. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcNatStatus GetSecureNATStatus(VpnRpcNatStatus input_param) => GetSecureNATStatusAsync(input_param).Result;

        /// <summary>
        /// Get List of Network Adapters Usable as Local Bridge (Async mode). Use this to get a list of Ethernet devices (network adapters) that can be used as a bridge destination device as part of a Local Bridge connection. If possible, network connection name is displayed. You can use a device displayed here by using the AddLocalBridge API. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public async Task<VpnRpcEnumEth> EnumEthernetAsync() => await CallAsync<VpnRpcEnumEth>("EnumEthernet", new VpnRpcEnumEth());

        /// <summary>
        /// Get List of Network Adapters Usable as Local Bridge (Async mode). Use this to get a list of Ethernet devices (network adapters) that can be used as a bridge destination device as part of a Local Bridge connection. If possible, network connection name is displayed. You can use a device displayed here by using the AddLocalBridge API. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public VpnRpcEnumEth EnumEthernet() => EnumEthernetAsync().Result;

        /// <summary>
        /// Create Local Bridge Connection (Async mode). Use this to create a new Local Bridge connection on the VPN Server. By using a Local Bridge, you can configure a Layer 2 bridge connection between a Virtual Hub operating on this VPN server and a physical Ethernet Device (Network Adapter). You can create a tap device (virtual network interface) on the system and connect a bridge between Virtual Hubs (the tap device is only supported by Linux versions). It is possible to establish a bridge to an operating network adapter of your choice for the bridge destination Ethernet device (network adapter), but in high load environments, we recommend you prepare a network adapter dedicated to serve as a bridge. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public async Task<VpnRpcLocalBridge> AddLocalBridgeAsync(VpnRpcLocalBridge input_param) => await CallAsync<VpnRpcLocalBridge>("AddLocalBridge", input_param);

        /// <summary>
        /// Create Local Bridge Connection (Async mode). Use this to create a new Local Bridge connection on the VPN Server. By using a Local Bridge, you can configure a Layer 2 bridge connection between a Virtual Hub operating on this VPN server and a physical Ethernet Device (Network Adapter). You can create a tap device (virtual network interface) on the system and connect a bridge between Virtual Hubs (the tap device is only supported by Linux versions). It is possible to establish a bridge to an operating network adapter of your choice for the bridge destination Ethernet device (network adapter), but in high load environments, we recommend you prepare a network adapter dedicated to serve as a bridge. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public VpnRpcLocalBridge AddLocalBridge(VpnRpcLocalBridge input_param) => AddLocalBridgeAsync(input_param).Result;

        /// <summary>
        /// Delete Local Bridge Connection (Async mode). Use this to delete an existing Local Bridge connection. To get a list of current Local Bridge connections use the EnumLocalBridge API. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public async Task<VpnRpcLocalBridge> DeleteLocalBridgeAsync(VpnRpcLocalBridge input_param) => await CallAsync<VpnRpcLocalBridge>("DeleteLocalBridge", input_param);

        /// <summary>
        /// Delete Local Bridge Connection (Async mode). Use this to delete an existing Local Bridge connection. To get a list of current Local Bridge connections use the EnumLocalBridge API. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public VpnRpcLocalBridge DeleteLocalBridge(VpnRpcLocalBridge input_param) => DeleteLocalBridgeAsync(input_param).Result;

        /// <summary>
        /// Get List of Local Bridge Connection (Async mode). Use this to get a list of the currently defined Local Bridge connections. You can get the Local Bridge connection Virtual Hub name and the bridge destination Ethernet device (network adapter) name or tap device name, as well as the operating status.
        /// </summary>
        public async Task<VpnRpcEnumLocalBridge> EnumLocalBridgeAsync() => await CallAsync<VpnRpcEnumLocalBridge>("EnumLocalBridge", new VpnRpcEnumLocalBridge());

        /// <summary>
        /// Get List of Local Bridge Connection (Async mode). Use this to get a list of the currently defined Local Bridge connections. You can get the Local Bridge connection Virtual Hub name and the bridge destination Ethernet device (network adapter) name or tap device name, as well as the operating status.
        /// </summary>
        public VpnRpcEnumLocalBridge EnumLocalBridge() => EnumLocalBridgeAsync().Result;

        /// <summary>
        /// Get whether the localbridge function is supported on the current system (Async mode).
        /// </summary>
        public async Task<VpnRpcBridgeSupport> GetBridgeSupportAsync() => await CallAsync<VpnRpcBridgeSupport>("GetBridgeSupport", new VpnRpcBridgeSupport());

        /// <summary>
        /// Get whether the localbridge function is supported on the current system (Async mode).
        /// </summary>
        public VpnRpcBridgeSupport GetBridgeSupport() => GetBridgeSupportAsync().Result;

        /// <summary>
        /// Reboot VPN Server Service (Async mode). Use this to restart the VPN Server service. When you restart the VPN Server, all currently connected sessions and TCP connections will be disconnected and no new connections will be accepted until the restart process has completed. By using this API, only the VPN Server service program will be restarted and the physical computer that VPN Server is operating on does not restart. This management session will also be disconnected, so you will need to reconnect to continue management. Also, by specifying the "IntValue" parameter to "1", the contents of the configuration file (.config) held by the current VPN Server will be initialized. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public async Task<VpnRpcTest> RebootServerAsync(VpnRpcTest input_param) => await CallAsync<VpnRpcTest>("RebootServer", input_param);

        /// <summary>
        /// Reboot VPN Server Service (Async mode). Use this to restart the VPN Server service. When you restart the VPN Server, all currently connected sessions and TCP connections will be disconnected and no new connections will be accepted until the restart process has completed. By using this API, only the VPN Server service program will be restarted and the physical computer that VPN Server is operating on does not restart. This management session will also be disconnected, so you will need to reconnect to continue management. Also, by specifying the "IntValue" parameter to "1", the contents of the configuration file (.config) held by the current VPN Server will be initialized. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public VpnRpcTest RebootServer(VpnRpcTest input_param) => RebootServerAsync(input_param).Result;

        /// <summary>
        /// Get List of Server Functions / Capability (Async mode). Use this get a list of functions and capability of the VPN Server currently connected and being managed. The function and capability of VPN Servers are different depending on the operating VPN server's edition and version. Using this API, you can find out the capability of the target VPN Server and report it.
        /// </summary>
        public async Task<VpnCapslist> GetCapsAsync() => await CallAsync<VpnCapslist>("GetCaps", new VpnCapslist());

        /// <summary>
        /// Get List of Server Functions / Capability (Async mode). Use this get a list of functions and capability of the VPN Server currently connected and being managed. The function and capability of VPN Servers are different depending on the operating VPN server's edition and version. Using this API, you can find out the capability of the target VPN Server and report it.
        /// </summary>
        public VpnCapslist GetCaps() => GetCapsAsync().Result;

        /// <summary>
        /// Get the current configuration of the VPN Server (Async mode). Use this to get a text file (.config file) that contains the current configuration contents of the VPN server. You can get the status on the VPN Server at the instant this API is executed. You can edit the configuration file by using a regular text editor. To write an edited configuration to the VPN Server, use the SetConfig API. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public async Task<VpnRpcConfig> GetConfigAsync() => await CallAsync<VpnRpcConfig>("GetConfig", new VpnRpcConfig());

        /// <summary>
        /// Get the current configuration of the VPN Server (Async mode). Use this to get a text file (.config file) that contains the current configuration contents of the VPN server. You can get the status on the VPN Server at the instant this API is executed. You can edit the configuration file by using a regular text editor. To write an edited configuration to the VPN Server, use the SetConfig API. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public VpnRpcConfig GetConfig() => GetConfigAsync().Result;

        /// <summary>
        /// Write Configuration File to VPN Server (Async mode). Use this to write the configuration file to the VPN Server. By executing this API, the contents of the specified configuration file will be applied to the VPN Server and the VPN Server program will automatically restart and upon restart, operate according to the new configuration contents. Because it is difficult for an administrator to write all the contents of a configuration file, we recommend you use the GetConfig API to get the current contents of the VPN Server configuration and save it to file. You can then edit these contents in a regular text editor and then use the SetConfig API to rewrite the contents to the VPN Server. This API is for people with a detailed knowledge of the VPN Server and if an incorrectly configured configuration file is written to the VPN Server, it not only could cause errors, it could also result in the lost of the current setting data. Take special care when carrying out this action. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public async Task<VpnRpcConfig> SetConfigAsync(VpnRpcConfig input_param) => await CallAsync<VpnRpcConfig>("SetConfig", input_param);

        /// <summary>
        /// Write Configuration File to VPN Server (Async mode). Use this to write the configuration file to the VPN Server. By executing this API, the contents of the specified configuration file will be applied to the VPN Server and the VPN Server program will automatically restart and upon restart, operate according to the new configuration contents. Because it is difficult for an administrator to write all the contents of a configuration file, we recommend you use the GetConfig API to get the current contents of the VPN Server configuration and save it to file. You can then edit these contents in a regular text editor and then use the SetConfig API to rewrite the contents to the VPN Server. This API is for people with a detailed knowledge of the VPN Server and if an incorrectly configured configuration file is written to the VPN Server, it not only could cause errors, it could also result in the lost of the current setting data. Take special care when carrying out this action. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public VpnRpcConfig SetConfig(VpnRpcConfig input_param) => SetConfigAsync(input_param).Result;

        /// <summary>
        /// Get Virtual Hub Administration Option default values (Async mode).
        /// </summary>
        public async Task<VpnRpcAdminOption> GetDefaultHubAdminOptionsAsync(VpnRpcAdminOption input_param) => await CallAsync<VpnRpcAdminOption>("GetDefaultHubAdminOptions", input_param);

        /// <summary>
        /// Get Virtual Hub Administration Option default values (Async mode).
        /// </summary>
        public VpnRpcAdminOption GetDefaultHubAdminOptions(VpnRpcAdminOption input_param) => GetDefaultHubAdminOptionsAsync(input_param).Result;

        /// <summary>
        /// Get List of Virtual Hub Administration Options (Async mode). Use this to get a list of Virtual Hub administration options that are set on the currently managed Virtual Hub. The purpose of the Virtual Hub administration options is for the VPN Server Administrator to set limits for the setting ranges when the administration of the Virtual Hub is to be trusted to each Virtual Hub administrator. Only an administrator with administration privileges for this entire VPN Server is able to add, edit and delete the Virtual Hub administration options. The Virtual Hub administrators are unable to make changes to the administration options, however they are able to view them. There is an exception however. If allow_hub_admin_change_option is set to "1", even Virtual Hub administrators are able to edit the administration options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member.
        /// </summary>
        public async Task<VpnRpcAdminOption> GetHubAdminOptionsAsync(VpnRpcAdminOption input_param) => await CallAsync<VpnRpcAdminOption>("GetHubAdminOptions", input_param);

        /// <summary>
        /// Get List of Virtual Hub Administration Options (Async mode). Use this to get a list of Virtual Hub administration options that are set on the currently managed Virtual Hub. The purpose of the Virtual Hub administration options is for the VPN Server Administrator to set limits for the setting ranges when the administration of the Virtual Hub is to be trusted to each Virtual Hub administrator. Only an administrator with administration privileges for this entire VPN Server is able to add, edit and delete the Virtual Hub administration options. The Virtual Hub administrators are unable to make changes to the administration options, however they are able to view them. There is an exception however. If allow_hub_admin_change_option is set to "1", even Virtual Hub administrators are able to edit the administration options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member.
        /// </summary>
        public VpnRpcAdminOption GetHubAdminOptions(VpnRpcAdminOption input_param) => GetHubAdminOptionsAsync(input_param).Result;

        /// <summary>
        /// Set Values of Virtual Hub Administration Options (Async mode). Use this to change the values of Virtual Hub administration options that are set on the currently managed Virtual Hub. The purpose of the Virtual Hub administration options is for the VPN Server Administrator to set limits for the setting ranges when the administration of the Virtual Hub is to be trusted to each Virtual Hub administrator. Only an administrator with administration privileges for this entire VPN Server is able to add, edit and delete the Virtual Hub administration options. The Virtual Hub administrators are unable to make changes to the administration options, however they are able to view them. There is an exception however. If allow_hub_admin_change_option is set to "1", even Virtual Hub administrators are able to edit the administration options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member.
        /// </summary>
        public async Task<VpnRpcAdminOption> SetHubAdminOptionsAsync(VpnRpcAdminOption input_param) => await CallAsync<VpnRpcAdminOption>("SetHubAdminOptions", input_param);

        /// <summary>
        /// Set Values of Virtual Hub Administration Options (Async mode). Use this to change the values of Virtual Hub administration options that are set on the currently managed Virtual Hub. The purpose of the Virtual Hub administration options is for the VPN Server Administrator to set limits for the setting ranges when the administration of the Virtual Hub is to be trusted to each Virtual Hub administrator. Only an administrator with administration privileges for this entire VPN Server is able to add, edit and delete the Virtual Hub administration options. The Virtual Hub administrators are unable to make changes to the administration options, however they are able to view them. There is an exception however. If allow_hub_admin_change_option is set to "1", even Virtual Hub administrators are able to edit the administration options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member.
        /// </summary>
        public VpnRpcAdminOption SetHubAdminOptions(VpnRpcAdminOption input_param) => SetHubAdminOptionsAsync(input_param).Result;

        /// <summary>
        /// Get List of Virtual Hub Extended Options (Async mode). Use this to get a Virtual Hub Extended Options List that is set on the currently managed Virtual Hub. Virtual Hub Extended Option enables you to configure more detail settings of the Virtual Hub. By default, both VPN Server's global administrators and individual Virtual Hub's administrators can modify the Virtual Hub Extended Options. However, if the deny_hub_admin_change_ext_option is set to 1 on the Virtual Hub Admin Options, the individual Virtual Hub's administrators cannot modify the Virtual Hub Extended Options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member.
        /// </summary>
        public async Task<VpnRpcAdminOption> GetHubExtOptionsAsync(VpnRpcAdminOption input_param) => await CallAsync<VpnRpcAdminOption>("GetHubExtOptions", input_param);

        /// <summary>
        /// Get List of Virtual Hub Extended Options (Async mode). Use this to get a Virtual Hub Extended Options List that is set on the currently managed Virtual Hub. Virtual Hub Extended Option enables you to configure more detail settings of the Virtual Hub. By default, both VPN Server's global administrators and individual Virtual Hub's administrators can modify the Virtual Hub Extended Options. However, if the deny_hub_admin_change_ext_option is set to 1 on the Virtual Hub Admin Options, the individual Virtual Hub's administrators cannot modify the Virtual Hub Extended Options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member.
        /// </summary>
        public VpnRpcAdminOption GetHubExtOptions(VpnRpcAdminOption input_param) => GetHubExtOptionsAsync(input_param).Result;

        /// <summary>
        /// Set a Value of Virtual Hub Extended Options (Async mode). Use this to set a value in the Virtual Hub Extended Options List that is set on the currently managed Virtual Hub. Virtual Hub Extended Option enables you to configure more detail settings of the Virtual Hub. By default, both VPN Server's global administrators and individual Virtual Hub's administrators can modify the Virtual Hub Extended Options. However, if the deny_hub_admin_change_ext_option is set to 1 on the Virtual Hub Admin Options, the individual Virtual Hub's administrators cannot modify the Virtual Hub Extended Options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member.
        /// </summary>
        public async Task<VpnRpcAdminOption> SetHubExtOptionsAsync(VpnRpcAdminOption input_param) => await CallAsync<VpnRpcAdminOption>("SetHubExtOptions", input_param);

        /// <summary>
        /// Set a Value of Virtual Hub Extended Options (Async mode). Use this to set a value in the Virtual Hub Extended Options List that is set on the currently managed Virtual Hub. Virtual Hub Extended Option enables you to configure more detail settings of the Virtual Hub. By default, both VPN Server's global administrators and individual Virtual Hub's administrators can modify the Virtual Hub Extended Options. However, if the deny_hub_admin_change_ext_option is set to 1 on the Virtual Hub Admin Options, the individual Virtual Hub's administrators cannot modify the Virtual Hub Extended Options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member.
        /// </summary>
        public VpnRpcAdminOption SetHubExtOptions(VpnRpcAdminOption input_param) => SetHubExtOptionsAsync(input_param).Result;

        /// <summary>
        /// Define New Virtual Layer 3 Switch (Async mode). Use this to define a new Virtual Layer 3 Switch on the VPN Server. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. [Explanation on Virtual Layer 3 Switch Function] You can define Virtual Layer 3 Switches between multiple Virtual Hubs operating on this VPN Server and configure routing between different IP networks. [Caution about the Virtual Layer 3 Switch Function] The Virtual Layer 3 Switch functions are provided for network administrators and other people who know a lot about networks and IP routing. If you are using the regular VPN functions, you do not need to use the Virtual Layer 3 Switch functions. If the Virtual Layer 3 Switch functions are to be used, the person who configures them must have sufficient knowledge of IP routing and be perfectly capable of not impacting the network.
        /// </summary>
        public async Task<VpnRpcL3Sw> AddL3SwitchAsync(VpnRpcL3Sw input_param) => await CallAsync<VpnRpcL3Sw>("AddL3Switch", input_param);

        /// <summary>
        /// Define New Virtual Layer 3 Switch (Async mode). Use this to define a new Virtual Layer 3 Switch on the VPN Server. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. [Explanation on Virtual Layer 3 Switch Function] You can define Virtual Layer 3 Switches between multiple Virtual Hubs operating on this VPN Server and configure routing between different IP networks. [Caution about the Virtual Layer 3 Switch Function] The Virtual Layer 3 Switch functions are provided for network administrators and other people who know a lot about networks and IP routing. If you are using the regular VPN functions, you do not need to use the Virtual Layer 3 Switch functions. If the Virtual Layer 3 Switch functions are to be used, the person who configures them must have sufficient knowledge of IP routing and be perfectly capable of not impacting the network.
        /// </summary>
        public VpnRpcL3Sw AddL3Switch(VpnRpcL3Sw input_param) => AddL3SwitchAsync(input_param).Result;

        /// <summary>
        /// Delete Virtual Layer 3 Switch (Async mode). Use this to delete an existing Virtual Layer 3 Switch that is defined on the VPN Server. When the specified Virtual Layer 3 Switch is operating, it will be automatically deleted after operation stops. To get a list of existing Virtual Layer 3 Switches, use the EnumL3Switch API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge.
        /// </summary>
        public async Task<VpnRpcL3Sw> DelL3SwitchAsync(VpnRpcL3Sw input_param) => await CallAsync<VpnRpcL3Sw>("DelL3Switch", input_param);

        /// <summary>
        /// Delete Virtual Layer 3 Switch (Async mode). Use this to delete an existing Virtual Layer 3 Switch that is defined on the VPN Server. When the specified Virtual Layer 3 Switch is operating, it will be automatically deleted after operation stops. To get a list of existing Virtual Layer 3 Switches, use the EnumL3Switch API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge.
        /// </summary>
        public VpnRpcL3Sw DelL3Switch(VpnRpcL3Sw input_param) => DelL3SwitchAsync(input_param).Result;

        /// <summary>
        /// Get List of Virtual Layer 3 Switches (Async mode). Use this to define a new Virtual Layer 3 Switch on the VPN Server. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. [Explanation on Virtual Layer 3 Switch Function] You can define Virtual Layer 3 Switches between multiple Virtual Hubs operating on this VPN Server and configure routing between different IP networks. [Caution about the Virtual Layer 3 Switch Function] The Virtual Layer 3 Switch functions are provided for network administrators and other people who know a lot about networks and IP routing. If you are using the regular VPN functions, you do not need to use the Virtual Layer 3 Switch functions. If the Virtual Layer 3 Switch functions are to be used, the person who configures them must have sufficient knowledge of IP routing and be perfectly capable of not impacting the network.
        /// </summary>
        public async Task<VpnRpcEnumL3Sw> EnumL3SwitchAsync() => await CallAsync<VpnRpcEnumL3Sw>("EnumL3Switch", new VpnRpcEnumL3Sw());

        /// <summary>
        /// Get List of Virtual Layer 3 Switches (Async mode). Use this to define a new Virtual Layer 3 Switch on the VPN Server. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. [Explanation on Virtual Layer 3 Switch Function] You can define Virtual Layer 3 Switches between multiple Virtual Hubs operating on this VPN Server and configure routing between different IP networks. [Caution about the Virtual Layer 3 Switch Function] The Virtual Layer 3 Switch functions are provided for network administrators and other people who know a lot about networks and IP routing. If you are using the regular VPN functions, you do not need to use the Virtual Layer 3 Switch functions. If the Virtual Layer 3 Switch functions are to be used, the person who configures them must have sufficient knowledge of IP routing and be perfectly capable of not impacting the network.
        /// </summary>
        public VpnRpcEnumL3Sw EnumL3Switch() => EnumL3SwitchAsync().Result;

        /// <summary>
        /// Start Virtual Layer 3 Switch Operation (Async mode). Use this to start the operation of an existing Virtual Layer 3 Switch defined on the VPN Server whose operation is currently stopped. To get a list of existing Virtual Layer 3 Switches, use the EnumL3Switch API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. [Explanation on Virtual Layer 3 Switch Function] You can define Virtual Layer 3 Switches between multiple Virtual Hubs operating on this VPN Server and configure routing between different IP networks. [Caution about the Virtual Layer 3 Switch Function] The Virtual Layer 3 Switch functions are provided for network administrators and other people who know a lot about networks and IP routing. If you are using the regular VPN functions, you do not need to use the Virtual Layer 3 Switch functions. If the Virtual Layer 3 Switch functions are to be used, the person who configures them must have sufficient knowledge of IP routing and be perfectly capable of not impacting the network.
        /// </summary>
        public async Task<VpnRpcL3Sw> StartL3SwitchAsync(VpnRpcL3Sw input_param) => await CallAsync<VpnRpcL3Sw>("StartL3Switch", input_param);

        /// <summary>
        /// Start Virtual Layer 3 Switch Operation (Async mode). Use this to start the operation of an existing Virtual Layer 3 Switch defined on the VPN Server whose operation is currently stopped. To get a list of existing Virtual Layer 3 Switches, use the EnumL3Switch API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. [Explanation on Virtual Layer 3 Switch Function] You can define Virtual Layer 3 Switches between multiple Virtual Hubs operating on this VPN Server and configure routing between different IP networks. [Caution about the Virtual Layer 3 Switch Function] The Virtual Layer 3 Switch functions are provided for network administrators and other people who know a lot about networks and IP routing. If you are using the regular VPN functions, you do not need to use the Virtual Layer 3 Switch functions. If the Virtual Layer 3 Switch functions are to be used, the person who configures them must have sufficient knowledge of IP routing and be perfectly capable of not impacting the network.
        /// </summary>
        public VpnRpcL3Sw StartL3Switch(VpnRpcL3Sw input_param) => StartL3SwitchAsync(input_param).Result;

        /// <summary>
        /// Stop Virtual Layer 3 Switch Operation (Async mode). Use this to stop the operation of an existing Virtual Layer 3 Switch defined on the VPN Server whose operation is currently operating. To get a list of existing Virtual Layer 3 Switches, use the EnumL3Switch API. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public async Task<VpnRpcL3Sw> StopL3SwitchAsync(VpnRpcL3Sw input_param) => await CallAsync<VpnRpcL3Sw>("StopL3Switch", input_param);

        /// <summary>
        /// Stop Virtual Layer 3 Switch Operation (Async mode). Use this to stop the operation of an existing Virtual Layer 3 Switch defined on the VPN Server whose operation is currently operating. To get a list of existing Virtual Layer 3 Switches, use the EnumL3Switch API. To call this API, you must have VPN Server administrator privileges.
        /// </summary>
        public VpnRpcL3Sw StopL3Switch(VpnRpcL3Sw input_param) => StopL3SwitchAsync(input_param).Result;

        /// <summary>
        /// Add Virtual Interface to Virtual Layer 3 Switch (Async mode). Use this to add to a specified Virtual Layer 3 Switch, a virtual interface that connects to a Virtual Hub operating on the same VPN Server. You can define multiple virtual interfaces and routing tables for a single Virtual Layer 3 Switch. A virtual interface is associated to a virtual Hub and operates as a single IP host on the Virtual Hub when that Virtual Hub is operating. When multiple virtual interfaces that respectively belong to a different IP network of a different Virtual Hub are defined, IP routing will be automatically performed between these interfaces. You must define the IP network space that the virtual interface belongs to and the IP address of the interface itself. Also, you must specify the name of the Virtual Hub that the interface will connect to. You can specify a Virtual Hub that currently doesn't exist for the Virtual Hub name. The virtual interface must have one IP address in the Virtual Hub. You also must specify the subnet mask of an IP network that the IP address belongs to. Routing via the Virtual Layer 3 Switches of IP spaces of multiple virtual Hubs operates based on the IP address is specified here. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API.
        /// </summary>
        public async Task<VpnRpcL3If> AddL3IfAsync(VpnRpcL3If input_param) => await CallAsync<VpnRpcL3If>("AddL3If", input_param);

        /// <summary>
        /// Add Virtual Interface to Virtual Layer 3 Switch (Async mode). Use this to add to a specified Virtual Layer 3 Switch, a virtual interface that connects to a Virtual Hub operating on the same VPN Server. You can define multiple virtual interfaces and routing tables for a single Virtual Layer 3 Switch. A virtual interface is associated to a virtual Hub and operates as a single IP host on the Virtual Hub when that Virtual Hub is operating. When multiple virtual interfaces that respectively belong to a different IP network of a different Virtual Hub are defined, IP routing will be automatically performed between these interfaces. You must define the IP network space that the virtual interface belongs to and the IP address of the interface itself. Also, you must specify the name of the Virtual Hub that the interface will connect to. You can specify a Virtual Hub that currently doesn't exist for the Virtual Hub name. The virtual interface must have one IP address in the Virtual Hub. You also must specify the subnet mask of an IP network that the IP address belongs to. Routing via the Virtual Layer 3 Switches of IP spaces of multiple virtual Hubs operates based on the IP address is specified here. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API.
        /// </summary>
        public VpnRpcL3If AddL3If(VpnRpcL3If input_param) => AddL3IfAsync(input_param).Result;

        /// <summary>
        /// Delete Virtual Interface of Virtual Layer 3 Switch (Async mode). Use this to delete a virtual interface already defined in the specified Virtual Layer 3 Switch. You can get a list of the virtual interfaces currently defined, by using the EnumL3If API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API.
        /// </summary>
        public async Task<VpnRpcL3If> DelL3IfAsync(VpnRpcL3If input_param) => await CallAsync<VpnRpcL3If>("DelL3If", input_param);

        /// <summary>
        /// Delete Virtual Interface of Virtual Layer 3 Switch (Async mode). Use this to delete a virtual interface already defined in the specified Virtual Layer 3 Switch. You can get a list of the virtual interfaces currently defined, by using the EnumL3If API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API.
        /// </summary>
        public VpnRpcL3If DelL3If(VpnRpcL3If input_param) => DelL3IfAsync(input_param).Result;

        /// <summary>
        /// Get List of Interfaces Registered on the Virtual Layer 3 Switch (Async mode). Use this to get a list of virtual interfaces when virtual interfaces have been defined on a specified Virtual Layer 3 Switch. You can define multiple virtual interfaces and routing tables for a single Virtual Layer 3 Switch. A virtual interface is associated to a virtual Hub and operates as a single IP host on the Virtual Hub when that Virtual Hub is operating. When multiple virtual interfaces that respectively belong to a different IP network of a different Virtual Hub are defined, IP routing will be automatically performed between these interfaces. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge.
        /// </summary>
        public async Task<VpnRpcEnumL3If> EnumL3IfAsync(VpnRpcEnumL3If input_param) => await CallAsync<VpnRpcEnumL3If>("EnumL3If", input_param);

        /// <summary>
        /// Get List of Interfaces Registered on the Virtual Layer 3 Switch (Async mode). Use this to get a list of virtual interfaces when virtual interfaces have been defined on a specified Virtual Layer 3 Switch. You can define multiple virtual interfaces and routing tables for a single Virtual Layer 3 Switch. A virtual interface is associated to a virtual Hub and operates as a single IP host on the Virtual Hub when that Virtual Hub is operating. When multiple virtual interfaces that respectively belong to a different IP network of a different Virtual Hub are defined, IP routing will be automatically performed between these interfaces. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge.
        /// </summary>
        public VpnRpcEnumL3If EnumL3If(VpnRpcEnumL3If input_param) => EnumL3IfAsync(input_param).Result;

        /// <summary>
        /// Add Routing Table Entry for Virtual Layer 3 Switch (Async mode). Here you can add a new routing table entry to the routing table of the specified Virtual Layer 3 Switch. If the destination IP address of the IP packet does not belong to any IP network that belongs to a virtual interface, the IP routing engine of the Virtual Layer 3 Switch will reference the routing table and execute routing. You must specify the contents of the routing table entry to be added to the Virtual Layer 3 Switch. You must specify any IP address that belongs to the same IP network in the virtual interface of this Virtual Layer 3 Switch as the gateway address. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API.
        /// </summary>
        public async Task<VpnRpcL3Table> AddL3TableAsync(VpnRpcL3Table input_param) => await CallAsync<VpnRpcL3Table>("AddL3Table", input_param);

        /// <summary>
        /// Add Routing Table Entry for Virtual Layer 3 Switch (Async mode). Here you can add a new routing table entry to the routing table of the specified Virtual Layer 3 Switch. If the destination IP address of the IP packet does not belong to any IP network that belongs to a virtual interface, the IP routing engine of the Virtual Layer 3 Switch will reference the routing table and execute routing. You must specify the contents of the routing table entry to be added to the Virtual Layer 3 Switch. You must specify any IP address that belongs to the same IP network in the virtual interface of this Virtual Layer 3 Switch as the gateway address. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API.
        /// </summary>
        public VpnRpcL3Table AddL3Table(VpnRpcL3Table input_param) => AddL3TableAsync(input_param).Result;

        /// <summary>
        /// Delete Routing Table Entry of Virtual Layer 3 Switch (Async mode). Use this to delete a routing table entry that is defined in the specified Virtual Layer 3 Switch. You can get a list of the already defined routing table entries by using the EnumL3Table API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API.
        /// </summary>
        public async Task<VpnRpcL3Table> DelL3TableAsync(VpnRpcL3Table input_param) => await CallAsync<VpnRpcL3Table>("DelL3Table", input_param);

        /// <summary>
        /// Delete Routing Table Entry of Virtual Layer 3 Switch (Async mode). Use this to delete a routing table entry that is defined in the specified Virtual Layer 3 Switch. You can get a list of the already defined routing table entries by using the EnumL3Table API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API.
        /// </summary>
        public VpnRpcL3Table DelL3Table(VpnRpcL3Table input_param) => DelL3TableAsync(input_param).Result;

        /// <summary>
        /// Get List of Routing Tables of Virtual Layer 3 Switch (Async mode). Use this to get a list of routing tables when routing tables have been defined on a specified Virtual Layer 3 Switch. If the destination IP address of the IP packet does not belong to any IP network that belongs to a virtual interface, the IP routing engine of the Virtual Layer 3 Switch will reference this routing table and execute routing. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge.
        /// </summary>
        public async Task<VpnRpcEnumL3Table> EnumL3TableAsync(VpnRpcEnumL3Table input_param) => await CallAsync<VpnRpcEnumL3Table>("EnumL3Table", input_param);

        /// <summary>
        /// Get List of Routing Tables of Virtual Layer 3 Switch (Async mode). Use this to get a list of routing tables when routing tables have been defined on a specified Virtual Layer 3 Switch. If the destination IP address of the IP packet does not belong to any IP network that belongs to a virtual interface, the IP routing engine of the Virtual Layer 3 Switch will reference this routing table and execute routing. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge.
        /// </summary>
        public VpnRpcEnumL3Table EnumL3Table(VpnRpcEnumL3Table input_param) => EnumL3TableAsync(input_param).Result;

        /// <summary>
        /// Get List of Certificates Revocation List (Async mode). Use this to get a Certificates Revocation List that is set on the currently managed Virtual Hub. By registering certificates in the Certificates Revocation List, the clients who provide these certificates will be unable to connect to this Virtual Hub using certificate authentication mode. Normally with this function, in cases where the security of a private key has been compromised or where a person holding a certificate has been stripped of their privileges, by registering that certificate as invalid on the Virtual Hub, it is possible to deny user authentication when that certificate is used by a client to connect to the Virtual Hub. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcEnumCrl> EnumCrlAsync(VpnRpcEnumCrl input_param) => await CallAsync<VpnRpcEnumCrl>("EnumCrl", input_param);

        /// <summary>
        /// Get List of Certificates Revocation List (Async mode). Use this to get a Certificates Revocation List that is set on the currently managed Virtual Hub. By registering certificates in the Certificates Revocation List, the clients who provide these certificates will be unable to connect to this Virtual Hub using certificate authentication mode. Normally with this function, in cases where the security of a private key has been compromised or where a person holding a certificate has been stripped of their privileges, by registering that certificate as invalid on the Virtual Hub, it is possible to deny user authentication when that certificate is used by a client to connect to the Virtual Hub. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcEnumCrl EnumCrl(VpnRpcEnumCrl input_param) => EnumCrlAsync(input_param).Result;

        /// <summary>
        /// Add a Revoked Certificate (Async mode). Use this to add a new revoked certificate definition in the Certificate Revocation List that is set on the currently managed Virtual Hub. Specify the contents to be registered in the Certificate Revocation List by using the parameters of this API. When a user connects to a Virtual Hub in certificate authentication mode and that certificate matches 1 or more of the contents registered in the certificates revocation list, the user is denied connection. A certificate that matches all the conditions that are defined by the parameters specified by this API will be judged as invalid. The items that can be set are as follows: Name (CN), Organization (O), Organization Unit (OU), Country (C), State (ST), Locale (L), Serial Number (hexadecimal), MD5 Digest Value (hexadecimal, 128 bit), and SHA-1 Digest Value (hexadecimal, 160 bit). For the specification of a digest value (hash value) a certificate is optionally specified depending on the circumstances. Normally when a MD5 or SHA-1 digest value is input, it is not necessary to input the other items. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcCrl> AddCrlAsync(VpnRpcCrl input_param) => await CallAsync<VpnRpcCrl>("AddCrl", input_param);

        /// <summary>
        /// Add a Revoked Certificate (Async mode). Use this to add a new revoked certificate definition in the Certificate Revocation List that is set on the currently managed Virtual Hub. Specify the contents to be registered in the Certificate Revocation List by using the parameters of this API. When a user connects to a Virtual Hub in certificate authentication mode and that certificate matches 1 or more of the contents registered in the certificates revocation list, the user is denied connection. A certificate that matches all the conditions that are defined by the parameters specified by this API will be judged as invalid. The items that can be set are as follows: Name (CN), Organization (O), Organization Unit (OU), Country (C), State (ST), Locale (L), Serial Number (hexadecimal), MD5 Digest Value (hexadecimal, 128 bit), and SHA-1 Digest Value (hexadecimal, 160 bit). For the specification of a digest value (hash value) a certificate is optionally specified depending on the circumstances. Normally when a MD5 or SHA-1 digest value is input, it is not necessary to input the other items. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcCrl AddCrl(VpnRpcCrl input_param) => AddCrlAsync(input_param).Result;

        /// <summary>
        /// Delete a Revoked Certificate (Async mode). Use this to specify and delete a revoked certificate definition from the certificate revocation list that is set on the currently managed Virtual Hub. To get the list of currently registered revoked certificate definitions, use the EnumCrl API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcCrl> DelCrlAsync(VpnRpcCrl input_param) => await CallAsync<VpnRpcCrl>("DelCrl", input_param);

        /// <summary>
        /// Delete a Revoked Certificate (Async mode). Use this to specify and delete a revoked certificate definition from the certificate revocation list that is set on the currently managed Virtual Hub. To get the list of currently registered revoked certificate definitions, use the EnumCrl API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcCrl DelCrl(VpnRpcCrl input_param) => DelCrlAsync(input_param).Result;

        /// <summary>
        /// Get a Revoked Certificate (Async mode). Use this to specify and get the contents of a revoked certificate definition from the Certificates Revocation List that is set on the currently managed Virtual Hub. To get the list of currently registered revoked certificate definitions, use the EnumCrl API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcCrl> GetCrlAsync(VpnRpcCrl input_param) => await CallAsync<VpnRpcCrl>("GetCrl", input_param);

        /// <summary>
        /// Get a Revoked Certificate (Async mode). Use this to specify and get the contents of a revoked certificate definition from the Certificates Revocation List that is set on the currently managed Virtual Hub. To get the list of currently registered revoked certificate definitions, use the EnumCrl API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcCrl GetCrl(VpnRpcCrl input_param) => GetCrlAsync(input_param).Result;

        /// <summary>
        /// Change Existing CRL (Certificate Revocation List) Entry (Async mode). Use this to alter an existing revoked certificate definition in the Certificate Revocation List that is set on the currently managed Virtual Hub. Specify the contents to be registered in the Certificate Revocation List by using the parameters of this API. When a user connects to a Virtual Hub in certificate authentication mode and that certificate matches 1 or more of the contents registered in the certificates revocation list, the user is denied connection. A certificate that matches all the conditions that are defined by the parameters specified by this API will be judged as invalid. The items that can be set are as follows: Name (CN), Organization (O), Organization Unit (OU), Country (C), State (ST), Locale (L), Serial Number (hexadecimal), MD5 Digest Value (hexadecimal, 128 bit), and SHA-1 Digest Value (hexadecimal, 160 bit). For the specification of a digest value (hash value) a certificate is optionally specified depending on the circumstances. Normally when a MD5 or SHA-1 digest value is input, it is not necessary to input the other items. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcCrl> SetCrlAsync(VpnRpcCrl input_param) => await CallAsync<VpnRpcCrl>("SetCrl", input_param);

        /// <summary>
        /// Change Existing CRL (Certificate Revocation List) Entry (Async mode). Use this to alter an existing revoked certificate definition in the Certificate Revocation List that is set on the currently managed Virtual Hub. Specify the contents to be registered in the Certificate Revocation List by using the parameters of this API. When a user connects to a Virtual Hub in certificate authentication mode and that certificate matches 1 or more of the contents registered in the certificates revocation list, the user is denied connection. A certificate that matches all the conditions that are defined by the parameters specified by this API will be judged as invalid. The items that can be set are as follows: Name (CN), Organization (O), Organization Unit (OU), Country (C), State (ST), Locale (L), Serial Number (hexadecimal), MD5 Digest Value (hexadecimal, 128 bit), and SHA-1 Digest Value (hexadecimal, 160 bit). For the specification of a digest value (hash value) a certificate is optionally specified depending on the circumstances. Normally when a MD5 or SHA-1 digest value is input, it is not necessary to input the other items. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcCrl SetCrl(VpnRpcCrl input_param) => SetCrlAsync(input_param).Result;

        /// <summary>
        /// Add Rule to Source IP Address Limit List (Async mode). Use this to add a new rule to the Source IP Address Limit List that is set on the currently managed Virtual Hub. The items set here will be used to decide whether to allow or deny connection from a VPN Client when this client attempts connection to the Virtual Hub. You can specify a client IP address, or IP address or mask to match the rule as the contents of the rule item. By specifying an IP address only, there will only be one specified computer that will match the rule, but by specifying an IP net mask address or subnet mask address, all the computers in the range of that subnet will match the rule. You can specify the priority for the rule. You can specify an integer of 1 or greater for the priority and the smaller the number, the higher the priority. To get a list of the currently registered Source IP Address Limit List, use the GetAcList API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcAcList> SetAcListAsync(VpnRpcAcList input_param) => await CallAsync<VpnRpcAcList>("SetAcList", input_param);

        /// <summary>
        /// Add Rule to Source IP Address Limit List (Async mode). Use this to add a new rule to the Source IP Address Limit List that is set on the currently managed Virtual Hub. The items set here will be used to decide whether to allow or deny connection from a VPN Client when this client attempts connection to the Virtual Hub. You can specify a client IP address, or IP address or mask to match the rule as the contents of the rule item. By specifying an IP address only, there will only be one specified computer that will match the rule, but by specifying an IP net mask address or subnet mask address, all the computers in the range of that subnet will match the rule. You can specify the priority for the rule. You can specify an integer of 1 or greater for the priority and the smaller the number, the higher the priority. To get a list of the currently registered Source IP Address Limit List, use the GetAcList API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcAcList SetAcList(VpnRpcAcList input_param) => SetAcListAsync(input_param).Result;

        /// <summary>
        /// Get List of Rule Items of Source IP Address Limit List (Async mode). Use this to get a list of Source IP Address Limit List rules that is set on the currently managed Virtual Hub. You can allow or deny VPN connections to this Virtual Hub according to the client computer's source IP address. You can define multiple rules and set a priority for each rule. The search proceeds from the rule with the highest order or priority and based on the action of the rule that the IP address first matches, the connection from the client is either allowed or denied. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcAcList> GetAcListAsync(VpnRpcAcList input_param) => await CallAsync<VpnRpcAcList>("GetAcList", input_param);

        /// <summary>
        /// Get List of Rule Items of Source IP Address Limit List (Async mode). Use this to get a list of Source IP Address Limit List rules that is set on the currently managed Virtual Hub. You can allow or deny VPN connections to this Virtual Hub according to the client computer's source IP address. You can define multiple rules and set a priority for each rule. The search proceeds from the rule with the highest order or priority and based on the action of the rule that the IP address first matches, the connection from the client is either allowed or denied. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcAcList GetAcList(VpnRpcAcList input_param) => GetAcListAsync(input_param).Result;

        /// <summary>
        /// Get List of Log Files (Async mode). Use this to display a list of log files outputted by the VPN Server that have been saved on the VPN Server computer. By specifying a log file file name displayed here and calling it using the ReadLogFile API you can download the contents of the log file. If you are connected to the VPN Server in server admin mode, you can display or download the packet logs and security logs of all Virtual Hubs and the server log of the VPN Server. When connected in Virtual Hub Admin Mode, you are able to view or download only the packet log and security log of the Virtual Hub that is the target of management.
        /// </summary>
        public async Task<VpnRpcEnumLogFile> EnumLogFileAsync() => await CallAsync<VpnRpcEnumLogFile>("EnumLogFile", new VpnRpcEnumLogFile());

        /// <summary>
        /// Get List of Log Files (Async mode). Use this to display a list of log files outputted by the VPN Server that have been saved on the VPN Server computer. By specifying a log file file name displayed here and calling it using the ReadLogFile API you can download the contents of the log file. If you are connected to the VPN Server in server admin mode, you can display or download the packet logs and security logs of all Virtual Hubs and the server log of the VPN Server. When connected in Virtual Hub Admin Mode, you are able to view or download only the packet log and security log of the Virtual Hub that is the target of management.
        /// </summary>
        public VpnRpcEnumLogFile EnumLogFile() => EnumLogFileAsync().Result;

        /// <summary>
        /// Download a part of Log File (Async mode). Use this to download the log file that is saved on the VPN Server computer. To download the log file first get the list of log files using the EnumLogFile API and then download the log file using the ReadLogFile API. If you are connected to the VPN Server in server admin mode, you can display or download the packet logs and security logs of all Virtual Hubs and the server log of the VPN Server. When connected in Virtual Hub Admin Mode, you are able to view or download only the packet log and security log of the Virtual Hub that is the target of management.
        /// </summary>
        public async Task<VpnRpcReadLogFile> ReadLogFileAsync(VpnRpcReadLogFile input_param) => await CallAsync<VpnRpcReadLogFile>("ReadLogFile", input_param);

        /// <summary>
        /// Download a part of Log File (Async mode). Use this to download the log file that is saved on the VPN Server computer. To download the log file first get the list of log files using the EnumLogFile API and then download the log file using the ReadLogFile API. If you are connected to the VPN Server in server admin mode, you can display or download the packet logs and security logs of all Virtual Hubs and the server log of the VPN Server. When connected in Virtual Hub Admin Mode, you are able to view or download only the packet log and security log of the Virtual Hub that is the target of management.
        /// </summary>
        public VpnRpcReadLogFile ReadLogFile(VpnRpcReadLogFile input_param) => ReadLogFileAsync(input_param).Result;

        /// <summary>
        /// Set syslog Send Function (Async mode). Use this to set the usage of syslog send function and which syslog server to use.
        /// </summary>
        public async Task<VpnSyslogSetting> SetSysLogAsync(VpnSyslogSetting input_param) => await CallAsync<VpnSyslogSetting>("SetSysLog", input_param);

        /// <summary>
        /// Set syslog Send Function (Async mode). Use this to set the usage of syslog send function and which syslog server to use.
        /// </summary>
        public VpnSyslogSetting SetSysLog(VpnSyslogSetting input_param) => SetSysLogAsync(input_param).Result;

        /// <summary>
        /// Get syslog Send Function (Async mode). This allows you to get the current setting contents of the syslog send function. You can get the usage setting of the syslog function and the host name and port number of the syslog server to use.
        /// </summary>
        public async Task<VpnSyslogSetting> GetSysLogAsync(VpnSyslogSetting input_param) => await CallAsync<VpnSyslogSetting>("GetSysLog", input_param);

        /// <summary>
        /// Get syslog Send Function (Async mode). This allows you to get the current setting contents of the syslog send function. You can get the usage setting of the syslog function and the host name and port number of the syslog server to use.
        /// </summary>
        public VpnSyslogSetting GetSysLog(VpnSyslogSetting input_param) => GetSysLogAsync(input_param).Result;

        /// <summary>
        /// Set Today's Message of Virtual Hub (Async mode). The message will be displayed on VPN Client UI when a user will establish a connection to the Virtual Hub.
        /// </summary>
        public async Task<VpnRpcMsg> SetHubMsgAsync(VpnRpcMsg input_param) => await CallAsync<VpnRpcMsg>("SetHubMsg", input_param);

        /// <summary>
        /// Set Today's Message of Virtual Hub (Async mode). The message will be displayed on VPN Client UI when a user will establish a connection to the Virtual Hub.
        /// </summary>
        public VpnRpcMsg SetHubMsg(VpnRpcMsg input_param) => SetHubMsgAsync(input_param).Result;

        /// <summary>
        /// Get Today's Message of Virtual Hub (Async mode). The message will be displayed on VPN Client UI when a user will establish a connection to the Virtual Hub.
        /// </summary>
        public async Task<VpnRpcMsg> GetHubMsgAsync(VpnRpcMsg input_param) => await CallAsync<VpnRpcMsg>("GetHubMsg", input_param);

        /// <summary>
        /// Get Today's Message of Virtual Hub (Async mode). The message will be displayed on VPN Client UI when a user will establish a connection to the Virtual Hub.
        /// </summary>
        public VpnRpcMsg GetHubMsg(VpnRpcMsg input_param) => GetHubMsgAsync(input_param).Result;

        /// <summary>
        /// Raise a vital error on the VPN Server / Bridge to terminate the process forcefully (Async mode). This API will raise a fatal error (memory access violation) on the VPN Server / Bridge running process in order to crash the process. As the result, VPN Server / Bridge will be terminated and restarted if it is running as a service mode. If the VPN Server is running as a user mode, the process will not automatically restarted. This API is for a situation when the VPN Server / Bridge is under a non-recoverable error or the process is in an infinite loop. This API will disconnect all VPN Sessions on the VPN Server / Bridge. All unsaved settings in the memory of VPN Server / Bridge will be lost. Before run this API, call the Flush API to try to save volatile data to the configuration file. To execute this API, you must have VPN Server / VPN Bridge administrator privileges.
        /// </summary>
        public async Task<VpnRpcTest> CrashAsync(VpnRpcTest input_param) => await CallAsync<VpnRpcTest>("Crash", input_param);

        /// <summary>
        /// Raise a vital error on the VPN Server / Bridge to terminate the process forcefully (Async mode). This API will raise a fatal error (memory access violation) on the VPN Server / Bridge running process in order to crash the process. As the result, VPN Server / Bridge will be terminated and restarted if it is running as a service mode. If the VPN Server is running as a user mode, the process will not automatically restarted. This API is for a situation when the VPN Server / Bridge is under a non-recoverable error or the process is in an infinite loop. This API will disconnect all VPN Sessions on the VPN Server / Bridge. All unsaved settings in the memory of VPN Server / Bridge will be lost. Before run this API, call the Flush API to try to save volatile data to the configuration file. To execute this API, you must have VPN Server / VPN Bridge administrator privileges.
        /// </summary>
        public VpnRpcTest Crash(VpnRpcTest input_param) => CrashAsync(input_param).Result;

        /// <summary>
        /// Get the message for administrators (Async mode).
        /// </summary>
        public async Task<VpnRpcMsg> GetAdminMsgAsync() => await CallAsync<VpnRpcMsg>("GetAdminMsg", new VpnRpcMsg());

        /// <summary>
        /// Get message for administrators (Sync mode)
        /// </summary>
        public VpnRpcMsg GetAdminMsg() => GetAdminMsgAsync().Result;

        /// <summary>
        /// Save All Volatile Data of VPN Server / Bridge to the Configuration File (Async mode). The number of configuration file bytes will be returned as the "IntValue" parameter. Normally, the VPN Server / VPN Bridge retains the volatile configuration data in memory. It is flushed to the disk as vpn_server.config or vpn_bridge.config periodically. The period is 300 seconds (5 minutes) by default. (The period can be altered by modifying the AutoSaveConfigSpan item in the configuration file.) The data will be saved on the timing of shutting down normally of the VPN Server / Bridge. Execute the Flush API to make the VPN Server / Bridge save the settings to the file immediately. The setting data will be stored on the disk drive of the server computer. Use the Flush API in a situation that you do not have an enough time to shut down the server process normally. To call this API, you must have VPN Server administrator privileges. To execute this API, you must have VPN Server / VPN Bridge administrator privileges.
        /// </summary>
        public async Task<VpnRpcTest> FlushAsync(VpnRpcTest input_param) => await CallAsync<VpnRpcTest>("Flush", input_param);

        /// <summary>
        /// Save All Volatile Data of VPN Server / Bridge to the Configuration File (Sync mode). The number of configuration file bytes will be returned as the "IntValue" parameter. Normally, the VPN Server / VPN Bridge retains the volatile configuration data in memory. It is flushed to the disk as vpn_server.config or vpn_bridge.config periodically. The period is 300 seconds (5 minutes) by default. (The period can be altered by modifying the AutoSaveConfigSpan item in the configuration file.) The data will be saved on the timing of shutting down normally of the VPN Server / Bridge. Execute the Flush API to make the VPN Server / Bridge save the settings to the file immediately. The setting data will be stored on the disk drive of the server computer. Use the Flush API in a situation that you do not have an enough time to shut down the server process normally. To call this API, you must have VPN Server administrator privileges. To execute this API, you must have VPN Server / VPN Bridge administrator privileges.
        /// </summary>
        public VpnRpcTest Flush(VpnRpcTest input_param) => FlushAsync(input_param).Result;

        /// <summary>
        /// Enable or Disable IPsec VPN Server Function (Async mode). Enable or Disable IPsec VPN Server Function on the VPN Server. If you enable this function, Virtual Hubs on the VPN Server will be able to accept Remote-Access VPN connections from L2TP-compatible PCs, Mac OS X and Smartphones, and also can accept EtherIP Site-to-Site VPN Connection. VPN Connections from Smartphones suchlike iPhone, iPad and Android, and also from native VPN Clients on Mac OS X and Windows can be accepted. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnIPsecServices> SetIPsecServicesAsync(VpnIPsecServices input_param) => await CallAsync<VpnIPsecServices>("SetIPsecServices", input_param);

        /// <summary>
        /// Enable or Disable IPsec VPN Server Function (Async mode). Enable or Disable IPsec VPN Server Function on the VPN Server. If you enable this function, Virtual Hubs on the VPN Server will be able to accept Remote-Access VPN connections from L2TP-compatible PCs, Mac OS X and Smartphones, and also can accept EtherIP Site-to-Site VPN Connection. VPN Connections from Smartphones suchlike iPhone, iPad and Android, and also from native VPN Clients on Mac OS X and Windows can be accepted. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnIPsecServices SetIPsecServices(VpnIPsecServices input_param) => SetIPsecServicesAsync(input_param).Result;

        /// <summary>
        /// Get the Current IPsec VPN Server Settings (Async mode). Get and view the current IPsec VPN Server settings on the VPN Server. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnIPsecServices> GetIPsecServicesAsync() => await CallAsync<VpnIPsecServices>("GetIPsecServices", new VpnIPsecServices());

        /// <summary>
        /// Get the Current IPsec VPN Server Settings (Async mode). Get and view the current IPsec VPN Server settings on the VPN Server. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnIPsecServices GetIPsecServices() => GetIPsecServicesAsync().Result;

        /// <summary>
        /// Add New EtherIP / L2TPv3 over IPsec Client Setting to Accept EthreIP / L2TPv3 Client Devices (Async mode). Add a new setting entry to enable the EtherIP / L2TPv3 over IPsec Server Function to accept client devices. In order to accept connections from routers by the EtherIP / L2TPv3 over IPsec Server Function, you have to define the relation table between an IPsec Phase 1 string which is presented by client devices of EtherIP / L2TPv3 over IPsec compatible router, and the designation of the destination Virtual Hub. After you add a definition entry by AddEtherIpId API, the defined connection setting to the Virtual Hub will be applied on the login-attepting session from an EtherIP / L2TPv3 over IPsec client device. The username and password in an entry must be registered on the Virtual Hub. An EtherIP / L2TPv3 client will be regarded as it connected the Virtual HUB with the identification of the above user information. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnEtherIpId> AddEtherIpIdAsync(VpnEtherIpId input_param) => await CallAsync<VpnEtherIpId>("AddEtherIpId", input_param);

        /// <summary>
        /// Add New EtherIP / L2TPv3 over IPsec Client Setting to Accept EthreIP / L2TPv3 Client Devices (Async mode). Add a new setting entry to enable the EtherIP / L2TPv3 over IPsec Server Function to accept client devices. In order to accept connections from routers by the EtherIP / L2TPv3 over IPsec Server Function, you have to define the relation table between an IPsec Phase 1 string which is presented by client devices of EtherIP / L2TPv3 over IPsec compatible router, and the designation of the destination Virtual Hub. After you add a definition entry by AddEtherIpId API, the defined connection setting to the Virtual Hub will be applied on the login-attepting session from an EtherIP / L2TPv3 over IPsec client device. The username and password in an entry must be registered on the Virtual Hub. An EtherIP / L2TPv3 client will be regarded as it connected the Virtual HUB with the identification of the above user information. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnEtherIpId AddEtherIpId(VpnEtherIpId input_param) => AddEtherIpIdAsync(input_param).Result;

        /// <summary>
        /// Get the Current List of EtherIP / L2TPv3 Client Device Entry Definitions (Async mode). This API gets and shows the list of entries to accept VPN clients by EtherIP / L2TPv3 over IPsec Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnEtherIpId> GetEtherIpIdAsync(VpnEtherIpId input_param) => await CallAsync<VpnEtherIpId>("GetEtherIpId", input_param);

        /// <summary>
        /// Get the Current List of EtherIP / L2TPv3 Client Device Entry Definitions (Async mode). This API gets and shows the list of entries to accept VPN clients by EtherIP / L2TPv3 over IPsec Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnEtherIpId GetEtherIpId(VpnEtherIpId input_param) => GetEtherIpIdAsync(input_param).Result;

        /// <summary>
        /// Delete an EtherIP / L2TPv3 over IPsec Client Setting (Async mode). This API deletes an entry to accept VPN clients by EtherIP / L2TPv3 over IPsec Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnEtherIpId> DeleteEtherIpIdAsync(VpnEtherIpId input_param) => await CallAsync<VpnEtherIpId>("DeleteEtherIpId", input_param);

        /// <summary>
        /// Delete an EtherIP / L2TPv3 over IPsec Client Setting (Async mode). This API deletes an entry to accept VPN clients by EtherIP / L2TPv3 over IPsec Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnEtherIpId DeleteEtherIpId(VpnEtherIpId input_param) => DeleteEtherIpIdAsync(input_param).Result;

        /// <summary>
        /// Get the Current List of EtherIP / L2TPv3 Client Device Entry Definitions (Async mode). This API gets and shows the list of entries to accept VPN clients by EtherIP / L2TPv3 over IPsec Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcEnumEtherIpId> EnumEtherIpIdAsync() => await CallAsync<VpnRpcEnumEtherIpId>("EnumEtherIpId", new VpnRpcEnumEtherIpId());

        /// <summary>
        /// Get the Current List of EtherIP / L2TPv3 Client Device Entry Definitions (Async mode). This API gets and shows the list of entries to accept VPN clients by EtherIP / L2TPv3 over IPsec Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcEnumEtherIpId EnumEtherIpId() => EnumEtherIpIdAsync().Result;

        /// <summary>
        /// Set Settings for OpenVPN Clone Server Function (Async mode). The VPN Server has the clone functions of OpenVPN software products by OpenVPN Technologies, Inc. Any OpenVPN Clients can connect to this VPN Server. The manner to specify a username to connect to the Virtual Hub, and the selection rule of default Hub by using this clone server functions are same to the IPsec Server functions. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnOpenVpnSstpConfig> SetOpenVpnSstpConfigAsync(VpnOpenVpnSstpConfig input_param) => await CallAsync<VpnOpenVpnSstpConfig>("SetOpenVpnSstpConfig", input_param);

        /// <summary>
        /// Set Settings for OpenVPN Clone Server Function (Async mode). The VPN Server has the clone functions of OpenVPN software products by OpenVPN Technologies, Inc. Any OpenVPN Clients can connect to this VPN Server. The manner to specify a username to connect to the Virtual Hub, and the selection rule of default Hub by using this clone server functions are same to the IPsec Server functions. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnOpenVpnSstpConfig SetOpenVpnSstpConfig(VpnOpenVpnSstpConfig input_param) => SetOpenVpnSstpConfigAsync(input_param).Result;

        /// <summary>
        /// Get the Current Settings of OpenVPN Clone Server Function (Async mode). Get and show the current settings of OpenVPN Clone Server Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnOpenVpnSstpConfig> GetOpenVpnSstpConfigAsync() => await CallAsync<VpnOpenVpnSstpConfig>("GetOpenVpnSstpConfig", new VpnOpenVpnSstpConfig());

        /// <summary>
        /// Get the Current Settings of OpenVPN Clone Server Function (Async mode). Get and show the current settings of OpenVPN Clone Server Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnOpenVpnSstpConfig GetOpenVpnSstpConfig() => GetOpenVpnSstpConfigAsync().Result;

        /// <summary>
        /// Show the Current Status of Dynamic DNS Function (Async mode). Get and show the current status of the Dynamic DNS function. The Dynamic DNS assigns a unique and permanent DNS hostname for this VPN Server. You can use that hostname to specify this VPN Server on the settings for VPN Client and VPN Bridge. You need not to register and keep a domain name. Also, if your ISP assignes you a dynamic (not-fixed) IP address, the corresponding IP address of your Dynamic DNS hostname will be automatically changed. It enables you to keep running the VPN Server by using only a dynamic IP address. Therefore, you need not any longer to keep static global IP addresses with expenses monthly costs. [Caution] To disable the Dynamic DNS Function, modify the configuration file of VPN Server. The "declare root" directive has the "declare DDnsClient" directive. In this directive, you can switch "bool Disable" from false to true, and reboot the VPN Server, then the Dynamic DNS Function will be disabled. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge.
        /// </summary>
        public async Task<VpnDDnsClientStatus> GetDDnsClientStatusAsync() => await CallAsync<VpnDDnsClientStatus>("GetDDnsClientStatus", new VpnDDnsClientStatus());

        /// <summary>
        /// Show the Current Status of Dynamic DNS Function (Async mode). Get and show the current status of the Dynamic DNS function. The Dynamic DNS assigns a unique and permanent DNS hostname for this VPN Server. You can use that hostname to specify this VPN Server on the settings for VPN Client and VPN Bridge. You need not to register and keep a domain name. Also, if your ISP assignes you a dynamic (not-fixed) IP address, the corresponding IP address of your Dynamic DNS hostname will be automatically changed. It enables you to keep running the VPN Server by using only a dynamic IP address. Therefore, you need not any longer to keep static global IP addresses with expenses monthly costs. [Caution] To disable the Dynamic DNS Function, modify the configuration file of VPN Server. The "declare root" directive has the "declare DDnsClient" directive. In this directive, you can switch "bool Disable" from false to true, and reboot the VPN Server, then the Dynamic DNS Function will be disabled. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge.
        /// </summary>
        public VpnDDnsClientStatus GetDDnsClientStatus() => GetDDnsClientStatusAsync().Result;

        /// <summary>
        /// Set the Dynamic DNS Hostname (Async mode). You must specify the new hostname on the StrValue_str field. You can use this API to change the hostname assigned by the Dynamic DNS function. The currently assigned hostname can be showen by the GetDDnsClientStatus API. The Dynamic DNS assigns a unique and permanent DNS hostname for this VPN Server. You can use that hostname to specify this VPN Server on the settings for VPN Client and VPN Bridge. You need not to register and keep a domain name. Also, if your ISP assignes you a dynamic (not-fixed) IP address, the corresponding IP address of your Dynamic DNS hostname will be automatically changed. It enables you to keep running the VPN Server by using only a dynamic IP address. Therefore, you need not any longer to keep static global IP addresses with expenses monthly costs. [Caution] To disable the Dynamic DNS Function, modify the configuration file of VPN Server. The "declare root" directive has the "declare DDnsClient" directive. In this directive, you can switch "bool Disable" from false to true, and reboot the VPN Server, then the Dynamic DNS Function will be disabled. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge.
        /// </summary>
        public async Task<VpnRpcTest> ChangeDDnsClientHostnameAsync(VpnRpcTest input_param) => await CallAsync<VpnRpcTest>("ChangeDDnsClientHostname", input_param);

        /// <summary>
        /// Set the Dynamic DNS Hostname (Async mode). You must specify the new hostname on the StrValue_str field. You can use this API to change the hostname assigned by the Dynamic DNS function. The currently assigned hostname can be showen by the GetDDnsClientStatus API. The Dynamic DNS assigns a unique and permanent DNS hostname for this VPN Server. You can use that hostname to specify this VPN Server on the settings for VPN Client and VPN Bridge. You need not to register and keep a domain name. Also, if your ISP assignes you a dynamic (not-fixed) IP address, the corresponding IP address of your Dynamic DNS hostname will be automatically changed. It enables you to keep running the VPN Server by using only a dynamic IP address. Therefore, you need not any longer to keep static global IP addresses with expenses monthly costs. [Caution] To disable the Dynamic DNS Function, modify the configuration file of VPN Server. The "declare root" directive has the "declare DDnsClient" directive. In this directive, you can switch "bool Disable" from false to true, and reboot the VPN Server, then the Dynamic DNS Function will be disabled. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge.
        /// </summary>
        public VpnRpcTest ChangeDDnsClientHostname(VpnRpcTest input_param) => ChangeDDnsClientHostnameAsync(input_param).Result;

        /// <summary>
        /// Generate New Self-Signed Certificate with Specified CN (Common Name) and Register on VPN Server (Async mode). You can specify the new CN (common name) value on the StrValue_str field. You can use this API to replace the current certificate on the VPN Server to a new self-signed certificate which has the CN (Common Name) value in the fields. This API is convenient if you are planning to use Microsoft SSTP VPN Clone Server Function. Because of the value of CN (Common Name) on the SSL certificate of VPN Server must match to the hostname specified on the SSTP VPN client. This API will delete the existing SSL certificate of the VPN Server. It is recommended to backup the current SSL certificate and private key by using the GetServerCert API beforehand. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcTest> RegenerateServerCertAsync(VpnRpcTest input_param) => await CallAsync<VpnRpcTest>("RegenerateServerCert", input_param);

        /// <summary>
        /// Generate New Self-Signed Certificate with Specified CN (Common Name) and Register on VPN Server (Async mode). You can specify the new CN (common name) value on the StrValue_str field. You can use this API to replace the current certificate on the VPN Server to a new self-signed certificate which has the CN (Common Name) value in the fields. This API is convenient if you are planning to use Microsoft SSTP VPN Clone Server Function. Because of the value of CN (Common Name) on the SSL certificate of VPN Server must match to the hostname specified on the SSTP VPN client. This API will delete the existing SSL certificate of the VPN Server. It is recommended to backup the current SSL certificate and private key by using the GetServerCert API beforehand. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcTest RegenerateServerCert(VpnRpcTest input_param) => RegenerateServerCertAsync(input_param).Result;

        /// <summary>
        /// Generate a Sample Setting File for OpenVPN Client (Async mode). Originally, the OpenVPN Client requires a user to write a very difficult configuration file manually. This API helps you to make a useful configuration sample. What you need to generate the configuration file for the OpenVPN Client is to run this API. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcReadLogFile> MakeOpenVpnConfigFileAsync() => await CallAsync<VpnRpcReadLogFile>("MakeOpenVpnConfigFile", new VpnRpcReadLogFile());

        /// <summary>
        /// Generate a Sample Setting File for OpenVPN Client (Async mode). Originally, the OpenVPN Client requires a user to write a very difficult configuration file manually. This API helps you to make a useful configuration sample. What you need to generate the configuration file for the OpenVPN Client is to run this API. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcReadLogFile MakeOpenVpnConfigFile() => MakeOpenVpnConfigFileAsync().Result;

        /// <summary>
        /// Enable / Disable the VPN over ICMP / VPN over DNS Server Function (Async mode). You can establish a VPN only with ICMP or DNS packets even if there is a firewall or routers which blocks TCP/IP communications. You have to enable the following functions beforehand. Warning: Use this function for emergency only. It is helpful when a firewall or router is misconfigured to blocks TCP/IP, but either ICMP or DNS is not blocked. It is not for long-term stable using. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge.
        /// </summary>
        public async Task<VpnRpcSpecialListener> SetSpecialListenerAsync(VpnRpcSpecialListener input_param) => await CallAsync<VpnRpcSpecialListener>("SetSpecialListener", input_param);

        /// <summary>
        /// Enable / Disable the VPN over ICMP / VPN over DNS Server Function (Async mode). You can establish a VPN only with ICMP or DNS packets even if there is a firewall or routers which blocks TCP/IP communications. You have to enable the following functions beforehand. Warning: Use this function for emergency only. It is helpful when a firewall or router is misconfigured to blocks TCP/IP, but either ICMP or DNS is not blocked. It is not for long-term stable using. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge.
        /// </summary>
        public VpnRpcSpecialListener SetSpecialListener(VpnRpcSpecialListener input_param) => SetSpecialListenerAsync(input_param).Result;

        /// <summary>
        /// Get Current Setting of the VPN over ICMP / VPN over DNS Function (Async mode). Get and show the current VPN over ICMP / VPN over DNS Function status. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge.
        /// </summary>
        public async Task<VpnRpcSpecialListener> GetSpecialListenerAsync() => await CallAsync<VpnRpcSpecialListener>("GetSpecialListener", new VpnRpcSpecialListener());

        /// <summary>
        /// Get Current Setting of the VPN over ICMP / VPN over DNS Function (Async mode). Get and show the current VPN over ICMP / VPN over DNS Function status. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge.
        /// </summary>
        public VpnRpcSpecialListener GetSpecialListener() => GetSpecialListenerAsync().Result;

        /// <summary>
        /// Show the current status of VPN Azure function (Async mode). Get and show the current status of the VPN Azure function. VPN Azure makes it easier to establish a VPN Session from your home PC to your office PC. While a VPN connection is established, you can access to any other servers on the private network of your company. You don't need a global IP address on the office PC (VPN Server). It can work behind firewalls or NATs. No network administrator's configuration required. You can use the built-in SSTP-VPN Client of Windows in your home PC. VPN Azure is a cloud VPN service operated by SoftEther Corporation. VPN Azure is free of charge and available to anyone. Visit http://www.vpnazure.net/ to see details and how-to-use instructions. The VPN Azure hostname is same to the hostname of the Dynamic DNS setting, but altering the domain suffix to "vpnazure.net". To change the hostname use the ChangeDDnsClientHostname API. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcAzureStatus> GetAzureStatusAsync() => await CallAsync<VpnRpcAzureStatus>("GetAzureStatus", new VpnRpcAzureStatus());

        /// <summary>
        /// Show the current status of VPN Azure function (Async mode). Get and show the current status of the VPN Azure function. VPN Azure makes it easier to establish a VPN Session from your home PC to your office PC. While a VPN connection is established, you can access to any other servers on the private network of your company. You don't need a global IP address on the office PC (VPN Server). It can work behind firewalls or NATs. No network administrator's configuration required. You can use the built-in SSTP-VPN Client of Windows in your home PC. VPN Azure is a cloud VPN service operated by SoftEther Corporation. VPN Azure is free of charge and available to anyone. Visit http://www.vpnazure.net/ to see details and how-to-use instructions. The VPN Azure hostname is same to the hostname of the Dynamic DNS setting, but altering the domain suffix to "vpnazure.net". To change the hostname use the ChangeDDnsClientHostname API. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcAzureStatus GetAzureStatus() => GetAzureStatusAsync().Result;

        /// <summary>
        /// Enable / Disable VPN Azure Function (Async mode). Enable or disable the VPN Azure function. VPN Azure makes it easier to establish a VPN Session from your home PC to your office PC. While a VPN connection is established, you can access to any other servers on the private network of your company. You don't need a global IP address on the office PC (VPN Server). It can work behind firewalls or NATs. No network administrator's configuration required. You can use the built-in SSTP-VPN Client of Windows in your home PC. VPN Azure is a cloud VPN service operated by SoftEther Corporation. VPN Azure is free of charge and available to anyone. Visit http://www.vpnazure.net/ to see details and how-to-use instructions. The VPN Azure hostname is same to the hostname of the Dynamic DNS setting, but altering the domain suffix to "vpnazure.net". To change the hostname use the ChangeDDnsClientHostname API. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public async Task<VpnRpcAzureStatus> SetAzureStatusAsync(VpnRpcAzureStatus input_param) => await CallAsync<VpnRpcAzureStatus>("SetAzureStatus", input_param);

        /// <summary>
        /// Enable / Disable VPN Azure Function (Async mode). Enable or disable the VPN Azure function. VPN Azure makes it easier to establish a VPN Session from your home PC to your office PC. While a VPN connection is established, you can access to any other servers on the private network of your company. You don't need a global IP address on the office PC (VPN Server). It can work behind firewalls or NATs. No network administrator's configuration required. You can use the built-in SSTP-VPN Client of Windows in your home PC. VPN Azure is a cloud VPN service operated by SoftEther Corporation. VPN Azure is free of charge and available to anyone. Visit http://www.vpnazure.net/ to see details and how-to-use instructions. The VPN Azure hostname is same to the hostname of the Dynamic DNS setting, but altering the domain suffix to "vpnazure.net". To change the hostname use the ChangeDDnsClientHostname API. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.
        /// </summary>
        public VpnRpcAzureStatus SetAzureStatus(VpnRpcAzureStatus input_param) => SetAzureStatusAsync(input_param).Result;

        /// <summary>
        /// Get the Proxy Settings for Connecting to the DDNS server (Async mode).
        /// </summary>
        public async Task<VpnInternetSetting> GetDDnsInternetSettingAsync() => await CallAsync<VpnInternetSetting>("GetDDnsInternetSetting", new VpnInternetSetting());

        /// <summary>
        /// Get the Proxy Settings for Connecting to the DDNS server (Async mode).
        /// </summary>
        public VpnInternetSetting GetDDnsInternetSetting() => GetDDnsInternetSettingAsync().Result;

        /// <summary>
        /// Set the Proxy Settings for Connecting to the DDNS server (Async mode).
        /// </summary>
        public async Task<VpnInternetSetting> SetDDnsInternetSettingAsync(VpnInternetSetting input_param) => await CallAsync<VpnInternetSetting>("SetDDnsInternetSetting", input_param);

        /// <summary>
        /// Set the Proxy Settings for Connecting to the DDNS server (Sync mode).
        /// </summary>
        public VpnInternetSetting SetDDnsInternetSetting(VpnInternetSetting input_param) => SetDDnsInternetSettingAsync(input_param).Result;

        /// <summary>
        /// Set the VPN Gate Server Configuration (Async mode). This API is valid for Win32 binary distribution of the Stable Edition of SoftEther VPN Server.
        /// </summary>
        public async Task<VpnVgsConfig> SetVgsConfigAsync(VpnVgsConfig input_param) => await CallAsync<VpnVgsConfig>("SetVgsConfig", input_param);

        /// <summary>
        /// Set the VPN Gate Server Configuration (Sync mode). This API is valid for Win32 binary distribution of the Stable Edition of SoftEther VPN Server.
        /// </summary>
        public VpnVgsConfig SetVgsConfig(VpnVgsConfig input_param) => SetVgsConfigAsync(input_param).Result;

        /// <summary>
        /// Get the VPN Gate Server Configuration (Async mode). This API is valid for Win32 binary distribution of the Stable Edition of SoftEther VPN Server.
        /// </summary>
        public async Task<VpnVgsConfig> GetVgsConfigAsync() => await CallAsync<VpnVgsConfig>("GetVgsConfig", new VpnVgsConfig());

        /// <summary>
        /// Get the VPN Gate Server Configuration (Sync mode). This API is valid for Win32 binary distribution of the Stable Edition of SoftEther VPN Server.
        /// </summary>
        public VpnVgsConfig GetVgsConfig() => GetVgsConfigAsync().Result;


    }
}

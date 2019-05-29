/** VPN Server RPC Stubs */
export declare class VpnServerRpc {
    /** Determine if this JavaScript environment is on the Node.js or not. */
    static IsNodeJS(): boolean;
    /** Set the debug mode flag */
    static SetDebugMode(flag: boolean): void;
    private rpc_url;
    private rpc_client;
    /**
     * Constructor of the VpnServerRpc class
     * @param vpnserver_hostname The hostname or IP address of the destination VPN Server. In the web browser you can specify null if you want to connect to the server itself.
     * @param vpnserver_port The port number of the destination VPN Server. In the web browser you can specify null if you want to connect to the server itself.
     * @param hubname The name of the Virtual Hub if you want to connect to the VPN Server as a Virtual Hub Admin Mode. Specify null if you want to connect to the VPN Server as the Entire VPN Server Admin Mode.
     * @param password Specify the administration password. This value is valid only if vpnserver_hostname is sepcified.
     * @param nodejs_https_client_reject_untrusted_server_cert In Node.js set this true to check the SSL server certificate on the destination VPN Server. Set this false to ignore the SSL server certification.
     */
    constructor(vpnserver_hostname?: string, vpnserver_port?: number, hubname?: string, password?: string, nodejs_https_client_reject_untrusted_server_cert?: boolean);
    /** Test RPC function. Input any integer value to the IntValue_u32 field. Then the server will convert the integer to the string, and return the string in the StrValue_str field. */
    Test: (in_param: VpnRpcTest) => Promise<VpnRpcTest>;
    /** Get server information. This allows you to obtain the server information of the currently connected VPN Server or VPN Bridge. Included in the server information are the version number, build number and build information. You can also obtain information on the current server operation mode and the information of operating system that the server is operating on. */
    GetServerInfo: () => Promise<VpnRpcServerInfo>;
    /** Get Current Server Status. This allows you to obtain in real-time the current status of the currently connected VPN Server or VPN Bridge. You can get statistical information on data communication and the number of different kinds of objects that exist on the server. You can get information on how much memory is being used on the current computer by the OS. */
    GetServerStatus: () => Promise<VpnRpcServerStatus>;
    /** Create New TCP Listener. This allows you to create a new TCP Listener on the server. By creating the TCP Listener the server starts listening for a connection from clients at the specified TCP/IP port number. A TCP Listener that has been created can be deleted by the DeleteListener API. You can also get a list of TCP Listeners currently registered by using the EnumListener API. To execute this API, you must have VPN Server administrator privileges. */
    CreateListener: (in_param: VpnRpcListener) => Promise<VpnRpcListener>;
    /** Get List of TCP Listeners. This allows you to get a list of TCP listeners registered on the current server. You can obtain information on whether the various TCP listeners have a status of operating or error. To call this API, you must have VPN Server administrator privileges. */
    EnumListener: () => Promise<VpnRpcListenerList>;
    /** Delete TCP Listener. This allows you to delete a TCP Listener that's registered on the server. When the TCP Listener is in a state of operation, the listener will automatically be deleted when its operation stops. You can also get a list of TCP Listeners currently registered by using the EnumListener API. To call this API, you must have VPN Server administrator privileges. */
    DeleteListener: (in_param: VpnRpcListener) => Promise<VpnRpcListener>;
    /** Enable / Disable TCP Listener. This starts or stops the operation of TCP Listeners registered on the current server. You can also get a list of TCP Listeners currently registered by using the EnumListener API. To call this API, you must have VPN Server administrator privileges. */
    EnableListener: (in_param: VpnRpcListener) => Promise<VpnRpcListener>;
    /** Set VPN Server Administrator Password. This sets the VPN Server administrator password. You can specify the password as a parameter. To call this API, you must have VPN Server administrator privileges. */
    SetServerPassword: (in_param: VpnRpcSetPassword) => Promise<VpnRpcSetPassword>;
    /** Set the VPN Server clustering configuration. Use this to set the VPN Server type as Standalone Server, Cluster Controller Server or Cluster Member Server. Standalone server means a VPN Server that does not belong to any cluster in its current state. When VPN Server is installed, by default it will be in standalone server mode. Unless you have particular plans to configure a cluster, we recommend the VPN Server be operated in standalone mode. A cluster controller is the central computer of all member servers of a cluster in the case where a clustering environment is made up of multiple VPN Servers. Multiple cluster members can be added to the cluster as required. A cluster requires one computer to serve this role. The other cluster member servers that are configured in the same cluster begin operation as a cluster member by connecting to the cluster controller. To call this API, you must have VPN Server administrator privileges. Also, when this API is executed, VPN Server will automatically restart. This API cannot be called on VPN Bridge. */
    SetFarmSetting: (in_param: VpnRpcFarm) => Promise<VpnRpcFarm>;
    /** Get Clustering Configuration of Current VPN Server. You can use this to acquire the clustering configuration of the current VPN Server. To call this API, you must have VPN Server administrator privileges. */
    GetFarmSetting: () => Promise<VpnRpcFarm>;
    /** Get Cluster Member Information. When the VPN Server is operating as a cluster controller, you can get information on cluster member servers on that cluster by specifying the IDs of the member servers. You can get the following information about the specified cluster member server: Server Type, Time Connection has been Established, IP Address, Host Name, Points, Public Port List, Number of Operating Virtual Hubs, First Virtual Hub, Number of Sessions and Number of TCP Connections. This API cannot be invoked on VPN Bridge. */
    GetFarmInfo: (in_param: VpnRpcFarmInfo) => Promise<VpnRpcFarmInfo>;
    /** Get List of Cluster Members. Use this API when the VPN Server is operating as a cluster controller to get a list of the cluster member servers on the same cluster, including the cluster controller itself. For each member, the following information is also listed: Type, Connection Start, Host Name, Points, Number of Session, Number of TCP Connections, Number of Operating Virtual Hubs, Using Client Connection License and Using Bridge Connection License. This API cannot be invoked on VPN Bridge. */
    EnumFarmMember: () => Promise<VpnRpcEnumFarm>;
    /** Get Connection Status to Cluster Controller. Use this API when the VPN Server is operating as a cluster controller to get the status of connection to the cluster controller. You can get the following information: Controller IP Address, Port Number, Connection Status, Connection Start Time, First Connection Established Time, Current Connection Established Time, Number of Connection Attempts, Number of Successful Connections, Number of Failed Connections. This API cannot be invoked on VPN Bridge. */
    GetFarmConnectionStatus: () => Promise<VpnRpcFarmConnectionStatus>;
    /** Set SSL Certificate and Private Key of VPN Server. You can set the SSL certificate that the VPN Server provides to the connected client and the private key for that certificate. The certificate must be in X.509 format and the private key must be Base 64 encoded format. To call this API, you must have VPN Server administrator privileges. */
    SetServerCert: (in_param: VpnRpcKeyPair) => Promise<VpnRpcKeyPair>;
    /** Get SSL Certificate and Private Key of VPN Server. Use this to get the SSL certificate private key that the VPN Server provides to the connected client. To call this API, you must have VPN Server administrator privileges. */
    GetServerCert: () => Promise<VpnRpcKeyPair>;
    /** Get the Encrypted Algorithm Used for VPN Communication. Use this API to get the current setting of the algorithm used for the electronic signature and encrypted for SSL connection to be used for communication between the VPN Server and the connected client and the list of algorithms that can be used on the VPN Server. */
    GetServerCipher: () => Promise<VpnRpcStr>;
    /** Set the Encrypted Algorithm Used for VPN Communication. Use this API to set the algorithm used for the electronic signature and encrypted for SSL connections to be used for communication between the VPN Server and the connected client. By specifying the algorithm name, the specified algorithm will be used later between the VPN Client and VPN Bridge connected to this server and the data will be encrypted. To call this API, you must have VPN Server administrator privileges. */
    SetServerCipher: (in_param: VpnRpcStr) => Promise<VpnRpcStr>;
    /** Create New Virtual Hub. Use this to create a new Virtual Hub on the VPN Server. The created Virtual Hub will begin operation immediately. When the VPN Server is operating on a cluster, this API is only valid for the cluster controller. Also, the new Virtual Hub will operate as a dynamic Virtual Hub. You can change it to a static Virtual Hub by using the SetHub API. To get a list of Virtual Hubs that are already on the VPN Server, use the EnumHub API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Servers that are operating as a VPN Bridge or cluster member. */
    CreateHub: (in_param: VpnRpcCreateHub) => Promise<VpnRpcCreateHub>;
    /** Set the Virtual Hub configuration. You can call this API to change the configuration of the specified Virtual Hub. You can set the Virtual Hub online or offline. You can set the maximum number of sessions that can be concurrently connected to the Virtual Hub that is currently being managed. You can set the Virtual Hub administrator password. You can set other parameters for the Virtual Hub. Before call this API, you need to obtain the latest state of the Virtual Hub by using the GetHub API. */
    SetHub: (in_param: VpnRpcCreateHub) => Promise<VpnRpcCreateHub>;
    /** Get the Virtual Hub configuration. You can call this API to get the current configuration of the specified Virtual Hub. To change the configuration of the Virtual Hub, call the SetHub API. */
    GetHub: (in_param: VpnRpcCreateHub) => Promise<VpnRpcCreateHub>;
    /** Get List of Virtual Hubs. Use this to get a list of existing Virtual Hubs on the VPN Server. For each Virtual Hub, you can get the following information: Virtual Hub Name, Status, Type, Number of Users, Number of Groups, Number of Sessions, Number of MAC Tables, Number of IP Tables, Number of Logins, Last Login, and Last Communication. Note that when connecting in Virtual Hub Admin Mode, if in the options of a Virtual Hub that you do not have administrator privileges for, the option Don't Enumerate this Virtual Hub for Anonymous Users is enabled then that Virtual Hub will not be enumerated. If you are connected in Server Admin Mode, then the list of all Virtual Hubs will be displayed. When connecting to and managing a non-cluster-controller cluster member of a clustering environment, only the Virtual Hub currently being hosted by that VPN Server will be displayed. When connecting to a cluster controller for administration purposes, all the Virtual Hubs will be displayed. */
    EnumHub: () => Promise<VpnRpcEnumHub>;
    /** Delete Virtual Hub. Use this to delete an existing Virtual Hub on the VPN Server. If you delete the Virtual Hub, all sessions that are currently connected to the Virtual Hub will be disconnected and new sessions will be unable to connect to the Virtual Hub. Also, this will also delete all the Hub settings, user objects, group objects, certificates and Cascade Connections. Once you delete the Virtual Hub, it cannot be recovered. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Servers that are operating as a VPN Bridge or cluster member. */
    DeleteHub: (in_param: VpnRpcDeleteHub) => Promise<VpnRpcDeleteHub>;
    /** Get Setting of RADIUS Server Used for User Authentication. Use this to get the current settings for the RADIUS server used when a user connects to the currently managed Virtual Hub using RADIUS Server Authentication Mode. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    GetHubRadius: (in_param: VpnRpcRadius) => Promise<VpnRpcRadius>;
    /** Set RADIUS Server to use for User Authentication. To accept users to the currently managed Virtual Hub in RADIUS server authentication mode, you can specify an external RADIUS server that confirms the user name and password. (You can specify multiple hostname by splitting with comma or semicolon.) The RADIUS server must be set to receive requests from IP addresses of this VPN Server. Also, authentication by Password Authentication Protocol (PAP) must be enabled. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    SetHubRadius: (in_param: VpnRpcRadius) => Promise<VpnRpcRadius>;
    /** Get List of TCP Connections Connecting to the VPN Server. Use this to get a list of TCP/IP connections that are currently connecting to the VPN Server. It does not display the TCP connections that have been established as VPN sessions. To get the list of TCP/IP connections that have been established as VPN sessions, you can use the EnumSession API. You can get the following: Connection Name, Connection Source, Connection Start and Type. To call this API, you must have VPN Server administrator privileges. */
    EnumConnection: () => Promise<VpnRpcEnumConnection>;
    /** Disconnect TCP Connections Connecting to the VPN Server. Use this to forcefully disconnect specific TCP/IP connections that are connecting to the VPN Server. To call this API, you must have VPN Server administrator privileges. */
    DisconnectConnection: (in_param: VpnRpcDisconnectConnection) => Promise<VpnRpcDisconnectConnection>;
    /** Get Information of TCP Connections Connecting to the VPN Server. Use this to get detailed information of a specific TCP/IP connection that is connecting to the VPN Server. You can get the following information: Connection Name, Connection Type, Source Hostname, Source IP Address, Source Port Number (TCP), Connection Start, Server Product Name, Server Version, Server Build Number, Client Product Name, Client Version, and Client Build Number. To call this API, you must have VPN Server administrator privileges. */
    GetConnectionInfo: (in_param: VpnRpcConnectionInfo) => Promise<VpnRpcConnectionInfo>;
    /** Switch Virtual Hub to Online or Offline. Use this to set the Virtual Hub to online or offline. A Virtual Hub with an offline status cannot receive VPN connections from clients. When you set the Virtual Hub offline, all sessions will be disconnected. A Virtual Hub with an offline status cannot receive VPN connections from clients. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    SetHubOnline: (in_param: VpnRpcSetHubOnline) => Promise<VpnRpcSetHubOnline>;
    /** Get Current Status of Virtual Hub. Use this to get the current status of the Virtual Hub currently being managed. You can get the following information: Virtual Hub Type, Number of Sessions, Number of Each Type of Object, Number of Logins, Last Login, Last Communication, and Communication Statistical Data. */
    GetHubStatus: (in_param: VpnRpcHubStatus) => Promise<VpnRpcHubStatus>;
    /** Set the logging configuration of the Virtual Hub. Use this to enable or disable a security log or packet logs of the Virtual Hub currently being managed, set the save contents of the packet log for each type of packet to be saved, and set the log file switch cycle for the security log or packet log that the currently managed Virtual Hub saves. There are the following packet types: TCP Connection Log, TCP Packet Log, DHCP Packet Log, UDP Packet Log, ICMP Packet Log, IP Packet Log, ARP Packet Log, and Ethernet Packet Log. To get the current setting, you can use the LogGet API. The log file switch cycle can be changed to switch in every second, every minute, every hour, every day, every month or not switch. To get the current setting, you can use the GetHubLog API. */
    SetHubLog: (in_param: VpnRpcHubLog) => Promise<VpnRpcHubLog>;
    /** Get the logging configuration of the Virtual Hub. Use this to get the configuration for a security log or packet logs of the Virtual Hub currently being managed, get the setting for save contents of the packet log for each type of packet to be saved, and get the log file switch cycle for the security log or packet log that the currently managed Virtual Hub saves. To set the current setting, you can use the SetHubLog API. */
    GetHubLog: (in_param: VpnRpcHubLog) => Promise<VpnRpcHubLog>;
    /** Add Trusted CA Certificate. Use this to add a new certificate to a list of CA certificates trusted by the currently managed Virtual Hub. The list of certificate authority certificates that are registered is used to verify certificates when a VPN Client is connected in signed certificate authentication mode. To get a list of the current certificates you can use the EnumCa API. The certificate you add must be saved in the X.509 file format. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
    AddCa: (in_param: VpnRpcHubAddCA) => Promise<VpnRpcHubAddCA>;
    /** Get List of Trusted CA Certificates. Here you can manage the certificate authority certificates that are trusted by this currently managed Virtual Hub. The list of certificate authority certificates that are registered is used to verify certificates when a VPN Client is connected in signed certificate authentication mode. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
    EnumCa: (in_param: VpnRpcHubEnumCA) => Promise<VpnRpcHubEnumCA>;
    /** Get Trusted CA Certificate. Use this to get an existing certificate from the list of CA certificates trusted by the currently managed Virtual Hub and save it as a file in X.509 format. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
    GetCa: (in_param: VpnRpcHubGetCA) => Promise<VpnRpcHubGetCA>;
    /** Delete Trusted CA Certificate. Use this to delete an existing certificate from the list of CA certificates trusted by the currently managed Virtual Hub. To get a list of the current certificates you can use the EnumCa API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
    DeleteCa: (in_param: VpnRpcHubDeleteCA) => Promise<VpnRpcHubDeleteCA>;
    /** Create New Cascade Connection. Use this to create a new Cascade Connection on the currently managed Virtual Hub. By using a Cascade Connection, you can connect this Virtual Hub by Cascade Connection to another Virtual Hub that is operating on the same or a different computer. To create a Cascade Connection, you must specify the name of the Cascade Connection, destination server and destination Virtual Hub and user name. When a new Cascade Connection is created, the type of user authentication is initially set as Anonymous Authentication and the proxy server setting and the verification options of the server certificate is not set. To change these settings and other advanced settings after a Cascade Connection has been created, use the other APIs that include the name "Link". [Warning About Cascade Connections] By connecting using a Cascade Connection you can create a Layer 2 bridge between multiple Virtual Hubs but if the connection is incorrectly configured, a loopback Cascade Connection could inadvertently be created. When using a Cascade Connection function please design the network topology with care. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    CreateLink: (in_param: VpnRpcCreateLink) => Promise<VpnRpcCreateLink>;
    /** Get the Cascade Connection Setting. Use this to get the Connection Setting of a Cascade Connection that is registered on the currently managed Virtual Hub. To change the Connection Setting contents of the Cascade Connection, use the APIs that include the name "Link" after creating the Cascade Connection. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    GetLink: (in_param: VpnRpcCreateLink) => Promise<VpnRpcCreateLink>;
    /** Change Existing Cascade Connection. Use this to alter the setting of an existing Cascade Connection on the currently managed Virtual Hub. */
    SetLink: (in_param: VpnRpcCreateLink) => Promise<VpnRpcCreateLink>;
    /** Get List of Cascade Connections. Use this to get a list of Cascade Connections that are registered on the currently managed Virtual Hub. By using a Cascade Connection, you can connect this Virtual Hub by Layer 2 Cascade Connection to another Virtual Hub that is operating on the same or a different computer. [Warning About Cascade Connections] By connecting using a Cascade Connection you can create a Layer 2 bridge between multiple Virtual Hubs but if the connection is incorrectly configured, a loopback Cascade Connection could inadvertently be created. When using a Cascade Connection function please design the network topology with care. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    EnumLink: (in_param: VpnRpcEnumLink) => Promise<VpnRpcEnumLink>;
    /** Switch Cascade Connection to Online Status. When a Cascade Connection registered on the currently managed Virtual Hub is specified, use this to switch that Cascade Connection to online status. The Cascade Connection that is switched to online status begins the process of connecting to the destination VPN Server in accordance with the Connection Setting. The Cascade Connection that is switched to online status will establish normal connection to the VPN Server or continue to attempt connection until it is switched to offline status. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    SetLinkOnline: (in_param: VpnRpcLink) => Promise<VpnRpcLink>;
    /** Switch Cascade Connection to Offline Status. When a Cascade Connection registered on the currently managed Virtual Hub is specified, use this to switch that Cascade Connection to offline status. The Cascade Connection that is switched to offline will not connect to the VPN Server until next time it is switched to the online status using the SetLinkOnline API You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    SetLinkOffline: (in_param: VpnRpcLink) => Promise<VpnRpcLink>;
    /** Delete Cascade Connection Setting. Use this to delete a Cascade Connection that is registered on the currently managed Virtual Hub. If the specified Cascade Connection has a status of online, the connections will be automatically disconnected and then the Cascade Connection will be deleted. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    DeleteLink: (in_param: VpnRpcLink) => Promise<VpnRpcLink>;
    /** Change Name of Cascade Connection. When a Cascade Connection registered on the currently managed Virtual Hub is specified, use this to change the name of that Cascade Connection. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    RenameLink: (in_param: VpnRpcRenameLink) => Promise<VpnRpcRenameLink>;
    /** Get Current Cascade Connection Status. When a Cascade Connection registered on the currently managed Virtual Hub is specified and that Cascade Connection is currently online, use this to get its connection status and other information. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    GetLinkStatus: (in_param: VpnRpcLinkStatus) => Promise<VpnRpcLinkStatus>;
    /** Add Access List Rule. Use this to add a new rule to the access list of the currently managed Virtual Hub. The access list is a set of packet file rules that are applied to packets that flow through the Virtual Hub. You can register multiple rules in an access list and you can also define an priority for each rule. All packets are checked for the conditions specified by the rules registered in the access list and based on the operation that is stipulated by the first matching rule, they either pass or are discarded. Packets that do not match any rule are implicitly allowed to pass. You can also use the access list to generate delays, jitters and packet losses. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
    AddAccess: (in_param: VpnRpcAddAccess) => Promise<VpnRpcAddAccess>;
    /** Delete Rule from Access List. Use this to specify a packet filter rule registered on the access list of the currently managed Virtual Hub and delete it. To delete a rule, you must specify that rule's ID. You can display the ID by using the EnumAccess API. If you wish not to delete the rule but to only temporarily disable it, use the SetAccessList API to set the rule status to disable. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
    DeleteAccess: (in_param: VpnRpcDeleteAccess) => Promise<VpnRpcDeleteAccess>;
    /** Get Access List Rule List. Use this to get a list of packet filter rules that are registered on access list of the currently managed Virtual Hub. The access list is a set of packet file rules that are applied to packets that flow through the Virtual Hub. You can register multiple rules in an access list and you can also define a priority for each rule. All packets are checked for the conditions specified by the rules registered in the access list and based on the operation that is stipulated by the first matching rule, they either pass or are discarded. Packets that do not match any rule are implicitly allowed to pass. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
    EnumAccess: (in_param: VpnRpcEnumAccessList) => Promise<VpnRpcEnumAccessList>;
    /** Replace all access lists on a single bulk API call. This API removes all existing access list rules on the Virtual Hub, and replace them by new access list rules specified by the parameter. */
    SetAccessList: (in_param: VpnRpcEnumAccessList) => Promise<VpnRpcEnumAccessList>;
    /** Create a user. Use this to create a new user in the security account database of the currently managed Virtual Hub. By creating a user, the VPN Client can connect to the Virtual Hub by using the authentication information of that user. Note that a user whose user name has been created as "*" (a single asterisk character) will automatically be registered as a RADIUS authentication user. For cases where there are users with "*" as the name, when a user, whose user name that has been provided when a client connected to a VPN Server does not match existing user names, is able to be authenticated by a RADIUS server or NT domain controller by inputting a user name and password, the authentication settings and security policy settings will follow the setting for the user "*". To change the user information of a user that has been created, use the SetUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
    CreateUser: (in_param: VpnRpcSetUser) => Promise<VpnRpcSetUser>;
    /** Change User Settings. Use this to change user settings that is registered on the security account database of the currently managed Virtual Hub. The user settings that can be changed using this API are the three items that are specified when a new user is created using the CreateUser API: Group Name, Full Name, and Description. To get the list of currently registered users, use the EnumUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
    SetUser: (in_param: VpnRpcSetUser) => Promise<VpnRpcSetUser>;
    /** Get User Settings. Use this to get user settings information that is registered on the security account database of the currently managed Virtual Hub. The information that you can get using this API are User Name, Full Name, Group Name, Expiration Date, Security Policy, and Auth Type, as well as parameters that are specified as auth type attributes and the statistical data of that user. To get the list of currently registered users, use the EnumUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
    GetUser: (in_param: VpnRpcSetUser) => Promise<VpnRpcSetUser>;
    /** Delete a user. Use this to delete a user that is registered on the security account database of the currently managed Virtual Hub. By deleting the user, that user will no long be able to connect to the Virtual Hub. You can use the SetUser API to set the user's security policy to deny access instead of deleting a user, set the user to be temporarily denied from logging in. To get the list of currently registered users, use the EnumUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
    DeleteUser: (in_param: VpnRpcDeleteUser) => Promise<VpnRpcDeleteUser>;
    /** Get List of Users. Use this to get a list of users that are registered on the security account database of the currently managed Virtual Hub. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
    EnumUser: (in_param: VpnRpcEnumUser) => Promise<VpnRpcEnumUser>;
    /** Create Group. Use this to create a new group in the security account database of the currently managed Virtual Hub. You can register multiple users in a group. To register users in a group use the SetUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
    CreateGroup: (in_param: VpnRpcSetGroup) => Promise<VpnRpcSetGroup>;
    /** Set group settings. Use this to set group settings that is registered on the security account database of the currently managed Virtual Hub. To get the list of currently registered groups, use the EnumGroup API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
    SetGroup: (in_param: VpnRpcSetGroup) => Promise<VpnRpcSetGroup>;
    /** Get Group Setting (Sync mode). Use this to get the setting of a group that is registered on the security account database of the currently managed Virtual Hub. To get the list of currently registered groups, use the EnumGroup API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
    GetGroup: (in_param: VpnRpcSetGroup) => Promise<VpnRpcSetGroup>;
    /** Delete User from Group. Use this to delete a specified user from the group that is registered on the security account database of the currently managed Virtual Hub. By deleting a user from the group, that user becomes unassigned. To get the list of currently registered groups, use the EnumGroup API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
    DeleteGroup: (in_param: VpnRpcDeleteUser) => Promise<VpnRpcDeleteUser>;
    /** Get List of Groups. Use this to get a list of groups that are registered on the security account database of the currently managed Virtual Hub. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster. */
    EnumGroup: (in_param: VpnRpcEnumGroup) => Promise<VpnRpcEnumGroup>;
    /** Get List of Connected VPN Sessions. Use this to get a list of the sessions connected to the Virtual Hub currently being managed. In the list of sessions, the following information will be obtained for each connection: Session Name, Session Site, User Name, Source Host Name, TCP Connection, Transfer Bytes and Transfer Packets. If the currently connected VPN Server is a cluster controller and the currently managed Virtual Hub is a static Virtual Hub, you can get an all-linked-together list of all sessions connected to that Virtual Hub on all cluster members. In all other cases, only the list of sessions that are actually connected to the currently managed VPN Server will be obtained. */
    EnumSession: (in_param: VpnRpcEnumSession) => Promise<VpnRpcEnumSession>;
    /** Get Session Status. Use this to specify a session currently connected to the currently managed Virtual Hub and get the session information. The session status includes the following: source host name and user name, version information, time information, number of TCP connections, communication parameters, session key, statistical information on data transferred, and other client and server information. To get the list of currently connected sessions, use the EnumSession API. */
    GetSessionStatus: (in_param: VpnRpcSessionStatus) => Promise<VpnRpcSessionStatus>;
    /** Disconnect Session. Use this to specify a session currently connected to the currently managed Virtual Hub and forcefully disconnect that session using manager privileges. Note that when communication is disconnected by settings on the source client side and the automatically reconnect option is enabled, it is possible that the client will reconnect. To get the list of currently connected sessions, use the EnumSession API. */
    DeleteSession: (in_param: VpnRpcDeleteSession) => Promise<VpnRpcDeleteSession>;
    /** Get the MAC Address Table Database. Use this to get the MAC address table database that is held by the currently managed Virtual Hub. The MAC address table database is a table that the Virtual Hub requires to perform the action of switching Ethernet frames and the Virtual Hub decides the sorting destination session of each Ethernet frame based on the MAC address table database. The MAC address database is built by the Virtual Hub automatically analyzing the contents of the communication. */
    EnumMacTable: (in_param: VpnRpcEnumMacTable) => Promise<VpnRpcEnumMacTable>;
    /** Delete MAC Address Table Entry. Use this API to operate the MAC address table database held by the currently managed Virtual Hub and delete a specified MAC address table entry from the database. To get the contents of the current MAC address table database use the EnumMacTable API. */
    DeleteMacTable: (in_param: VpnRpcDeleteTable) => Promise<VpnRpcDeleteTable>;
    /** Get the IP Address Table Database. Use this to get the IP address table database that is held by the currently managed Virtual Hub. The IP address table database is a table that is automatically generated by analyzing the contents of communication so that the Virtual Hub can always know which session is using which IP address and it is frequently used by the engine that applies the Virtual Hub security policy. By specifying the session name you can get the IP address table entry that has been associated with that session. */
    EnumIpTable: (in_param: VpnRpcEnumIpTable) => Promise<VpnRpcEnumIpTable>;
    /** Delete IP Address Table Entry. Use this API to operate the IP address table database held by the currently managed Virtual Hub and delete a specified IP address table entry from the database. To get the contents of the current IP address table database use the EnumIpTable API. */
    DeleteIpTable: (in_param: VpnRpcDeleteTable) => Promise<VpnRpcDeleteTable>;
    /** Set the Keep Alive Internet Connection Function. Use this to set the destination host name etc. of the Keep Alive Internet Connection Function. For network connection environments where connections will automatically be disconnected where there are periods of no communication that are longer than a set period, by using the Keep Alive Internet Connection Function, it is possible to keep alive the Internet connection by sending packets to a nominated server on the Internet at set intervals. When using this API, you can specify the following: Host Name, Port Number, Packet Send Interval, and Protocol. Packets sent to keep alive the Internet connection will have random content and personal information that could identify a computer or user is not sent. You can use the SetKeep API to enable/disable the Keep Alive Internet Connection Function. To execute this API on a VPN Server or VPN Bridge, you must have administrator privileges. */
    SetKeep: (in_param: VpnRpcKeep) => Promise<VpnRpcKeep>;
    /** Get the Keep Alive Internet Connection Function. Use this to get the current setting contents of the Keep Alive Internet Connection Function. In addition to the destination's Host Name, Port Number, Packet Send Interval and Protocol, you can obtain the current enabled/disabled status of the Keep Alive Internet Connection Function. */
    GetKeep: (in_param: VpnRpcKeep) => Promise<VpnRpcKeep>;
    /** Enable the Virtual NAT and DHCP Server Function (SecureNAT Function). Use this to enable the Virtual NAT and DHCP Server function (SecureNAT Function) on the currently managed Virtual Hub and begin its operation. Before executing this API, you must first check the setting contents of the current Virtual NAT function and DHCP Server function using the SetSecureNATOption API and GetSecureNATOption API. By enabling the SecureNAT function, you can virtually operate a NAT router (IP masquerade) and the DHCP Server function on a virtual network on the Virtual Hub. [Warning about SecureNAT Function] The SecureNAT function is recommended only for system administrators and people with a detailed knowledge of networks. If you use the SecureNAT function correctly, it is possible to achieve a safe form of remote access via a VPN. However when used in the wrong way, it can put the entire network in danger. Anyone who does not have a thorough knowledge of networks and anyone who does not have the network administrator's permission must not enable the SecureNAT function. For a detailed explanation of the SecureNAT function, please refer to the VPN Server's manual and online documentation. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    EnableSecureNAT: (in_param: VpnRpcHub) => Promise<VpnRpcHub>;
    /** Disable the Virtual NAT and DHCP Server Function (SecureNAT Function). Use this to disable the Virtual NAT and DHCP Server function (SecureNAT Function) on the currently managed Virtual Hub. By executing this API the Virtual NAT function immediately stops operating and the Virtual DHCP Server function deletes the DHCP lease database and stops the service. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    DisableSecureNAT: (in_param: VpnRpcHub) => Promise<VpnRpcHub>;
    /** Change Settings of SecureNAT Function. Use this to change and save the virtual host network interface settings, virtual NAT function settings and virtual DHCP server settings of the Virtual NAT and DHCP Server function (SecureNAT function) on the currently managed Virtual Hub. The SecureNAT function holds one virtual network adapter on the L2 segment inside the Virtual Hub and it has been assigned a MAC address and an IP address. By doing this, another host connected to the same L2 segment is able to communicate with the SecureNAT virtual host as if it is an actual IP host existing on the network. [Warning about SecureNAT Function] The SecureNAT function is recommended only for system administrators and people with a detailed knowledge of networks. If you use the SecureNAT function correctly, it is possible to achieve a safe form of remote access via a VPN. However when used in the wrong way, it can put the entire network in danger. Anyone who does not have a thorough knowledge of networks and anyone who does not have the network administrators permission must not enable the SecureNAT function. For a detailed explanation of the SecureNAT function, please refer to the VPN Server's manual and online documentation. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    SetSecureNATOption: (in_param: VpnVhOption) => Promise<VpnVhOption>;
    /** Get Settings of SecureNAT Function. This API get the registered settings for the SecureNAT function which is set by the SetSecureNATOption API. */
    GetSecureNATOption: (in_param: VpnVhOption) => Promise<VpnVhOption>;
    /** Get Virtual NAT Function Session Table of SecureNAT Function. Use this to get the table of TCP and UDP sessions currently communicating via the Virtual NAT (NAT table) in cases when the Virtual NAT function is operating on the currently managed Virtual Hub. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    EnumNAT: (in_param: VpnRpcEnumNat) => Promise<VpnRpcEnumNat>;
    /** Get Virtual DHCP Server Function Lease Table of SecureNAT Function. Use this to get the lease table of IP addresses, held by the Virtual DHCP Server, that are assigned to clients in cases when the Virtual NAT function is operating on the currently managed Virtual Hub. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    EnumDHCP: (in_param: VpnRpcEnumDhcp) => Promise<VpnRpcEnumDhcp>;
    /** Get the Operating Status of the Virtual NAT and DHCP Server Function (SecureNAT Function). Use this to get the operating status of the Virtual NAT and DHCP Server function (SecureNAT Function) when it is operating on the currently managed Virtual Hub. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    GetSecureNATStatus: (in_param: VpnRpcNatStatus) => Promise<VpnRpcNatStatus>;
    /** Get List of Network Adapters Usable as Local Bridge. Use this to get a list of Ethernet devices (network adapters) that can be used as a bridge destination device as part of a Local Bridge connection. If possible, network connection name is displayed. You can use a device displayed here by using the AddLocalBridge API. To call this API, you must have VPN Server administrator privileges. */
    EnumEthernet: () => Promise<VpnRpcEnumEth>;
    /** Create Local Bridge Connection. Use this to create a new Local Bridge connection on the VPN Server. By using a Local Bridge, you can configure a Layer 2 bridge connection between a Virtual Hub operating on this VPN server and a physical Ethernet Device (Network Adapter). You can create a tap device (virtual network interface) on the system and connect a bridge between Virtual Hubs (the tap device is only supported by Linux versions). It is possible to establish a bridge to an operating network adapter of your choice for the bridge destination Ethernet device (network adapter), but in high load environments, we recommend you prepare a network adapter dedicated to serve as a bridge. To call this API, you must have VPN Server administrator privileges. */
    AddLocalBridge: (in_param: VpnRpcLocalBridge) => Promise<VpnRpcLocalBridge>;
    /** Delete Local Bridge Connection. Use this to delete an existing Local Bridge connection. To get a list of current Local Bridge connections use the EnumLocalBridge API. To call this API, you must have VPN Server administrator privileges. */
    DeleteLocalBridge: (in_param: VpnRpcLocalBridge) => Promise<VpnRpcLocalBridge>;
    /** Get List of Local Bridge Connection. Use this to get a list of the currently defined Local Bridge connections. You can get the Local Bridge connection Virtual Hub name and the bridge destination Ethernet device (network adapter) name or tap device name, as well as the operating status. */
    EnumLocalBridge: () => Promise<VpnRpcEnumLocalBridge>;
    /** Get whether the localbridge function is supported on the current system. */
    GetBridgeSupport: () => Promise<VpnRpcBridgeSupport>;
    /** Reboot VPN Server Service. Use this to restart the VPN Server service. When you restart the VPN Server, all currently connected sessions and TCP connections will be disconnected and no new connections will be accepted until the restart process has completed. By using this API, only the VPN Server service program will be restarted and the physical computer that VPN Server is operating on does not restart. This management session will also be disconnected, so you will need to reconnect to continue management. Also, by specifying the "IntValue" parameter to "1", the contents of the configuration file (.config) held by the current VPN Server will be initialized. To call this API, you must have VPN Server administrator privileges. */
    RebootServer: (in_param: VpnRpcTest) => Promise<VpnRpcTest>;
    /** Get List of Server Functions / Capability. Use this get a list of functions and capability of the VPN Server currently connected and being managed. The function and capability of VPN Servers are different depending on the operating VPN server's edition and version. Using this API, you can find out the capability of the target VPN Server and report it. */
    GetCaps: () => Promise<VpnCapslist>;
    /** Get the current configuration of the VPN Server. Use this to get a text file (.config file) that contains the current configuration contents of the VPN server. You can get the status on the VPN Server at the instant this API is executed. You can edit the configuration file by using a regular text editor. To write an edited configuration to the VPN Server, use the SetConfig API. To call this API, you must have VPN Server administrator privileges. */
    GetConfig: () => Promise<VpnRpcConfig>;
    /** Write Configuration File to VPN Server. Use this to write the configuration file to the VPN Server. By executing this API, the contents of the specified configuration file will be applied to the VPN Server and the VPN Server program will automatically restart and upon restart, operate according to the new configuration contents. Because it is difficult for an administrator to write all the contents of a configuration file, we recommend you use the GetConfig API to get the current contents of the VPN Server configuration and save it to file. You can then edit these contents in a regular text editor and then use the SetConfig API to rewrite the contents to the VPN Server. This API is for people with a detailed knowledge of the VPN Server and if an incorrectly configured configuration file is written to the VPN Server, it not only could cause errors, it could also result in the lost of the current setting data. Take special care when carrying out this action. To call this API, you must have VPN Server administrator privileges. */
    SetConfig: (in_param: VpnRpcConfig) => Promise<VpnRpcConfig>;
    /** Get Virtual Hub Administration Option default values. */
    GetDefaultHubAdminOptions: (in_param: VpnRpcAdminOption) => Promise<VpnRpcAdminOption>;
    /** Get List of Virtual Hub Administration Options. Use this to get a list of Virtual Hub administration options that are set on the currently managed Virtual Hub. The purpose of the Virtual Hub administration options is for the VPN Server Administrator to set limits for the setting ranges when the administration of the Virtual Hub is to be trusted to each Virtual Hub administrator. Only an administrator with administration privileges for this entire VPN Server is able to add, edit and delete the Virtual Hub administration options. The Virtual Hub administrators are unable to make changes to the administration options, however they are able to view them. There is an exception however. If allow_hub_admin_change_option is set to "1", even Virtual Hub administrators are able to edit the administration options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member. */
    GetHubAdminOptions: (in_param: VpnRpcAdminOption) => Promise<VpnRpcAdminOption>;
    /** Set Values of Virtual Hub Administration Options. Use this to change the values of Virtual Hub administration options that are set on the currently managed Virtual Hub. The purpose of the Virtual Hub administration options is for the VPN Server Administrator to set limits for the setting ranges when the administration of the Virtual Hub is to be trusted to each Virtual Hub administrator. Only an administrator with administration privileges for this entire VPN Server is able to add, edit and delete the Virtual Hub administration options. The Virtual Hub administrators are unable to make changes to the administration options, however they are able to view them. There is an exception however. If allow_hub_admin_change_option is set to "1", even Virtual Hub administrators are able to edit the administration options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member. */
    SetHubAdminOptions: (in_param: VpnRpcAdminOption) => Promise<VpnRpcAdminOption>;
    /** Get List of Virtual Hub Extended Options. Use this to get a Virtual Hub Extended Options List that is set on the currently managed Virtual Hub. Virtual Hub Extended Option enables you to configure more detail settings of the Virtual Hub. By default, both VPN Server's global administrators and individual Virtual Hub's administrators can modify the Virtual Hub Extended Options. However, if the deny_hub_admin_change_ext_option is set to 1 on the Virtual Hub Admin Options, the individual Virtual Hub's administrators cannot modify the Virtual Hub Extended Options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member. */
    GetHubExtOptions: (in_param: VpnRpcAdminOption) => Promise<VpnRpcAdminOption>;
    /** Set a Value of Virtual Hub Extended Options. Use this to set a value in the Virtual Hub Extended Options List that is set on the currently managed Virtual Hub. Virtual Hub Extended Option enables you to configure more detail settings of the Virtual Hub. By default, both VPN Server's global administrators and individual Virtual Hub's administrators can modify the Virtual Hub Extended Options. However, if the deny_hub_admin_change_ext_option is set to 1 on the Virtual Hub Admin Options, the individual Virtual Hub's administrators cannot modify the Virtual Hub Extended Options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member. */
    SetHubExtOptions: (in_param: VpnRpcAdminOption) => Promise<VpnRpcAdminOption>;
    /** Define New Virtual Layer 3 Switch. Use this to define a new Virtual Layer 3 Switch on the VPN Server. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. [Explanation on Virtual Layer 3 Switch Function] You can define Virtual Layer 3 Switches between multiple Virtual Hubs operating on this VPN Server and configure routing between different IP networks. [Caution about the Virtual Layer 3 Switch Function] The Virtual Layer 3 Switch functions are provided for network administrators and other people who know a lot about networks and IP routing. If you are using the regular VPN functions, you do not need to use the Virtual Layer 3 Switch functions. If the Virtual Layer 3 Switch functions are to be used, the person who configures them must have sufficient knowledge of IP routing and be perfectly capable of not impacting the network. */
    AddL3Switch: (in_param: VpnRpcL3Sw) => Promise<VpnRpcL3Sw>;
    /** Delete Virtual Layer 3 Switch. Use this to delete an existing Virtual Layer 3 Switch that is defined on the VPN Server. When the specified Virtual Layer 3 Switch is operating, it will be automatically deleted after operation stops. To get a list of existing Virtual Layer 3 Switches, use the EnumL3Switch API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. */
    DelL3Switch: (in_param: VpnRpcL3Sw) => Promise<VpnRpcL3Sw>;
    /** Get List of Virtual Layer 3 Switches. Use this to define a new Virtual Layer 3 Switch on the VPN Server. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. [Explanation on Virtual Layer 3 Switch Function] You can define Virtual Layer 3 Switches between multiple Virtual Hubs operating on this VPN Server and configure routing between different IP networks. [Caution about the Virtual Layer 3 Switch Function] The Virtual Layer 3 Switch functions are provided for network administrators and other people who know a lot about networks and IP routing. If you are using the regular VPN functions, you do not need to use the Virtual Layer 3 Switch functions. If the Virtual Layer 3 Switch functions are to be used, the person who configures them must have sufficient knowledge of IP routing and be perfectly capable of not impacting the network. */
    EnumL3Switch: () => Promise<VpnRpcEnumL3Sw>;
    /** Start Virtual Layer 3 Switch Operation. Use this to start the operation of an existing Virtual Layer 3 Switch defined on the VPN Server whose operation is currently stopped. To get a list of existing Virtual Layer 3 Switches, use the EnumL3Switch API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. [Explanation on Virtual Layer 3 Switch Function] You can define Virtual Layer 3 Switches between multiple Virtual Hubs operating on this VPN Server and configure routing between different IP networks. [Caution about the Virtual Layer 3 Switch Function] The Virtual Layer 3 Switch functions are provided for network administrators and other people who know a lot about networks and IP routing. If you are using the regular VPN functions, you do not need to use the Virtual Layer 3 Switch functions. If the Virtual Layer 3 Switch functions are to be used, the person who configures them must have sufficient knowledge of IP routing and be perfectly capable of not impacting the network. */
    StartL3Switch: (in_param: VpnRpcL3Sw) => Promise<VpnRpcL3Sw>;
    /** Stop Virtual Layer 3 Switch Operation. Use this to stop the operation of an existing Virtual Layer 3 Switch defined on the VPN Server whose operation is currently operating. To get a list of existing Virtual Layer 3 Switches, use the EnumL3Switch API. To call this API, you must have VPN Server administrator privileges. */
    StopL3Switch: (in_param: VpnRpcL3Sw) => Promise<VpnRpcL3Sw>;
    /** Add Virtual Interface to Virtual Layer 3 Switch. Use this to add to a specified Virtual Layer 3 Switch, a virtual interface that connects to a Virtual Hub operating on the same VPN Server. You can define multiple virtual interfaces and routing tables for a single Virtual Layer 3 Switch. A virtual interface is associated to a virtual Hub and operates as a single IP host on the Virtual Hub when that Virtual Hub is operating. When multiple virtual interfaces that respectively belong to a different IP network of a different Virtual Hub are defined, IP routing will be automatically performed between these interfaces. You must define the IP network space that the virtual interface belongs to and the IP address of the interface itself. Also, you must specify the name of the Virtual Hub that the interface will connect to. You can specify a Virtual Hub that currently doesn't exist for the Virtual Hub name. The virtual interface must have one IP address in the Virtual Hub. You also must specify the subnet mask of an IP network that the IP address belongs to. Routing via the Virtual Layer 3 Switches of IP spaces of multiple virtual Hubs operates based on the IP address is specified here. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API. */
    AddL3If: (in_param: VpnRpcL3If) => Promise<VpnRpcL3If>;
    /** Delete Virtual Interface of Virtual Layer 3 Switch. Use this to delete a virtual interface already defined in the specified Virtual Layer 3 Switch. You can get a list of the virtual interfaces currently defined, by using the EnumL3If API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API. */
    DelL3If: (in_param: VpnRpcL3If) => Promise<VpnRpcL3If>;
    /** Get List of Interfaces Registered on the Virtual Layer 3 Switch. Use this to get a list of virtual interfaces when virtual interfaces have been defined on a specified Virtual Layer 3 Switch. You can define multiple virtual interfaces and routing tables for a single Virtual Layer 3 Switch. A virtual interface is associated to a virtual Hub and operates as a single IP host on the Virtual Hub when that Virtual Hub is operating. When multiple virtual interfaces that respectively belong to a different IP network of a different Virtual Hub are defined, IP routing will be automatically performed between these interfaces. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. */
    EnumL3If: (in_param: VpnRpcEnumL3If) => Promise<VpnRpcEnumL3If>;
    /** Add Routing Table Entry for Virtual Layer 3 Switch. Here you can add a new routing table entry to the routing table of the specified Virtual Layer 3 Switch. If the destination IP address of the IP packet does not belong to any IP network that belongs to a virtual interface, the IP routing engine of the Virtual Layer 3 Switch will reference the routing table and execute routing. You must specify the contents of the routing table entry to be added to the Virtual Layer 3 Switch. You must specify any IP address that belongs to the same IP network in the virtual interface of this Virtual Layer 3 Switch as the gateway address. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API. */
    AddL3Table: (in_param: VpnRpcL3Table) => Promise<VpnRpcL3Table>;
    /** Delete Routing Table Entry of Virtual Layer 3 Switch. Use this to delete a routing table entry that is defined in the specified Virtual Layer 3 Switch. You can get a list of the already defined routing table entries by using the EnumL3Table API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API. */
    DelL3Table: (in_param: VpnRpcL3Table) => Promise<VpnRpcL3Table>;
    /** Get List of Routing Tables of Virtual Layer 3 Switch. Use this to get a list of routing tables when routing tables have been defined on a specified Virtual Layer 3 Switch. If the destination IP address of the IP packet does not belong to any IP network that belongs to a virtual interface, the IP routing engine of the Virtual Layer 3 Switch will reference this routing table and execute routing. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. */
    EnumL3Table: (in_param: VpnRpcEnumL3Table) => Promise<VpnRpcEnumL3Table>;
    /** Get List of Certificates Revocation List. Use this to get a Certificates Revocation List that is set on the currently managed Virtual Hub. By registering certificates in the Certificates Revocation List, the clients who provide these certificates will be unable to connect to this Virtual Hub using certificate authentication mode. Normally with this function, in cases where the security of a private key has been compromised or where a person holding a certificate has been stripped of their privileges, by registering that certificate as invalid on the Virtual Hub, it is possible to deny user authentication when that certificate is used by a client to connect to the Virtual Hub. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    EnumCrl: (in_param: VpnRpcEnumCrl) => Promise<VpnRpcEnumCrl>;
    /** Add a Revoked Certificate. Use this to add a new revoked certificate definition in the Certificate Revocation List that is set on the currently managed Virtual Hub. Specify the contents to be registered in the Certificate Revocation List by using the parameters of this API. When a user connects to a Virtual Hub in certificate authentication mode and that certificate matches 1 or more of the contents registered in the certificates revocation list, the user is denied connection. A certificate that matches all the conditions that are defined by the parameters specified by this API will be judged as invalid. The items that can be set are as follows: Name (CN), Organization (O), Organization Unit (OU), Country (C), State (ST), Locale (L), Serial Number (hexadecimal), MD5 Digest Value (hexadecimal, 128 bit), and SHA-1 Digest Value (hexadecimal, 160 bit). For the specification of a digest value (hash value) a certificate is optionally specified depending on the circumstances. Normally when a MD5 or SHA-1 digest value is input, it is not necessary to input the other items. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    AddCrl: (in_param: VpnRpcCrl) => Promise<VpnRpcCrl>;
    /** Delete a Revoked Certificate. Use this to specify and delete a revoked certificate definition from the certificate revocation list that is set on the currently managed Virtual Hub. To get the list of currently registered revoked certificate definitions, use the EnumCrl API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    DelCrl: (in_param: VpnRpcCrl) => Promise<VpnRpcCrl>;
    /** Get a Revoked Certificate. Use this to specify and get the contents of a revoked certificate definition from the Certificates Revocation List that is set on the currently managed Virtual Hub. To get the list of currently registered revoked certificate definitions, use the EnumCrl API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    GetCrl: (in_param: VpnRpcCrl) => Promise<VpnRpcCrl>;
    /** Change Existing CRL (Certificate Revocation List) Entry. Use this to alter an existing revoked certificate definition in the Certificate Revocation List that is set on the currently managed Virtual Hub. Specify the contents to be registered in the Certificate Revocation List by using the parameters of this API. When a user connects to a Virtual Hub in certificate authentication mode and that certificate matches 1 or more of the contents registered in the certificates revocation list, the user is denied connection. A certificate that matches all the conditions that are defined by the parameters specified by this API will be judged as invalid. The items that can be set are as follows: Name (CN), Organization (O), Organization Unit (OU), Country (C), State (ST), Locale (L), Serial Number (hexadecimal), MD5 Digest Value (hexadecimal, 128 bit), and SHA-1 Digest Value (hexadecimal, 160 bit). For the specification of a digest value (hash value) a certificate is optionally specified depending on the circumstances. Normally when a MD5 or SHA-1 digest value is input, it is not necessary to input the other items. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    SetCrl: (in_param: VpnRpcCrl) => Promise<VpnRpcCrl>;
    /** Add Rule to Source IP Address Limit List. Use this to add a new rule to the Source IP Address Limit List that is set on the currently managed Virtual Hub. The items set here will be used to decide whether to allow or deny connection from a VPN Client when this client attempts connection to the Virtual Hub. You can specify a client IP address, or IP address or mask to match the rule as the contents of the rule item. By specifying an IP address only, there will only be one specified computer that will match the rule, but by specifying an IP net mask address or subnet mask address, all the computers in the range of that subnet will match the rule. You can specify the priority for the rule. You can specify an integer of 1 or greater for the priority and the smaller the number, the higher the priority. To get a list of the currently registered Source IP Address Limit List, use the GetAcList API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    SetAcList: (in_param: VpnRpcAcList) => Promise<VpnRpcAcList>;
    /** Get List of Rule Items of Source IP Address Limit List. Use this to get a list of Source IP Address Limit List rules that is set on the currently managed Virtual Hub. You can allow or deny VPN connections to this Virtual Hub according to the client computer's source IP address. You can define multiple rules and set a priority for each rule. The search proceeds from the rule with the highest order or priority and based on the action of the rule that the IP address first matches, the connection from the client is either allowed or denied. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    GetAcList: (in_param: VpnRpcAcList) => Promise<VpnRpcAcList>;
    /** Get List of Log Files. Use this to display a list of log files outputted by the VPN Server that have been saved on the VPN Server computer. By specifying a log file file name displayed here and calling it using the ReadLogFile API you can download the contents of the log file. If you are connected to the VPN Server in server admin mode, you can display or download the packet logs and security logs of all Virtual Hubs and the server log of the VPN Server. When connected in Virtual Hub Admin Mode, you are able to view or download only the packet log and security log of the Virtual Hub that is the target of management. */
    EnumLogFile: () => Promise<VpnRpcEnumLogFile>;
    /** Download a part of Log File. Use this to download the log file that is saved on the VPN Server computer. To download the log file first get the list of log files using the EnumLogFile API and then download the log file using the ReadLogFile API. If you are connected to the VPN Server in server admin mode, you can display or download the packet logs and security logs of all Virtual Hubs and the server log of the VPN Server. When connected in Virtual Hub Admin Mode, you are able to view or download only the packet log and security log of the Virtual Hub that is the target of management. */
    ReadLogFile: (in_param: VpnRpcReadLogFile) => Promise<VpnRpcReadLogFile>;
    /** Set syslog Send Function. Use this to set the usage of syslog send function and which syslog server to use. */
    SetSysLog: (in_param: VpnSyslogSetting) => Promise<VpnSyslogSetting>;
    /** Get syslog Send Function. This allows you to get the current setting contents of the syslog send function. You can get the usage setting of the syslog function and the host name and port number of the syslog server to use. */
    GetSysLog: (in_param: VpnSyslogSetting) => Promise<VpnSyslogSetting>;
    /** Set Today's Message of Virtual Hub. The message will be displayed on VPN Client UI when a user will establish a connection to the Virtual Hub. */
    SetHubMsg: (in_param: VpnRpcMsg) => Promise<VpnRpcMsg>;
    /** Get Today's Message of Virtual Hub. The message will be displayed on VPN Client UI when a user will establish a connection to the Virtual Hub. */
    GetHubMsg: (in_param: VpnRpcMsg) => Promise<VpnRpcMsg>;
    /** Raise a vital error on the VPN Server / Bridge to terminate the process forcefully. This API will raise a fatal error (memory access violation) on the VPN Server / Bridge running process in order to crash the process. As the result, VPN Server / Bridge will be terminated and restarted if it is running as a service mode. If the VPN Server is running as a user mode, the process will not automatically restarted. This API is for a situation when the VPN Server / Bridge is under a non-recoverable error or the process is in an infinite loop. This API will disconnect all VPN Sessions on the VPN Server / Bridge. All unsaved settings in the memory of VPN Server / Bridge will be lost. Before run this API, call the Flush API to try to save volatile data to the configuration file. To execute this API, you must have VPN Server / VPN Bridge administrator privileges. */
    Crash: (in_param: VpnRpcTest) => Promise<VpnRpcTest>;
    /** Get the message for administrators. */
    GetAdminMsg: () => Promise<VpnRpcMsg>;
    /** Save All Volatile Data of VPN Server / Bridge to the Configuration File. The number of configuration file bytes will be returned as the "IntValue" parameter. Normally, the VPN Server / VPN Bridge retains the volatile configuration data in memory. It is flushed to the disk as vpn_server.config or vpn_bridge.config periodically. The period is 300 seconds (5 minutes) by default. (The period can be altered by modifying the AutoSaveConfigSpan item in the configuration file.) The data will be saved on the timing of shutting down normally of the VPN Server / Bridge. Execute the Flush API to make the VPN Server / Bridge save the settings to the file immediately. The setting data will be stored on the disk drive of the server computer. Use the Flush API in a situation that you do not have an enough time to shut down the server process normally. To call this API, you must have VPN Server administrator privileges. To execute this API, you must have VPN Server / VPN Bridge administrator privileges. */
    Flush: (in_param: VpnRpcTest) => Promise<VpnRpcTest>;
    /** Enable or Disable IPsec VPN Server Function. Enable or Disable IPsec VPN Server Function on the VPN Server. If you enable this function, Virtual Hubs on the VPN Server will be able to accept Remote-Access VPN connections from L2TP-compatible PCs, Mac OS X and Smartphones, and also can accept EtherIP Site-to-Site VPN Connection. VPN Connections from Smartphones suchlike iPhone, iPad and Android, and also from native VPN Clients on Mac OS X and Windows can be accepted. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    SetIPsecServices: (in_param: VpnIPsecServices) => Promise<VpnIPsecServices>;
    /** Get the Current IPsec VPN Server Settings. Get and view the current IPsec VPN Server settings on the VPN Server. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    GetIPsecServices: () => Promise<VpnIPsecServices>;
    /** Add New EtherIP / L2TPv3 over IPsec Client Setting to Accept EthreIP / L2TPv3 Client Devices. Add a new setting entry to enable the EtherIP / L2TPv3 over IPsec Server Function to accept client devices. In order to accept connections from routers by the EtherIP / L2TPv3 over IPsec Server Function, you have to define the relation table between an IPsec Phase 1 string which is presented by client devices of EtherIP / L2TPv3 over IPsec compatible router, and the designation of the destination Virtual Hub. After you add a definition entry by AddEtherIpId API, the defined connection setting to the Virtual Hub will be applied on the login-attepting session from an EtherIP / L2TPv3 over IPsec client device. The username and password in an entry must be registered on the Virtual Hub. An EtherIP / L2TPv3 client will be regarded as it connected the Virtual HUB with the identification of the above user information. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    AddEtherIpId: (in_param: VpnEtherIpId) => Promise<VpnEtherIpId>;
    /** Get the Current List of EtherIP / L2TPv3 Client Device Entry Definitions. This API gets and shows the list of entries to accept VPN clients by EtherIP / L2TPv3 over IPsec Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    GetEtherIpId: (in_param: VpnEtherIpId) => Promise<VpnEtherIpId>;
    /** Delete an EtherIP / L2TPv3 over IPsec Client Setting. This API deletes an entry to accept VPN clients by EtherIP / L2TPv3 over IPsec Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    DeleteEtherIpId: (in_param: VpnEtherIpId) => Promise<VpnEtherIpId>;
    /** Get the Current List of EtherIP / L2TPv3 Client Device Entry Definitions. This API gets and shows the list of entries to accept VPN clients by EtherIP / L2TPv3 over IPsec Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    EnumEtherIpId: () => Promise<VpnRpcEnumEtherIpId>;
    /** Set Settings for OpenVPN Clone Server Function. The VPN Server has the clone functions of OpenVPN software products by OpenVPN Technologies, Inc. Any OpenVPN Clients can connect to this VPN Server. The manner to specify a username to connect to the Virtual Hub, and the selection rule of default Hub by using this clone server functions are same to the IPsec Server functions. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    SetOpenVpnSstpConfig: (in_param: VpnOpenVpnSstpConfig) => Promise<VpnOpenVpnSstpConfig>;
    /** Get the Current Settings of OpenVPN Clone Server Function. Get and show the current settings of OpenVPN Clone Server Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    GetOpenVpnSstpConfig: () => Promise<VpnOpenVpnSstpConfig>;
    /** Show the Current Status of Dynamic DNS Function. Get and show the current status of the Dynamic DNS function. The Dynamic DNS assigns a unique and permanent DNS hostname for this VPN Server. You can use that hostname to specify this VPN Server on the settings for VPN Client and VPN Bridge. You need not to register and keep a domain name. Also, if your ISP assignes you a dynamic (not-fixed) IP address, the corresponding IP address of your Dynamic DNS hostname will be automatically changed. It enables you to keep running the VPN Server by using only a dynamic IP address. Therefore, you need not any longer to keep static global IP addresses with expenses monthly costs. [Caution] To disable the Dynamic DNS Function, modify the configuration file of VPN Server. The "declare root" directive has the "declare DDnsClient" directive. In this directive, you can switch "bool Disable" from false to true, and reboot the VPN Server, then the Dynamic DNS Function will be disabled. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. */
    GetDDnsClientStatus: () => Promise<VpnDDnsClientStatus>;
    /** Set the Dynamic DNS Hostname. You must specify the new hostname on the StrValue_str field. You can use this API to change the hostname assigned by the Dynamic DNS function. The currently assigned hostname can be showen by the GetDDnsClientStatus API. The Dynamic DNS assigns a unique and permanent DNS hostname for this VPN Server. You can use that hostname to specify this VPN Server on the settings for VPN Client and VPN Bridge. You need not to register and keep a domain name. Also, if your ISP assignes you a dynamic (not-fixed) IP address, the corresponding IP address of your Dynamic DNS hostname will be automatically changed. It enables you to keep running the VPN Server by using only a dynamic IP address. Therefore, you need not any longer to keep static global IP addresses with expenses monthly costs. [Caution] To disable the Dynamic DNS Function, modify the configuration file of VPN Server. The "declare root" directive has the "declare DDnsClient" directive. In this directive, you can switch "bool Disable" from false to true, and reboot the VPN Server, then the Dynamic DNS Function will be disabled. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. */
    ChangeDDnsClientHostname: (in_param: VpnRpcTest) => Promise<VpnRpcTest>;
    /** Generate New Self-Signed Certificate with Specified CN (Common Name) and Register on VPN Server. You can specify the new CN (common name) value on the StrValue_str field. You can use this API to replace the current certificate on the VPN Server to a new self-signed certificate which has the CN (Common Name) value in the fields. This API is convenient if you are planning to use Microsoft SSTP VPN Clone Server Function. Because of the value of CN (Common Name) on the SSL certificate of VPN Server must match to the hostname specified on the SSTP VPN client. This API will delete the existing SSL certificate of the VPN Server. It is recommended to backup the current SSL certificate and private key by using the GetServerCert API beforehand. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    RegenerateServerCert: (in_param: VpnRpcTest) => Promise<VpnRpcTest>;
    /** Generate a Sample Setting File for OpenVPN Client. Originally, the OpenVPN Client requires a user to write a very difficult configuration file manually. This API helps you to make a useful configuration sample. What you need to generate the configuration file for the OpenVPN Client is to run this API. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    MakeOpenVpnConfigFile: () => Promise<VpnRpcReadLogFile>;
    /** Enable / Disable the VPN over ICMP / VPN over DNS Server Function. You can establish a VPN only with ICMP or DNS packets even if there is a firewall or routers which blocks TCP/IP communications. You have to enable the following functions beforehand. Warning: Use this function for emergency only. It is helpful when a firewall or router is misconfigured to blocks TCP/IP, but either ICMP or DNS is not blocked. It is not for long-term stable using. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. */
    SetSpecialListener: (in_param: VpnRpcSpecialListener) => Promise<VpnRpcSpecialListener>;
    /** Get Current Setting of the VPN over ICMP / VPN over DNS Function. Get and show the current VPN over ICMP / VPN over DNS Function status. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. */
    GetSpecialListener: () => Promise<VpnRpcSpecialListener>;
    /** Show the current status of VPN Azure function. Get and show the current status of the VPN Azure function. VPN Azure makes it easier to establish a VPN Session from your home PC to your office PC. While a VPN connection is established, you can access to any other servers on the private network of your company. You don't need a global IP address on the office PC (VPN Server). It can work behind firewalls or NATs. No network administrator's configuration required. You can use the built-in SSTP-VPN Client of Windows in your home PC. VPN Azure is a cloud VPN service operated by SoftEther Corporation. VPN Azure is free of charge and available to anyone. Visit http://www.vpnazure.net/ to see details and how-to-use instructions. The VPN Azure hostname is same to the hostname of the Dynamic DNS setting, but altering the domain suffix to "vpnazure.net". To change the hostname use the ChangeDDnsClientHostname API. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    GetAzureStatus: () => Promise<VpnRpcAzureStatus>;
    /** Enable / Disable VPN Azure Function. Enable or disable the VPN Azure function. VPN Azure makes it easier to establish a VPN Session from your home PC to your office PC. While a VPN connection is established, you can access to any other servers on the private network of your company. You don't need a global IP address on the office PC (VPN Server). It can work behind firewalls or NATs. No network administrator's configuration required. You can use the built-in SSTP-VPN Client of Windows in your home PC. VPN Azure is a cloud VPN service operated by SoftEther Corporation. VPN Azure is free of charge and available to anyone. Visit http://www.vpnazure.net/ to see details and how-to-use instructions. The VPN Azure hostname is same to the hostname of the Dynamic DNS setting, but altering the domain suffix to "vpnazure.net". To change the hostname use the ChangeDDnsClientHostname API. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster. */
    SetAzureStatus: (in_param: VpnRpcAzureStatus) => Promise<VpnRpcAzureStatus>;
    /** Get the Proxy Settings for Connecting to the DDNS server. */
    GetDDnsInternetSettng: () => Promise<VpnInternetSetting>;
    /** Set the Proxy Settings for Connecting to the DDNS server. */
    SetDDnsInternetSettng: (in_param: VpnInternetSetting) => Promise<VpnInternetSetting>;
    /** Set the VPN Gate Server Configuration. This API is valid for Win32 binary distribution of the Stable Edition of SoftEther VPN Server. */
    SetVgsConfig: (in_param: VpnVgsConfig) => Promise<VpnVgsConfig>;
    /** Get the VPN Gate Server Configuration. This API is valid for Win32 binary distribution of the Stable Edition of SoftEther VPN Server. */
    GetVgsConfig: () => Promise<VpnVgsConfig>;
    /** Call a RPC procedure */
    CallAsync<T>(method_name: string, request: T): Promise<T>;
}
/** IP Protocol Numbers */
export declare enum VpnIpProtocolNumber {
    /** ICMP for IPv4 */
    ICMPv4 = 1,
    /** TCP */
    TCP = 6,
    /** UDP */
    UDP = 17,
    /** ICMP for IPv6 */
    ICMPv6 = 58
}
/** The body of the Access list */
export declare class VpnAccess {
    /** ID */
    Id_u32: number;
    /** Specify a description (note) for this rule */
    Note_utf: string;
    /** Enabled flag (true: enabled, false: disabled) */
    Active_bool: boolean;
    /** Specify an integer of 1 or higher to indicate the priority of the rule. Higher priority is given to rules with the lower priority values. */
    Priority_u32: number;
    /** The flag if the rule is DISCARD operation or PASS operation. When a packet matches this rule condition, this operation is decided. When the operation of the rule is PASS, the packet is allowed to pass, otherwise the packet will be discarded. */
    Discard_bool: boolean;
    /** The flag if the rule is for IPv6. Specify false for IPv4, or specify true for IPv6. */
    IsIPv6_bool: boolean;
    /** Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a source IPv4 address as a rule condition. You must also specify the SrcSubnetMask_ip field. */
    SrcIpAddress_ip: string;
    /** Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a source IPv4 subnet mask as a rule condition. "0.0.0.0" means all hosts. "255.255.255.255" means one single host. */
    SrcSubnetMask_ip: string;
    /** Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a destination IPv4 address as a rule condition. You must also specify the DestSubnetMask_ip field. */
    DestIpAddress_ip: string;
    /** Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a destination IPv4 subnet mask as a rule condition. "0.0.0.0" means all hosts. "255.255.255.255" means one single host. */
    DestSubnetMask_ip: string;
    /** Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a source IPv6 address as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 address in binary form. You must also specify the SrcSubnetMask6_bin field. */
    SrcIpAddress6_bin: Uint8Array;
    /** Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a source IPv6 subnet mask as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 subnet mask in binary form. */
    SrcSubnetMask6_bin: Uint8Array;
    /** Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a destination IPv6 address as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 address in binary form. You must also specify the DestSubnetMask6_bin field. */
    DestIpAddress6_bin: Uint8Array;
    /** Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a destination IPv6 subnet mask as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 subnet mask in binary form. */
    DestSubnetMask6_bin: Uint8Array;
    /** The IP protocol number */
    Protocol_u32: VpnIpProtocolNumber;
    /** The Start Value of the Source Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the source port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers. */
    SrcPortStart_u32: number;
    /** The End Value of the Source Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the source port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers. */
    SrcPortEnd_u32: number;
    /** The Start Value of the Destination Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the destination port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers. */
    DestPortStart_u32: number;
    /** The End Value of the Destination Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the destination port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers. */
    DestPortEnd_u32: number;
    /** Source user name. You can apply this rule to only the packets sent by a user session of a user name that has been specified as a rule condition. In this case, specify the user name. */
    SrcUsername_str: string;
    /** Destination user name. You can apply this rule to only the packets received by a user session of a user name that has been specified as a rule condition. In this case, specify the user name. */
    DestUsername_str: string;
    /** Specify true if you want to check the source MAC address. */
    CheckSrcMac_bool: boolean;
    /** Source MAC address (6 bytes), valid only if CheckSrcMac_bool == true. */
    SrcMacAddress_bin: Uint8Array;
    /** Source MAC address mask (6 bytes), valid only if CheckSrcMac_bool == true. */
    SrcMacMask_bin: Uint8Array;
    /** Specify true if you want to check the destination MAC address. */
    CheckDstMac_bool: boolean;
    /** Destination MAC address (6 bytes), valid only if CheckSrcMac_bool == true. */
    DstMacAddress_bin: Uint8Array;
    /** Destination MAC address mask (6 bytes), valid only if CheckSrcMac_bool == true. */
    DstMacMask_bin: Uint8Array;
    /** Specify true if you want to check the state of the TCP connection. */
    CheckTcpState_bool: boolean;
    /** Valid only if CheckTcpState_bool == true. Set this field true to match only TCP-established packets. Set this field false to match only TCP-non established packets. */
    Established_bool: boolean;
    /** Set this value to generate delays when packets is passing. Specify the delay period in milliseconds. Specify 0 means no delays to generate. The delays must be 10000 milliseconds at most. */
    Delay_u32: number;
    /** Set this value to generate jitters when packets is passing. Specify the ratio of fluctuation of jitters within 0% to 100% range. Specify 0 means no jitters to generate. */
    Jitter_u32: number;
    /** Set this value to generate packet losses when packets is passing. Specify the ratio of packet losses within 0% to 100% range. Specify 0 means no packet losses to generate. */
    Loss_u32: number;
    /** The specified URL will be mandatory replied to the client as a response for TCP connecting request packets which matches the conditions of this access list entry via this Virtual Hub. To use this setting, you can enforce the web browser of the VPN Client computer to show the specified web site when that web browser tries to access the specific IP address. */
    RedirectUrl_str: string;
    /** Constructor for the 'VpnAccess' class: The body of the Access list */
    constructor(init?: Partial<VpnAccess>);
}
/** Add an item to Access List */
export declare class VpnRpcAddAccess {
    /** The Virtual Hub name */
    HubName_str: string;
    /** Access list (Must be a single item) */
    AccessListSingle: VpnAccess[];
    /** Constructor for the 'VpnRpcAddAccess' class: Add an item to Access List */
    constructor(init?: Partial<VpnRpcAddAccess>);
}
/** Add CA to HUB */
export declare class VpnRpcHubAddCA {
    /** The Virtual Hub name */
    HubName_str: string;
    /** The body of the X.509 certificate */
    Cert_bin: Uint8Array;
    /** Constructor for the 'VpnRpcHubAddCA' class: Add CA to HUB */
    constructor(init?: Partial<VpnRpcHubAddCA>);
}
/** CRL entry */
export declare class VpnRpcCrl {
    /** The Virtual Hub name */
    HubName_str: string;
    /** Key ID */
    Key_u32: number;
    /** CN, optional */
    CommonName_utf: string;
    /** O, optional */
    Organization_utf: string;
    /** OU, optional */
    Unit_utf: string;
    /** C, optional */
    Country_utf: string;
    /** ST, optional */
    State_utf: string;
    /** L, optional */
    Local_utf: string;
    /** Serial, optional */
    Serial_bin: Uint8Array;
    /** MD5 Digest, optional */
    DigestMD5_bin: Uint8Array;
    /** SHA1 Digest, optional */
    DigestSHA1_bin: Uint8Array;
    /** Constructor for the 'VpnRpcCrl' class: CRL entry */
    constructor(init?: Partial<VpnRpcCrl>);
}
/** EtherIP key list entry */
export declare class VpnEtherIpId {
    /** Specify an ISAKMP Phase 1 ID. The ID must be exactly same as a ID in the configuration of the EtherIP / L2TPv3 Client. You can specify IP address as well as characters as ID, if the EtherIP Client uses IP address as Phase 1 ID. If you specify '*' (asterisk), it will be a wildcard to match any clients which doesn't match other explicit rules. */
    Id_str: string;
    /** Specify the name of the Virtual Hub to connect. */
    HubName_str: string;
    /** Specify the username to login to the destination Virtual Hub. */
    UserName_str: string;
    /** Specify the password to login to the destination Virtual Hub. */
    Password_str: string;
    /** Constructor for the 'VpnEtherIpId' class: EtherIP key list entry */
    constructor(init?: Partial<VpnEtherIpId>);
}
/** Layer-3 virtual interface */
export declare class VpnRpcL3If {
    /** L3 switch name */
    Name_str: string;
    /** Virtual HUB name */
    HubName_str: string;
    /** IP address */
    IpAddress_ip: string;
    /** Subnet mask */
    SubnetMask_ip: string;
    /** Constructor for the 'VpnRpcL3If' class: Layer-3 virtual interface */
    constructor(init?: Partial<VpnRpcL3If>);
}
/** Layer-3 switch */
export declare class VpnRpcL3Sw {
    /** Layer-3 Switch name */
    Name_str: string;
    /** Constructor for the 'VpnRpcL3Sw' class: Layer-3 switch */
    constructor(init?: Partial<VpnRpcL3Sw>);
}
/** Routing table */
export declare class VpnRpcL3Table {
    /** L3 switch name */
    Name_str: string;
    /** Network address */
    NetworkAddress_ip: string;
    /** Subnet mask */
    SubnetMask_ip: string;
    /** Gateway address */
    GatewayAddress_ip: string;
    /** Metric */
    Metric_u32: number;
    /** Constructor for the 'VpnRpcL3Table' class: Routing table */
    constructor(init?: Partial<VpnRpcL3Table>);
}
/** Generic parameter to contain u32, u64, ascii_string and unicode string */
export declare class VpnRpcTest {
    /** A 32-bit integer field */
    IntValue_u32: number;
    /** A 64-bit integer field */
    Int64Value_u64: number;
    /** An Ascii string field */
    StrValue_str: string;
    /** An UTF-8 string field */
    UniStrValue_utf: string;
    /** Constructor for the 'VpnRpcTest' class: Generic parameter to contain u32, u64, ascii_string and unicode string */
    constructor(init?: Partial<VpnRpcTest>);
}
/** Local Bridge list item */
export declare class VpnRpcLocalBridge {
    /** Physical Ethernet device name */
    DeviceName_str: string;
    /** The Virtual Hub name */
    HubNameLB_str: string;
    /** Online flag */
    Online_bool: boolean;
    /** Running flag */
    Active_bool: boolean;
    /** Specify true if you are using a tap device rather than a network adapter for the bridge destination (only supported for Linux versions). */
    TapMode_bool: boolean;
    /** Constructor for the 'VpnRpcLocalBridge' class: Local Bridge list item */
    constructor(init?: Partial<VpnRpcLocalBridge>);
}
/** Create, configure, and get the group */
export declare class VpnRpcSetGroup {
    /** The Virtual Hub name */
    HubName_str: string;
    /** The group name */
    Name_str: string;
    /** Optional real name (full name) of the group, allow using any Unicode characters */
    Realname_utf: string;
    /** Optional, specify a description of the group */
    Note_utf: string;
    /** Number of broadcast packets (Recv) */
    ["Recv.BroadcastBytes_u64"]: number;
    /** Broadcast bytes (Recv) */
    ["Recv.BroadcastCount_u64"]: number;
    /** Unicast count (Recv) */
    ["Recv.UnicastBytes_u64"]: number;
    /** Unicast bytes (Recv) */
    ["Recv.UnicastCount_u64"]: number;
    /** Number of broadcast packets (Send) */
    ["Send.BroadcastBytes_u64"]: number;
    /** Broadcast bytes (Send) */
    ["Send.BroadcastCount_u64"]: number;
    /** Unicast bytes (Send) */
    ["Send.UnicastBytes_u64"]: number;
    /** Unicast bytes (Send) */
    ["Send.UnicastCount_u64"]: number;
    /** The flag whether to use security policy */
    UsePolicy_bool: boolean;
    /** Security policy: Allow Access. The users, which this policy value is true, have permission to make VPN connection to VPN Server. */
    ["policy:Access_bool"]: boolean;
    /** Security policy: Filter DHCP Packets (IPv4). All IPv4 DHCP packets in sessions defined this policy will be filtered. */
    ["policy:DHCPFilter_bool"]: boolean;
    /** Security policy: Disallow DHCP Server Operation (IPv4). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv4 addresses to DHCP clients. */
    ["policy:DHCPNoServer_bool"]: boolean;
    /** Security policy: Enforce DHCP Allocated IP Addresses (IPv4). Computers in sessions that have this policy setting will only be able to use IPv4 addresses allocated by a DHCP server on the virtual network side. */
    ["policy:DHCPForce_bool"]: boolean;
    /** Security policy: Deny Bridge Operation. Bridge-mode connections are denied for user sessions that have this policy setting. Even in cases when the Ethernet Bridge is configured in the client side, communication will not be possible. */
    ["policy:NoBridge_bool"]: boolean;
    /** Security policy: Deny Routing Operation (IPv4). IPv4 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible. */
    ["policy:NoRouting_bool"]: boolean;
    /** Security policy: Deny MAC Addresses Duplication. The use of duplicating MAC addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting. */
    ["policy:CheckMac_bool"]: boolean;
    /** Security policy: Deny IP Address Duplication (IPv4). The use of duplicating IPv4 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting. */
    ["policy:CheckIP_bool"]: boolean;
    /** Security policy: Deny Non-ARP / Non-DHCP / Non-ICMPv6 broadcasts. The sending or receiving of broadcast packets that are not ARP protocol, DHCP protocol, nor ICMPv6 on the virtual network will not be allowed for sessions with this policy setting. */
    ["policy:ArpDhcpOnly_bool"]: boolean;
    /** Security policy: Privacy Filter Mode. All direct communication between sessions with the privacy filter mode policy setting will be filtered. */
    ["policy:PrivacyFilter_bool"]: boolean;
    /** Security policy: Deny Operation as TCP/IP Server (IPv4). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv4. */
    ["policy:NoServer_bool"]: boolean;
    /** Security policy: Unlimited Number of Broadcasts. If a computer of a session with this policy setting sends broadcast packets of a number unusually larger than what would be considered normal on the virtual network, there will be no automatic limiting. */
    ["policy:NoBroadcastLimiter_bool"]: boolean;
    /** Security policy: Allow Monitoring Mode. Users with this policy setting will be granted to connect to the Virtual Hub in Monitoring Mode. Sessions in Monitoring Mode are able to monitor (tap) all packets flowing through the Virtual Hub. */
    ["policy:MonitorPort_bool"]: boolean;
    /** Security policy: Maximum Number of TCP Connections. For sessions with this policy setting, this sets the maximum number of physical TCP connections consists in a physical VPN session. */
    ["policy:MaxConnection_u32"]: number;
    /** Security policy: Time-out Period. For sessions with this policy setting, this sets, in seconds, the time-out period to wait before disconnecting a session when communication trouble occurs between the VPN Client / VPN Server. */
    ["policy:TimeOut_u32"]: number;
    /** Security policy: Maximum Number of MAC Addresses. For sessions with this policy setting, this limits the number of MAC addresses per session. */
    ["policy:MaxMac_u32"]: number;
    /** Security policy: Maximum Number of IP Addresses (IPv4). For sessions with this policy setting, this specifies the number of IPv4 addresses that can be registered for a single session. */
    ["policy:MaxIP_u32"]: number;
    /** Security policy: Upload Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the inwards direction from outside to inside the Virtual Hub. */
    ["policy:MaxUpload_u32"]: number;
    /** Security policy: Download Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the outwards direction from inside the Virtual Hub to outside the Virtual Hub. */
    ["policy:MaxDownload_u32"]: number;
    /** Security policy: Deny Changing Password. The users which use password authentication with this policy setting are not allowed to change their own password from the VPN Client Manager or similar. */
    ["policy:FixPassword_bool"]: boolean;
    /** Security policy: Maximum Number of Multiple Logins. Users with this policy setting are unable to have more than this number of concurrent logins. Bridge Mode sessions are not subjects to this policy. */
    ["policy:MultiLogins_u32"]: number;
    /** Security policy: Deny VoIP / QoS Function. Users with this security policy are unable to use VoIP / QoS functions in VPN connection sessions. */
    ["policy:NoQoS_bool"]: boolean;
    /** Security policy: Filter RS / RA Packets (IPv6). All ICMPv6 packets which the message-type is 133 (Router Solicitation) or 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, an IPv6 client will be unable to use IPv6 address prefix auto detection and IPv6 default gateway auto detection. */
    ["policy:RSandRAFilter_bool"]: boolean;
    /** Security policy: Filter RA Packets (IPv6). All ICMPv6 packets which the message-type is 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, a malicious users will be unable to spread illegal IPv6 prefix or default gateway advertisements on the network. */
    ["policy:RAFilter_bool"]: boolean;
    /** Security policy: Filter DHCP Packets (IPv6). All IPv6 DHCP packets in sessions defined this policy will be filtered. */
    ["policy:DHCPv6Filter_bool"]: boolean;
    /** Security policy: Disallow DHCP Server Operation (IPv6). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv6 addresses to DHCP clients. */
    ["policy:DHCPv6NoServer_bool"]: boolean;
    /** Security policy: Deny Routing Operation (IPv6). IPv6 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible. */
    ["policy:NoRoutingV6_bool"]: boolean;
    /** Security policy: Deny IP Address Duplication (IPv6). The use of duplicating IPv6 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting. */
    ["policy:CheckIPv6_bool"]: boolean;
    /** Security policy: Deny Operation as TCP/IP Server (IPv6). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv6. */
    ["policy:NoServerV6_bool"]: boolean;
    /** Security policy: Maximum Number of IP Addresses (IPv6). For sessions with this policy setting, this specifies the number of IPv6 addresses that can be registered for a single session. */
    ["policy:MaxIPv6_u32"]: number;
    /** Security policy: Disallow Password Save in VPN Client. For users with this policy setting, when the user is using *standard* password authentication, the user will be unable to save the password in VPN Client. The user will be required to input passwords for every time to connect a VPN. This will improve the security. If this policy is enabled, VPN Client Version 2.0 will be denied to access. */
    ["policy:NoSavePassword_bool"]: boolean;
    /** Security policy: VPN Client Automatic Disconnect. For users with this policy setting, a user's VPN session will be disconnected automatically after the specific period will elapse. In this case no automatic re-connection will be performed. This can prevent a lot of inactive VPN Sessions. If this policy is enabled, VPN Client Version 2.0 will be denied to access. */
    ["policy:AutoDisconnect_u32"]: number;
    /** Security policy: Filter All IPv4 Packets. All IPv4 and ARP packets in sessions defined this policy will be filtered. */
    ["policy:FilterIPv4_bool"]: boolean;
    /** Security policy: Filter All IPv6 Packets. All IPv6 packets in sessions defined this policy will be filtered. */
    ["policy:FilterIPv6_bool"]: boolean;
    /** Security policy: Filter All Non-IP Packets. All non-IP packets in sessions defined this policy will be filtered. "Non-IP packet" mean a packet which is not IPv4, ARP nor IPv6. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. */
    ["policy:FilterNonIP_bool"]: boolean;
    /** Security policy: No Default-Router on IPv6 RA. In all VPN Sessions defines this policy, any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router. */
    ["policy:NoIPv6DefaultRouterInRA_bool"]: boolean;
    /** Security policy: No Default-Router on IPv6 RA (physical IPv6). In all VPN Sessions defines this policy (only when the physical communication protocol between VPN Client / VPN Bridge and VPN Server is IPv6), any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router. */
    ["policy:NoIPv6DefaultRouterInRAWhenIPv6_bool"]: boolean;
    /** Security policy: VLAN ID (IEEE802.1Q). You can specify the VLAN ID on the security policy. All VPN Sessions defines this policy, all Ethernet packets toward the Virtual Hub from the user will be inserted a VLAN tag (IEEE 802.1Q) with the VLAN ID. The user can also receive only packets with a VLAN tag which has the same VLAN ID. (Receiving process removes the VLAN tag automatically.) Any Ethernet packets with any other VLAN IDs or non-VLAN packets will not be received. All VPN Sessions without this policy definition can send / receive any kinds of Ethernet packets regardless of VLAN tags, and VLAN tags are not inserted or removed automatically. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. Therefore, tagged-VLAN packets are not subjects for IPv4 / IPv6 security policies, access lists nor other IPv4 / IPv6 specific deep processing. */
    ["policy:VLanId_u32"]: number;
    /** Security policy: Whether version 3.0 (must be true) */
    ["policy:Ver3_bool"]: boolean;
    /** Constructor for the 'VpnRpcSetGroup' class: Create, configure, and get the group */
    constructor(init?: Partial<VpnRpcSetGroup>);
}
/** Hub types */
export declare enum VpnRpcHubType {
    /** Stand-alone HUB */
    Standalone = 0,
    /** Static HUB */
    FarmStatic = 1,
    /** Dynamic HUB */
    FarmDynamic = 2
}
/** Create a HUB */
export declare class VpnRpcCreateHub {
    /** Specify the name of the Virtual Hub to create / update. */
    HubName_str: string;
    /** Specify an administrator password when the administrator password is going to be set for the Virtual Hub. On the update, leave it to empty string if you don't want to change the password. */
    AdminPasswordPlainText_str: string;
    /** Online flag */
    Online_bool: boolean;
    /** Maximum number of VPN sessions */
    MaxSession_u32: number;
    /** No Enum flag. By enabling this option, the VPN Client user will be unable to enumerate this Virtual Hub even if they send a Virtual Hub enumeration request to the VPN Server. */
    NoEnum_bool: boolean;
    /** Type of the Virtual Hub (Valid only for Clustered VPN Servers) */
    HubType_u32: VpnRpcHubType;
    /** Constructor for the 'VpnRpcCreateHub' class: Create a HUB */
    constructor(init?: Partial<VpnRpcCreateHub>);
}
export declare enum VpnRpcClientAuthType {
    /** Anonymous authentication */
    Anonymous = 0,
    /** SHA-0 hashed password authentication */
    SHA0_Hashed_Password = 1,
    /** Plain password authentication */
    PlainPassword = 2,
    /** Certificate authentication */
    Cert = 3
}
/** Create and set of link */
export declare class VpnRpcCreateLink {
    /** The Virtual Hub name */
    HubName_Ex_str: string;
    /** Online flag */
    Online_bool: boolean;
    /** The flag to enable validation for the server certificate */
    CheckServerCert_bool: boolean;
    /** The body of server X.509 certificate to compare. Valid only if the CheckServerCert_bool flag is true. */
    ServerCert_bin: Uint8Array;
    /** Client Option Parameters: Specify the name of the Cascade Connection */
    AccountName_utf: string;
    /** Client Option Parameters: Specify the hostname of the destination VPN Server. You can also specify by IP address. */
    Hostname_str: string;
    /** Client Option Parameters: Specify the port number of the destination VPN Server. */
    Port_u32: number;
    /** Client Option Parameters: The type of the proxy server */
    ProxyType_u32: VpnRpcProxyType;
    /** Client Option Parameters: The hostname or IP address of the proxy server name */
    ProxyName_str: string;
    /** Client Option Parameters: The port number of the proxy server */
    ProxyPort_u32: number;
    /** Client Option Parameters: The username to connect to the proxy server */
    ProxyUsername_str: string;
    /** Client Option Parameters: The password to connect to the proxy server */
    ProxyPassword_str: string;
    /** Client Option Parameters: The Virtual Hub on the destination VPN Server */
    HubName_str: string;
    /** Client Option Parameters: Number of TCP Connections to Use in VPN Communication */
    MaxConnection_u32: number;
    /** Client Option Parameters: The flag to enable the encryption on the communication */
    UseEncrypt_bool: boolean;
    /** Client Option Parameters: Enable / Disable Data Compression when Communicating by Cascade Connection */
    UseCompress_bool: boolean;
    /** Client Option Parameters: Specify true when enabling half duplex mode. When using two or more TCP connections for VPN communication, it is possible to use Half Duplex Mode. By enabling half duplex mode it is possible to automatically fix data transmission direction as half and half for each TCP connection. In the case where a VPN using 8 TCP connections is established, for example, when half-duplex is enabled, communication can be fixes so that 4 TCP connections are dedicated to the upload direction and the other 4 connections are dedicated to the download direction. */
    HalfConnection_bool: boolean;
    /** Client Option Parameters: Connection attempt interval when additional connection will be established */
    AdditionalConnectionInterval_u32: number;
    /** Client Option Parameters: Connection Life of Each TCP Connection (0 for no keep-alive) */
    ConnectionDisconnectSpan_u32: number;
    /** Client Option Parameters: Disable QoS Control Function if the value is true */
    DisableQoS_bool: boolean;
    /** Client Option Parameters: Do not use TLS 1.x of the value is true */
    NoTls1_bool: boolean;
    /** Client Option Parameters: Do not use UDP acceleration mode if the value is true */
    NoUdpAcceleration_bool: boolean;
    /** Authentication type */
    AuthType_u32: VpnRpcClientAuthType;
    /** User name */
    Username_str: string;
    /** SHA-0 Hashed password. Valid only if ClientAuth_AuthType_u32 == SHA0_Hashed_Password (1). The SHA-0 hashed password must be caluclated by the SHA0(UpperCase(username_ascii_string) + password_ascii_string). */
    HashedPassword_bin: Uint8Array;
    /** Plaintext Password. Valid only if ClientAuth_AuthType_u32 == PlainPassword (2). */
    PlainPassword_str: string;
    /** Client certificate. Valid only if ClientAuth_AuthType_u32 == Cert (3). */
    ClientX_bin: Uint8Array;
    /** Client private key of the certificate. Valid only if ClientAuth_AuthType_u32 == Cert (3). */
    ClientK_bin: Uint8Array;
    /** Security policy: Filter DHCP Packets (IPv4). All IPv4 DHCP packets in sessions defined this policy will be filtered. */
    ["policy:DHCPFilter_bool"]: boolean;
    /** Security policy: Disallow DHCP Server Operation (IPv4). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv4 addresses to DHCP clients. */
    ["policy:DHCPNoServer_bool"]: boolean;
    /** Security policy: Enforce DHCP Allocated IP Addresses (IPv4). Computers in sessions that have this policy setting will only be able to use IPv4 addresses allocated by a DHCP server on the virtual network side. */
    ["policy:DHCPForce_bool"]: boolean;
    /** Security policy: Prohibit the duplicate MAC address */
    SecPol_CheckMac_bool: boolean;
    /** Security policy: Prohibit a duplicate IP address (IPv4) */
    SecPol_CheckIP_bool: boolean;
    /** Security policy: Deny Non-ARP / Non-DHCP / Non-ICMPv6 broadcasts. The sending or receiving of broadcast packets that are not ARP protocol, DHCP protocol, nor ICMPv6 on the virtual network will not be allowed for sessions with this policy setting. */
    ["policy:ArpDhcpOnly_bool"]: boolean;
    /** Security policy: Privacy Filter Mode. All direct communication between sessions with the privacy filter mode policy setting will be filtered. */
    ["policy:PrivacyFilter_bool"]: boolean;
    /** Security policy: Deny Operation as TCP/IP Server (IPv4). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv4. */
    ["policy:NoServer_bool"]: boolean;
    /** Security policy: Unlimited Number of Broadcasts. If a computer of a session with this policy setting sends broadcast packets of a number unusually larger than what would be considered normal on the virtual network, there will be no automatic limiting. */
    ["policy:NoBroadcastLimiter_bool"]: boolean;
    /** Security policy: Maximum Number of MAC Addresses. For sessions with this policy setting, this limits the number of MAC addresses per session. */
    ["policy:MaxMac_u32"]: number;
    /** Security policy: Maximum Number of IP Addresses (IPv4). For sessions with this policy setting, this specifies the number of IPv4 addresses that can be registered for a single session. */
    ["policy:MaxIP_u32"]: number;
    /** Security policy: Upload Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the inwards direction from outside to inside the Virtual Hub. */
    ["policy:MaxUpload_u32"]: number;
    /** Security policy: Download Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the outwards direction from inside the Virtual Hub to outside the Virtual Hub. */
    ["policy:MaxDownload_u32"]: number;
    /** Security policy: Filter RS / RA Packets (IPv6). All ICMPv6 packets which the message-type is 133 (Router Solicitation) or 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, an IPv6 client will be unable to use IPv6 address prefix auto detection and IPv6 default gateway auto detection. */
    ["policy:RSandRAFilter_bool"]: boolean;
    /** Security policy: Filter the router advertisement packet (IPv6) */
    SecPol_RAFilter_bool: boolean;
    /** Security policy: Filter DHCP Packets (IPv6). All IPv6 DHCP packets in sessions defined this policy will be filtered. */
    ["policy:DHCPv6Filter_bool"]: boolean;
    /** Security policy: Disallow DHCP Server Operation (IPv6). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv6 addresses to DHCP clients. */
    ["policy:DHCPv6NoServer_bool"]: boolean;
    /** Security policy: Prohibit the duplicate IP address (IPv6) */
    SecPol_CheckIPv6_bool: boolean;
    /** Security policy: Deny Operation as TCP/IP Server (IPv6). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv6. */
    ["policy:NoServerV6_bool"]: boolean;
    /** Security policy: Maximum Number of IP Addresses (IPv6). For sessions with this policy setting, this specifies the number of IPv6 addresses that can be registered for a single session. */
    ["policy:MaxIPv6_u32"]: number;
    /** Security policy: Filter All IPv4 Packets. All IPv4 and ARP packets in sessions defined this policy will be filtered. */
    ["policy:FilterIPv4_bool"]: boolean;
    /** Security policy: Filter All IPv6 Packets. All IPv6 packets in sessions defined this policy will be filtered. */
    ["policy:FilterIPv6_bool"]: boolean;
    /** Security policy: Filter All Non-IP Packets. All non-IP packets in sessions defined this policy will be filtered. "Non-IP packet" mean a packet which is not IPv4, ARP nor IPv6. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. */
    ["policy:FilterNonIP_bool"]: boolean;
    /** Security policy: No Default-Router on IPv6 RA. In all VPN Sessions defines this policy, any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router. */
    ["policy:NoIPv6DefaultRouterInRA_bool"]: boolean;
    /** Security policy: VLAN ID (IEEE802.1Q). You can specify the VLAN ID on the security policy. All VPN Sessions defines this policy, all Ethernet packets toward the Virtual Hub from the user will be inserted a VLAN tag (IEEE 802.1Q) with the VLAN ID. The user can also receive only packets with a VLAN tag which has the same VLAN ID. (Receiving process removes the VLAN tag automatically.) Any Ethernet packets with any other VLAN IDs or non-VLAN packets will not be received. All VPN Sessions without this policy definition can send / receive any kinds of Ethernet packets regardless of VLAN tags, and VLAN tags are not inserted or removed automatically. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. Therefore, tagged-VLAN packets are not subjects for IPv4 / IPv6 security policies, access lists nor other IPv4 / IPv6 specific deep processing. */
    ["policy:VLanId_u32"]: number;
    /** Security policy: Whether version 3.0 (must be true) */
    ["policy:Ver3_bool"]: boolean;
    /** Constructor for the 'VpnRpcCreateLink' class: Create and set of link */
    constructor(init?: Partial<VpnRpcCreateLink>);
}
/** Listener */
export declare class VpnRpcListener {
    /** Port number (Range: 1 - 65535) */
    Port_u32: number;
    /** Active state */
    Enable_bool: boolean;
    /** Constructor for the 'VpnRpcListener' class: Listener */
    constructor(init?: Partial<VpnRpcListener>);
}
/** User authentication type (server side) */
export declare enum VpnRpcUserAuthType {
    /** Anonymous authentication */
    Anonymous = 0,
    /** Password authentication */
    Password = 1,
    /** User certificate authentication */
    UserCert = 2,
    /** Root certificate which is issued by trusted Certificate Authority */
    RootCert = 3,
    /** Radius authentication */
    Radius = 4,
    /** Windows NT authentication */
    NTDomain = 5
}
/** Create, configure, and get the user */
export declare class VpnRpcSetUser {
    /** The Virtual Hub name */
    HubName_str: string;
    /** Specify the user name of the user */
    Name_str: string;
    /** Assigned group name for the user */
    GroupName_str: string;
    /** Optional real name (full name) of the user, allow using any Unicode characters */
    Realname_utf: string;
    /** Optional User Description */
    Note_utf: string;
    /** Creation date and time */
    CreatedTime_dt: Date;
    /** Last modified date and time */
    UpdatedTime_dt: Date;
    /** Expiration date and time */
    ExpireTime_dt: Date;
    /** Authentication method of the user */
    AuthType_u32: VpnRpcUserAuthType;
    /** User password, valid only if AuthType_u32 == Password(1). Valid only to create or set operations. */
    Auth_Password_str: string;
    /** User certificate, valid only if AuthType_u32 == UserCert(2). */
    UserX_bin: Uint8Array;
    /** Certificate Serial Number, optional, valid only if AuthType_u32 == RootCert(3). */
    Serial_bin: Uint8Array;
    /** Certificate Common Name, optional, valid only if AuthType_u32 == RootCert(3). */
    CommonName_utf: string;
    /** Username in RADIUS server, optional, valid only if AuthType_u32 == Radius(4). */
    RadiusUsername_utf: string;
    /** Username in NT Domain server, optional, valid only if AuthType_u32 == NT(5). */
    NtUsername_utf: string;
    /** Number of total logins of the user */
    NumLogin_u32: number;
    /** Number of broadcast packets (Recv) */
    ["Recv.BroadcastBytes_u64"]: number;
    /** Broadcast bytes (Recv) */
    ["Recv.BroadcastCount_u64"]: number;
    /** Unicast count (Recv) */
    ["Recv.UnicastBytes_u64"]: number;
    /** Unicast bytes (Recv) */
    ["Recv.UnicastCount_u64"]: number;
    /** Number of broadcast packets (Send) */
    ["Send.BroadcastBytes_u64"]: number;
    /** Broadcast bytes (Send) */
    ["Send.BroadcastCount_u64"]: number;
    /** Unicast bytes (Send) */
    ["Send.UnicastBytes_u64"]: number;
    /** Unicast bytes (Send) */
    ["Send.UnicastCount_u64"]: number;
    /** The flag whether to use security policy */
    UsePolicy_bool: boolean;
    /** Security policy: Allow Access. The users, which this policy value is true, have permission to make VPN connection to VPN Server. */
    ["policy:Access_bool"]: boolean;
    /** Security policy: Filter DHCP Packets (IPv4). All IPv4 DHCP packets in sessions defined this policy will be filtered. */
    ["policy:DHCPFilter_bool"]: boolean;
    /** Security policy: Disallow DHCP Server Operation (IPv4). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv4 addresses to DHCP clients. */
    ["policy:DHCPNoServer_bool"]: boolean;
    /** Security policy: Enforce DHCP Allocated IP Addresses (IPv4). Computers in sessions that have this policy setting will only be able to use IPv4 addresses allocated by a DHCP server on the virtual network side. */
    ["policy:DHCPForce_bool"]: boolean;
    /** Security policy: Deny Bridge Operation. Bridge-mode connections are denied for user sessions that have this policy setting. Even in cases when the Ethernet Bridge is configured in the client side, communication will not be possible. */
    ["policy:NoBridge_bool"]: boolean;
    /** Security policy: Deny Routing Operation (IPv4). IPv4 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible. */
    ["policy:NoRouting_bool"]: boolean;
    /** Security policy: Deny MAC Addresses Duplication. The use of duplicating MAC addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting. */
    ["policy:CheckMac_bool"]: boolean;
    /** Security policy: Deny IP Address Duplication (IPv4). The use of duplicating IPv4 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting. */
    ["policy:CheckIP_bool"]: boolean;
    /** Security policy: Deny Non-ARP / Non-DHCP / Non-ICMPv6 broadcasts. The sending or receiving of broadcast packets that are not ARP protocol, DHCP protocol, nor ICMPv6 on the virtual network will not be allowed for sessions with this policy setting. */
    ["policy:ArpDhcpOnly_bool"]: boolean;
    /** Security policy: Privacy Filter Mode. All direct communication between sessions with the privacy filter mode policy setting will be filtered. */
    ["policy:PrivacyFilter_bool"]: boolean;
    /** Security policy: Deny Operation as TCP/IP Server (IPv4). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv4. */
    ["policy:NoServer_bool"]: boolean;
    /** Security policy: Unlimited Number of Broadcasts. If a computer of a session with this policy setting sends broadcast packets of a number unusually larger than what would be considered normal on the virtual network, there will be no automatic limiting. */
    ["policy:NoBroadcastLimiter_bool"]: boolean;
    /** Security policy: Allow Monitoring Mode. Users with this policy setting will be granted to connect to the Virtual Hub in Monitoring Mode. Sessions in Monitoring Mode are able to monitor (tap) all packets flowing through the Virtual Hub. */
    ["policy:MonitorPort_bool"]: boolean;
    /** Security policy: Maximum Number of TCP Connections. For sessions with this policy setting, this sets the maximum number of physical TCP connections consists in a physical VPN session. */
    ["policy:MaxConnection_u32"]: number;
    /** Security policy: Time-out Period. For sessions with this policy setting, this sets, in seconds, the time-out period to wait before disconnecting a session when communication trouble occurs between the VPN Client / VPN Server. */
    ["policy:TimeOut_u32"]: number;
    /** Security policy: Maximum Number of MAC Addresses. For sessions with this policy setting, this limits the number of MAC addresses per session. */
    ["policy:MaxMac_u32"]: number;
    /** Security policy: Maximum Number of IP Addresses (IPv4). For sessions with this policy setting, this specifies the number of IPv4 addresses that can be registered for a single session. */
    ["policy:MaxIP_u32"]: number;
    /** Security policy: Upload Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the inwards direction from outside to inside the Virtual Hub. */
    ["policy:MaxUpload_u32"]: number;
    /** Security policy: Download Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the outwards direction from inside the Virtual Hub to outside the Virtual Hub. */
    ["policy:MaxDownload_u32"]: number;
    /** Security policy: Deny Changing Password. The users which use password authentication with this policy setting are not allowed to change their own password from the VPN Client Manager or similar. */
    ["policy:FixPassword_bool"]: boolean;
    /** Security policy: Maximum Number of Multiple Logins. Users with this policy setting are unable to have more than this number of concurrent logins. Bridge Mode sessions are not subjects to this policy. */
    ["policy:MultiLogins_u32"]: number;
    /** Security policy: Deny VoIP / QoS Function. Users with this security policy are unable to use VoIP / QoS functions in VPN connection sessions. */
    ["policy:NoQoS_bool"]: boolean;
    /** Security policy: Filter RS / RA Packets (IPv6). All ICMPv6 packets which the message-type is 133 (Router Solicitation) or 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, an IPv6 client will be unable to use IPv6 address prefix auto detection and IPv6 default gateway auto detection. */
    ["policy:RSandRAFilter_bool"]: boolean;
    /** Security policy: Filter RA Packets (IPv6). All ICMPv6 packets which the message-type is 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, a malicious users will be unable to spread illegal IPv6 prefix or default gateway advertisements on the network. */
    ["policy:RAFilter_bool"]: boolean;
    /** Security policy: Filter DHCP Packets (IPv6). All IPv6 DHCP packets in sessions defined this policy will be filtered. */
    ["policy:DHCPv6Filter_bool"]: boolean;
    /** Security policy: Disallow DHCP Server Operation (IPv6). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv6 addresses to DHCP clients. */
    ["policy:DHCPv6NoServer_bool"]: boolean;
    /** Security policy: Deny Routing Operation (IPv6). IPv6 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible. */
    ["policy:NoRoutingV6_bool"]: boolean;
    /** Security policy: Deny IP Address Duplication (IPv6). The use of duplicating IPv6 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting. */
    ["policy:CheckIPv6_bool"]: boolean;
    /** Security policy: Deny Operation as TCP/IP Server (IPv6). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv6. */
    ["policy:NoServerV6_bool"]: boolean;
    /** Security policy: Maximum Number of IP Addresses (IPv6). For sessions with this policy setting, this specifies the number of IPv6 addresses that can be registered for a single session. */
    ["policy:MaxIPv6_u32"]: number;
    /** Security policy: Disallow Password Save in VPN Client. For users with this policy setting, when the user is using *standard* password authentication, the user will be unable to save the password in VPN Client. The user will be required to input passwords for every time to connect a VPN. This will improve the security. If this policy is enabled, VPN Client Version 2.0 will be denied to access. */
    ["policy:NoSavePassword_bool"]: boolean;
    /** Security policy: VPN Client Automatic Disconnect. For users with this policy setting, a user's VPN session will be disconnected automatically after the specific period will elapse. In this case no automatic re-connection will be performed. This can prevent a lot of inactive VPN Sessions. If this policy is enabled, VPN Client Version 2.0 will be denied to access. */
    ["policy:AutoDisconnect_u32"]: number;
    /** Security policy: Filter All IPv4 Packets. All IPv4 and ARP packets in sessions defined this policy will be filtered. */
    ["policy:FilterIPv4_bool"]: boolean;
    /** Security policy: Filter All IPv6 Packets. All IPv6 packets in sessions defined this policy will be filtered. */
    ["policy:FilterIPv6_bool"]: boolean;
    /** Security policy: Filter All Non-IP Packets. All non-IP packets in sessions defined this policy will be filtered. "Non-IP packet" mean a packet which is not IPv4, ARP nor IPv6. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. */
    ["policy:FilterNonIP_bool"]: boolean;
    /** Security policy: No Default-Router on IPv6 RA. In all VPN Sessions defines this policy, any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router. */
    ["policy:NoIPv6DefaultRouterInRA_bool"]: boolean;
    /** Security policy: No Default-Router on IPv6 RA (physical IPv6). In all VPN Sessions defines this policy (only when the physical communication protocol between VPN Client / VPN Bridge and VPN Server is IPv6), any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router. */
    ["policy:NoIPv6DefaultRouterInRAWhenIPv6_bool"]: boolean;
    /** Security policy: VLAN ID (IEEE802.1Q). You can specify the VLAN ID on the security policy. All VPN Sessions defines this policy, all Ethernet packets toward the Virtual Hub from the user will be inserted a VLAN tag (IEEE 802.1Q) with the VLAN ID. The user can also receive only packets with a VLAN tag which has the same VLAN ID. (Receiving process removes the VLAN tag automatically.) Any Ethernet packets with any other VLAN IDs or non-VLAN packets will not be received. All VPN Sessions without this policy definition can send / receive any kinds of Ethernet packets regardless of VLAN tags, and VLAN tags are not inserted or removed automatically. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. Therefore, tagged-VLAN packets are not subjects for IPv4 / IPv6 security policies, access lists nor other IPv4 / IPv6 specific deep processing. */
    ["policy:VLanId_u32"]: number;
    /** Security policy: Whether version 3.0 (must be true) */
    ["policy:Ver3_bool"]: boolean;
    /** Constructor for the 'VpnRpcSetUser' class: Create, configure, and get the user */
    constructor(init?: Partial<VpnRpcSetUser>);
}
/** Delete the access list */
export declare class VpnRpcDeleteAccess {
    /** The Virtual Hub name */
    HubName_str: string;
    /** ID */
    Id_u32: number;
    /** Constructor for the 'VpnRpcDeleteAccess' class: Delete the access list */
    constructor(init?: Partial<VpnRpcDeleteAccess>);
}
/** Delete the CA of HUB */
export declare class VpnRpcHubDeleteCA {
    /** The Virtual Hub name */
    HubName_str: string;
    /** Certificate key id to be deleted */
    Key_u32: number;
    /** Constructor for the 'VpnRpcHubDeleteCA' class: Delete the CA of HUB */
    constructor(init?: Partial<VpnRpcHubDeleteCA>);
}
/** Deleting a user or group */
export declare class VpnRpcDeleteUser {
    /** The Virtual Hub name */
    HubName_str: string;
    /** User or group name */
    Name_str: string;
    /** Constructor for the 'VpnRpcDeleteUser' class: Deleting a user or group */
    constructor(init?: Partial<VpnRpcDeleteUser>);
}
/** Delete the HUB */
export declare class VpnRpcDeleteHub {
    /** The Virtual Hub name */
    HubName_str: string;
    /** Constructor for the 'VpnRpcDeleteHub' class: Delete the HUB */
    constructor(init?: Partial<VpnRpcDeleteHub>);
}
/** Delete the table */
export declare class VpnRpcDeleteTable {
    /** The Virtual Hub name */
    HubName_str: string;
    /** Key ID */
    Key_u32: number;
    /** Constructor for the 'VpnRpcDeleteTable' class: Delete the table */
    constructor(init?: Partial<VpnRpcDeleteTable>);
}
/** Specify the Link */
export declare class VpnRpcLink {
    /** The Virtual Hub name */
    HubName_str: string;
    /** The name of the cascade connection */
    AccountName_utf: string;
    /** Constructor for the 'VpnRpcLink' class: Specify the Link */
    constructor(init?: Partial<VpnRpcLink>);
}
/** Disconnect the session */
export declare class VpnRpcDeleteSession {
    /** The Virtual Hub name */
    HubName_str: string;
    /** Session name */
    Name_str: string;
    /** Constructor for the 'VpnRpcDeleteSession' class: Disconnect the session */
    constructor(init?: Partial<VpnRpcDeleteSession>);
}
/** Specify the HUB */
export declare class VpnRpcHub {
    /** The Virtual Hub name */
    HubName_str: string;
    /** Constructor for the 'VpnRpcHub' class: Specify the HUB */
    constructor(init?: Partial<VpnRpcHub>);
}
/** Disconnect a connection */
export declare class VpnRpcDisconnectConnection {
    /** Connection name */
    Name_str: string;
    /** Constructor for the 'VpnRpcDisconnectConnection' class: Disconnect a connection */
    constructor(init?: Partial<VpnRpcDisconnectConnection>);
}
/** Enumeration of the access list */
export declare class VpnRpcEnumAccessList {
    /** The Virtual Hub name */
    HubName_str: string;
    /** Access list */
    AccessList: VpnAccess[];
    /** Constructor for the 'VpnRpcEnumAccessList' class: Enumeration of the access list */
    constructor(init?: Partial<VpnRpcEnumAccessList>);
}
/** CA enumeration items of HUB */
export declare class VpnRpcHubEnumCAItem {
    /** The key id of the item */
    Key_u32: number;
    /** Subject */
    SubjectName_utf: string;
    /** Issuer */
    IssuerName_utf: string;
    /** Expiration date */
    Expires_dt: Date;
    /** Constructor for the 'VpnRpcHubEnumCAItem' class: CA enumeration items of HUB */
    constructor(init?: Partial<VpnRpcHubEnumCAItem>);
}
/** CA enumeration of HUB */
export declare class VpnRpcHubEnumCA {
    /** The Virtual Hub name */
    HubName_str: string;
    /** The list of CA */
    CAList: VpnRpcHubEnumCAItem[];
    /** Constructor for the 'VpnRpcHubEnumCA' class: CA enumeration of HUB */
    constructor(init?: Partial<VpnRpcHubEnumCA>);
}
/** Type of connection */
export declare enum VpnRpcConnectionType {
    /** VPN Client */
    Client = 0,
    /** During initialization */
    Init = 1,
    /** Login connection */
    Login = 2,
    /** Additional connection */
    Additional = 3,
    /** RPC for server farm */
    FarmRpc = 4,
    /** RPC for Management */
    AdminRpc = 5,
    /** HUB enumeration */
    EnumHub = 6,
    /** Password change */
    Password = 7,
    /** SSTP */
    SSTP = 8,
    /** OpenVPN */
    OpenVPN = 9
}
/** Connection enumeration items */
export declare class VpnRpcEnumConnectionItem {
    /** Connection name */
    Name_str: string;
    /** Host name */
    Hostname_str: string;
    /** IP address */
    Ip_ip: string;
    /** Port number */
    Port_u32: number;
    /** Connected time */
    ConnectedTime_dt: Date;
    /** Connection type */
    Type_u32: VpnRpcConnectionType;
    /** Constructor for the 'VpnRpcEnumConnectionItem' class: Connection enumeration items */
    constructor(init?: Partial<VpnRpcEnumConnectionItem>);
}
/** Connection enumeration */
export declare class VpnRpcEnumConnection {
    /** Number of connections */
    NumConnection_u32: number;
    /** Connection list */
    ConnectionList: VpnRpcEnumConnectionItem[];
    /** Constructor for the 'VpnRpcEnumConnection' class: Connection enumeration */
    constructor(init?: Partial<VpnRpcEnumConnection>);
}
/** Enum CRL Item */
export declare class VpnRpcEnumCrlItem {
    /** Key ID */
    Key_u32: number;
    /** The contents of the CRL item */
    CrlInfo_utf: string;
    /** Constructor for the 'VpnRpcEnumCrlItem' class: Enum CRL Item */
    constructor(init?: Partial<VpnRpcEnumCrlItem>);
}
/** Enum CRL */
export declare class VpnRpcEnumCrl {
    /** The Virtual Hub name */
    HubName_str: string;
    /** CRL list */
    CRLList: VpnRpcEnumCrlItem[];
    /** Constructor for the 'VpnRpcEnumCrl' class: Enum CRL */
    constructor(init?: Partial<VpnRpcEnumCrl>);
}
/** RPC_ENUM_DHCP_ITEM */
export declare class VpnRpcEnumDhcpItem {
    /** ID */
    Id_u32: number;
    /** Lease time */
    LeasedTime_dt: Date;
    /** Expiration date */
    ExpireTime_dt: Date;
    /** MAC address */
    MacAddress_bin: Uint8Array;
    /** IP address */
    IpAddress_ip: string;
    /** Subnet mask */
    Mask_u32: number;
    /** Host name */
    Hostname_str: string;
    /** Constructor for the 'VpnRpcEnumDhcpItem' class: RPC_ENUM_DHCP_ITEM */
    constructor(init?: Partial<VpnRpcEnumDhcpItem>);
}
/** RPC_ENUM_DHCP */
export declare class VpnRpcEnumDhcp {
    /** Virtual Hub Name */
    HubName_str: string;
    /** DHCP Item */
    DhcpTable: VpnRpcEnumDhcpItem[];
    /** Constructor for the 'VpnRpcEnumDhcp' class: RPC_ENUM_DHCP */
    constructor(init?: Partial<VpnRpcEnumDhcp>);
}
/** EtherIP setting list */
export declare class VpnRpcEnumEtherIpId {
    /** Setting list */
    Settings: VpnEtherIpId[];
    /** Constructor for the 'VpnRpcEnumEtherIpId' class: EtherIP setting list */
    constructor(init?: Partial<VpnRpcEnumEtherIpId>);
}
/** Ethernet Network Adapters list item */
export declare class VpnRpcEnumEthItem {
    /** Device name */
    DeviceName_str: string;
    /** Network connection name (description) */
    NetworkConnectionName_utf: string;
    /** Constructor for the 'VpnRpcEnumEthItem' class: Ethernet Network Adapters list item */
    constructor(init?: Partial<VpnRpcEnumEthItem>);
}
/** Ethernet Network Adapters list */
export declare class VpnRpcEnumEth {
    /** Ethernet Network Adapters list */
    EthList: VpnRpcEnumEthItem[];
    /** Constructor for the 'VpnRpcEnumEth' class: Ethernet Network Adapters list */
    constructor(init?: Partial<VpnRpcEnumEth>);
}
/** Server farm members enumeration items */
export declare class VpnRpcEnumFarmItem {
    /** ID */
    Id_u32: number;
    /** Controller */
    Controller_bool: boolean;
    /** Connection time */
    ConnectedTime_dt: Date;
    /** IP address */
    Ip_ip: string;
    /** Host name */
    Hostname_str: string;
    /** Point */
    Point_u32: number;
    /** Number of sessions */
    NumSessions_u32: number;
    /** Number of TCP connections */
    NumTcpConnections_u32: number;
    /** Number of HUBs */
    NumHubs_u32: number;
    /** Number of assigned client licenses */
    AssignedClientLicense_u32: number;
    /** Number of assigned bridge licenses */
    AssignedBridgeLicense_u32: number;
    /** Constructor for the 'VpnRpcEnumFarmItem' class: Server farm members enumeration items */
    constructor(init?: Partial<VpnRpcEnumFarmItem>);
}
/** Server farm member enumeration */
export declare class VpnRpcEnumFarm {
    /** Number of Cluster Members */
    NumFarm_u32: number;
    /** Cluster Members list */
    FarmMemberList: VpnRpcEnumFarmItem[];
    /** Constructor for the 'VpnRpcEnumFarm' class: Server farm member enumeration */
    constructor(init?: Partial<VpnRpcEnumFarm>);
}
/** Enumeration items in the group */
export declare class VpnRpcEnumGroupItem {
    /** User name */
    Name_str: string;
    /** Real name */
    Realname_utf: string;
    /** Note */
    Note_utf: string;
    /** Number of users */
    NumUsers_u32: number;
    /** Access denied */
    DenyAccess_bool: boolean;
    /** Constructor for the 'VpnRpcEnumGroupItem' class: Enumeration items in the group */
    constructor(init?: Partial<VpnRpcEnumGroupItem>);
}
/** Group enumeration */
export declare class VpnRpcEnumGroup {
    /** The Virtual Hub name */
    HubName_str: string;
    /** Group list */
    GroupList: VpnRpcEnumGroupItem[];
    /** Constructor for the 'VpnRpcEnumGroup' class: Group enumeration */
    constructor(init?: Partial<VpnRpcEnumGroup>);
}
/** Enumeration items of HUB */
export declare class VpnRpcEnumHubItem {
    /** The name of the Virtual Hub */
    HubName_str: string;
    /** Online state */
    Online_bool: boolean;
    /** Type of HUB (Valid only for Clustered VPN Servers) */
    HubType_u32: VpnRpcHubType;
    /** Number of users */
    NumUsers_u32: number;
    /** Number of registered groups */
    NumGroups_u32: number;
    /** Number of registered sessions */
    NumSessions_u32: number;
    /** Number of current MAC table entries */
    NumMacTables_u32: number;
    /** Number of current IP table entries */
    NumIpTables_u32: number;
    /** Last communication date and time */
    LastCommTime_dt: Date;
    /** Last login date and time */
    LastLoginTime_dt: Date;
    /** Creation date and time */
    CreatedTime_dt: Date;
    /** Number of accumulated logins */
    NumLogin_u32: number;
    /** Whether the traffic information is provided */
    IsTrafficFilled_bool: boolean;
    /** Number of broadcast packets (Recv) */
    ["Ex.Recv.BroadcastBytes_u64"]: number;
    /** Broadcast bytes (Recv) */
    ["Ex.Recv.BroadcastCount_u64"]: number;
    /** Unicast count (Recv) */
    ["Ex.Recv.UnicastBytes_u64"]: number;
    /** Unicast bytes (Recv) */
    ["Ex.Recv.UnicastCount_u64"]: number;
    /** Number of broadcast packets (Send) */
    ["Ex.Send.BroadcastBytes_u64"]: number;
    /** Broadcast bytes (Send) */
    ["Ex.Send.BroadcastCount_u64"]: number;
    /** Unicast bytes (Send) */
    ["Ex.Send.UnicastBytes_u64"]: number;
    /** Unicast bytes (Send) */
    ["Ex.Send.UnicastCount_u64"]: number;
    /** Constructor for the 'VpnRpcEnumHubItem' class: Enumeration items of HUB */
    constructor(init?: Partial<VpnRpcEnumHubItem>);
}
/** Enumeration of HUB */
export declare class VpnRpcEnumHub {
    /** Number of Virtual Hubs */
    NumHub_u32: number;
    /** Virtual Hubs */
    HubList: VpnRpcEnumHubItem[];
    /** Constructor for the 'VpnRpcEnumHub' class: Enumeration of HUB */
    constructor(init?: Partial<VpnRpcEnumHub>);
}
/** Enumeration items of IP table */
export declare class VpnRpcEnumIpTableItem {
    /** Key ID */
    Key_u32: number;
    /** Session name */
    SessionName_str: string;
    /** IP address */
    IpAddress_ip: string;
    /** Assigned by the DHCP */
    DhcpAllocated_bool: boolean;
    /** Creation date and time */
    CreatedTime_dt: Date;
    /** Updating date */
    UpdatedTime_dt: Date;
    /** Remote items */
    RemoteItem_bool: boolean;
    /** Remote host name */
    RemoteHostname_str: string;
    /** Constructor for the 'VpnRpcEnumIpTableItem' class: Enumeration items of IP table */
    constructor(init?: Partial<VpnRpcEnumIpTableItem>);
}
/** Enumeration of IP table */
export declare class VpnRpcEnumIpTable {
    /** The Virtual Hub name */
    HubName_str: string;
    /** MAC table */
    IpTable: VpnRpcEnumIpTableItem[];
    /** Constructor for the 'VpnRpcEnumIpTable' class: Enumeration of IP table */
    constructor(init?: Partial<VpnRpcEnumIpTable>);
}
/** Layer-3 interface enumeration */
export declare class VpnRpcEnumL3If {
    /** Layer-3 switch name */
    Name_str: string;
    /** Layer-3 interface list */
    L3IFList: VpnRpcL3If[];
    /** Constructor for the 'VpnRpcEnumL3If' class: Layer-3 interface enumeration */
    constructor(init?: Partial<VpnRpcEnumL3If>);
}
/** Layer-3 switch enumeration item */
export declare class VpnRpcEnumL3SwItem {
    /** Name of the layer-3 switch */
    Name_str: string;
    /** Number of layer-3 switch virtual interfaces */
    NumInterfaces_u32: number;
    /** Number of routing tables */
    NumTables_u32: number;
    /** Activated flag */
    Active_bool: boolean;
    /** Online flag */
    Online_bool: boolean;
    /** Constructor for the 'VpnRpcEnumL3SwItem' class: Layer-3 switch enumeration item */
    constructor(init?: Partial<VpnRpcEnumL3SwItem>);
}
/** Layer-3 switch enumeration */
export declare class VpnRpcEnumL3Sw {
    /** Layer-3 switch list */
    L3SWList: VpnRpcEnumL3SwItem[];
    /** Constructor for the 'VpnRpcEnumL3Sw' class: Layer-3 switch enumeration */
    constructor(init?: Partial<VpnRpcEnumL3Sw>);
}
/** Routing table enumeration */
export declare class VpnRpcEnumL3Table {
    /** L3 switch name */
    Name_str: string;
    /** Routing table item list */
    L3Table: VpnRpcL3Table[];
    /** Constructor for the 'VpnRpcEnumL3Table' class: Routing table enumeration */
    constructor(init?: Partial<VpnRpcEnumL3Table>);
}
/** Cascade Connection Enumeration */
export declare class VpnRpcEnumLinkItem {
    /** The name of cascade connection */
    AccountName_utf: string;
    /** Online flag */
    Online_bool: boolean;
    /** The flag indicates whether the cascade connection is established */
    Connected_bool: boolean;
    /** The error last occurred if the cascade connection is in the fail state */
    LastError_u32: number;
    /** Connection completion time */
    ConnectedTime_dt: Date;
    /** Host name of the destination VPN server */
    Hostname_str: string;
    /** The Virtual Hub name */
    TargetHubName_str: string;
    /** Constructor for the 'VpnRpcEnumLinkItem' class: Cascade Connection Enumeration */
    constructor(init?: Partial<VpnRpcEnumLinkItem>);
}
/** Enumeration of the link */
export declare class VpnRpcEnumLink {
    /** The Virtual Hub name */
    HubName_str: string;
    /** Number of cascade connections */
    NumLink_u32: number;
    /** The list of cascade connections */
    LinkList: VpnRpcEnumLinkItem[];
    /** Constructor for the 'VpnRpcEnumLink' class: Enumeration of the link */
    constructor(init?: Partial<VpnRpcEnumLink>);
}
/** List of listeners item */
export declare class VpnRpcListenerListItem {
    /** TCP port number (range: 1 - 65535) */
    Ports_u32: number;
    /** Active state */
    Enables_bool: boolean;
    /** The flag to indicate if the error occurred on the listener port */
    Errors_bool: boolean;
    /** Constructor for the 'VpnRpcListenerListItem' class: List of listeners item */
    constructor(init?: Partial<VpnRpcListenerListItem>);
}
/** List of listeners */
export declare class VpnRpcListenerList {
    /** List of listener items */
    ListenerList: VpnRpcListenerListItem[];
    /** Constructor for the 'VpnRpcListenerList' class: List of listeners */
    constructor(init?: Partial<VpnRpcListenerList>);
}
/** Local Bridge enumeration */
export declare class VpnRpcEnumLocalBridge {
    /** Local Bridge list */
    LocalBridgeList: VpnRpcLocalBridge[];
    /** Constructor for the 'VpnRpcEnumLocalBridge' class: Local Bridge enumeration */
    constructor(init?: Partial<VpnRpcEnumLocalBridge>);
}
/** Log file enumeration */
export declare class VpnRpcEnumLogFileItem {
    /** Server name */
    ServerName_str: string;
    /** File path */
    FilePath_str: string;
    /** File size */
    FileSize_u32: number;
    /** Last write date */
    UpdatedTime_dt: Date;
    /** Constructor for the 'VpnRpcEnumLogFileItem' class: Log file enumeration */
    constructor(init?: Partial<VpnRpcEnumLogFileItem>);
}
/** Log file enumeration */
export declare class VpnRpcEnumLogFile {
    /** Log file list */
    LogFiles: VpnRpcEnumLogFileItem[];
    /** Constructor for the 'VpnRpcEnumLogFile' class: Log file enumeration */
    constructor(init?: Partial<VpnRpcEnumLogFile>);
}
/** Enumeration items of the MAC table */
export declare class VpnRpcEnumMacTableItem {
    /** Key ID */
    Key_u32: number;
    /** Session name */
    SessionName_str: string;
    /** MAC address */
    MacAddress_bin: Uint8Array;
    /** Creation date and time */
    CreatedTime_dt: Date;
    /** Updating date */
    UpdatedTime_dt: Date;
    /** Remote items */
    RemoteItem_bool: boolean;
    /** Remote host name */
    RemoteHostname_str: string;
    /** VLAN ID */
    VlanId_u32: number;
    /** Constructor for the 'VpnRpcEnumMacTableItem' class: Enumeration items of the MAC table */
    constructor(init?: Partial<VpnRpcEnumMacTableItem>);
}
/** Enumeration of the MAC table */
export declare class VpnRpcEnumMacTable {
    /** The Virtual Hub name */
    HubName_str: string;
    /** MAC table */
    MacTable: VpnRpcEnumMacTableItem[];
    /** Constructor for the 'VpnRpcEnumMacTable' class: Enumeration of the MAC table */
    constructor(init?: Partial<VpnRpcEnumMacTable>);
}
/** NAT Entry Protocol Number */
export declare enum VpnRpcNatProtocol {
    /** TCP */
    TCP = 0,
    /** UDP */
    UDP = 1,
    /** DNS */
    DNS = 2,
    /** ICMP */
    ICMP = 3
}
/** State of NAT session (TCP) */
export declare enum VpnRpcNatTcpState {
    /** Connecting */
    Connecting = 0,
    /** Send the RST (Connection failure or disconnected) */
    SendReset = 1,
    /** Connection complete */
    Connected = 2,
    /** Connection established */
    Established = 3,
    /** Wait for socket disconnection */
    WaitDisconnect = 4
}
/** VpnRpcEnumNat List Item */
export declare class VpnRpcEnumNatItem {
    /** ID */
    Id_u32: number;
    /** Protocol */
    Protocol_u32: VpnRpcNatProtocol;
    /** Source IP address */
    SrcIp_ip: string;
    /** Source host name */
    SrcHost_str: string;
    /** Source port number */
    SrcPort_u32: number;
    /** Destination IP address */
    DestIp_ip: string;
    /** Destination host name */
    DestHost_str: string;
    /** Destination port number */
    DestPort_u32: number;
    /** Connection time */
    CreatedTime_dt: Date;
    /** Last communication time */
    LastCommTime_dt: Date;
    /** Transmission size */
    SendSize_u64: number;
    /** Receive size */
    RecvSize_u64: number;
    /** TCP state */
    TcpStatus_u32: VpnRpcNatTcpState;
    /** Constructor for the 'VpnRpcEnumNatItem' class: VpnRpcEnumNat List Item */
    constructor(init?: Partial<VpnRpcEnumNatItem>);
}
/** RPC_ENUM_NAT */
export declare class VpnRpcEnumNat {
    /** Virtual Hub Name */
    HubName_str: string;
    /** NAT item */
    NatTable: VpnRpcEnumNatItem[];
    /** Constructor for the 'VpnRpcEnumNat' class: RPC_ENUM_NAT */
    constructor(init?: Partial<VpnRpcEnumNat>);
}
/** Enumeration item of VPN session */
export declare class VpnRpcEnumSessionItem {
    /** Session name */
    Name_str: string;
    /** Remote session */
    RemoteSession_bool: boolean;
    /** Remote server name */
    RemoteHostname_str: string;
    /** User name */
    Username_str: string;
    /** IP address */
    ClientIP_ip: string;
    /** Host name */
    Hostname_str: string;
    /** Maximum number of underlying TCP connections */
    MaxNumTcp_u32: number;
    /** Number of current underlying TCP connections */
    CurrentNumTcp_u32: number;
    /** Packet size transmitted */
    PacketSize_u64: number;
    /** Number of packets transmitted */
    PacketNum_u64: number;
    /** Is a Cascade VPN session */
    LinkMode_bool: boolean;
    /** Is a SecureNAT VPN session */
    SecureNATMode_bool: boolean;
    /** Is the VPN session for Local Bridge */
    BridgeMode_bool: boolean;
    /** Is a Layer-3 Switch VPN session */
    Layer3Mode_bool: boolean;
    /** Is in Bridge Mode */
    Client_BridgeMode_bool: boolean;
    /** Is in Monitor Mode */
    Client_MonitorMode_bool: boolean;
    /** VLAN ID */
    VLanId_u32: number;
    /** Unique ID of the VPN Session */
    UniqueId_bin: Uint8Array;
    /** Creation date and time */
    CreatedTime_dt: Date;
    /** Last communication date and time */
    LastCommTime_dt: Date;
    /** Constructor for the 'VpnRpcEnumSessionItem' class: Enumeration item of VPN session */
    constructor(init?: Partial<VpnRpcEnumSessionItem>);
}
/** Enumerate VPN sessions */
export declare class VpnRpcEnumSession {
    /** The Virtual Hub name */
    HubName_str: string;
    /** VPN sessions list */
    SessionList: VpnRpcEnumSessionItem[];
    /** Constructor for the 'VpnRpcEnumSession' class: Enumerate VPN sessions */
    constructor(init?: Partial<VpnRpcEnumSession>);
}
/** Enumeration item of user */
export declare class VpnRpcEnumUserItem {
    /** User name */
    Name_str: string;
    /** Group name */
    GroupName_str: string;
    /** Real name */
    Realname_utf: string;
    /** Note */
    Note_utf: string;
    /** Authentication method */
    AuthType_u32: VpnRpcUserAuthType;
    /** Number of logins */
    NumLogin_u32: number;
    /** Last login date and time */
    LastLoginTime_dt: Date;
    /** Access denied */
    DenyAccess_bool: boolean;
    /** Flag of whether the traffic variable is set */
    IsTrafficFilled_bool: boolean;
    /** Flag of whether expiration date variable is set */
    IsExpiresFilled_bool: boolean;
    /** Expiration date */
    Expires_dt: Date;
    /** Number of broadcast packets (Recv) */
    ["Ex.Recv.BroadcastBytes_u64"]: number;
    /** Broadcast bytes (Recv) */
    ["Ex.Recv.BroadcastCount_u64"]: number;
    /** Unicast count (Recv) */
    ["Ex.Recv.UnicastBytes_u64"]: number;
    /** Unicast bytes (Recv) */
    ["Ex.Recv.UnicastCount_u64"]: number;
    /** Number of broadcast packets (Send) */
    ["Ex.Send.BroadcastBytes_u64"]: number;
    /** Broadcast bytes (Send) */
    ["Ex.Send.BroadcastCount_u64"]: number;
    /** Unicast bytes (Send) */
    ["Ex.Send.UnicastBytes_u64"]: number;
    /** Unicast bytes (Send) */
    ["Ex.Send.UnicastCount_u64"]: number;
    /** Constructor for the 'VpnRpcEnumUserItem' class: Enumeration item of user */
    constructor(init?: Partial<VpnRpcEnumUserItem>);
}
/** Enumeration of user */
export declare class VpnRpcEnumUser {
    /** The Virtual Hub name */
    HubName_str: string;
    /** User list */
    UserList: VpnRpcEnumUserItem[];
    /** Constructor for the 'VpnRpcEnumUser' class: Enumeration of user */
    constructor(init?: Partial<VpnRpcEnumUser>);
}
/** Source IP Address Limit List Item */
export declare class VpnAc {
    /** ID */
    Id_u32: number;
    /** Priority */
    Priority_u32: number;
    /** Deny access */
    Deny_bool: boolean;
    /** Set true if you want to specify the SubnetMask_ip item. */
    Masked_bool: boolean;
    /** IP address */
    IpAddress_ip: string;
    /** Subnet mask, valid only if Masked_bool == true */
    SubnetMask_ip: string;
    /** Constructor for the 'VpnAc' class: Source IP Address Limit List Item */
    constructor(init?: Partial<VpnAc>);
}
/** Source IP Address Limit List */
export declare class VpnRpcAcList {
    /** The Virtual Hub name */
    HubName_str: string;
    /** Source IP Address Limit List */
    ACList: VpnAc[];
    /** Constructor for the 'VpnRpcAcList' class: Source IP Address Limit List */
    constructor(init?: Partial<VpnRpcAcList>);
}
/** Message */
export declare class VpnRpcMsg {
    /** The Virtual Hub name */
    HubName_str: string;
    /** Message (Unicode strings acceptable) */
    Msg_bin: Uint8Array;
    /** Constructor for the 'VpnRpcMsg' class: Message */
    constructor(init?: Partial<VpnRpcMsg>);
}
/** Get / Set the Azure state */
export declare class VpnRpcAzureStatus {
    /** Whether VPN Azure Function is Enabled */
    IsEnabled_bool: boolean;
    /** Whether connection to VPN Azure Cloud Server is established */
    IsConnected_bool: boolean;
    /** Constructor for the 'VpnRpcAzureStatus' class: Get / Set the Azure state */
    constructor(init?: Partial<VpnRpcAzureStatus>);
}
/** Local Bridge support information */
export declare class VpnRpcBridgeSupport {
    /** Whether the OS supports the Local Bridge function */
    IsBridgeSupportedOs_bool: boolean;
    /** Whether WinPcap is necessary to install */
    IsWinPcapNeeded_bool: boolean;
    /** Constructor for the 'VpnRpcBridgeSupport' class: Local Bridge support information */
    constructor(init?: Partial<VpnRpcBridgeSupport>);
}
/** Get the CA of HUB */
export declare class VpnRpcHubGetCA {
    /** The Virtual Hub name */
    HubName_str: string;
    /** The key id of the certificate */
    Key_u32: number;
    /** The body of the X.509 certificate */
    Cert_bin: Uint8Array;
    /** Constructor for the 'VpnRpcHubGetCA' class: Get the CA of HUB */
    constructor(init?: Partial<VpnRpcHubGetCA>);
}
/** Caps item of the VPN Server */
export declare class VpnCaps {
    /** Name */
    CapsName_str: string;
    /** Value */
    CapsValue_u32: number;
    /** Descrption */
    CapsDescrption_utf: string;
    /** Constructor for the 'VpnCaps' class: Caps item of the VPN Server */
    constructor(init?: Partial<VpnCaps>);
}
/** Caps list of the VPN Server */
export declare class VpnCapslist {
    /** Caps list of the VPN Server */
    CapsList: VpnCaps[];
    /** Constructor for the 'VpnCapslist' class: Caps list of the VPN Server */
    constructor(init?: Partial<VpnCapslist>);
}
/** Config operation */
export declare class VpnRpcConfig {
    /** File name (valid only for returning from the server) */
    FileName_str: string;
    /** File data */
    FileData_bin: Uint8Array;
    /** Constructor for the 'VpnRpcConfig' class: Config operation */
    constructor(init?: Partial<VpnRpcConfig>);
}
/** Connection information */
export declare class VpnRpcConnectionInfo {
    /** Connection name */
    Name_str: string;
    /** Type */
    Type_u32: VpnRpcConnectionType;
    /** Host name */
    Hostname_str: string;
    /** IP address */
    Ip_ip: string;
    /** Port number */
    Port_u32: number;
    /** Connected time */
    ConnectedTime_dt: Date;
    /** Server string */
    ServerStr_str: string;
    /** Server version */
    ServerVer_u32: number;
    /** Server build number */
    ServerBuild_u32: number;
    /** Client string */
    ClientStr_str: string;
    /** Client version */
    ClientVer_u32: number;
    /** Client build number */
    ClientBuild_u32: number;
    /** Constructor for the 'VpnRpcConnectionInfo' class: Connection information */
    constructor(init?: Partial<VpnRpcConnectionInfo>);
}
/** Proxy type */
export declare enum VpnRpcProxyType {
    /** Direct TCP connection */
    Direct = 0,
    /** Connection via HTTP proxy server */
    HTTP = 1,
    /** Connection via SOCKS proxy server */
    SOCKS = 2
}
/** The current status of the DDNS */
export declare class VpnDDnsClientStatus {
    /** Last error code (IPv4) */
    Err_IPv4_u32: number;
    /** Last error string (IPv4) */
    ErrStr_IPv4_utf: string;
    /** Last error code (IPv6) */
    Err_IPv6_u32: number;
    /** Last error string (IPv6) */
    ErrStr_IPv6_utf: string;
    /** Current DDNS host name */
    CurrentHostName_str: string;
    /** Current FQDN of the DDNS hostname */
    CurrentFqdn_str: string;
    /** DDNS suffix */
    DnsSuffix_str: string;
    /** Current IPv4 address of the VPN Server */
    CurrentIPv4_str: string;
    /** Current IPv6 address of the VPN Server */
    CurrentIPv6_str: string;
    /** Constructor for the 'VpnDDnsClientStatus' class: The current status of the DDNS */
    constructor(init?: Partial<VpnDDnsClientStatus>);
}
/** Internet connection settings */
export declare class VpnInternetSetting {
    /** Type of proxy server */
    ProxyType_u32: VpnRpcProxyType;
    /** Proxy server host name */
    ProxyHostName_str: string;
    /** Proxy server port number */
    ProxyPort_u32: number;
    /** Proxy server user name */
    ProxyUsername_str: string;
    /** Proxy server password */
    ProxyPassword_str: string;
    /** Constructor for the 'VpnInternetSetting' class: Internet connection settings */
    constructor(init?: Partial<VpnInternetSetting>);
}
/** Administration options */
export declare class VpnAdminOption {
    /** Name */
    Name_str: string;
    /** Data */
    Value_u32: number;
    /** Descrption */
    Descrption_utf: string;
    /** Constructor for the 'VpnAdminOption' class: Administration options */
    constructor(init?: Partial<VpnAdminOption>);
}
/** Administration options list */
export declare class VpnRpcAdminOption {
    /** Virtual HUB name */
    HubName_str: string;
    /** List data */
    AdminOptionList: VpnAdminOption[];
    /** Constructor for the 'VpnRpcAdminOption' class: Administration options list */
    constructor(init?: Partial<VpnRpcAdminOption>);
}
/** Connection state to the controller */
export declare class VpnRpcFarmConnectionStatus {
    /** IP address */
    Ip_ip: string;
    /** Port number */
    Port_u32: number;
    /** Online state */
    Online_bool: boolean;
    /** Last error code */
    LastError_u32: number;
    /** Connection start time */
    StartedTime_dt: Date;
    /** First connection time */
    FirstConnectedTime_dt: Date;
    /** Connection time of this time */
    CurrentConnectedTime_dt: Date;
    /** Number of retries */
    NumTry_u32: number;
    /** Number of connection count */
    NumConnected_u32: number;
    /** Connection failure count */
    NumFailed_u32: number;
    /** Constructor for the 'VpnRpcFarmConnectionStatus' class: Connection state to the controller */
    constructor(init?: Partial<VpnRpcFarmConnectionStatus>);
}
/** HUB item of each farm member */
export declare class VpnRpcFarmHub {
    /** The Virtual Hub name */
    HubName_str: string;
    /** Dynamic HUB */
    DynamicHub_bool: boolean;
    /** Constructor for the 'VpnRpcFarmHub' class: HUB item of each farm member */
    constructor(init?: Partial<VpnRpcFarmHub>);
}
/** Server farm member information acquisition */
export declare class VpnRpcFarmInfo {
    /** ID */
    Id_u32: number;
    /** The flag if the server is Cluster Controller (false: Cluster Member servers) */
    Controller_bool: boolean;
    /** Connection Established Time */
    ConnectedTime_dt: Date;
    /** IP address */
    Ip_ip: string;
    /** Host name */
    Hostname_str: string;
    /** Point */
    Point_u32: number;
    /** Number of Public Ports */
    NumPort_u32: number;
    /** Public Ports */
    Ports_u32: number[];
    /** Server certificate */
    ServerCert_bin: Uint8Array;
    /** Number of farm HUB */
    NumFarmHub_u32: number;
    /** The hosted Virtual Hub list */
    HubsList: VpnRpcFarmHub[];
    /** Number of hosted VPN sessions */
    NumSessions_u32: number;
    /** Number of TCP connections */
    NumTcpConnections_u32: number;
    /** Performance Standard Ratio */
    Weight_u32: number;
    /** Constructor for the 'VpnRpcFarmInfo' class: Server farm member information acquisition */
    constructor(init?: Partial<VpnRpcFarmInfo>);
}
/** Server farm configuration */
export declare class VpnRpcFarm {
    /** Type of server */
    ServerType_u32: VpnRpcServerType;
    /** Valid only for Cluster Member servers. Number of the Ports_u32 element. */
    NumPort_u32: number;
    /** Valid only for Cluster Member servers. Specify the list of public port numbers on this server. The list must have at least one public port number set, and it is also possible to set multiple public port numbers. */
    Ports_u32: number[];
    /** Valid only for Cluster Member servers. Specify the public IP address of this server. If you wish to leave public IP address unspecified, specify the empty string. When a public IP address is not specified, the IP address of the network interface used when connecting to the cluster controller will be automatically used. */
    PublicIp_ip: string;
    /** Valid only for Cluster Member servers. Specify the host name or IP address of the destination cluster controller. */
    ControllerName_str: string;
    /** Valid only for Cluster Member servers. Specify the TCP port number of the destination cluster controller. */
    ControllerPort_u32: number;
    /** Valid only for Cluster Member servers. Specify the password required to connect to the destination controller. It needs to be the same as an administrator password on the destination controller. */
    MemberPasswordPlaintext_str: string;
    /** This sets a value for the performance standard ratio of this VPN Server. This is the standard value for when load balancing is performed in the cluster. For example, making only one machine 200 while the other members have a status of 100, will regulate that machine to receive twice as many connections as the other members. Specify 1 or higher for the value. If this parameter is left unspecified, 100 will be used. */
    Weight_u32: number;
    /** Valid only for Cluster Controller server. By specifying true, the VPN Server will operate only as a controller on the cluster and it will always distribute general VPN Client connections to members other than itself. This function is used in high-load environments. */
    ControllerOnly_bool: boolean;
    /** Constructor for the 'VpnRpcFarm' class: Server farm configuration */
    constructor(init?: Partial<VpnRpcFarm>);
}
/** Log switch type */
export declare enum VpnRpcLogSwitchType {
    /** No switching */
    No = 0,
    /** Secondly basis */
    Second = 1,
    /** Minutely basis */
    Minute = 2,
    /** Hourly basis */
    Hour = 3,
    /** Daily basis */
    Day = 4,
    /** Monthly basis */
    Month = 5
}
/** Packet log settings */
export declare enum VpnRpcPacketLogSetting {
    /** Not save */
    None = 0,
    /** Only header */
    Header = 1,
    /** All payloads */
    All = 2
}
/** Packet log settings array index */
export declare enum VpnRpcPacketLogSettingIndex {
    /** TCP connection log */
    TcpConnection = 0,
    /** TCP packet log */
    TcpAll = 1,
    /** DHCP Log */
    Dhcp = 2,
    /** UDP log */
    Udp = 3,
    /** ICMP log */
    Icmp = 4,
    /** IP log */
    Ip = 5,
    /** ARP log */
    Arp = 6,
    /** Ethernet log */
    Ethernet = 7
}
/** HUB log settings */
export declare class VpnRpcHubLog {
    /** The Virtual Hub name */
    HubName_str: string;
    /** The flag to enable / disable saving the security log */
    SaveSecurityLog_bool: boolean;
    /** The log filename switching setting of the security log */
    SecurityLogSwitchType_u32: VpnRpcLogSwitchType;
    /** The flag to enable / disable saving the security log */
    SavePacketLog_bool: boolean;
    /** The log filename switching settings of the packet logs */
    PacketLogSwitchType_u32: VpnRpcLogSwitchType;
    /** Specify the save contents of the packet logs (uint * 16 array). The index numbers: TcpConnection = 0, TcpAll = 1, DHCP = 2, UDP = 3, ICMP = 4, IP = 5, ARP = 6, Ethernet = 7. */
    PacketLogConfig_u32: VpnRpcPacketLogSetting[];
    /** Constructor for the 'VpnRpcHubLog' class: HUB log settings */
    constructor(init?: Partial<VpnRpcHubLog>);
}
/** RADIUS server options */
export declare class VpnRpcRadius {
    /** The Virtual Hub name */
    HubName_str: string;
    /** RADIUS server name */
    RadiusServerName_str: string;
    /** RADIUS port number */
    RadiusPort_u32: number;
    /** Secret key */
    RadiusSecret_str: string;
    /** Radius retry interval */
    RadiusRetryInterval_u32: number;
    /** Constructor for the 'VpnRpcRadius' class: RADIUS server options */
    constructor(init?: Partial<VpnRpcRadius>);
}
/** Get the state HUB */
export declare class VpnRpcHubStatus {
    /** The Virtual Hub name */
    HubName_str: string;
    /** Online */
    Online_bool: boolean;
    /** Type of HUB */
    HubType_u32: VpnRpcHubType;
    /** Number of sessions */
    NumSessions_u32: number;
    /** Number of sessions (client mode) */
    NumSessionsClient_u32: number;
    /** Number of sessions (bridge mode) */
    NumSessionsBridge_u32: number;
    /** Number of Access list entries */
    NumAccessLists_u32: number;
    /** Number of users */
    NumUsers_u32: number;
    /** Number of groups */
    NumGroups_u32: number;
    /** Number of MAC table entries */
    NumMacTables_u32: number;
    /** Number of IP table entries */
    NumIpTables_u32: number;
    /** Number of broadcast packets (Recv) */
    ["Recv.BroadcastBytes_u64"]: number;
    /** Broadcast bytes (Recv) */
    ["Recv.BroadcastCount_u64"]: number;
    /** Unicast count (Recv) */
    ["Recv.UnicastBytes_u64"]: number;
    /** Unicast bytes (Recv) */
    ["Recv.UnicastCount_u64"]: number;
    /** Number of broadcast packets (Send) */
    ["Send.BroadcastBytes_u64"]: number;
    /** Broadcast bytes (Send) */
    ["Send.BroadcastCount_u64"]: number;
    /** Unicast bytes (Send) */
    ["Send.UnicastBytes_u64"]: number;
    /** Unicast bytes (Send) */
    ["Send.UnicastCount_u64"]: number;
    /** Whether SecureNAT is enabled */
    SecureNATEnabled_bool: boolean;
    /** Last communication date and time */
    LastCommTime_dt: Date;
    /** Last login date and time */
    LastLoginTime_dt: Date;
    /** Creation date and time */
    CreatedTime_dt: Date;
    /** Number of logins */
    NumLogin_u32: number;
    /** Constructor for the 'VpnRpcHubStatus' class: Get the state HUB */
    constructor(init?: Partial<VpnRpcHubStatus>);
}
/** List of services provided by IPsec server */
export declare class VpnIPsecServices {
    /** Enable or Disable the L2TP Server Function (Raw L2TP with No Encryptions). To accept special VPN clients, enable this option. */
    L2TP_Raw_bool: boolean;
    /** Enable or Disable the L2TP over IPsec Server Function. To accept VPN connections from iPhone, iPad, Android, Windows or Mac OS X, enable this option. */
    L2TP_IPsec_bool: boolean;
    /** Enable or Disable the EtherIP / L2TPv3 over IPsec Server Function (for site-to-site VPN Server function). Router Products which are compatible with EtherIP over IPsec can connect to Virtual Hubs on the VPN Server and establish Layer-2 (Ethernet) Bridging. */
    EtherIP_IPsec_bool: boolean;
    /** Specify the IPsec Pre-Shared Key. An IPsec Pre-Shared Key is also called as "PSK" or "secret". Specify it equal or less than 8 letters, and distribute it to every users who will connect to the VPN Server. Please note: Google Android 4.0 has a bug which a Pre-Shared Key with 10 or more letters causes a unexpected behavior. For that reason, the letters of a Pre-Shared Key should be 9 or less characters. */
    IPsec_Secret_str: string;
    /** Specify the default Virtual HUB in a case of omitting the name of HUB on the Username. Users should specify their username such as "Username@Target Virtual HUB Name" to connect this L2TP Server. If the designation of the Virtual Hub is omitted, the above HUB will be used as the target. */
    L2TP_DefaultHub_str: string;
    /** Constructor for the 'VpnIPsecServices' class: List of services provided by IPsec server */
    constructor(init?: Partial<VpnIPsecServices>);
}
/** Keep alive protocol */
export declare enum VpnRpcKeepAliveProtocol {
    /** TCP */
    TCP = 0,
    /** UDP */
    UDP = 1
}
/** Keep Alive settings */
export declare class VpnRpcKeep {
    /** The flag to enable keep-alive to the Internet */
    UseKeepConnect_bool: boolean;
    /** Specify the host name or IP address of the destination */
    KeepConnectHost_str: string;
    /** Specify the port number of the destination */
    KeepConnectPort_u32: number;
    /** Protocol type */
    KeepConnectProtocol_u32: VpnRpcKeepAliveProtocol;
    /** Interval Between Packets Sends (Seconds) */
    KeepConnectInterval_u32: number;
    /** Constructor for the 'VpnRpcKeep' class: Keep Alive settings */
    constructor(init?: Partial<VpnRpcKeep>);
}
/** State of the client session */
export declare enum VpnRpcClientSessionStatus {
    /** Connecting */
    Connecting = 0,
    /** Negotiating */
    Negotiation = 1,
    /** During user authentication */
    Auth = 2,
    /** Connection complete */
    Established = 3,
    /** Wait to retry */
    Retry = 4,
    /** Idle state */
    Idle = 5
}
/** Get the link state */
export declare class VpnRpcLinkStatus {
    /** The Virtual Hub name */
    HubName_Ex_str: string;
    /** The name of the cascade connection */
    AccountName_utf: string;
    /** The flag whether the cascade connection is enabled */
    Active_bool: boolean;
    /** The flag whether the cascade connection is established */
    Connected_bool: boolean;
    /** The session status */
    SessionStatus_u32: VpnRpcClientSessionStatus;
    /** The destination VPN server name */
    ServerName_str: string;
    /** The port number of the server */
    ServerPort_u32: number;
    /** Server product name */
    ServerProductName_str: string;
    /** Server product version */
    ServerProductVer_u32: number;
    /** Server product build number */
    ServerProductBuild_u32: number;
    /** Server's X.509 certificate */
    ServerX_bin: Uint8Array;
    /** Client certificate */
    ClientX_bin: Uint8Array;
    /** Connection start time */
    StartTime_dt: Date;
    /** Connection completion time of the first connection */
    FirstConnectionEstablisiedTime_dt: Date;
    /** Connection completion time of this connection */
    CurrentConnectionEstablishTime_dt: Date;
    /** Number of connections have been established so far */
    NumConnectionsEatablished_u32: number;
    /** Half-connection */
    HalfConnection_bool: boolean;
    /** VoIP / QoS */
    QoS_bool: boolean;
    /** Maximum number of the underlying TCP connections */
    MaxTcpConnections_u32: number;
    /** Number of current underlying TCP connections */
    NumTcpConnections_u32: number;
    /** Number of underlying inbound TCP connections */
    NumTcpConnectionsUpload_u32: number;
    /** Number of underlying outbound TCP connections */
    NumTcpConnectionsDownload_u32: number;
    /** Use of encryption */
    UseEncrypt_bool: boolean;
    /** Cipher algorithm name */
    CipherName_str: string;
    /** Use of compression */
    UseCompress_bool: boolean;
    /** The flag whether this is a R-UDP session */
    IsRUDPSession_bool: boolean;
    /** Underlying physical communication protocol */
    UnderlayProtocol_str: string;
    /** The UDP acceleration is enabled */
    IsUdpAccelerationEnabled_bool: boolean;
    /** The UDP acceleration is being actually used */
    IsUsingUdpAcceleration_bool: boolean;
    /** Session name */
    SessionName_str: string;
    /** Connection name */
    ConnectionName_str: string;
    /** Session key */
    SessionKey_bin: Uint8Array;
    /** Total transmitted data size */
    TotalSendSize_u64: number;
    /** Total received data size */
    TotalRecvSize_u64: number;
    /** Total transmitted data size (no compression) */
    TotalSendSizeReal_u64: number;
    /** Total received data size (no compression) */
    TotalRecvSizeReal_u64: number;
    /** The flag whether the VPN session is Bridge Mode */
    IsBridgeMode_bool: boolean;
    /** The flag whether the VPN session is Monitor mode */
    IsMonitorMode_bool: boolean;
    /** VLAN ID */
    VLanId_u32: number;
    /** Constructor for the 'VpnRpcLinkStatus' class: Get the link state */
    constructor(init?: Partial<VpnRpcLinkStatus>);
}
/** Setting of SSTP and OpenVPN */
export declare class VpnOpenVpnSstpConfig {
    /** Specify true to enable the OpenVPN Clone Server Function. Specify false to disable. */
    EnableOpenVPN_bool: boolean;
    /** Specify UDP ports to listen for OpenVPN. Multiple UDP ports can be specified with splitting by space or comma letters, for example: "1194, 2001, 2010, 2012". The default port for OpenVPN is UDP 1194. You can specify any other UDP ports. */
    OpenVPNPortList_str: string;
    /** pecify true to enable the Microsoft SSTP VPN Clone Server Function. Specify false to disable. */
    EnableSSTP_bool: boolean;
    /** Constructor for the 'VpnOpenVpnSstpConfig' class: Setting of SSTP and OpenVPN */
    constructor(init?: Partial<VpnOpenVpnSstpConfig>);
}
/** Virtual host option */
export declare class VpnVhOption {
    /** Target Virtual HUB name */
    RpcHubName_str: string;
    /** MAC address */
    MacAddress_bin: Uint8Array;
    /** IP address */
    Ip_ip: string;
    /** Subnet mask */
    Mask_ip: string;
    /** Use flag of the Virtual NAT function */
    UseNat_bool: boolean;
    /** MTU value (Standard: 1500) */
    Mtu_u32: number;
    /** NAT TCP timeout in seconds */
    NatTcpTimeout_u32: number;
    /** NAT UDP timeout in seconds */
    NatUdpTimeout_u32: number;
    /** Using flag of DHCP function */
    UseDhcp_bool: boolean;
    /** Specify the start point of the address band to be distributed to the client. (Example: 192.168.30.10) */
    DhcpLeaseIPStart_ip: string;
    /** Specify the end point of the address band to be distributed to the client. (Example: 192.168.30.200) */
    DhcpLeaseIPEnd_ip: string;
    /** Specify the subnet mask to be specified for the client. (Example: 255.255.255.0) */
    DhcpSubnetMask_ip: string;
    /** Specify the expiration date in second units for leasing an IP address to a client. */
    DhcpExpireTimeSpan_u32: number;
    /** Specify the IP address of the default gateway to be notified to the client. You can specify a SecureNAT Virtual Host IP address for this when the SecureNAT Function's Virtual NAT Function has been enabled and is being used also. If you specify 0 or none, then the client will not be notified of the default gateway. */
    DhcpGatewayAddress_ip: string;
    /** Specify the IP address of the primary DNS Server to be notified to the client. You can specify a SecureNAT Virtual Host IP address for this when the SecureNAT Function's Virtual NAT Function has been enabled and is being used also. If you specify empty, then the client will not be notified of the DNS Server address. */
    DhcpDnsServerAddress_ip: string;
    /** Specify the IP address of the secondary DNS Server to be notified to the client. You can specify a SecureNAT Virtual Host IP address for this when the SecureNAT Function's Virtual NAT Function has been enabled and is being used also. If you specify empty, then the client will not be notified of the DNS Server address. */
    DhcpDnsServerAddress2_ip: string;
    /** Specify the domain name to be notified to the client. If you specify none, then the client will not be notified of the domain name. */
    DhcpDomainName_str: string;
    /** Specify whether or not to save the Virtual DHCP Server operation in the Virtual Hub security log. Specify true to save it. This value is interlinked with the Virtual NAT Function log save setting. */
    SaveLog_bool: boolean;
    /** The flag to enable the DhcpPushRoutes_str field. */
    ApplyDhcpPushRoutes_bool: boolean;
    /** Specify the static routing table to push. Example: "192.168.5.0/255.255.255.0/192.168.4.254, 10.0.0.0/255.0.0.0/192.168.4.253" Split multiple entries (maximum: 64 entries) by comma or space characters. Each entry must be specified in the "IP network address/subnet mask/gateway IP address" format. This Virtual DHCP Server can push the classless static routes (RFC 3442) with DHCP reply messages to VPN clients. Whether or not a VPN client can recognize the classless static routes (RFC 3442) depends on the target VPN client software. SoftEther VPN Client and OpenVPN Client are supporting the classless static routes. On L2TP/IPsec and MS-SSTP protocols, the compatibility depends on the implementation of the client software. You can realize the split tunneling if you clear the default gateway field on the Virtual DHCP Server options. On the client side, L2TP/IPsec and MS-SSTP clients need to be configured not to set up the default gateway for the split tunneling usage. You can also push the classless static routes (RFC 3442) by your existing external DHCP server. In that case, disable the Virtual DHCP Server function on SecureNAT, and you need not to set up the classless routes on this API. See the RFC 3442 to understand the classless routes. */
    DhcpPushRoutes_str: string;
    /** Constructor for the 'VpnVhOption' class: Virtual host option */
    constructor(init?: Partial<VpnVhOption>);
}
/** RPC_NAT_STATUS */
export declare class VpnRpcNatStatus {
    /** Virtual Hub Name */
    HubName_str: string;
    /** Number of TCP sessions */
    NumTcpSessions_u32: number;
    /** Ntmber of UDP sessions */
    NumUdpSessions_u32: number;
    /** Nymber of ICMP sessions */
    NumIcmpSessions_u32: number;
    /** Number of DNS sessions */
    NumDnsSessions_u32: number;
    /** Number of DHCP clients */
    NumDhcpClients_u32: number;
    /** Whether the NAT is operating in the Kernel Mode */
    IsKernelMode_bool: boolean;
    /** Whether the NAT is operating in the Raw IP Mode */
    IsRawIpMode_bool: boolean;
    /** Constructor for the 'VpnRpcNatStatus' class: RPC_NAT_STATUS */
    constructor(init?: Partial<VpnRpcNatStatus>);
}
/** Key pair */
export declare class VpnRpcKeyPair {
    /** The body of the certificate */
    Cert_bin: Uint8Array;
    /** The body of the private key */
    Key_bin: Uint8Array;
    /** Constructor for the 'VpnRpcKeyPair' class: Key pair */
    constructor(init?: Partial<VpnRpcKeyPair>);
}
/** Single string value */
export declare class VpnRpcStr {
    /** A string value */
    String_str: string;
    /** Constructor for the 'VpnRpcStr' class: Single string value */
    constructor(init?: Partial<VpnRpcStr>);
}
/** Type of VPN Server */
export declare enum VpnRpcServerType {
    /** Stand-alone server */
    Standalone = 0,
    /** Farm controller server */
    FarmController = 1,
    /** Farm member server */
    FarmMember = 2
}
/** Operating system type */
export declare enum VpnRpcOsType {
    /** Windows 95 */
    WINDOWS_95 = 1100,
    /** Windows 98 */
    WINDOWS_98 = 1200,
    /** Windows Me */
    WINDOWS_ME = 1300,
    /** Windows (unknown) */
    WINDOWS_UNKNOWN = 1400,
    /** Windows NT 4.0 Workstation */
    WINDOWS_NT_4_WORKSTATION = 2100,
    /** Windows NT 4.0 Server */
    WINDOWS_NT_4_SERVER = 2110,
    /** Windows NT 4.0 Server, Enterprise Edition */
    WINDOWS_NT_4_SERVER_ENTERPRISE = 2111,
    /** Windows NT 4.0 Terminal Server */
    WINDOWS_NT_4_TERMINAL_SERVER = 2112,
    /** BackOffice Server 4.5 */
    WINDOWS_NT_4_BACKOFFICE = 2113,
    /** Small Business Server 4.5 */
    WINDOWS_NT_4_SMS = 2114,
    /** Windows 2000 Professional */
    WINDOWS_2000_PROFESSIONAL = 2200,
    /** Windows 2000 Server */
    WINDOWS_2000_SERVER = 2211,
    /** Windows 2000 Advanced Server */
    WINDOWS_2000_ADVANCED_SERVER = 2212,
    /** Windows 2000 Datacenter Server */
    WINDOWS_2000_DATACENTER_SERVER = 2213,
    /** BackOffice Server 2000 */
    WINDOWS_2000_BACKOFFICE = 2214,
    /** Small Business Server 2000 */
    WINDOWS_2000_SBS = 2215,
    /** Windows XP Home Edition */
    WINDOWS_XP_HOME = 2300,
    /** Windows XP Professional */
    WINDOWS_XP_PROFESSIONAL = 2301,
    /** Windows Server 2003 Web Edition */
    WINDOWS_2003_WEB = 2410,
    /** Windows Server 2003 Standard Edition */
    WINDOWS_2003_STANDARD = 2411,
    /** Windows Server 2003 Enterprise Edition */
    WINDOWS_2003_ENTERPRISE = 2412,
    /** Windows Server 2003 DataCenter Edition */
    WINDOWS_2003_DATACENTER = 2413,
    /** BackOffice Server 2003 */
    WINDOWS_2003_BACKOFFICE = 2414,
    /** Small Business Server 2003 */
    WINDOWS_2003_SBS = 2415,
    /** Windows Vista */
    WINDOWS_LONGHORN_PROFESSIONAL = 2500,
    /** Windows Server 2008 */
    WINDOWS_LONGHORN_SERVER = 2510,
    /** Windows 7 */
    WINDOWS_7 = 2600,
    /** Windows Server 2008 R2 */
    WINDOWS_SERVER_2008_R2 = 2610,
    /** Windows 8 */
    WINDOWS_8 = 2700,
    /** Windows Server 2012 */
    WINDOWS_SERVER_8 = 2710,
    /** Windows 8.1 */
    WINDOWS_81 = 2701,
    /** Windows Server 2012 R2 */
    WINDOWS_SERVER_81 = 2711,
    /** Windows 10 */
    WINDOWS_10 = 2702,
    /** Windows Server 10 */
    WINDOWS_SERVER_10 = 2712,
    /** Windows 11 or later */
    WINDOWS_11 = 2800,
    /** Windows Server 11 or later */
    WINDOWS_SERVER_11 = 2810,
    /** Unknown UNIX */
    UNIX_UNKNOWN = 3000,
    /** Linux */
    LINUX = 3100,
    /** Solaris */
    SOLARIS = 3200,
    /** Cygwin */
    CYGWIN = 3300,
    /** BSD */
    BSD = 3400,
    /** MacOS X */
    MACOS_X = 3500
}
/** VPN Server Information */
export declare class VpnRpcServerInfo {
    /** Server product name */
    ServerProductName_str: string;
    /** Server version string */
    ServerVersionString_str: string;
    /** Server build information string */
    ServerBuildInfoString_str: string;
    /** Server version integer value */
    ServerVerInt_u32: number;
    /** Server build number integer value */
    ServerBuildInt_u32: number;
    /** Server host name */
    ServerHostName_str: string;
    /** Type of server */
    ServerType_u32: VpnRpcServerType;
    /** Build date and time of the server */
    ServerBuildDate_dt: Date;
    /** Family name */
    ServerFamilyName_str: string;
    /** OS type */
    OsType_u32: VpnRpcOsType;
    /** Service pack number */
    OsServicePack_u32: number;
    /** OS system name */
    OsSystemName_str: string;
    /** OS product name */
    OsProductName_str: string;
    /** OS vendor name */
    OsVendorName_str: string;
    /** OS version */
    OsVersion_str: string;
    /** Kernel name */
    KernelName_str: string;
    /** Kernel version */
    KernelVersion_str: string;
    /** Constructor for the 'VpnRpcServerInfo' class: VPN Server Information */
    constructor(init?: Partial<VpnRpcServerInfo>);
}
/** Server status */
export declare class VpnRpcServerStatus {
    /** Type of server */
    ServerType_u32: VpnRpcServerType;
    /** Total number of TCP connections */
    NumTcpConnections_u32: number;
    /** Number of Local TCP connections */
    NumTcpConnectionsLocal_u32: number;
    /** Number of remote TCP connections */
    NumTcpConnectionsRemote_u32: number;
    /** Total number of HUBs */
    NumHubTotal_u32: number;
    /** Nymber of stand-alone HUB */
    NumHubStandalone_u32: number;
    /** Number of static HUBs */
    NumHubStatic_u32: number;
    /** Number of Dynamic HUBs */
    NumHubDynamic_u32: number;
    /** Total number of sessions */
    NumSessionsTotal_u32: number;
    /** Number of local VPN sessions */
    NumSessionsLocal_u32: number;
    /** The number of remote sessions */
    NumSessionsRemote_u32: number;
    /** Number of MAC table entries (total sum of all Virtual Hubs) */
    NumMacTables_u32: number;
    /** Number of IP table entries (total sum of all Virtual Hubs) */
    NumIpTables_u32: number;
    /** Number of users (total sum of all Virtual Hubs) */
    NumUsers_u32: number;
    /** Number of groups (total sum of all Virtual Hubs) */
    NumGroups_u32: number;
    /** Number of assigned bridge licenses (Useful to make a commercial version) */
    AssignedBridgeLicenses_u32: number;
    /** Number of assigned client licenses (Useful to make a commercial version) */
    AssignedClientLicenses_u32: number;
    /** Number of Assigned bridge license (cluster-wide), useful to make a commercial version */
    AssignedBridgeLicensesTotal_u32: number;
    /** Number of assigned client licenses (cluster-wide), useful to make a commercial version */
    AssignedClientLicensesTotal_u32: number;
    /** Number of broadcast packets (Recv) */
    ["Recv.BroadcastBytes_u64"]: number;
    /** Broadcast bytes (Recv) */
    ["Recv.BroadcastCount_u64"]: number;
    /** Unicast count (Recv) */
    ["Recv.UnicastBytes_u64"]: number;
    /** Unicast bytes (Recv) */
    ["Recv.UnicastCount_u64"]: number;
    /** Number of broadcast packets (Send) */
    ["Send.BroadcastBytes_u64"]: number;
    /** Broadcast bytes (Send) */
    ["Send.BroadcastCount_u64"]: number;
    /** Unicast bytes (Send) */
    ["Send.UnicastBytes_u64"]: number;
    /** Unicast bytes (Send) */
    ["Send.UnicastCount_u64"]: number;
    /** Current time */
    CurrentTime_dt: Date;
    /** 64 bit High-Precision Logical System Clock */
    CurrentTick_u64: number;
    /** VPN Server Start-up time */
    StartTime_dt: Date;
    /** Memory information: Total Memory */
    TotalMemory_u64: number;
    /** Memory information: Used Memory */
    UsedMemory_u64: number;
    /** Memory information: Free Memory */
    FreeMemory_u64: number;
    /** Memory information: Total Phys */
    TotalPhys_u64: number;
    /** Memory information: Used Phys */
    UsedPhys_u64: number;
    /** Memory information: Free Phys */
    FreePhys_u64: number;
    /** Constructor for the 'VpnRpcServerStatus' class: Server status */
    constructor(init?: Partial<VpnRpcServerStatus>);
}
/** VPN Session status */
export declare class VpnRpcSessionStatus {
    /** The Virtual Hub name */
    HubName_str: string;
    /** VPN session name */
    Name_str: string;
    /** User name */
    Username_str: string;
    /** Real user name which was used for the authentication */
    RealUsername_str: string;
    /** Group name */
    GroupName_str: string;
    /** Is Cascade Session */
    LinkMode_bool: boolean;
    /** Client IP address */
    Client_Ip_Address_ip: string;
    /** Client host name */
    SessionStatus_ClientHostName_str: string;
    /** Operation flag */
    Active_bool: boolean;
    /** Connected flag */
    Connected_bool: boolean;
    /** State of the client session */
    SessionStatus_u32: VpnRpcClientSessionStatus;
    /** Server name */
    ServerName_str: string;
    /** Port number of the server */
    ServerPort_u32: number;
    /** Server product name */
    ServerProductName_str: string;
    /** Server product version */
    ServerProductVer_u32: number;
    /** Server product build number */
    ServerProductBuild_u32: number;
    /** Connection start time */
    StartTime_dt: Date;
    /** Connection completion time of the first connection */
    FirstConnectionEstablisiedTime_dt: Date;
    /** Connection completion time of this connection */
    CurrentConnectionEstablishTime_dt: Date;
    /** Number of connections have been established so far */
    NumConnectionsEatablished_u32: number;
    /** Half-connection */
    HalfConnection_bool: boolean;
    /** VoIP / QoS */
    QoS_bool: boolean;
    /** Maximum number of the underlying TCP connections */
    MaxTcpConnections_u32: number;
    /** Number of current underlying TCP connections */
    NumTcpConnections_u32: number;
    /** Number of inbound underlying connections */
    NumTcpConnectionsUpload_u32: number;
    /** Number of outbound underlying connections */
    NumTcpConnectionsDownload_u32: number;
    /** Use of encryption */
    UseEncrypt_bool: boolean;
    /** Cipher algorithm name */
    CipherName_str: string;
    /** Use of compression */
    UseCompress_bool: boolean;
    /** Is R-UDP session */
    IsRUDPSession_bool: boolean;
    /** Physical underlying communication protocol */
    UnderlayProtocol_str: string;
    /** The UDP acceleration is enabled */
    IsUdpAccelerationEnabled_bool: boolean;
    /** Using the UDP acceleration function */
    IsUsingUdpAcceleration_bool: boolean;
    /** VPN session name */
    SessionName_str: string;
    /** Connection name */
    ConnectionName_str: string;
    /** Session key */
    SessionKey_bin: Uint8Array;
    /** Total transmitted data size */
    TotalSendSize_u64: number;
    /** Total received data size */
    TotalRecvSize_u64: number;
    /** Total transmitted data size (no compression) */
    TotalSendSizeReal_u64: number;
    /** Total received data size (no compression) */
    TotalRecvSizeReal_u64: number;
    /** Is Bridge Mode */
    IsBridgeMode_bool: boolean;
    /** Is Monitor mode */
    IsMonitorMode_bool: boolean;
    /** VLAN ID */
    VLanId_u32: number;
    /** Client product name */
    ClientProductName_str: string;
    /** Client version */
    ClientProductVer_u32: number;
    /** Client build number */
    ClientProductBuild_u32: number;
    /** Client OS name */
    ClientOsName_str: string;
    /** Client OS version */
    ClientOsVer_str: string;
    /** Client OS Product ID */
    ClientOsProductId_str: string;
    /** Client host name */
    ClientHostname_str: string;
    /** Unique ID */
    UniqueId_bin: Uint8Array;
    /** Constructor for the 'VpnRpcSessionStatus' class: VPN Session status */
    constructor(init?: Partial<VpnRpcSessionStatus>);
}
/** Set the special listener */
export declare class VpnRpcSpecialListener {
    /** The flag to activate the VPN over ICMP server function */
    VpnOverIcmpListener_bool: boolean;
    /** The flag to activate the VPN over DNS function */
    VpnOverDnsListener_bool: boolean;
    /** Constructor for the 'VpnRpcSpecialListener' class: Set the special listener */
    constructor(init?: Partial<VpnRpcSpecialListener>);
}
/** Syslog configuration */
export declare enum VpnSyslogSaveType {
    /** Do not use syslog */
    None = 0,
    /** Only server log */
    ServerLog = 1,
    /** Server and Virtual HUB security log */
    ServerAndHubSecurityLog = 2,
    /** Server, Virtual HUB security, and packet log */
    ServerAndHubAllLog = 3
}
/** Syslog configuration */
export declare class VpnSyslogSetting {
    /** The behavior of the syslog function */
    SaveType_u32: VpnSyslogSaveType;
    /** Specify the host name or IP address of the syslog server */
    Hostname_str: string;
    /** Specify the port number of the syslog server */
    Port_u32: number;
    /** Constructor for the 'VpnSyslogSetting' class: Syslog configuration */
    constructor(init?: Partial<VpnSyslogSetting>);
}
/** VPN Gate Server Config */
export declare class VpnVgsConfig {
    /** Active flag */
    IsEnabled_bool: boolean;
    /** Message */
    Message_utf: string;
    /** Owner name */
    Owner_utf: string;
    /** Abuse email */
    Abuse_utf: string;
    /** Log save flag */
    NoLog_bool: boolean;
    /** Save log permanently */
    LogPermanent_bool: boolean;
    /** Enable the L2TP VPN function */
    EnableL2TP_bool: boolean;
    /** Constructor for the 'VpnVgsConfig' class: VPN Gate Server Config */
    constructor(init?: Partial<VpnVgsConfig>);
}
/** Read a Log file */
export declare class VpnRpcReadLogFile {
    /** Server name */
    ServerName_str: string;
    /** File Path */
    FilePath_str: string;
    /** Offset to download. You have to call the ReadLogFile API multiple times to download the entire log file with requesting a part of the file by specifying the Offset_u32 field. */
    Offset_u32: number;
    /** Received buffer */
    Buffer_bin: Uint8Array;
    /** Constructor for the 'VpnRpcReadLogFile' class: Read a Log file */
    constructor(init?: Partial<VpnRpcReadLogFile>);
}
/** Rename link */
export declare class VpnRpcRenameLink {
    /** The Virtual Hub name */
    HubName_str: string;
    /** The old name of the cascade connection */
    OldAccountName_utf: string;
    /** The new name of the cascade connection */
    NewAccountName_utf: string;
    /** Constructor for the 'VpnRpcRenameLink' class: Rename link */
    constructor(init?: Partial<VpnRpcRenameLink>);
}
/** Online or offline the HUB */
export declare class VpnRpcSetHubOnline {
    /** The Virtual Hub name */
    HubName_str: string;
    /** Online / offline flag */
    Online_bool: boolean;
    /** Constructor for the 'VpnRpcSetHubOnline' class: Online or offline the HUB */
    constructor(init?: Partial<VpnRpcSetHubOnline>);
}
/** Set Password */
export declare class VpnRpcSetPassword {
    /** The plaintext password */
    PlainTextPassword_str: string;
    /** Constructor for the 'VpnRpcSetPassword' class: Set Password */
    constructor(init?: Partial<VpnRpcSetPassword>);
}
/** JSON-RPC request class. See https://www.jsonrpc.org/specification */
export declare class JsonRpcRequest {
    jsonrpc: string;
    method: string;
    params: any;
    id: string;
    constructor(method?: string, param?: any, id?: string);
}
/** JSON-RPC error class. See https://www.jsonrpc.org/specification */
export declare class JsonRpcError {
    code: number;
    message: string;
    data: any;
    constructor(code?: number, message?: string, data?: any);
}
/** JSON-RPC response class with generics */
export declare class JsonRpcResponse<TResult> {
    jsonrpc: string;
    result: TResult;
    error: JsonRpcError;
    id: string;
}
/** JSON-RPC client class. See https://www.jsonrpc.org/specification */
export declare class JsonRpcClient {
    /** A utility function to convert any object to JSON string */
    static ObjectToJson(obj: any): string;
    /** A utility function to convert JSON string to object */
    static JsonToObject(str: string): any;
    /** Base URL */
    BaseUrl: string;
    /** The instance of HTTP client */
    private client;
    /** Additional HTTP headers */
    private headers;
    /**
     * JSON-RPC client class constructor
     * @param url The URL
     * @param headers Additional HTTP headers
     * @param send_credential Set true to use the same credential with the browsing web site. Valid only if the code is running on the web browser.
     */
    constructor(url: string, headers: {
        [name: string]: string;
    }, send_credential: boolean, nodejs_https_client_reject_untrusted_server_cert: boolean);
    /**
     * Call a single RPC call (without error check). You can wait for the response with Promise<string> or await statement.
     * @param method_name The name of RPC method
     * @param param The parameters
     */
    CallInternalAsync(method_name: string, param: any): Promise<string>;
    /**
     * Call a single RPC call (with error check). You can wait for the response with Promise<TResult> or await statement. In the case of error, it will be thrown.
     * @param method_name The name of RPC method
     * @param param The parameters
     */
    CallAsync<TResult>(method_name: string, param: any): Promise<TResult>;
}
/** JSON-RPC exception class */
export declare class JsonRpcException extends Error {
    Error: JsonRpcError;
    constructor(error: JsonRpcError);
}
/** HTTP client exception class */
export declare class HttpClientException extends Error {
    constructor(message: string);
}
/** HTTP client response class */
export declare class HttpClientResponse {
    Body: string;
}
/** An HTTP client which can be used in both web browsers and Node.js */
export declare class HttpClient {
    TimeoutMsecs: number;
    SendCredential: boolean;
    NodeJS_HTTPS_Client_Reject_Unauthorized: boolean;
    /** Post method. In web browsers this function will process the request by itself. In Node.js this function will call PostAsync_NodeJS() instead. */
    PostAsync(url: string, headers: {
        [name: string]: string;
    }, req_body: string, req_media_type: string): Promise<HttpClientResponse>;
    /** Post method for Node.js. */
    PostAsync_NodeJS(url: string, headers: {
        [name: string]: string;
    }, req_body: string, req_media_type: string): Promise<HttpClientResponse>;
}
export declare function Util_Base64_Decode(b64: any): Uint8Array;
export declare function Util_Base64_Encode(uint8: any): string;
//# sourceMappingURL=vpnrpc.d.ts.map
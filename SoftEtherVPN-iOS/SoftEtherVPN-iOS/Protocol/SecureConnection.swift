import Foundation
import Network
import Security

/// SecureConnection handles the TLS connection with the SoftEther VPN server
class SecureConnection {
    
    // MARK: - Properties
    
    private var connection: NWConnection?
    private let host: String
    private let port: UInt16
    private let queue = DispatchQueue(label: "com.softether.connection", qos: .userInitiated)
    
    // MARK: - Initialization
    
    /// Initialize a secure connection
    /// - Parameters:
    ///   - host: Server hostname or IP address
    ///   - port: Server port number
    init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }
    
    // MARK: - Public Methods
    
    /// Connect to the server using TLS
    /// - Parameter completion: Callback with connection result
    func connect(completion: @escaping (Bool, Error?) -> Void) {
        let hostEndpoint = NWEndpoint.Host(host)
        let portEndpoint = NWEndpoint.Port(rawValue: port)!
        
        // Create TLS parameters
        let tlsOptions = NWProtocolTLS.Options()
        
        // Configure TLS for maximum compatibility with SoftEther
        let securityOptions = tlsOptions.securityProtocolOptions
        sec_protocol_options_set_tls_min_version(securityOptions, .TLSv12)
        sec_protocol_options_set_tls_max_version(securityOptions, .TLSv13)
        
        // Allow all cipher suites for compatibility
        sec_protocol_options_set_cipher_suites(securityOptions, nil, 0)
        
        // Disable certificate validation for initial development (ENABLE IN PRODUCTION)
        sec_protocol_options_set_verify_block(securityOptions, { (_, _, trustResult, _) in
            return true // Accept all certificates for testing
        }, queue)
        
        // Create TCP options with TLS
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.enableKeepalive = true
        tcpOptions.keepaliveIdle = 30
        
        // Create connection parameters
        let parameters = NWParameters(tls: tlsOptions, tcp: tcpOptions)
        
        // Create the connection
        connection = NWConnection(host: hostEndpoint, port: portEndpoint, using: parameters)
        
        // Set up state handling
        connection?.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                completion(true, nil)
            case .failed(let error):
                self?.disconnect()
                completion(false, error)
            case .cancelled:
                completion(false, NSError(domain: "SoftEtherError", code: 1000, userInfo: [NSLocalizedDescriptionKey: "Connection cancelled"]))
            default:
                break
            }
        }
        
        // Start the connection
        connection?.start(queue: queue)
    }
    
    /// Disconnect from the server
    func disconnect() {
        connection?.cancel()
        connection = nil
    }
    
    /// Send data to the server
    /// - Parameters:
    ///   - data: Data to send
    ///   - completion: Callback with error if any
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        guard let connection = connection, connection.state == .ready else {
            completion(NSError(domain: "SoftEtherError", code: 1001, userInfo: [NSLocalizedDescriptionKey: "Connection not ready"]))
            return
        }
        
        connection.send(content: data, completion: .contentProcessed { error in
            completion(error)
        })
    }
    
    /// Receive data from the server
    /// - Parameter completion: Callback with received data and error if any
    func receive(completion: @escaping (Data?, Error?) -> Void) {
        guard let connection = connection, connection.state == .ready else {
            completion(nil, NSError(domain: "SoftEtherError", code: 1001, userInfo: [NSLocalizedDescriptionKey: "Connection not ready"]))
            return
        }
        
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
            completion(data, error)
            
            if isComplete {
                // Connection was closed by the peer
                self.disconnect()
            }
        }
    }
}
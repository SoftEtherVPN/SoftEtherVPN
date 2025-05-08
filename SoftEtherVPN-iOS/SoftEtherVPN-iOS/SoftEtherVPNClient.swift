import Foundation
import UIKit

/// SoftEtherVPNClient provides a simple interface for connecting to SoftEther VPN servers
public class SoftEtherVPNClient {
    
    // MARK: - Properties
    
    private let protocol: SoftEtherProtocol
    private var connectionState: ConnectionState = .disconnected
    
    // MARK: - Public Types
    
    /// Connection states for the VPN client
    public enum ConnectionState {
        case disconnected
        case connecting
        case connected
        case disconnecting
        case error(Error)
    }
    
    /// Connection delegate to receive state updates
    public protocol ConnectionDelegate: AnyObject {
        func connectionStateDidChange(_ state: ConnectionState)
    }
    
    /// Weak reference to the delegate
    public weak var delegate: ConnectionDelegate?
    
    // MARK: - Initialization
    
    public init() {
        self.protocol = SoftEtherProtocol()
    }
    
    // MARK: - Public Methods
    
    /// Connect to a SoftEther VPN server
    /// - Parameters:
    ///   - host: Server hostname or IP address
    ///   - port: Server port (default: 443)
    ///   - completion: Optional completion handler
    public func connect(to host: String, port: UInt16 = 443, completion: ((Bool, Error?) -> Void)? = nil) {
        // Update state
        connectionState = .connecting
        delegate?.connectionStateDidChange(connectionState)
        
        // Connect using the protocol implementation
        protocol.connect(to: host, port: port) { [weak self] success, error in
            guard let self = self else { return }
            
            if success {
                self.connectionState = .connected
            } else if let error = error {
                self.connectionState = .error(error)
            } else {
                self.connectionState = .disconnected
            }
            
            self.delegate?.connectionStateDidChange(self.connectionState)
            completion?(success, error)
        }
    }
    
    /// Disconnect from the server
    /// - Parameter completion: Optional completion handler
    public func disconnect(completion: (() -> Void)? = nil) {
        // Update state
        connectionState = .disconnecting
        delegate?.connectionStateDidChange(connectionState)
        
        // Disconnect
        protocol.disconnect()
        
        // Update state again
        connectionState = .disconnected
        delegate?.connectionStateDidChange(connectionState)
        
        completion?()
    }
    
    /// Get the current connection state
    /// - Returns: Current ConnectionState
    public func getConnectionState() -> ConnectionState {
        return connectionState
    }
    
    /// Check if currently connected
    /// - Returns: True if connected, false otherwise
    public func isConnected() -> Bool {
        if case .connected = connectionState {
            return true
        }
        return false
    }
    
    // MARK: - Example Usage
    
    /// Example showing how to use this class in a view controller
    public static func exampleUsage() -> String {
        return """
        // In your view controller:
        
        private let vpnClient = SoftEtherVPNClient()
        
        override func viewDidLoad() {
            super.viewDidLoad()
            
            // Set delegate
            vpnClient.delegate = self
        }
        
        @IBAction func connectButtonTapped(_ sender: UIButton) {
            if vpnClient.isConnected() {
                vpnClient.disconnect()
            } else {
                vpnClient.connect(to: "vpn.example.com") { success, error in
                    if !success {
                        print("Failed to connect: \\(error?.localizedDescription ?? "Unknown error")")
                    }
                }
            }
        }
        
        // MARK: - ConnectionDelegate
        
        extension YourViewController: SoftEtherVPNClient.ConnectionDelegate {
            func connectionStateDidChange(_ state: SoftEtherVPNClient.ConnectionState) {
                switch state {
                case .connected:
                    connectButton.setTitle("Disconnect", for: .normal)
                    statusLabel.text = "Connected"
                case .connecting:
                    statusLabel.text = "Connecting..."
                case .disconnecting:
                    statusLabel.text = "Disconnecting..."
                case .disconnected:
                    connectButton.setTitle("Connect", for: .normal)
                    statusLabel.text = "Disconnected"
                case .error(let error):
                    statusLabel.text = "Error: \\(error.localizedDescription)"
                    connectButton.setTitle("Connect", for: .normal)
                }
            }
        }
        """
    }
}
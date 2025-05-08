import Foundation
import Network
import Security
import CryptoKit

/// SoftEtherProtocol manages the communication between iOS client and SoftEther VPN server
class SoftEtherProtocol {
    
    // MARK: - Properties
    
    private var secureConnection: SecureConnection?
    private var isConnected = false
    private var host: String = ""
    private var port: UInt16 = 443
    private var nextPacketId: UInt32 = 1
    
    // MARK: - Public Methods
    
    /// Connect to a SoftEther VPN server
    /// - Parameters:
    ///   - host: The server hostname or IP address
    ///   - port: The server port (default: 443)
    ///   - completion: Callback with connection result
    public func connect(to host: String, port: UInt16 = 443, completion: @escaping (Bool, Error?) -> Void) {
        self.host = host
        self.port = port
        
        // Create a secure connection
        secureConnection = SecureConnection(host: host, port: port)
        
        // Connect using TLS
        secureConnection?.connect { [weak self] success, error in
            guard let self = self, success else {
                completion(false, error ?? NSError(domain: "SoftEtherError", code: 1, userInfo: [NSLocalizedDescriptionKey: "TLS connection failed"]))
                return
            }
            
            // After successful TLS connection, send the client signature
            self.sendClientSignature { success, error in
                if success {
                    self.isConnected = true
                }
                completion(success, error)
            }
        }
    }
    
    /// Disconnect from the server
    public func disconnect() {
        secureConnection?.disconnect()
        isConnected = false
    }
    
    // MARK: - Private Methods
    
    /// Send the SoftEther client signature to identify as a legitimate client
    /// - Parameter completion: Callback with result
    private func sendClientSignature(completion: @escaping (Bool, Error?) -> Void) {
        // Generate client signature using our specialized class
        let signatureData = SoftEtherClientSignature.generateSignature()
        
        // Create a packet with the signature data
        let packetId = self.nextPacketId
        self.nextPacketId += 1
        
        let packet = SoftEtherPacket(type: 0x01, id: packetId, data: signatureData)
        let packetData = packet.serialize()
        
        print("Sending client signature packet: \(packetData.count) bytes")
        
        // Send the packet
        secureConnection?.send(data: packetData) { [weak self] error in
            guard let self = self else { return }
            
            if let error = error {
                print("Error sending client signature: \(error)")
                completion(false, error)
                return
            }
            
            // After sending signature, wait for server response
            self.receiveServerResponse { success, error in
                completion(success, error)
            }
        }
    }
    
    /// Receive and process server response after sending signature
    /// - Parameter completion: Callback with result
    private func receiveServerResponse(completion: @escaping (Bool, Error?) -> Void) {
        secureConnection?.receive { data, error in
            if let error = error {
                print("Error receiving server response: \(error)")
                completion(false, error)
                return
            }
            
            guard let data = data, data.count > 4 else {
                let error = NSError(domain: "SoftEtherError", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid server response"])
                print("Invalid server response: insufficient data")
                completion(false, error)
                return
            }
            
            print("Received server response: \(data.count) bytes")
            
            // Parse the response packet
            guard let packet = SoftEtherPacket(fromData: data) else {
                let error = NSError(domain: "SoftEtherError", code: 3, userInfo: [NSLocalizedDescriptionKey: "Invalid packet format"])
                print("Could not parse server response packet")
                completion(false, error)
                return
            }
            
            // Verify the response
            let packetData = packet.getData()
            let isValid = SoftEtherClientSignature.verifyServerResponse(packetData)
            
            if isValid {
                print("Server accepted our client signature")
                completion(true, nil)
            } else {
                print("Server rejected our client signature")
                let error = NSError(domain: "SoftEtherError", code: 4, userInfo: [NSLocalizedDescriptionKey: "Server rejected client signature"])
                completion(false, error)
            }
        }
    }
    
    /// Send a data packet to the server
    /// - Parameters:
    ///   - data: Data to send
    ///   - completion: Callback with result
    func sendData(data: Data, completion: @escaping (Bool, Error?) -> Void) {
        guard isConnected else {
            completion(false, NSError(domain: "SoftEtherError", code: 5, userInfo: [NSLocalizedDescriptionKey: "Not connected to server"]))
            return
        }
        
        let packetId = self.nextPacketId
        self.nextPacketId += 1
        
        let packet = SoftEtherPacket(type: 0x05, id: packetId, data: data)
        let packetData = packet.serialize()
        
        secureConnection?.send(data: packetData) { error in
            if let error = error {
                completion(false, error)
                return
            }
            
            completion(true, nil)
        }
    }
    
    /// Receive data from the server
    /// - Parameter completion: Callback with received data and result
    func receiveData(completion: @escaping (Data?, Bool, Error?) -> Void) {
        guard isConnected else {
            completion(nil, false, NSError(domain: "SoftEtherError", code: 5, userInfo: [NSLocalizedDescriptionKey: "Not connected to server"]))
            return
        }
        
        secureConnection?.receive { data, error in
            if let error = error {
                completion(nil, false, error)
                return
            }
            
            guard let data = data, data.count > 4 else {
                completion(nil, false, NSError(domain: "SoftEtherError", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid server response"]))
                return
            }
            
            // Parse the packet
            guard let packet = SoftEtherPacket(fromData: data) else {
                completion(nil, false, NSError(domain: "SoftEtherError", code: 3, userInfo: [NSLocalizedDescriptionKey: "Invalid packet format"]))
                return
            }
            
            completion(packet.getData(), true, nil)
        }
    }
}
import Foundation

/// Handles the specific client signature format that SoftEther expects
class SoftEtherClientSignature {
    
    // MARK: - Constants
    
    private enum Constants {
        static let clientBuildNumber: UInt32 = 5187
        static let clientVersion: UInt32 = 5_02_0000 + clientBuildNumber
        static let clientString = "SoftEther VPN Client"
        static let softEtherMagic: [UInt8] = [0x5E, 0x68] // 'Se' in hex
        
        // Protocol identification constants from SoftEther source
        static let cedar = "CEDAR"
        static let sessionKey = "sessionkey"
        static let protocol1 = "PROTOCOL"
        static let protocol2 = "PROTOCOL2"
    }
    
    // MARK: - Public Methods
    
    /// Generate the client signature packet that identifies this client as a legitimate SoftEther VPN client
    /// - Returns: Data containing the formatted client signature
    static func generateSignature() -> Data {
        var data = Data()
        
        // 1. Add SoftEther magic bytes
        data.append(contentsOf: Constants.softEtherMagic)
        
        // 2. Add client version in network byte order (big endian)
        data.appendUInt32(Constants.clientVersion)
        
        // 3. Add client build number in network byte order
        data.appendUInt32(Constants.clientBuildNumber)
        
        // 4. Add cedar protocol identifier
        if let cedarData = Constants.cedar.data(using: .ascii) {
            data.append(cedarData)
            data.append(0) // null terminator
        }
        
        // 5. Add client string with null terminator
        if let clientString = (Constants.clientString + "\0").data(using: .ascii) {
            data.append(clientString)
        }
        
        // 6. Add protocol identifiers
        if let protocolData = (Constants.protocol1 + "\0").data(using: .ascii) {
            data.append(protocolData)
        }
        
        if let protocol2Data = (Constants.protocol2 + "\0").data(using: .ascii) {
            data.append(protocol2Data)
        }
        
        // 7. Add session key marker
        if let sessionKeyData = (Constants.sessionKey + "\0").data(using: .ascii) {
            data.append(sessionKeyData)
        }
        
        // 8. Add random data for session key (typically 20 bytes)
        let randomSessionKey = SoftEtherCrypto.randomBytes(count: 20)
        data.append(randomSessionKey)
        
        // 9. Calculate and append SHA-1 hash of the entire data for integrity verification
        let hash = SoftEtherCrypto.sha1(data)
        data.append(hash)
        
        return data
    }
    
    /// Verify a server response to the client signature
    /// - Parameter data: Response data from server
    /// - Returns: True if valid response, false otherwise
    static func verifyServerResponse(_ data: Data) -> Bool {
        // Basic validation - a real implementation would parse and validate the server response format
        // This is a minimal check to see if we have enough data and it starts with the magic bytes
        guard data.count >= 8 else {
            return false
        }
        
        // Check if response starts with SoftEther magic bytes
        if data[0] == Constants.softEtherMagic[0] && data[1] == Constants.softEtherMagic[1] {
            return true
        }
        
        return false
    }
}
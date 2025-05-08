import Foundation
import CryptoKit

/// Handles encryption operations for SoftEther protocol
class SoftEtherCrypto {
    
    // MARK: - Constants
    
    private enum Constants {
        static let sha1Size = 20
        static let md5Size = 16
    }
    
    // MARK: - Public Methods
    
    /// Generate secure random bytes
    /// - Parameter count: Number of random bytes to generate
    /// - Returns: Data containing random bytes
    static func randomBytes(count: Int) -> Data {
        var data = Data(count: count)
        _ = data.withUnsafeMutableBytes { 
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        return data
    }
    
    /// Calculate SHA-1 hash
    /// - Parameter data: Input data
    /// - Returns: SHA-1 hash of the input data
    static func sha1(_ data: Data) -> Data {
        let digest = SHA1.hash(data: data)
        return Data(digest)
    }
    
    /// Calculate MD5 hash
    /// - Parameter data: Input data
    /// - Returns: MD5 hash of the input data
    static func md5(_ data: Data) -> Data {
        let digest = Insecure.MD5.hash(data: data)
        return Data(digest)
    }
    
    /// Encrypt data using RC4 algorithm (for SoftEther compatibility)
    /// - Parameters:
    ///   - data: Data to encrypt
    ///   - key: Encryption key
    /// - Returns: Encrypted data
    static func rc4Encrypt(data: Data, key: Data) -> Data {
        let rc4 = RC4(key: key)
        return rc4.process(data)
    }
    
    /// Decrypt data using RC4 algorithm (for SoftEther compatibility)
    /// - Parameters:
    ///   - data: Data to decrypt
    ///   - key: Decryption key
    /// - Returns: Decrypted data
    static func rc4Decrypt(data: Data, key: Data) -> Data {
        // RC4 is symmetric, so encryption and decryption are the same operation
        return rc4Encrypt(data: data, key: key)
    }
}

/// Simple RC4 implementation for SoftEther compatibility
/// Note: RC4 is considered insecure, but SoftEther uses it in parts of its protocol
private class RC4 {
    private var state: [UInt8]
    
    init(key: Data) {
        state = Array(0...255)
        var j: Int = 0
        
        // Key scheduling algorithm
        for i in 0..<256 {
            let keyByte = key[i % key.count]
            j = (j + Int(state[i]) + Int(keyByte)) & 0xFF
            state.swapAt(i, j)
        }
    }
    
    func process(_ data: Data) -> Data {
        var result = Data(count: data.count)
        var i: Int = 0
        var j: Int = 0
        
        // Generate keystream and XOR with plaintext
        for k in 0..<data.count {
            i = (i + 1) & 0xFF
            j = (j + Int(state[i])) & 0xFF
            state.swapAt(i, j)
            let keyStreamByte = state[(Int(state[i]) + Int(state[j])) & 0xFF]
            result[k] = data[k] ^ keyStreamByte
        }
        
        return result
    }
}
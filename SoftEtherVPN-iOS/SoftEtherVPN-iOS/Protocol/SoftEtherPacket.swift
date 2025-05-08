import Foundation

/// Handles the SoftEther packet structure for communication
class SoftEtherPacket {
    
    // MARK: - Constants
    
    private enum PacketType: UInt32 {
        case clientSignature = 0x01
        case serverResponse = 0x02
        case sessionRequest = 0x03
        case sessionResponse = 0x04
        case data = 0x05
        case keepAlive = 0x06
    }
    
    private enum Constants {
        static let headerSize: UInt32 = 16
        static let maxPacketSize: UInt32 = 1024 * 1024 // 1MB
    }
    
    // MARK: - Properties
    
    private var packetType: PacketType
    private var packetId: UInt32
    private var packetData: Data
    
    // MARK: - Initialization
    
    /// Initialize a packet with type, ID and data
    /// - Parameters:
    ///   - type: Packet type
    ///   - id: Packet ID
    ///   - data: Packet payload
    init(type: UInt32, id: UInt32, data: Data) {
        self.packetType = PacketType(rawValue: type) ?? .data
        self.packetId = id
        self.packetData = data
    }
    
    /// Initialize a packet from raw data
    /// - Parameter data: Raw packet data
    init?(fromData data: Data) {
        guard data.count >= Int(Constants.headerSize) else {
            return nil
        }
        
        // Parse header
        let typeValue = data.readUInt32(at: 0)
        self.packetId = data.readUInt32(at: 4)
        let dataSize = data.readUInt32(at: 8)
        
        // Validate packet
        guard let type = PacketType(rawValue: typeValue),
              dataSize <= Constants.maxPacketSize,
              data.count >= Int(Constants.headerSize + dataSize) else {
            return nil
        }
        
        self.packetType = type
        
        // Extract payload
        let startIndex = Int(Constants.headerSize)
        let endIndex = startIndex + Int(dataSize)
        self.packetData = data.subdata(in: startIndex..<endIndex)
    }
    
    // MARK: - Public Methods
    
    /// Serialize the packet to binary data format
    /// - Returns: Serialized packet data
    func serialize() -> Data {
        var result = Data(capacity: Int(Constants.headerSize) + packetData.count)
        
        // Write header
        result.appendUInt32(packetType.rawValue)
        result.appendUInt32(packetId)
        result.appendUInt32(UInt32(packetData.count))
        result.appendUInt32(0) // Reserved
        
        // Write payload
        result.append(packetData)
        
        return result
    }
    
    /// Get the packet type
    /// - Returns: Packet type
    func getType() -> UInt32 {
        return packetType.rawValue
    }
    
    /// Get the packet ID
    /// - Returns: Packet ID
    func getId() -> UInt32 {
        return packetId
    }
    
    /// Get the packet payload
    /// - Returns: Packet payload data
    func getData() -> Data {
        return packetData
    }
}

// MARK: - Extensions

extension Data {
    /// Read a UInt32 value from the data at specified offset
    /// - Parameter offset: Offset to read from
    /// - Returns: UInt32 value in big-endian order
    func readUInt32(at offset: Int) -> UInt32 {
        let slice = self.subdata(in: offset..<(offset + 4))
        return slice.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
    }
    
    /// Append a UInt32 value to the data in big-endian order
    /// - Parameter value: UInt32 value to append
    mutating func appendUInt32(_ value: UInt32) {
        var bigEndian = value.bigEndian
        append(UnsafeBufferPointer(start: &bigEndian, count: 1))
    }
}
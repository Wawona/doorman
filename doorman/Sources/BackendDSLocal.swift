import CommonCrypto
import Foundation

private let localUsersDir = "/var/db/dslocal/nodes/Default/users"

private func scrubVolatile(_ data: inout Data) {
    data.withUnsafeMutableBytes { buf in
        guard let base = buf.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
        for i in 0..<buf.count { base[i] = 0 }
    }
}

private struct Pbkdf2Params {
    var stored: Data?
    var salt: Data?
    var rounds: UInt32
}

private func secretMatches(_ secret: String, _ params: Pbkdf2Params) -> Bool {
    guard let stored = params.stored, let salt = params.salt, params.rounds > 0, !stored.isEmpty else {
        return false
    }
    guard let secretUTF8 = secret.cString(using: .utf8) else { return false }
    var scratch = Data(repeating: 0, count: stored.count)
    let kdf = scratch.withUnsafeMutableBytes { scratchBytes in
        salt.withUnsafeBytes { saltBytes in
            CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                secretUTF8, secret.utf8.count,
                saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
                params.rounds,
                scratchBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), stored.count
            )
        }
    }
    guard kdf == kCCSuccess else { return false }
    defer { scrubVolatile(&scratch) }
    return scratch.withUnsafeBytes { scratchBytes in
        stored.withUnsafeBytes { storedBytes in
            _dm_consttime_equal(
                scratchBytes.baseAddress,
                storedBytes.baseAddress,
                stored.count
            )
        }
    }
}

private func decodeShadowBlob(_ record: [String: Any]) -> [String: Any]? {
    guard let blobs = record["ShadowHashData"] as? [Any], let first = blobs.first as? Data else {
        return nil
    }
    var format = PropertyListSerialization.PropertyListFormat.binary
    guard let decoded = try? PropertyListSerialization.propertyList(
        from: first, options: [], format: &format
    ), let dict = decoded as? [String: Any] else {
        return nil
    }
    return dict
}

@_cdecl("_dm_verify_dslocal")
public func dmVerifyDSLocal(_ user: UnsafePointer<CChar>?, _ password: UnsafePointer<CChar>?) -> doorman_result_t {
    guard let user, let password else { return DOORMAN_ERR_INVALID_ARG }
    guard _dm_name_ok(user) else { return DOORMAN_ERR_USER_UNKNOWN }

    let name = String(cString: user)
    let secret = String(cString: password)
    let recordPath = (localUsersDir as NSString).appendingPathComponent("\(name).plist")
    guard let record = NSDictionary(contentsOfFile: recordPath) as? [String: Any] else {
        if !FileManager.default.fileExists(atPath: recordPath) { return DOORMAN_ERR_USER_UNKNOWN }
        return DOORMAN_ERR_PERM
    }
    guard let shadow = decodeShadowBlob(record) else { return DOORMAN_ERR_ACCT_DISABLED }
    guard let pbkdf2 = shadow["SALTED-SHA512-PBKDF2"] as? [String: Any] else { return DOORMAN_ERR_ACCT_DISABLED }
    let params = Pbkdf2Params(
        stored: pbkdf2["entropy"] as? Data,
        salt: pbkdf2["salt"] as? Data,
        rounds: UInt32((pbkdf2["iterations"] as? NSNumber)?.uintValue ?? 0)
    )
    guard params.stored != nil, params.salt != nil else { return DOORMAN_ERR_ACCT_DISABLED }
    return secretMatches(secret, params) ? DOORMAN_SUCCESS : DOORMAN_ERR_AUTH
}

@_silgen_name("_dm_name_ok")
private func _dm_name_ok(_ name: UnsafePointer<CChar>?) -> Bool

@_silgen_name("_dm_consttime_equal")
private func _dm_consttime_equal(_ a: UnsafeRawPointer?, _ b: UnsafeRawPointer?, _ len: Int) -> Bool

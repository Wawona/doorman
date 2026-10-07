import Foundation
import OpenDirectory

private enum ODErr {
    static let credentialsInvalid = 5000
    static let accountDisabled = 5001
    static let accountInactive = 5002
    static let accountExpired = 5003
    static let passwordExpired = 5004
}

private func fetchRecord(_ nodeType: UInt32, name: String) throws -> ODRecord {
    let session = ODSession.default()
    let node = try ODNode(session: session, type: ODNodeType(nodeType))
    return try node.record(withRecordType: kODRecordTypeUsers, name: name, attributes: nil as [AnyHashable: Any]?)
}

private func classifyVerify(_ verified: Bool, _ err: Error?) -> doorman_result_t {
    if verified { return DOORMAN_SUCCESS }
    let code = (err as NSError?)?.code ?? ODErr.credentialsInvalid
    switch code {
    case ODErr.credentialsInvalid:
        return DOORMAN_ERR_AUTH
    case ODErr.accountDisabled, ODErr.accountInactive, ODErr.accountExpired, ODErr.passwordExpired:
        return DOORMAN_ERR_ACCT_DISABLED
    default:
        return DOORMAN_ERR_SYSTEM
    }
}

@_cdecl("_dm_verify_opendirectory")
public func dmVerifyOpenDirectory(_ user: UnsafePointer<CChar>?, _ password: UnsafePointer<CChar>?) -> doorman_result_t {
    guard let user, let password else { return DOORMAN_ERR_INVALID_ARG }
    guard _dm_name_ok(user) else { return DOORMAN_ERR_USER_UNKNOWN }
    let name = String(cString: user)
    let secret = String(cString: password)
    do {
        let record = try fetchRecord(UInt32(kODNodeTypeAuthentication), name: name)
        do {
            try record.verifyPassword(secret)
            return DOORMAN_SUCCESS
        } catch {
            return classifyVerify(false, error)
        }
    } catch {
        return DOORMAN_ERR_USER_UNKNOWN
    }
}

@_cdecl("_dm_account_is_enabled")
public func dmAccountIsEnabled(_ user: UnsafePointer<CChar>?) -> doorman_result_t {
    guard let user else { return DOORMAN_ERR_INVALID_ARG }
    guard _dm_name_ok(user) else { return DOORMAN_ERR_USER_UNKNOWN }
    let name = String(cString: user)
    do {
        let record = try fetchRecord(UInt32(kODNodeTypeAuthentication), name: name)
        let authority = try record.values(forAttribute: kODAttributeTypeAuthenticationAuthority) as? [String] ?? []
        for value in authority where value.contains("DisabledUser") {
            return DOORMAN_ERR_ACCT_DISABLED
        }
        return DOORMAN_SUCCESS
    } catch {
        return DOORMAN_ERR_USER_UNKNOWN
    }
}

@_cdecl("_dm_od_set_password")
public func dmOdSetPassword(_ user: UnsafePointer<CChar>?, _ newPassword: UnsafePointer<CChar>?) -> doorman_result_t {
    guard let user, let newPassword else { return DOORMAN_ERR_INVALID_ARG }
    guard _dm_name_ok(user) else { return DOORMAN_ERR_USER_UNKNOWN }
    let name = String(cString: user)
    let secret = String(cString: newPassword)
    do {
        let record = try fetchRecord(UInt32(kODNodeTypeLocalNodes), name: name)
        do {
            try record.changePassword(nil, toPassword: secret)
            return DOORMAN_SUCCESS
        } catch {
            return DOORMAN_ERR_SYSTEM
        }
    } catch {
        return DOORMAN_ERR_USER_UNKNOWN
    }
}

@_silgen_name("_dm_name_ok")
private func _dm_name_ok(_ name: UnsafePointer<CChar>?) -> Bool

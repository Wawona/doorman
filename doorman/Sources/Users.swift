import Foundation

private let firstInteractiveUID: uid_t = 500

private func accountIsHidden(_ pw: UnsafePointer<passwd>) -> Bool {
    guard let name = pw.pointee.pw_name else { return true }
    if pw.pointee.pw_uid != 0 && pw.pointee.pw_uid < firstInteractiveUID { return true }
    if name.pointee == UInt8(ascii: "_") { return true }
    if let shell = pw.pointee.pw_shell {
        let shells = ["/usr/bin/false", "/sbin/nologin", "/usr/bin/nologin"]
        for s in shells where String(cString: shell) == s { return true }
    }
    return false
}

private func populateUser(_ pw: UnsafePointer<passwd>, _ u: UnsafeMutablePointer<doorman_user_t>) {
    u.pointee.name = pw.pointee.pw_name.map { strdup($0) } ?? nil
    if let gecos = pw.pointee.pw_gecos, gecos.pointee != 0 {
        u.pointee.full_name = strdup(gecos)
    } else {
        u.pointee.full_name = nil
    }
    u.pointee.home = pw.pointee.pw_dir.map { strdup($0) } ?? nil
    u.pointee.shell = pw.pointee.pw_shell.map { strdup($0) } ?? nil
    u.pointee.uid = pw.pointee.pw_uid
    u.pointee.gid = pw.pointee.pw_gid
    u.pointee.hidden = accountIsHidden(pw)
}

@_cdecl("doorman_enumerate_users")
public func doormanEnumerateUsers(
    _ interactiveOnly: Bool,
    _ out: UnsafeMutablePointer<UnsafeMutablePointer<doorman_user_t>?>?,
    _ count: UnsafeMutablePointer<Int>?
) -> Int32 {
    guard let out, let count else { return 9 }
    out.pointee = nil
    count.pointee = 0
    var cap = 16
    var n = 0
    guard var list = calloc(cap, MemoryLayout<doorman_user_t>.size)?.assumingMemoryBound(to: doorman_user_t.self) else {
        return 8
    }
    setpwent()
    while let pw = getpwent() {
        if interactiveOnly && accountIsHidden(pw) { continue }
        if n == cap {
            cap *= 2
            guard let grown = realloc(list, cap * MemoryLayout<doorman_user_t>.size)?.assumingMemoryBound(to: doorman_user_t.self) else {
                endpwent()
                for i in 0..<n { doormanFreeUserFields(list.advanced(by: i)) }
                free(list)
                return 8
            }
            list = grown
        }
        populateUser(pw, list.advanced(by: n))
        n += 1
    }
    endpwent()
    out.pointee = list
    count.pointee = n
    return 0
}

@_cdecl("doorman_free_users")
public func doormanFreeUsers(_ users: UnsafeMutablePointer<doorman_user_t>?, _ count: Int) {
    guard let users else { return }
    for i in 0..<count {
        doormanFreeUserFields(users.advanced(by: i))
    }
    free(users)
}

@_cdecl("doorman_free_user_fields")
public func doormanFreeUserFields(_ user: UnsafeMutablePointer<doorman_user_t>?) {
    guard let user else { return }
    free(user.pointee.name)
    free(user.pointee.full_name)
    free(user.pointee.home)
    free(user.pointee.shell)
    user.pointee = doorman_user_t()
}

@_cdecl("_dm_fill_user_from_passwd")
public func dmFillUserFromPasswd(_ name: UnsafePointer<CChar>?, _ out: UnsafeMutablePointer<doorman_user_t>?) -> Bool {
    guard let name, let out else { return false }
    guard let pw = getpwnam(name) else { return false }
    populateUser(pw, out)
    return true
}

@_cdecl("doorman_lookup_user")
public func doormanLookupUser(_ name: UnsafePointer<CChar>?, _ out: UnsafeMutablePointer<doorman_user_t>?) -> Int32 {
    guard let name, let out else { return 9 }
    out.pointee = doorman_user_t()
    if !dmFillUserFromPasswd(name, out) { return 2 }
    return 0
}

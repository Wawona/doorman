import Foundation

private let dsclPath = "/usr/bin/dscl"
private let dsEditGroupPath = "/usr/sbin/dseditgroup"
private let createHomePath = "/usr/sbin/createhomedir"

private func captureTool(path: String, args: [String], out: inout String?) -> Int32 {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: path)
    task.arguments = args
    let pipe = Pipe()
    task.standardOutput = pipe
    task.standardError = FileHandle.nullDevice
    do {
        try task.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        if out != nil { out = String(data: data, encoding: .utf8) }
        task.waitUntilExit()
        return task.terminationStatus
    } catch {
        return -1
    }
}

private func invokeTool(path: String, args: [String]) -> Int32 {
    var ignored: String?
    return captureTool(path: path, args: args, out: &ignored)
}

private func runningAsRoot() -> Bool { geteuid() == 0 }

private func allocateUID() -> uid_t {
    var out: String?
    guard captureTool(path: dsclPath, args: [".", "-list", "/Users", "UniqueID"], out: &out) == 0,
          let out else { return 501 }
    var highest: Int64 = 500
    for line in out.split(separator: "\n") {
        let last = line.split(whereSeparator: { $0.isWhitespace }).last.map(String.init) ?? ""
        guard !last.isEmpty, let value = Int64(last), value > highest, value < 100_000 else { continue }
        highest = value
    }
    return uid_t(highest + 1)
}

private func userDsclPath(_ name: String) -> String { "/Users/\(name)" }

@_cdecl("doorman_create_user")
public func doormanCreateUser(_ spec: UnsafePointer<doorman_user_spec_t>?) -> Int32 {
    guard let spec else { return 9 }
    let s = spec.pointee
    guard let cName = s.name, _dm_name_ok(cName) else { return 9 }
    guard runningAsRoot() else { return 4 }
    let shortName = String(cString: cName)
    if getpwnam(cName) != nil { return 8 }
    let recPath = userDsclPath(shortName)
    let realName = s.full_name.map { String(cString: $0) } ?? shortName
    let home = s.home.map { String(cString: $0) } ?? "/Users/\(shortName)"
    let shell = s.shell.map { String(cString: $0) } ?? "/bin/zsh"
    let uid = s.uid != 0 ? s.uid : allocateUID()
    let gid: gid_t = s.gid != 0 ? s.gid : 20
    let steps: [[String]] = [
        [".", "-create", recPath],
        [".", "-create", recPath, "RealName", realName],
        [".", "-create", recPath, "UniqueID", "\(uid)"],
        [".", "-create", recPath, "PrimaryGroupID", "\(gid)"],
        [".", "-create", recPath, "NFSHomeDirectory", home],
        [".", "-create", recPath, "UserShell", shell],
    ]
    for step in steps where invokeTool(path: dsclPath, args: step) != 0 {
        _ = invokeTool(path: dsclPath, args: [".", "-delete", recPath])
        return 8
    }
    if s.hidden {
        _ = invokeTool(path: dsclPath, args: [".", "-create", recPath, "IsHidden", "1"])
    }
    if let pw = s.password {
        if _dm_od_set_password(cName, pw) != 0 {
            _ = invokeTool(path: dsclPath, args: [".", "-delete", recPath])
            return 8
        }
    }
    if s.admin {
        _ = invokeTool(path: dsEditGroupPath, args: ["-o", "edit", "-a", shortName, "-t", "user", "admin"])
    }
    if s.create_home {
        if doormanCreateHome(cName) != 0 { return 8 }
    }
    return 0
}

@_cdecl("doorman_delete_user")
public func doormanDeleteUser(_ name: UnsafePointer<CChar>?, _ removeHome: Bool) -> Int32 {
    guard let name, _dm_name_ok(name) else { return 9 }
    guard runningAsRoot() else { return 4 }
    guard let pw = getpwnam(name) else { return 2 }
    let home = pw.pointee.pw_dir.map { String(cString: $0) }
    if invokeTool(path: dsclPath, args: [".", "-delete", userDsclPath(String(cString: name))]) != 0 { return 8 }
    if removeHome, let home, home.hasPrefix("/Users/"), !home.contains("..") {
        try? FileManager.default.removeItem(atPath: home)
    }
    return 0
}

@_cdecl("doorman_set_password")
public func doormanSetPassword(_ name: UnsafePointer<CChar>?, _ newPassword: UnsafePointer<CChar>?) -> Int32 {
    guard let name, let newPassword, _dm_name_ok(name) else { return 9 }
    guard runningAsRoot() else { return 4 }
    if getpwnam(name) == nil { return 2 }
    return _dm_od_set_password(name, newPassword)
}

@_cdecl("doorman_create_home")
public func doormanCreateHome(_ name: UnsafePointer<CChar>?) -> Int32 {
    guard let name, _dm_name_ok(name) else { return 9 }
    guard runningAsRoot() else { return 4 }
    let rc = invokeTool(path: createHomePath, args: ["-c", "-u", String(cString: name)])
    return rc == 0 ? 0 : 8
}

@_cdecl("doorman_create_group")
public func doormanCreateGroup(_ name: UnsafePointer<CChar>?, _ gid: gid_t, _ fullName: UnsafePointer<CChar>?) -> Int32 {
    guard let name, _dm_name_ok(name) else { return 9 }
    guard runningAsRoot() else { return 4 }
    var args = ["-o", "create"]
    if gid != 0 { args += ["-i", "\(gid)"] }
    if let fullName { args += ["-r", String(cString: fullName)] }
    args.append(String(cString: name))
    return invokeTool(path: dsEditGroupPath, args: args) == 0 ? 0 : 8
}

@_cdecl("doorman_delete_group")
public func doormanDeleteGroup(_ name: UnsafePointer<CChar>?) -> Int32 {
    guard let name, _dm_name_ok(name) else { return 9 }
    guard runningAsRoot() else { return 4 }
    return invokeTool(path: dsEditGroupPath, args: ["-o", "delete", String(cString: name)]) == 0 ? 0 : 8
}

@_cdecl("doorman_add_user_to_group")
public func doormanAddUserToGroup(_ user: UnsafePointer<CChar>?, _ group: UnsafePointer<CChar>?) -> Int32 {
    editMembership(user: user, group: group, add: true)
}

@_cdecl("doorman_remove_user_from_group")
public func doormanRemoveUserFromGroup(_ user: UnsafePointer<CChar>?, _ group: UnsafePointer<CChar>?) -> Int32 {
    editMembership(user: user, group: group, add: false)
}

private func editMembership(user: UnsafePointer<CChar>?, group: UnsafePointer<CChar>?, add: Bool) -> Int32 {
    guard let user, let group, _dm_name_ok(user), _dm_name_ok(group) else { return 9 }
    guard runningAsRoot() else { return 4 }
    if getpwnam(user) == nil { return 2 }
    let rc = invokeTool(
        path: dsEditGroupPath,
        args: ["-o", "edit", add ? "-a" : "-d", String(cString: user), "-t", "user", String(cString: group)]
    )
    return rc == 0 ? 0 : 8
}

@_silgen_name("_dm_name_ok")
private func _dm_name_ok(_ name: UnsafePointer<CChar>?) -> Bool

@_silgen_name("_dm_od_set_password")
private func _dm_od_set_password(_ user: UnsafePointer<CChar>?, _ password: UnsafePointer<CChar>?) -> Int32

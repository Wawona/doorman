import Darwin
import Foundation

private func dupC(_ s: String) -> UnsafePointer<CChar>? {
    guard let p = strdup(s) else { return nil }
    return UnsafePointer(p)
}

private func scrubFree(_ s: inout UnsafeMutablePointer<CChar>?) {
    guard var p = s else { return }
    let len = strlen(p)
    _ = p.withMemoryRebound(to: UInt8.self, capacity: len) { buf in
        for i in 0..<len { buf[i] = 0 }
    }
    free(p)
    s = nil
}

private func readLineRaw(_ prompt: String?) -> UnsafeMutablePointer<CChar>? {
    if let prompt { fputs(prompt, stderr); fflush(stderr) }
    var line: UnsafeMutablePointer<CChar>?
    var cap: size_t = 0
    let n = getline(&line, &cap, stdin)
    if n <= 0 { free(line); return nil }
    if line![Int(n - 1)] == 10 { line![Int(n - 1)] = 0 }
    return line
}

private func readSecret(_ prompt: String?) -> UnsafeMutablePointer<CChar>? {
    if let prompt { fputs(prompt, stderr); fflush(stderr) }
    var oldt = termios()
    let isTty = tcgetattr(STDIN_FILENO, &oldt) == 0
    var newt = termios()
    if isTty {
        newt = oldt
        newt.c_lflag &= ~UInt(ECHO)
        tcsetattr(STDIN_FILENO, TCSANOW, &newt)
    }
    defer {
        if isTty { tcsetattr(STDIN_FILENO, TCSANOW, &oldt); putchar(10) }
    }
    return readLineRaw(nil)
}

private func parseID(_ s: String?) -> UInt32? {
    guard let s, !s.isEmpty else { return nil }
    return s.withCString { cstr in
        var end: UnsafeMutablePointer<CChar>?
        errno = 0
        let v = strtoul(cstr, &end, 10)
        if errno != 0 { return nil }
        guard let end, end != cstr, end.pointee == 0, v <= UInt32.max else { return nil }
        return UInt32(v)
    }
}

private func parseBackend(_ s: String?) -> doorman_backend_t {
    guard let s else { return DOORMAN_BACKEND_AUTO }
    switch s {
    case "opendirectory": return DOORMAN_BACKEND_OPENDIRECTORY
    case "dslocal": return DOORMAN_BACKEND_DSLOCAL
    case "pam": return DOORMAN_BACKEND_PAM
    default: return DOORMAN_BACKEND_AUTO
    }
}

private func makeConv() -> doorman_conv_t {
    var conv = doorman_conv_t()
    conv.conv = doorman_cli_conv
    conv.appdata = nil
    return conv
}

private func cmdAuthenticate(_ args: [String]) -> Int32 {
    var user: String?
    var backend: String?
    var i = 0
    while i < args.count {
        if args[i] == "--backend", i + 1 < args.count { backend = args[i + 1]; i += 2; continue }
        if !args[i].hasPrefix("-") { user = args[i] }
        i += 1
    }
    guard let user else {
        fputs("usage: doorman authenticate <user> [--backend b]\n", stderr)
        return 2
    }
    var conv = makeConv()
    var h: UnsafeMutablePointer<doorman_handle_t>?
    if doorman_start("login", user, &conv, parseBackend(backend), &h) != DOORMAN_SUCCESS {
        fputs("doorman: could not start transaction\n", stderr)
        return 1
    }
    var r = doorman_authenticate(h)
    if r == DOORMAN_SUCCESS { r = doorman_acct_mgmt(h) }
    doorman_end(h)
    if r == DOORMAN_SUCCESS { print("authentication succeeded for \(user)"); return 0 }
    let err = doorman_strerror(r).map { String(cString: $0) } ?? "unknown"
    fputs("authentication failed for \(user): \(err)\n", stderr)
    return 1
}

private func cmdLogin(_ args: [String]) -> Int32 {
    var user: String?
    var backend: String?
    var sessionId: String?
    var execCmd: String?
    var i = 0
    while i < args.count {
        let a = args[i]
        if a == "--backend", i + 1 < args.count { backend = args[i + 1]; i += 2; continue }
        if a == "--exec", i + 1 < args.count { execCmd = args[i + 1]; i += 2; continue }
        if a == "--session", i + 1 < args.count { sessionId = args[i + 1]; i += 2; continue }
        if !a.hasPrefix("-") { user = a }
        i += 1
    }
    guard let user else {
        fputs("usage: doorman login <user> [--exec CMD] [--session ID]\n", stderr)
        return 2
    }
    var conv = makeConv()
    var h: UnsafeMutablePointer<doorman_handle_t>?
    if doorman_start("login", user, &conv, parseBackend(backend), &h) != DOORMAN_SUCCESS { return 1 }
    var r = doorman_authenticate(h)
    if r == DOORMAN_SUCCESS { r = doorman_acct_mgmt(h) }
    if r == DOORMAN_SUCCESS { r = doorman_setcred(h, DOORMAN_CRED_ESTABLISH) }
    if r != DOORMAN_SUCCESS {
        let err = doorman_strerror(r).map { String(cString: $0) } ?? "unknown"
        fputs("login failed for \(user): \(err)\n", stderr)
        doorman_end(h)
        return 1
    }
    var adhoc = doorman_session_t()
    var chosen: UnsafePointer<doorman_session_t>?
    var sessions: UnsafeMutablePointer<doorman_session_t>?
    var ns = 0
    if let execCmd {
        adhoc.id = strdup("cli")
        adhoc.name = strdup("cli")
        adhoc.exec = strdup(execCmd)
        adhoc.type = strdup("tty")
        chosen = withUnsafePointer(to: &adhoc) { $0 }
    } else {
        doorman_enumerate_sessions(&sessions, &ns)
        for j in 0..<ns {
            let s = sessions!.advanced(by: j)
            if let sessionId, let id = s.pointee.id, String(cString: id) == sessionId {
                chosen = UnsafePointer(s)
                break
            }
            if sessionId == nil && chosen == nil { chosen = UnsafePointer(s) }
        }
    }
    guard chosen != nil else {
        fputs("no session to launch\n", stderr)
        doorman_end(h)
        return 1
    }
    var pid: pid_t = 0
    r = doorman_open_session(h, chosen!, &pid)
    var rc: Int32 = 1
    if r == DOORMAN_SUCCESS {
        var status: Int32 = 0
        waitpid(pid, &status, 0)
        rc = (status & 0x7f) == 0 ? ((status >> 8) & 0xff) : 1
        doorman_close_session(h)
    } else {
        let err = doorman_strerror(r).map { String(cString: $0) } ?? "unknown"
        fputs("could not open session: \(err)\n", stderr)
    }
    if sessions != nil { doorman_free_sessions(sessions, ns) }
    doorman_end(h)
    return rc
}

private func cmdUseradd(_ args: [String]) -> Int32 {
    var spec = doorman_user_spec_t()
    spec.create_home = true
    var addGroups: String?
    var i = 0
    while i < args.count {
        let a = args[i]
        if a == "-m" || a == "--create-home" { spec.create_home = true }
        else if a == "-M" || a == "--no-create-home" { spec.create_home = false }
        else if (a == "-u" || a == "--uid"), i + 1 < args.count, let v = parseID(args[i + 1]) { spec.uid = uid_t(v); i += 1 }
        else if (a == "-g" || a == "--gid"), i + 1 < args.count, let v = parseID(args[i + 1]) { spec.gid = gid_t(v); i += 1 }
        else if (a == "-s" || a == "--shell"), i + 1 < args.count { spec.shell = dupC(args[i + 1]); i += 1 }
        else if (a == "-c" || a == "--comment"), i + 1 < args.count { spec.full_name = dupC(args[i + 1]); i += 1 }
        else if (a == "-d" || a == "--home-dir"), i + 1 < args.count { spec.home = dupC(args[i + 1]); i += 1 }
        else if (a == "-p" || a == "--password"), i + 1 < args.count { spec.password = dupC(args[i + 1]); i += 1 }
        else if (a == "-G" || a == "--groups"), i + 1 < args.count { addGroups = args[i + 1]; i += 1 }
        else if a == "--admin" { spec.admin = true }
        else if a == "--hidden" { spec.hidden = true }
        else if !a.hasPrefix("-") { spec.name = dupC(a) }
        i += 1
    }
    guard spec.name != nil else {
        fputs("usage: doorman useradd [opts] <name>\n", stderr)
        return 2
    }
    let r = doorman_create_user(&spec)
    if r != DOORMAN_SUCCESS {
        fputs("useradd: \(doorman_strerror(r).map { String(cString: $0) } ?? "?")\n", stderr)
        return 1
    }
    if let addGroups, let name = spec.name {
        for grp in addGroups.split(separator: ",") {
            let g = String(grp)
            if !g.isEmpty { _ = doorman_add_user_to_group(name, g) }
        }
    }
    print("created user \(String(cString: spec.name!))")
    return 0
}

private func cmdUserdel(_ args: [String]) -> Int32 {
    var name: String?
    var removeHome = false
    for a in args {
        if a == "-r" || a == "--remove" { removeHome = true }
        else if !a.hasPrefix("-") { name = a }
    }
    guard let name else { fputs("usage: doorman userdel [-r] <name>\n", stderr); return 2 }
    let r = doorman_delete_user(name, removeHome)
    if r != DOORMAN_SUCCESS { fputs("userdel: \(doorman_strerror(r).map { String(cString: $0) } ?? "?")\n", stderr); return 1 }
    print("deleted user \(name)")
    return 0
}

private func cmdPasswd(_ args: [String]) -> Int32 {
    var user: String?
    var useStdin = false
    for a in args {
        if a == "--stdin" { useStdin = true }
        else if !a.hasPrefix("-") { user = a }
    }
    guard let user else { fputs("usage: doorman passwd [--stdin] <user>\n", stderr); return 2 }
    var pw: UnsafeMutablePointer<CChar>?
    if useStdin || isatty(STDIN_FILENO) == 0 {
        pw = readLineRaw(nil)
    } else {
        pw = readSecret("New password: ")
        var confirm = readSecret("Retype new password: ")
        if pw == nil || confirm == nil || strcmp(pw, confirm) != 0 {
            fputs("passwd: passwords do not match\n", stderr)
            scrubFree(&pw); scrubFree(&confirm)
            return 1
        }
        scrubFree(&confirm)
    }
    guard pw != nil else { fputs("passwd: no password provided\n", stderr); return 1 }
    let r = doorman_set_password(user, pw)
    scrubFree(&pw)
    if r != DOORMAN_SUCCESS { fputs("passwd: \(doorman_strerror(r).map { String(cString: $0) } ?? "?")\n", stderr); return 1 }
    print("password updated for \(user)")
    return 0
}

private func cmdGroupadd(_ args: [String]) -> Int32 {
    var name: String?
    var real: String?
    var gid: gid_t = 0
    var i = 0
    while i < args.count {
        let a = args[i]
        if (a == "-g" || a == "--gid"), i + 1 < args.count, let v = parseID(args[i + 1]) { gid = gid_t(v); i += 1 }
        else if (a == "-r" || a == "--realname"), i + 1 < args.count { real = args[i + 1]; i += 1 }
        else if !a.hasPrefix("-") { name = a }
        i += 1
    }
    guard let name else { fputs("usage: doorman groupadd [-g gid] <name>\n", stderr); return 2 }
    let r = doorman_create_group(name, gid, real)
    if r != DOORMAN_SUCCESS { fputs("groupadd: \(doorman_strerror(r).map { String(cString: $0) } ?? "?")\n", stderr); return 1 }
    print("created group \(name)")
    return 0
}

private func cmdGroupdel(_ args: [String]) -> Int32 {
    let name = args.last.flatMap { $0.hasPrefix("-") ? nil : $0 }
    guard let name else { fputs("usage: doorman groupdel <name>\n", stderr); return 2 }
    let r = doorman_delete_group(name)
    if r != DOORMAN_SUCCESS { fputs("groupdel: \(doorman_strerror(r).map { String(cString: $0) } ?? "?")\n", stderr); return 1 }
    print("deleted group \(name)")
    return 0
}

private func cmdGpasswd(_ args: [String]) -> Int32 {
    var user: String?
    var group: String?
    var mode = 0
    var i = 0
    while i < args.count {
        let a = args[i]
        if (a == "-a" || a == "--add"), i + 1 < args.count { user = args[i + 1]; mode = 1; i += 1 }
        else if (a == "-d" || a == "--delete"), i + 1 < args.count { user = args[i + 1]; mode = -1; i += 1 }
        else if !a.hasPrefix("-") { group = a }
        i += 1
    }
    guard let user, let group, mode != 0 else {
        fputs("usage: doorman gpasswd -a|-d <user> <group>\n", stderr)
        return 2
    }
    let r = mode > 0 ? doorman_add_user_to_group(user, group) : doorman_remove_user_from_group(user, group)
    if r != DOORMAN_SUCCESS { fputs("gpasswd: \(doorman_strerror(r).map { String(cString: $0) } ?? "?")\n", stderr); return 1 }
    print("\(mode > 0 ? "added" : "removed") \(user) \(mode > 0 ? "to" : "from") group \(group)")
    return 0
}

private func cmdUsermod(_ args: [String]) -> Int32 {
    var group: String?
    var user: String?
    var i = 0
    while i < args.count {
        let a = args[i]
        if a == "-aG" || a == "-Ga", i + 1 < args.count { group = args[i + 1]; i += 1 }
        else if (a == "-G" || a == "--groups"), i + 1 < args.count { group = args[i + 1]; i += 1 }
        else if !a.hasPrefix("-") { user = a }
        i += 1
    }
    guard let group, let user else { fputs("usage: doorman usermod -aG <group> <user>\n", stderr); return 2 }
    let r = doorman_add_user_to_group(user, group)
    if r != DOORMAN_SUCCESS { fputs("usermod: \(doorman_strerror(r).map { String(cString: $0) } ?? "?")\n", stderr); return 1 }
    print("added \(user) to group \(group)")
    return 0
}

private func cmdUsers() -> Int32 {
    var users: UnsafeMutablePointer<doorman_user_t>?
    var n = 0
    if doorman_enumerate_users(true, &users, &n) != DOORMAN_SUCCESS { return 1 }
    for i in 0..<n {
        let u = users!.advanced(by: i).pointee
        let name = u.name.map { String(cString: $0) } ?? ""
        let full = u.full_name.map { String(cString: $0) } ?? ""
        print(String(format: "%-20s uid=%-6u %s", name, u.uid, full))
    }
    doorman_free_users(users, n)
    return 0
}

private func cmdSessions() -> Int32 {
    var s: UnsafeMutablePointer<doorman_session_t>?
    var n = 0
    if doorman_enumerate_sessions(&s, &n) != DOORMAN_SUCCESS { return 1 }
    for i in 0..<n {
        let e = s!.advanced(by: i).pointee
        let id = e.id.map { String(cString: $0) } ?? ""
        let type = e.type.map { String(cString: $0) } ?? ""
        let exec = e.exec.map { String(cString: $0) } ?? ""
        print(String(format: "%-16s [%s] %s", id, type, exec))
    }
    doorman_free_sessions(s, n)
    return 0
}

private func cmdGroups(_ args: [String]) -> Int32 {
    let user = args.last.flatMap { $0.hasPrefix("-") ? nil : $0 }
    guard let user else { fputs("usage: doorman groups <user>\n", stderr); return 2 }
    var g: UnsafeMutablePointer<gid_t>?
    var n = 0
    if doorman_get_groups(user, &g, &n) != DOORMAN_SUCCESS { fputs("no such user\n", stderr); return 1 }
    for i in 0..<n { print(String(format: "%u", g![i]), terminator: i + 1 < n ? " " : "\n") }
    free(g)
    return 0
}

private func usage() -> Int32 {
    fputs("""
doorman - macOS authentication & account management (libdoorman)

usage: doorman <command> [args]
  authenticate <user>            verify a password (stdin)
  login <user> [--exec CMD]      authenticate and open a session
  useradd [opts] <name>          create a user
  userdel [-r] <name>            delete a user
  passwd [--stdin] <user>        set/reset a password
  groupadd [-g gid] <name>       create a group
  groupdel <name>                delete a group
  usermod -aG <group> <user>     add a user to a group
  gpasswd -a|-d <user> <group>   add/remove a group member
  users | sessions | groups <user>

Also runs as useradd/userdel/passwd/groupadd/groupdel/usermod/gpasswd
when invoked under those names.

""", stderr)
    return 2
}

private func dispatch(_ cmd: String, _ args: [String]) -> Int32 {
    switch cmd {
    case "authenticate": return cmdAuthenticate(args)
    case "login": return cmdLogin(args)
    case "useradd": return cmdUseradd(args)
    case "userdel": return cmdUserdel(args)
    case "passwd": return cmdPasswd(args)
    case "groupadd": return cmdGroupadd(args)
    case "groupdel": return cmdGroupdel(args)
    case "usermod": return cmdUsermod(args)
    case "gpasswd": return cmdGpasswd(args)
    case "users": return cmdUsers()
    case "sessions": return cmdSessions()
    case "groups": return cmdGroups(args)
    case "help", "--help", "-h": return usage()
    default: return usage()
    }
}

@main
struct DoormanCLI {
    static func main() {
        let argv0 = CommandLine.arguments[0]
        let base = (argv0 as NSString).lastPathComponent
        let tools = ["useradd", "userdel", "passwd", "groupadd", "groupdel", "usermod", "gpasswd"]
        if tools.contains(base) {
            exit(dispatch(base, Array(CommandLine.arguments.dropFirst())))
        }
        guard CommandLine.arguments.count >= 2 else { exit(usage()) }
        exit(dispatch(CommandLine.arguments[1], Array(CommandLine.arguments.dropFirst(2))))
    }
}

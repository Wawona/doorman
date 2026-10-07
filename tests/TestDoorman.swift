import Foundation

@main
enum TestDoormanMain {
    private static var failures = 0
    private static var checks = 0

    private static func check(_ cond: Bool, _ msg: String) {
        checks += 1
        if cond { print("ok   - \(msg)") } else { print("FAIL - \(msg)"); failures += 1 }
    }

    static func main() {
        check(doorman_strerror(DOORMAN_SUCCESS) != nil, "strerror(SUCCESS) non-null")
        check(String(cString: doorman_strerror(DOORMAN_ERR_AUTH)!) != "unknown error", "strerror(ERR_AUTH) is specific")
        check(String(cString: doorman_strerror(doorman_result_t(rawValue: 999))!) == "unknown error", "strerror(bogus)")

        var users: UnsafeMutablePointer<doorman_user_t>?
        var nu = 0
        check(doorman_enumerate_users(false, &users, &nu) == DOORMAN_SUCCESS && nu > 0, "enumerate_users")
        var sawRoot = false
        if let users {
            for i in 0..<nu where users[i].name.map({ String(cString: $0) == "root" }) == true { sawRoot = true }
        }
        check(sawRoot, "includes root")
        doorman_free_users(users, nu)
        check(doorman_enumerate_users(true, nil, &nu) == DOORMAN_ERR_INVALID_ARG, "enumerate_users NULL")

        var one = doorman_user_t()
        check(doorman_lookup_user("root", &one) == DOORMAN_SUCCESS && one.uid == 0, "lookup root")
        doorman_free_user_fields(&one)
        check(doorman_lookup_user("definitely_no_such_user_xyz", &one) == DOORMAN_ERR_USER_UNKNOWN, "lookup missing")
        check(doorman_lookup_user(nil, &one) == DOORMAN_ERR_INVALID_ARG, "lookup NULL")

        var gids: UnsafeMutablePointer<gid_t>?
        var ng = 0
        check(doorman_get_groups("root", &gids, &ng) == DOORMAN_SUCCESS && ng >= 1, "get_groups")
        free(gids)

        var sessions: UnsafeMutablePointer<doorman_session_t>?
        var ns = 0
        check(doorman_enumerate_sessions(&sessions, &ns) == DOORMAN_SUCCESS, "enumerate_sessions")
        doorman_free_sessions(sessions, ns)

        check(doorman_authenticate_password("root", "wrong", DOORMAN_BACKEND_OPENDIRECTORY) != DOORMAN_SUCCESS, "auth wrong")
        check(doorman_authenticate_password("root", "x", DOORMAN_BACKEND_PAM) == DOORMAN_ERR_UNSUPPORTED, "PAM unsupported")
        check(doorman_authenticate_password("../../etc/passwd", "x", DOORMAN_BACKEND_DSLOCAL) == DOORMAN_ERR_USER_UNKNOWN, "traversal")

        check(doorman_start("login", "root", nil, DOORMAN_BACKEND_AUTO, nil) == DOORMAN_ERR_INVALID_ARG, "start NULL")

        var bad = doorman_user_spec_t()
        bad.name = UnsafePointer(strdup("bad/name"))
        check(doorman_create_user(&bad) == DOORMAN_ERR_INVALID_ARG, "bad name")
        if geteuid() != 0 {
            var sp = doorman_user_spec_t()
            sp.name = UnsafePointer(strdup("doorman_perm_probe"))
            check(doorman_create_user(&sp) == DOORMAN_ERR_PERM, "perm create")
        }

        print("\n\(checks) checks, \(failures) failures")
        exit(failures == 0 ? 0 : 1)
    }
}

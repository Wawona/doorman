import Foundation

private func dmStrdupOpt(_ s: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    guard let s else { return nil }
    return strdup(s)
}

private func rc(_ result: doorman_result_t) -> Int32 {
    Int32(result.rawValue)
}

@_cdecl("doorman_start")
public func doormanStart(
    _ service: UnsafePointer<CChar>?,
    _ user: UnsafePointer<CChar>?,
    _ conv: UnsafePointer<doorman_conv_t>?,
    _ backend: doorman_backend_t,
    _ out: UnsafeMutablePointer<UnsafeMutablePointer<doorman_handle_t>?>?
) -> Int32 {
    guard let out else { return rc(DOORMAN_ERR_INVALID_ARG) }
    out.pointee = nil
    guard let handle = calloc(1, MemoryLayout<doorman_handle_t>.size)?.assumingMemoryBound(to: doorman_handle_t.self) else {
        return rc(DOORMAN_ERR_SYSTEM)
    }
    handle.pointee.service = dmStrdupOpt(service) ?? dmStrdupOpt("login")
    handle.pointee.user = dmStrdupOpt(user)
    handle.pointee.backend = backend
    if let conv {
        handle.pointee.conv = conv.pointee
    }
    out.pointee = handle
    return rc(DOORMAN_SUCCESS)
}

@_cdecl("doorman_end")
public func doormanEnd(_ handle: UnsafeMutablePointer<doorman_handle_t>?) {
    guard let handle else { return }
    if handle.pointee.backend == DOORMAN_BACKEND_PAM, let state = handle.pointee.backend_state {
        let pamhField = state.assumingMemoryBound(to: OpaquePointer?.self)
        if pamhField.pointee != nil {
            _ = dm_pam_end(pamhField.pointee, 0)
        }
        free(state)
        handle.pointee.backend_state = nil
    }
    free(handle.pointee.service)
    free(handle.pointee.user)
    free(handle.pointee.rhost)
    free(handle.pointee.tty)
    free(handle)
}

@_cdecl("doorman_set_item")
public func doormanSetItem(
    _ handle: UnsafeMutablePointer<doorman_handle_t>?,
    _ item: doorman_item_t,
    _ value: UnsafePointer<CChar>?
) -> Int32 {
    guard let handle else { return rc(DOORMAN_ERR_INVALID_ARG) }
    let copy = dmStrdupOpt(value)
    if value != nil && copy == nil { return rc(DOORMAN_ERR_SYSTEM) }
    switch item {
    case DOORMAN_ITEM_SERVICE:
        free(handle.pointee.service)
        handle.pointee.service = copy
    case DOORMAN_ITEM_USER:
        free(handle.pointee.user)
        handle.pointee.user = copy
    case DOORMAN_ITEM_RHOST:
        free(handle.pointee.rhost)
        handle.pointee.rhost = copy
    case DOORMAN_ITEM_TTY:
        free(handle.pointee.tty)
        handle.pointee.tty = copy
    default:
        free(copy)
        return rc(DOORMAN_ERR_INVALID_ARG)
    }
    return rc(DOORMAN_SUCCESS)
}

@_cdecl("doorman_get_item")
public func doormanGetItem(
    _ handle: UnsafeMutablePointer<doorman_handle_t>?,
    _ item: doorman_item_t,
    _ value: UnsafeMutablePointer<UnsafePointer<CChar>?>?
) -> Int32 {
    guard let handle, let value else { return rc(DOORMAN_ERR_INVALID_ARG) }
    switch item {
    case DOORMAN_ITEM_SERVICE: value.pointee = UnsafePointer(handle.pointee.service)
    case DOORMAN_ITEM_USER: value.pointee = UnsafePointer(handle.pointee.user)
    case DOORMAN_ITEM_RHOST: value.pointee = UnsafePointer(handle.pointee.rhost)
    case DOORMAN_ITEM_TTY: value.pointee = UnsafePointer(handle.pointee.tty)
    default: return rc(DOORMAN_ERR_INVALID_ARG)
    }
    return rc(DOORMAN_SUCCESS)
}

private func discardResponses(_ resps: inout [doorman_response_t], _ n: Int) {
    for i in 0..<n {
        if resps[i].resp != nil {
            let len = strlen(resps[i].resp!)
            withUnsafeMutablePointer(to: &resps[i].resp) { slot in
                _dm_scrub_free(slot, len)
            }
        }
    }
}

private func runCredentialConversation(
    _ handle: UnsafeMutablePointer<doorman_handle_t>
) -> (doorman_result_t, UnsafeMutablePointer<CChar>?) {
    guard handle.pointee.conv.conv != nil else { return (DOORMAN_ERR_CONV, nil) }
    let askUser = handle.pointee.user == nil
    let count = askUser ? 2 : 1
    var prompts = [doorman_message_t(), doorman_message_t()]
    var promptPtrs = [UnsafePointer<doorman_message_t>?](repeating: nil, count: count)
    var answers = [doorman_response_t(), doorman_response_t()]
    var answerPtrs = [UnsafeMutablePointer<doorman_response_t>?](repeating: nil, count: count)
    var at = 0
    if askUser {
        prompts[at].style = DOORMAN_PROMPT_ECHO_ON
        prompts[at].msg = UnsafePointer(strdup("login: "))
        at += 1
    }
    prompts[at].style = DOORMAN_PROMPT_ECHO_OFF
    prompts[at].msg = UnsafePointer(strdup("Password: "))
    for i in 0..<count {
        promptPtrs[i] = withUnsafePointer(to: &prompts[i]) { $0 }
        answerPtrs[i] = withUnsafeMutablePointer(to: &answers[i]) { $0 }
    }
    if handle.pointee.conv.conv!(Int32(count), &promptPtrs, &answerPtrs, handle.pointee.conv.appdata) != 0 {
        discardResponses(&answers, count)
        return (DOORMAN_ERR_CONV, nil)
    }
    at = 0
    if askUser {
        if answers[at].resp != nil {
            free(handle.pointee.user)
            handle.pointee.user = strdup(answers[at].resp!)
            free(answers[at].resp)
            answers[at].resp = nil
        }
        at += 1
    }
    let secret = answers[at].resp
    answers[at].resp = nil
    if handle.pointee.user == nil { return (DOORMAN_ERR_USER_UNKNOWN, nil) }
    if secret == nil { return (DOORMAN_ERR_CONV, nil) }
    return (DOORMAN_SUCCESS, secret)
}

private func dispatchDirectoryVerify(
    _ backend: doorman_backend_t,
    _ user: UnsafePointer<CChar>,
    _ secret: UnsafePointer<CChar>
) -> doorman_result_t {
    switch backend {
    case DOORMAN_BACKEND_OPENDIRECTORY:
        return _dm_verify_opendirectory(user, secret)
    case DOORMAN_BACKEND_DSLOCAL:
        return _dm_verify_dslocal(user, secret)
    case DOORMAN_BACKEND_AUTO:
        let primary = _dm_verify_opendirectory(user, secret)
        if primary == DOORMAN_ERR_SYSTEM || primary == DOORMAN_ERR_USER_UNKNOWN {
            let offline = _dm_verify_dslocal(user, secret)
            if offline == DOORMAN_SUCCESS || offline == DOORMAN_ERR_AUTH { return offline }
        }
        return primary
    case DOORMAN_BACKEND_PAM:
        return DOORMAN_ERR_UNSUPPORTED
    default:
        return DOORMAN_ERR_INVALID_ARG
    }
}

@_cdecl("doorman_authenticate")
public func doormanAuthenticate(_ handle: UnsafeMutablePointer<doorman_handle_t>?) -> Int32 {
    guard let handle else { return rc(DOORMAN_ERR_INVALID_ARG) }
    if handle.pointee.backend == DOORMAN_BACKEND_PAM {
        let r = _dm_pam_authenticate(handle)
        handle.pointee.authenticated = r == DOORMAN_SUCCESS
        return rc(r)
    }
    let (convRc, secret) = runCredentialConversation(handle)
    if convRc != DOORMAN_SUCCESS { return rc(convRc) }
    guard let secret, let user = handle.pointee.user else { return rc(DOORMAN_ERR_CONV) }
    let r = dispatchDirectoryVerify(handle.pointee.backend, user, secret)
    var secretSlot: UnsafeMutablePointer<CChar>? = secret
    _dm_scrub_free(&secretSlot, strlen(secret))
    handle.pointee.authenticated = r == DOORMAN_SUCCESS
    return rc(r)
}

@_cdecl("doorman_acct_mgmt")
public func doormanAcctMgmt(_ handle: UnsafeMutablePointer<doorman_handle_t>?) -> Int32 {
    guard let handle else { return rc(DOORMAN_ERR_INVALID_ARG) }
    guard handle.pointee.authenticated else { return rc(DOORMAN_ERR_ABORT) }
    if handle.pointee.backend == DOORMAN_BACKEND_PAM {
        return rc(_dm_pam_check_account(handle))
    }
    guard let user = handle.pointee.user else { return rc(DOORMAN_ERR_USER_UNKNOWN) }
    return rc(_dm_account_is_enabled(user))
}

@_cdecl("doorman_setcred")
public func doormanSetcred(_ handle: UnsafeMutablePointer<doorman_handle_t>?, _ flag: doorman_cred_flag_t) -> Int32 {
    guard let handle else { return rc(DOORMAN_ERR_INVALID_ARG) }
    guard handle.pointee.authenticated else { return rc(DOORMAN_ERR_ABORT) }
    if handle.pointee.backend == DOORMAN_BACKEND_PAM {
        return rc(_dm_pam_setcred(handle, Int32(flag.rawValue)))
    }
    return rc(DOORMAN_SUCCESS)
}

@_cdecl("doorman_get_groups")
public func doormanGetGroups(
    _ user: UnsafePointer<CChar>?,
    _ gids: UnsafeMutablePointer<UnsafeMutablePointer<gid_t>?>?,
    _ count: UnsafeMutablePointer<Int>?
) -> Int32 {
    guard let user, let gids, let count else { return rc(DOORMAN_ERR_INVALID_ARG) }
    gids.pointee = nil
    count.pointee = 0
    var info = doorman_user_t()
    guard doormanLookupUser(user, &info) == rc(DOORMAN_SUCCESS) else { return rc(DOORMAN_ERR_USER_UNKNOWN) }
    let primary = info.gid
    doormanFreeUserFields(&info)
    var slots: Int32 = 32
    var scratch: UnsafeMutablePointer<Int32>?
    var done = false
    for _ in 0..<12 {
        scratch = realloc(scratch, Int(slots) * MemoryLayout<Int32>.size)?.assumingMemoryBound(to: Int32.self)
        guard scratch != nil else { free(scratch); return rc(DOORMAN_ERR_SYSTEM) }
        let before = slots
        if getgrouplist(user, Int32(primary), scratch, &slots) != -1 {
            done = true
            break
        }
        if slots <= before { slots = before * 2 }
    }
    guard done, let scratch else { return rc(DOORMAN_ERR_SYSTEM) }
    let n = Int(slots)
    guard let result = malloc(n * MemoryLayout<gid_t>.size)?.assumingMemoryBound(to: gid_t.self) else {
        free(scratch)
        return rc(DOORMAN_ERR_SYSTEM)
    }
    for i in 0..<n { result[i] = gid_t(scratch[i]) }
    free(scratch)
    gids.pointee = result
    count.pointee = n
    return rc(DOORMAN_SUCCESS)
}

@_cdecl("doorman_authenticate_password")
public func doormanAuthenticatePassword(
    _ user: UnsafePointer<CChar>?,
    _ password: UnsafePointer<CChar>?,
    _ backend: doorman_backend_t
) -> Int32 {
    guard let user, let password else { return rc(DOORMAN_ERR_INVALID_ARG) }
    if backend == DOORMAN_BACKEND_PAM { return rc(DOORMAN_ERR_UNSUPPORTED) }
    return rc(dispatchDirectoryVerify(backend, user, password))
}

@_silgen_name("_dm_verify_opendirectory")
private func _dm_verify_opendirectory(_ user: UnsafePointer<CChar>?, _ password: UnsafePointer<CChar>?) -> doorman_result_t

@_silgen_name("_dm_verify_dslocal")
private func _dm_verify_dslocal(_ user: UnsafePointer<CChar>?, _ password: UnsafePointer<CChar>?) -> doorman_result_t

@_silgen_name("_dm_account_is_enabled")
private func _dm_account_is_enabled(_ user: UnsafePointer<CChar>?) -> doorman_result_t

@_silgen_name("_dm_pam_authenticate")
private func _dm_pam_authenticate(_ handle: UnsafeMutablePointer<doorman_handle_t>?) -> doorman_result_t

@_silgen_name("_dm_pam_check_account")
private func _dm_pam_check_account(_ handle: UnsafeMutablePointer<doorman_handle_t>?) -> doorman_result_t

@_silgen_name("_dm_pam_setcred")
private func _dm_pam_setcred(_ handle: UnsafeMutablePointer<doorman_handle_t>?, _ flag: Int32) -> doorman_result_t

@_silgen_name("_dm_scrub_free")
private func _dm_scrub_free(_ slot: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?, _ len: Int)

@_silgen_name("pam_end")
private func dm_pam_end(_ pamh: OpaquePointer?, _ status: Int32) -> Int32

@_silgen_name("doorman_lookup_user")
private func doormanLookupUser(_ name: UnsafePointer<CChar>?, _ out: UnsafeMutablePointer<doorman_user_t>?) -> Int32

@_silgen_name("doorman_free_user_fields")
private func doormanFreeUserFields(_ user: UnsafeMutablePointer<doorman_user_t>?)

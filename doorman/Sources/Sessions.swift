import Foundation

private func readDesktopEntry(path: String) -> [String: String]? {
    guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }
    var fields: [String: String] = [:]
    var inEntry = false
    for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
        let line = raw.trimmingCharacters(in: .whitespaces)
        if line.isEmpty || line.hasPrefix("#") { continue }
        if line.hasPrefix("[") {
            inEntry = line == "[Desktop Entry]"
            continue
        }
        guard inEntry else { continue }
        guard let eq = line.firstIndex(of: "=") else { continue }
        let key = String(line[..<eq]).trimmingCharacters(in: .whitespaces)
        let val = String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
        if key.contains("[") { continue }
        if fields[key] == nil { fields[key] = val }
    }
    return fields
}

private func xdgDataRoots() -> [String] {
    if let env = getenv("XDG_DATA_DIRS"), env.pointee != 0 {
        return String(cString: env).split(separator: ":").map(String.init)
    }
    return ["/usr/local/share", "/usr/share"]
}

private func copyCStr(_ s: String?) -> UnsafeMutablePointer<CChar>? {
    guard let s else { return nil }
    return strdup(s)
}

@_cdecl("doorman_enumerate_sessions")
public func doormanEnumerateSessions(
    _ out: UnsafeMutablePointer<UnsafeMutablePointer<doorman_session_t>?>?,
    _ count: UnsafeMutablePointer<Int>?
) -> Int32 {
    guard let out, let count else { return 9 }
    out.pointee = nil
    count.pointee = 0
    var discovered: [[String: String]] = []
    var seen = Set<String>()
    let kinds = [("wayland-sessions", "wayland"), ("xsessions", "x11")]
    let fm = FileManager.default
    for root in xdgDataRoots() {
        for (sub, kind) in kinds {
            let dir = (root as NSString).appendingPathComponent(sub)
            guard let files = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for file in files where file.hasSuffix(".desktop") {
                let ident = (file as NSString).deletingPathExtension
                if seen.contains(ident) { continue }
                let path = (dir as NSString).appendingPathComponent(file)
                guard var entry = readDesktopEntry(path: path), entry["Exec"] != nil else { continue }
                entry["id"] = ident
                entry["type"] = kind
                if entry["name"] == nil { entry["name"] = ident }
                seen.insert(ident)
                discovered.append(entry)
            }
        }
    }
    discovered.append([
        "id": "aqua",
        "name": "macOS (Aqua)",
        "comment": "Stock macOS desktop session",
        "exec": "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow",
        "type": "aqua",
    ])
    let n = discovered.count
    guard let arr = calloc(n, MemoryLayout<doorman_session_t>.size)?.assumingMemoryBound(to: doorman_session_t.self) else {
        return 8
    }
    for i in 0..<n {
        let e = discovered[i]
        arr[i].id = copyCStr(e["id"])
        arr[i].name = copyCStr(e["name"])
        arr[i].comment = copyCStr(e["comment"])
        arr[i].exec = copyCStr(e["Exec"] ?? e["exec"])
        arr[i].type = copyCStr(e["type"])
    }
    out.pointee = arr
    count.pointee = n
    return 0
}

@_cdecl("doorman_free_sessions")
public func doormanFreeSessions(_ sessions: UnsafeMutablePointer<doorman_session_t>?, _ count: Int) {
    guard let sessions else { return }
    for i in 0..<count {
        free(sessions[i].id)
        free(sessions[i].name)
        free(sessions[i].comment)
        free(sessions[i].exec)
        free(sessions[i].type)
    }
    free(sessions)
}


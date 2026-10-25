import Darwin
import Foundation

/// Thin wrappers over libproc.
public enum ProcessLookup {
    public static func path(pid: Int32) -> String? {
        guard pid > 0 else { return pid == 0 ? "/kernel" : nil }
        var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        return buffer.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
    }

    static func bsdInfo(pid: Int32) -> proc_bsdinfo? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        return info
    }

    /// Process start time in microseconds; together with the pid it identifies one process instance.
    public static func startTime(pid: Int32) -> UInt64? {
        guard pid > 0, let info = bsdInfo(pid: pid) else { return nil }
        return info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec
    }

    public static func userID(pid: Int32) -> UInt32? { bsdInfo(pid: pid)?.pbi_uid }

    public static func parentPID(pid: Int32) -> Int32? { bsdInfo(pid: pid).map { Int32($0.pbi_ppid) } }

    public static func allPIDs() -> [Int32] {
        let estimate = proc_listallpids(nil, 0)
        guard estimate > 0 else { return [] }
        var pids = [Int32](repeating: 0, count: Int(estimate) + 64)
        let count = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<Int32>.size))
        guard count > 0 else { return [] }
        return Array(pids.prefix(Int(count))).filter { $0 > 0 }
    }

    /// Programs holding a `/dev/bpf*` device open. Without root only the caller's own
    /// processes can be inspected, which still catches the common case of a user-run sniffer.
    public static func bpfUsers() -> [BPFUser] {
        var users: [BPFUser] = []
        let fdInfoSize = MemoryLayout<proc_fdinfo>.stride
        for pid in allPIDs() {
            let bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
            guard bytes > 0 else { continue }
            var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(bytes) / fdInfoSize + 8)
            let filled = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, Int32(fds.count * fdInfoSize))
            guard filled > 0 else { continue }
            for fd in fds.prefix(Int(filled) / fdInfoSize) where fd.proc_fdtype == UInt32(PROX_FDTYPE_VNODE) {
                var vnode = vnode_fdinfowithpath()
                let size = Int32(MemoryLayout<vnode_fdinfowithpath>.size)
                guard proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDVNODEPATHINFO, &vnode, size) == size else { continue }
                let device = withUnsafeBytes(of: &vnode.pvip.vip_path) { raw in
                    String(cString: raw.baseAddress!.assumingMemoryBound(to: CChar.self))
                }
                guard device.hasPrefix("/dev/bpf") else { continue }
                let path = self.path(pid: pid) ?? "pid \(pid)"
                users.append(BPFUser(pid: pid, path: path, name: ProcessIdentity.defaultName(for: path), device: device,
                                     userID: userID(pid: pid) ?? 0))
            }
        }
        return users
    }
}

public enum SystemInfo {
    /// Changes on every boot; "until restart" rules remember it.
    public static var bootSessionID: String {
        var size = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 0 else { return "unknown" }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.bootsessionuuid", &buffer, &size, nil, 0) == 0 else { return "unknown" }
        return buffer.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
    }

    public static func userName(for uid: UInt32) -> String {
        guard let entry = getpwuid(uid) else { return "uid \(uid)" }
        return String(cString: entry.pointee.pw_name)
    }
}

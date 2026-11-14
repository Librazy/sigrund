/* Shared descriptor/event layout. build.rs emits Rust from these same fields.
 * The third field is the C declaration; SG_FIELD ignores Rust tokens in C. */
#ifndef SIGRUND_LAUNCHER_ABI_H
#define SIGRUND_LAUNCHER_ABI_H
#define SG_PAYLOAD_VERSION 4
#define SG_EVENT_READY 1
#define SG_EVENT_CHILD 2
#define SG_EVENT_BOOTSTRAP 3
#define SG_EVENT_BYTES 8
#define SG_STRUCT(rust, c) struct c {
#define SG_FIELD(name, rust, ...) __VA_ARGS__;
#define SG_END };
SG_STRUCT(ChildSpec, child_spec)
SG_FIELD(input, i32, int input)
SG_FIELD(output, i32, int output)
SG_FIELD(error, i32, int error)
SG_FIELD(executable, i32, int executable)
SG_FIELD(sync, i32, int sync)
SG_FIELD(uid, u32, uint32_t uid)
SG_FIELD(gid, u32, uint32_t gid)
SG_FIELD(mask, u32, uint32_t mask)
SG_FIELD(last_cap, u32, uint32_t last_cap)
SG_FIELD(capabilities, u64, uint64_t capabilities)
SG_FIELD(groups, *const u32, const uint32_t *groups)
SG_FIELD(groups_len, usize, size_t groups_len)
SG_FIELD(cwd, *const libc::c_char, const char *cwd)
SG_FIELD(direct_path, *const libc::c_char, const char *direct_path)
SG_FIELD(argv, *const *const libc::c_char, const char *const *argv)
SG_FIELD(envp, *const *const libc::c_char, const char *const *envp)
SG_FIELD(mountinfo, *mut u8, char *mountinfo)
SG_FIELD(mountinfo_capacity, usize, size_t mountinfo_capacity)
SG_FIELD(group_check, *mut u32, uint32_t *group_check)
SG_FIELD(isolated, i32, int isolated)
SG_FIELD(gate_read, i32, int gate_read)
SG_FIELD(gate_write, i32, int gate_write)
SG_FIELD(checkpoint, i32, int checkpoint)
SG_FIELD(namespace_mode, i32, int namespace_mode)
SG_FIELD(namespace_admin, i32, int namespace_admin)
SG_FIELD(production, i32, int production)
SG_FIELD(producer_guard, i32, int producer_guard)
SG_END
SG_STRUCT(NamespaceSpec, namespace_spec)
SG_FIELD(namespaces, [i32; 8], int namespaces[8])
SG_FIELD(enter_mask, u32, uint32_t enter_mask)
SG_FIELD(root, i32, int root)
SG_FIELD(cwd, i32, int cwd)
SG_FIELD(control, i32, int control)
SG_END
#undef SG_STRUCT
#undef SG_FIELD
#undef SG_END
#endif

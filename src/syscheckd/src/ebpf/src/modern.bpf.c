/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* Maximum lengths and limits */
#define TASK_COMM_LEN 32
#define FILENAME_LEN 4096
#define MAX_PATH_SIZE 4096           // PATH_MAX from <linux/limits.h>
#define LIMIT_PATH_SIZE(x) ((x) & (MAX_PATH_SIZE - 1))
#define MAX_PATH_COMPONENTS 20

/* Per-CPU buffer sizes and macros */
#define MAX_PERCPU_ARRAY_SIZE (1 << 15)
#define HALF_PERCPU_ARRAY_SIZE (MAX_PERCPU_ARRAY_SIZE >> 1)
#define LIMIT_PERCPU_ARRAY_SIZE(x) ((x) & (MAX_PERCPU_ARRAY_SIZE - 1))
#define LIMIT_HALF_PERCPU_ARRAY_SIZE(x) ((x) & (HALF_PERCPU_ARRAY_SIZE - 1))

/* Always-inline attribute for static functions */
#define statfunc static __attribute__((__always_inline__))

/* Per-CPU buffer structure for storing path strings */
struct buffer {
    u8 data[MAX_PERCPU_ARRAY_SIZE];
};

/* Per-CPU array map to store buffers */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct buffer);
    __uint(max_entries, 1);
} heaps_map SEC(".maps");

/* Function to retrieve a per-CPU buffer from the heaps_map */
statfunc struct buffer *get_buffer(void) {
    u32 zero = 0;
    return bpf_map_lookup_elem(&heaps_map, &zero);
}

/* Structure to hold file event data */
struct file_event {
    __u32 pid;                   // Process ID
    __u32 uid;                   // User ID
    __u32 gid;                   // Group ID
    char comm[TASK_COMM_LEN];    // Process command/name
    char filename[FILENAME_LEN]; // Full path or filename passed to syscall
    char cwd[FILENAME_LEN];      // Process current working directory
    char event_type[16];         // Event type ("open", "unlink", "mkdir")
    __u64 inode;                 // Inode number
    __u64 dev;                   // Device number
};

/* Ring buffer map to send events to user space */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} rb SEC(".maps");

/*
* Function to reconstruct the full absolute path from a given struct path.
* It traverses the dentry hierarchy and stores the constructed path in a per-CPU buffer.
* The resulting pointer is returned in "path_str".
*/
statfunc long get_path_str_from_path(u8 **path_str, struct path *path, struct buffer *out_buf) {
    long ret;
    struct dentry *dentry, *dentry_parent, *dentry_mnt;
    struct vfsmount *vfsmnt;
    struct mount *mnt, *mnt_parent;
    const u8 *name;
    size_t name_len;

    // Read the dentry and vfsmount from the given path
    dentry = BPF_CORE_READ(path, dentry);
    vfsmnt = BPF_CORE_READ(path, mnt);
    // Convert vfsmnt to mount structure using container_of
    mnt = container_of(vfsmnt, struct mount, mnt);
    mnt_parent = BPF_CORE_READ(mnt, mnt_parent);

    // Initialize the buffer offset to half the per-CPU buffer size
    size_t buf_off = HALF_PERCPU_ARRAY_SIZE;

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        // Get the mount root and the parent of the current dentry
        dentry_mnt = BPF_CORE_READ(vfsmnt, mnt_root);
        dentry_parent = BPF_CORE_READ(dentry, d_parent);

        // If we have reached the mount root or if the dentry's parent is itself, stop
        if (dentry == dentry_mnt || dentry == dentry_parent) {
            if (dentry != dentry_mnt)
                break;
            if (mnt != mnt_parent) {
                // Not global root; continue with the mount point path
                dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
                mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
                vfsmnt = __builtin_preserve_access_index(&mnt->mnt);
                continue;
            }
            break;
        }

        // Add this dentry's name to the path string
        name_len = LIMIT_PATH_SIZE(BPF_CORE_READ(dentry, d_name.len));
        name = BPF_CORE_READ(dentry, d_name.name);

        // Increase name length by one for the slash separator
        name_len = name_len + 1;
        // Check if the buffer is large enough for this dentry name
        if (name_len > buf_off) {
            break;
        }
        // Use a volatile variable for the new buffer offset (to satisfy the verifier)
        volatile size_t new_buff_offset = buf_off - name_len;
        ret = bpf_probe_read_kernel_str(&out_buf->data[LIMIT_HALF_PERCPU_ARRAY_SIZE(new_buff_offset)], name_len, name);
        if (ret < 0) {
            return ret;
        }

        if (ret > 1) {
            // Replace the null terminator with a slash
            buf_off -= 1;
            buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off);
            out_buf->data[buf_off] = '/';
            buf_off -= ret - 1;
            buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off);
        } else {
            break;
        }
        // Move to the parent dentry for the next iteration
        dentry = dentry_parent;
    }

    // Add a leading slash if there is space in the buffer
    if (buf_off != 0) {
        buf_off -= 1;
        buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off);
        out_buf->data[buf_off] = '/';
    }

    // Null-terminate the path string
    out_buf->data[HALF_PERCPU_ARRAY_SIZE - 1] = 0;
    // Set the output pointer to the beginning of the constructed path
    *path_str = &out_buf->data[buf_off];
    return HALF_PERCPU_ARRAY_SIZE - buf_off - 1;
}

/*
* Helper function to obtain the current working directory (CWD).
* It uses current->fs->pwd and reconstructs the absolute path.
*/
static __always_inline int get_cwd(char *buf, int buf_size) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct fs_struct *fs = BPF_CORE_READ(task, fs);
    u8 *cwd_path = 0;
    struct buffer *string_buf = get_buffer();
    if (fs && string_buf) {
        struct path *pwd = __builtin_preserve_access_index(&fs->pwd);
        get_path_str_from_path(&cwd_path, pwd, string_buf);
        if (cwd_path) {
            bpf_probe_read_kernel_str(buf, buf_size, cwd_path);
            return 0;
        }
    }
    buf[0] = '\0';
    return -1;
}

/*
* Common function to submit an event to the ring buffer.
* Copies event data (including filename, CWD, inode, and device) into a file_event structure.
*/
static __always_inline int submit_event_common(const char *event_type,
                                                const char *filename,
                                                const char *cwd,
                                                __u64 inode,
                                                __u64 dev)
{
    struct file_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid >> 32;
    e->gid = uid_gid;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memcpy(e->event_type, event_type, sizeof(e->event_type));
    bpf_probe_read_kernel_str(e->filename, FILENAME_LEN, filename);
    bpf_probe_read_kernel_str(e->cwd, FILENAME_LEN, cwd);
    e->inode = inode;
    e->dev = dev;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
* kretprobe for vfs_open (file open/create event).
* vfs_open returns a pointer to struct file. From that pointer, we extract
* the full path, inode, and device.
*/
SEC("kretprobe/vfs_open")
int kretprobe__vfs_open(struct pt_regs *ctx)
{
    struct file *file = (struct file *)PT_REGS_RC(ctx);
    if (!file)
        return 0; // Open failed

    /* Retrieve the absolute path from file->f_path */
    struct path *fpath = (struct path *)BPF_CORE_READ(file, f_path);
    struct buffer *string_buf = get_buffer();
    u8 *full_path = 0;
    if (!string_buf)
        return 0;
    if (get_path_str_from_path(&full_path, fpath, string_buf) < 0)
        return 0;

    /* Get the current working directory */
    char cwd[FILENAME_LEN];
    get_cwd(cwd, sizeof(cwd));

    /* Extract inode and device from file->f_inode */
    struct inode *f_inode = 0;
    bpf_probe_read_kernel(&f_inode, sizeof(f_inode), &file->f_inode);
    __u64 ino = 0, dev = 0;
    if (f_inode) {
        bpf_probe_read_kernel(&ino, sizeof(ino), &f_inode->i_ino);
        struct super_block *sb = 0;
        bpf_probe_read_kernel(&sb, sizeof(sb), &f_inode->i_sb);
        if (sb)
            bpf_probe_read_kernel(&dev, sizeof(dev), &sb->s_dev);
    }

    submit_event_common("open", (const char *)full_path, cwd, ino, dev);
    return 0;
}

/*
* kprobe for vfs_unlink (file deletion event).
* vfs_unlink receives the dentry of the file to be deleted.
* We extract the inode from the dentry and use its simple name as the filename.
*/
SEC("kprobe/vfs_unlink")
int kprobe__vfs_unlink(struct pt_regs *ctx)
{
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    if (!dentry)
        return 0;

    const char *name = BPF_CORE_READ(dentry, d_name.name);

    struct inode *inode = 0;
    bpf_probe_read_kernel(&inode, sizeof(inode), &dentry->d_inode);
    __u64 ino = 0, dev = 0;
    if (inode) {
        bpf_probe_read_kernel(&ino, sizeof(ino), &inode->i_ino);
        struct super_block *sb = 0;
        bpf_probe_read_kernel(&sb, sizeof(sb), &inode->i_sb);
        if (sb)
            bpf_probe_read_kernel(&dev, sizeof(dev), &sb->s_dev);
    }

    char cwd[FILENAME_LEN];
    get_cwd(cwd, sizeof(cwd));

    submit_event_common("unlink", name, cwd, ino, dev);
    return 0;
}

/*
* kprobe for vfs_mkdir (directory creation event).
* We extract the dentry of the new directory to obtain its inode.
*/
SEC("kprobe/vfs_mkdir")
int kprobe__vfs_mkdir(struct pt_regs *ctx)
{
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    if (!dentry)
        return 0;

    const char *name = BPF_CORE_READ(dentry, d_name.name);

    struct inode *inode = 0;
    bpf_probe_read_kernel(&inode, sizeof(inode), &dentry->d_inode);
    __u64 ino = 0, dev = 0;
    if (inode) {
        bpf_probe_read_kernel(&ino, sizeof(ino), &inode->i_ino);
        struct super_block *sb = 0;
        bpf_probe_read_kernel(&sb, sizeof(sb), &inode->i_sb);
        if (sb)
            bpf_probe_read_kernel(&dev, sizeof(dev), &sb->s_dev);
    }

    char cwd[FILENAME_LEN];
    get_cwd(cwd, sizeof(cwd));

    submit_event_common("mkdir", name, cwd, ino, dev);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

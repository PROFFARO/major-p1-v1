#ifndef __KUBEARMOR_POLICY_H__
#define __KUBEARMOR_POLICY_H__

#include "vmlinux.h"
#include "bpf_helpers.h"

/* KubeArmor Action Constants */
enum kubearmor_action {
    KUBEARMOR_ACTION_ALLOW = 0,
    KUBEARMOR_ACTION_AUDIT = 1,
    KUBEARMOR_ACTION_BLOCK = 2,
};

/* KubeArmor Policy Posture Categories */
enum kubearmor_posture {
    KUBEARMOR_POSTURE_PROCESS = 101,
    KUBEARMOR_POSTURE_FILE    = 102,
    KUBEARMOR_POSTURE_NETWORK = 103,
    KUBEARMOR_POSTURE_CAPABLE = 104,
};

/* KubeArmor Policy Match Structure */
struct kubearmor_policy_rule {
    u32 posture_type;
    u32 action;
    char path[256];
    char source[256];
};

/* KubeArmor Container Posture Config */
struct kubearmor_container_posture {
    u32 pid_ns;
    u32 mnt_ns;
    u32 proc_posture; /* AUDIT (1) or BLOCK (2) */
    u32 file_posture;
    u32 net_posture;
};

#endif /* __KUBEARMOR_POLICY_H__ */

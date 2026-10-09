#!/usr/bin/env python3
"""AKS upgrade pre-check.

Subcommands
-----------
resolve-target  Pick (or validate) the Kubernetes version the cluster will be upgraded to.
scan            Run all checks against one cluster and write report.json / report.md /
                per-namespace reports.
summary         Combine the report.json files of several clusters into one table.

Severity
--------
BLOCKER  The upgrade will fail, hang, or break something after it.   -> fix before upgrading
WARNING  Pre-existing problem or downtime risk during the node roll.  -> owner should look
INFO     Good to know.
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SEV_RANK = {"BLOCKER": 0, "WARNING": 1, "INFO": 2}
ICON = {"BLOCKER": "🔴", "WARNING": "🟠", "INFO": "🔵"}
CLUSTER_SCOPE = "(cluster)"

BAD_WAITING = {
    "CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError",
    "CreateContainerError", "InvalidImageName", "RunContainerError",
}
HOSTNAME_KEYS = {"kubernetes.io/hostname"}

DEFAULT_CONFIG = {
    "ownerLabels": ["team", "owner"],
    "platformNamespaces": ["kube-system", "kube-public", "kube-node-lease"],
    "ignoreNamespaces": [],
    "restartThreshold": 5,
    "pendingMinutes": 10,
}


# --------------------------------------------------------------------------- helpers
def ver(s):
    """'1.30.4' / 'v1.30' -> (1, 30, 4). None if unparsable."""
    m = re.match(r"v?(\d+)\.(\d+)(?:\.(\d+))?", (s or "").strip())
    return (int(m[1]), int(m[2]), int(m[3] or 0)) if m else None


def minor(s):
    v = ver(s)
    return v[:2] if v else None


def load_json(path, default=None):
    if not path or not Path(path).exists() or Path(path).stat().st_size == 0:
        return default
    with open(path) as fh:
        return json.load(fh)


class Findings:
    def __init__(self, ignore_namespaces=()):
        self.items = []
        self.ignore = set(ignore_namespaces)

    def add(self, severity, category, namespace, obj, message, action="", workload=None):
        if namespace in self.ignore:
            return
        ns = namespace or CLUSTER_SCOPE
        self.items.append({
            "severity": severity,
            "category": category,
            "namespace": ns,
            "object": obj,
            "workload": workload,
            "message": message,
            "action": action,
            # Stable identity used to diff pre vs post: pods are keyed by their owning
            # workload (pod names change when they reschedule) and numbers are masked.
            "key": "|".join([category, ns, workload or obj, re.sub(r"\d+", "#", message)]),
        })

    def count(self, sev):
        return sum(1 for f in self.items if f["severity"] == sev)


# --------------------------------------------------------------------------- versions
def current_version(cluster):
    return cluster.get("currentKubernetesVersion") or cluster.get("kubernetesVersion")


def available_upgrades(upgrades):
    cp = (upgrades or {}).get("controlPlaneProfile") or {}
    return {u["kubernetesVersion"]: bool(u.get("isPreview")) for u in (cp.get("upgrades") or [])}


def pick_target(current, avail, requested):
    """Requested version if given, else latest GA patch of the next minor
    (or of the current minor if no next minor is offered)."""
    if requested and requested.strip():
        return requested.strip().lstrip("v")
    cur = ver(current)
    ga = [v for v, preview in avail.items() if not preview and ver(v)]
    nxt = [v for v in ga if ver(v)[:2] == (cur[0], cur[1] + 1)]
    same = [v for v in ga if ver(v)[:2] == cur[:2] and ver(v) > cur]
    pool = nxt or same
    return max(pool, key=ver) if pool else current


def check_version(f, cluster, upgrades, nodepools, target):
    current = current_version(cluster)
    avail = available_upgrades(upgrades)
    cv, tv = ver(current), ver(target)

    if cluster.get("provisioningState") != "Succeeded":
        f.add("BLOCKER", "Cluster state", None, "AKS cluster",
              f"Cluster provisioningState is '{cluster.get('provisioningState')}'",
              "Fix the failed/in-progress operation before upgrading")
    power = (cluster.get("powerState") or {}).get("code")
    if power and power != "Running":
        f.add("BLOCKER", "Cluster state", None, "AKS cluster", f"Cluster powerState is '{power}'",
              "Start the cluster")

    if tv is None:
        f.add("BLOCKER", "Version", None, "Target version", f"Cannot parse target version '{target}'",
              "Pass a version like 1.31.2")
    elif tv == cv:
        f.add("INFO", "Version", None, "Target version",
              f"Cluster is already on {current}; no newer version is available or requested")
    elif tv < cv:
        f.add("BLOCKER", "Version", None, "Target version",
              f"Target {target} is lower than current {current}; AKS does not support downgrades")
    elif target not in avail:
        offered = ", ".join(sorted(avail, key=ver)) or "none"
        if tv[1] - cv[1] > 1:
            msg = (f"{current} → {target} skips minor versions; AKS upgrades one minor at a time")
            action = "Upgrade to the next minor first"
        else:
            msg = f"{target} is not offered as an upgrade for this cluster"
            action = f"Pick one of the offered versions: {offered}"
        f.add("BLOCKER", "Version", None, "Target version", msg, action)
    elif avail[target]:
        f.add("WARNING", "Version", None, "Target version", f"{target} is a preview version",
              "Use a GA version for UAT/prod")
    else:
        f.add("INFO", "Version", None, "Target version", f"Valid upgrade path: {current} → {target}")

    channel = ((cluster.get("autoUpgradeProfile") or {}).get("upgradeChannel") or "none")
    if channel.lower() != "none":
        f.add("WARNING", "Version", None, "Auto-upgrade",
              f"Auto-upgrade channel is '{channel}'; AKS may upgrade outside your monthly schedule",
              "Set the channel to 'none' or align it with a planned maintenance window")

    for np in nodepools or []:
        name = f"NodePool/{np.get('name')}"
        npv = np.get("currentOrchestratorVersion") or np.get("orchestratorVersion")
        if np.get("provisioningState") != "Succeeded":
            f.add("BLOCKER", "Cluster state", None, name,
                  f"Node pool provisioningState is '{np.get('provisioningState')}'",
                  "Fix the node pool before upgrading")
        if ((np.get("powerState") or {}).get("code")) == "Stopped":
            f.add("INFO", "Cluster state", None, name, "Node pool is stopped")
        if minor(npv) and cv and minor(npv) < cv[:2]:
            f.add("WARNING", "Version", None, name,
                  f"Node pool is on {npv}, behind the control plane ({current})",
                  "Upgrade node pools together with the control plane")
        if minor(npv) and tv and tv[1] - minor(npv)[1] > 3:
            f.add("BLOCKER", "Version", None, name,
                  f"Node pool {npv} would be more than 3 minors behind a {target} control plane "
                  "(outside the Kubernetes version-skew policy)",
                  "Upgrade this node pool first")


# --------------------------------------------------------------------------- removed APIs
def check_kubent(f, items, target):
    tv = ver(target)
    for it in items or []:
        rule = it.get("RuleSet", "")
        m = re.search(r"removed in (\d+\.\d+)", rule)
        removed = ver(m[1]) if m else None
        sev = "BLOCKER" if removed and tv and tv[:2] >= removed[:2] else "WARNING"
        ns = it.get("Namespace")
        ns = None if ns in (None, "", "<undefined>") else ns
        replace = it.get("ReplaceWith")
        f.add(sev, "Removed API", ns, f"{it.get('Kind')}/{it.get('Name')}",
              f"Uses {it.get('ApiVersion')} ({rule})",
              f"Migrate to {replace}" if replace and replace != "<removed>" else "Remove or replace this resource")


METRIC_RE = re.compile(r"^apiserver_requested_deprecated_apis\{([^}]*)\}\s+(\S+)")


def check_metric(f, text, err, target):
    """Runtime calls to deprecated APIs (catches clients that static scans can't see)."""
    tv = ver(target)
    seen = set()
    for line in (text or "").splitlines():
        m = METRIC_RE.match(line.strip())
        if not m or float(m[2]) <= 0:
            continue
        labels = dict(re.findall(r'(\w+)="([^"]*)"', m[1]))
        group = labels.get("group") or "core"
        res = f"{labels.get('resource')}.{group}/{labels.get('version')}"
        if labels.get("subresource"):
            res += f"/{labels['subresource']}"
        if res in seen:
            continue
        seen.add(res)
        rr = labels.get("removed_release")
        if rr and ver(rr) and tv and tv[:2] >= ver(rr)[:2]:
            sev, msg = "BLOCKER", f"Something is still calling {res}, which is removed in {rr}"
        elif rr:
            sev, msg = "WARNING", f"Something is calling {res}, deprecated and removed in {rr}"
        else:
            sev, msg = "INFO", f"Something is calling deprecated {res} (no removal planned yet)"
        f.add(sev, "Runtime API usage", None, res, msg,
              "Find the caller (userAgent) in API server audit logs and update its client/manifests")
    if not seen and (err or "").strip():
        f.add("INFO", "Runtime API usage", None, "API server metrics",
              f"Could not read API server metrics: {err.strip()[:200]}",
              "Grant 'get' on nonResourceURL /metrics, or check AKS 'Diagnose and solve problems'")


# --------------------------------------------------------------------------- live cluster
def collect(kubeconfig=None):
    """Read everything the checks need from the cluster (read-only)."""
    from kubernetes import client, config
    config.load_kube_config(config_file=kubeconfig)
    core, apps = client.CoreV1Api(), client.AppsV1Api()
    policy, batch, storage = client.PolicyV1Api(), client.BatchV1Api(), client.StorageV1Api()
    return {
        "namespaces": core.list_namespace().items,
        "nodes": core.list_node().items,
        "pods": core.list_pod_for_all_namespaces().items,
        "pvcs": core.list_persistent_volume_claim_for_all_namespaces().items,
        "storageclasses": storage.list_storage_class().items,
        "deployments": apps.list_deployment_for_all_namespaces().items,
        "statefulsets": apps.list_stateful_set_for_all_namespaces().items,
        "daemonsets": apps.list_daemon_set_for_all_namespaces().items,
        "pdbs": policy.list_pod_disruption_budget_for_all_namespaces().items,
        "jobs": batch.list_job_for_all_namespaces().items,
    }


def _pinned_to_node(spec):
    if spec.node_name:
        return f"nodeName={spec.node_name}"
    for k in (spec.node_selector or {}):
        if k in HOSTNAME_KEYS:
            return f"nodeSelector {k}={spec.node_selector[k]}"
    na = spec.affinity and spec.affinity.node_affinity
    req = na and na.required_during_scheduling_ignored_during_execution
    for term in (req.node_selector_terms if req else []) or []:
        for e in term.match_expressions or []:
            if e.key in HOSTNAME_KEYS:
                return f"required node affinity on {e.key}"
        for e in term.match_fields or []:
            if e.key == "metadata.name":
                return "required node affinity on node name"
    return None


def owner_workload(pod):
    """Pod -> 'Deployment/web', 'StatefulSet/db', ... (None for bare pods)."""
    for o in pod.metadata.owner_references or []:
        if o.kind == "ReplicaSet":
            # ReplicaSet name is <deployment>-<pod-template-hash>
            return f"Deployment/{o.name.rsplit('-', 1)[0]}"
        if o.kind in ("StatefulSet", "DaemonSet", "Job", "Node"):
            return f"{o.kind}/{o.name}"
    return None


def _workload_spec_checks(f, ns, obj, spec, check_probes=True, check_emptydir=False):
    pin = _pinned_to_node(spec)
    if pin:
        f.add("WARNING", "Drain readiness", ns, obj,
              f"Pinned to a single node ({pin}); it cannot reschedule when that node is replaced",
              "Remove the hostname pin or use zone/label-based affinity")
    if check_probes:
        missing = [c.name for c in spec.containers or [] if not c.readiness_probe]
        if missing:
            f.add("INFO", "Drain readiness", ns, obj,
                  f"No readiness probe on: {', '.join(missing)}; traffic may hit pods before they are ready",
                  "Add readiness probes")
    if check_emptydir:
        vols = [v.name for v in spec.volumes or [] if v.empty_dir is not None]
        if vols:
            f.add("INFO", "Storage", ns, obj,
                  f"Uses emptyDir volume(s) {', '.join(vols)}; contents are lost when the pod moves nodes")


def check_cluster_objects(f, data, cfg, now=None):
    now = now or datetime.now(timezone.utc)
    threshold, pending_min = cfg["restartThreshold"], cfg["pendingMinutes"]

    # Nodes
    for n in data["nodes"]:
        name = f"Node/{n.metadata.name}"
        conds = {c.type: c for c in (n.status.conditions or [])}
        ready = conds.get("Ready")
        if not ready or ready.status != "True":
            f.add("BLOCKER", "Cluster health", None, name, "Node is NotReady",
                  "Repair or remove the node before upgrading")
        for t in ("MemoryPressure", "DiskPressure", "PIDPressure"):
            if t in conds and conds[t].status == "True":
                f.add("WARNING", "Cluster health", None, name, f"Node has {t}")
        if n.spec.unschedulable:
            f.add("WARNING", "Cluster health", None, name,
                  "Node is cordoned (unschedulable) before the upgrade started",
                  "Confirm why; uncordon or remove it")

    # Namespaces stuck terminating
    for ns in data["namespaces"]:
        if (ns.status.phase or "") == "Terminating":
            f.add("WARNING", "Cluster health", ns.metadata.name, f"Namespace/{ns.metadata.name}",
                  "Namespace is stuck in Terminating", "Check finalizers on remaining resources")

    # Pods
    used_claims = set()
    for p in data["pods"]:
        ns, obj = p.metadata.namespace, f"Pod/{p.metadata.name}"
        for v in p.spec.volumes or []:
            if v.persistent_volume_claim:
                used_claims.add((ns, v.persistent_volume_claim.claim_name))
        owners = p.metadata.owner_references or []
        wl = owner_workload(p)
        phase = p.status.phase
        if phase == "Succeeded":
            continue
        if not owners:
            f.add("WARNING", "Drain readiness", ns, obj,
                  "Bare pod (no controller); it is deleted on drain and will not come back",
                  "Run it under a Deployment, StatefulSet or Job")
        if phase == "Failed":
            if p.status.reason == "Evicted":
                f.add("INFO", "Workload health", ns, obj, "Evicted pod left behind", "Clean it up",
                      workload=wl)
            elif not any(o.kind == "Job" for o in owners):
                f.add("WARNING", "Workload health", ns, obj,
                      f"Pod failed: {p.status.reason or ''} {p.status.message or ''}".strip(), workload=wl)
            continue

        issues = []
        age_min = (now - p.metadata.creation_timestamp).total_seconds() / 60 if p.metadata.creation_timestamp else 0
        if phase == "Pending" and age_min >= pending_min:
            why = next((c.message or c.reason for c in (p.status.conditions or [])
                        if c.type == "PodScheduled" and c.status == "False"), None)
            issues.append(f"Pending for {int(age_min)} min" + (f" ({why})" if why else ""))
        if phase == "Unknown":
            issues.append("Phase Unknown (node may be lost)")
        for cs in (p.status.init_container_statuses or []) + (p.status.container_statuses or []):
            w = cs.state and cs.state.waiting
            if w and w.reason in BAD_WAITING:
                issues.append(f"Container {cs.name}: {w.reason}")
            elif (cs.restart_count or 0) >= threshold:
                issues.append(f"Container {cs.name}: {cs.restart_count} restarts")
        if phase == "Running" and not issues:
            ready = next((c for c in (p.status.conditions or []) if c.type == "Ready"), None)
            if ready and ready.status != "True" and age_min >= pending_min:
                issues.append("Running but not Ready")
        # One finding per issue so the pre/post diff matches them individually
        for issue in issues:
            f.add("WARNING", "Workload health", ns, obj, issue,
                  "Check `kubectl describe pod` events and container logs", workload=wl)

    # Deployments
    for d in data["deployments"]:
        ns, obj = d.metadata.namespace, f"Deployment/{d.metadata.name}"
        desired = d.spec.replicas if d.spec.replicas is not None else 1
        avail = d.status.available_replicas or 0
        if desired > 0 and avail < desired:
            f.add("WARNING", "Workload health", ns, obj, f"Only {avail}/{desired} replicas available")
        if desired == 1:
            f.add("INFO", "Drain readiness", ns, obj,
                  "Single replica: brief downtime while its node is drained",
                  "Run ≥2 replicas with a PDB if this must stay up")
        if desired > 0:
            _workload_spec_checks(f, ns, obj, d.spec.template.spec)

    # StatefulSets
    for s in data["statefulsets"]:
        ns, obj = s.metadata.namespace, f"StatefulSet/{s.metadata.name}"
        desired = s.spec.replicas if s.spec.replicas is not None else 1
        ready = s.status.ready_replicas or 0
        if desired > 0 and ready < desired:
            f.add("WARNING", "Workload health", ns, obj, f"Only {ready}/{desired} replicas ready")
        if desired == 1:
            f.add("WARNING", "Drain readiness", ns, obj,
                  "Single-replica StatefulSet: downtime while its node is drained and its volume re-attaches",
                  "Plan for the downtime or run more replicas")
        if desired > 0:
            _workload_spec_checks(f, ns, obj, s.spec.template.spec, check_emptydir=True)

    # DaemonSets
    for ds in data["daemonsets"]:
        ns, obj = ds.metadata.namespace, f"DaemonSet/{ds.metadata.name}"
        desired, ready = ds.status.desired_number_scheduled or 0, ds.status.number_ready or 0
        if ready < desired:
            f.add("WARNING", "Workload health", ns, obj, f"Only {ready}/{desired} pods ready")

    # Jobs
    for j in data["jobs"]:
        if any(c.type == "Failed" and c.status == "True" for c in (j.status.conditions or [])):
            f.add("INFO", "Workload health", j.metadata.namespace, f"Job/{j.metadata.name}", "Job failed")

    # PVCs
    wffc = {sc.metadata.name for sc in data["storageclasses"] if sc.volume_binding_mode == "WaitForFirstConsumer"}
    for c in data["pvcs"]:
        ns, obj = c.metadata.namespace, f"PVC/{c.metadata.name}"
        phase = c.status.phase
        if phase == "Pending":
            if c.spec.storage_class_name in wffc and (ns, c.metadata.name) not in used_claims:
                f.add("INFO", "Storage", ns, obj, "Pending (WaitForFirstConsumer; no pod uses it yet)")
            else:
                f.add("WARNING", "Storage", ns, obj, "PVC is Pending", "Check `kubectl describe pvc` events")
        elif phase == "Lost":
            f.add("WARNING", "Storage", ns, obj, "PVC is Lost (its PV no longer exists)")

    # PDBs
    for b in data["pdbs"]:
        ns, obj = b.metadata.namespace, f"PDB/{b.metadata.name}"
        st = b.status
        expected, allowed = st.expected_pods or 0, st.disruptions_allowed or 0
        if expected == 0:
            f.add("INFO", "Drain readiness", ns, obj, "PDB matches no pods", "Remove it or fix its selector")
        elif allowed == 0:
            f.add("BLOCKER", "Drain readiness", ns, obj,
                  f"Allows 0 disruptions (healthy {st.current_healthy}/{expected}, needs {st.desired_healthy}); "
                  "node drain will stall and the upgrade can fail",
                  "Set maxUnavailable: 1, or scale up so healthy > required, before the upgrade")


# --------------------------------------------------------------------------- inventory
POOL_LABELS = ("kubernetes.azure.com/agentpool", "agentpool")


def build_inventory(data, ignore=()):
    """Snapshot of what was running, so the post-check can spot what stopped working."""
    inv = {"workloads": {}, "pvcs": {}, "nodes": []}
    for kind, items, ready_attr in (("Deployment", data["deployments"], "available_replicas"),
                                    ("StatefulSet", data["statefulsets"], "ready_replicas")):
        for w in items:
            if w.metadata.namespace in ignore:
                continue
            desired = w.spec.replicas if w.spec.replicas is not None else 1
            inv["workloads"][f"{w.metadata.namespace}/{kind}/{w.metadata.name}"] = {
                "desired": desired, "ready": getattr(w.status, ready_attr) or 0}
    for ds in data["daemonsets"]:
        if ds.metadata.namespace in ignore:
            continue
        inv["workloads"][f"{ds.metadata.namespace}/DaemonSet/{ds.metadata.name}"] = {
            "desired": ds.status.desired_number_scheduled or 0, "ready": ds.status.number_ready or 0}
    for c in data["pvcs"]:
        if c.metadata.namespace not in ignore:
            inv["pvcs"][f"{c.metadata.namespace}/{c.metadata.name}"] = c.status.phase
    for n in data["nodes"]:
        labels = n.metadata.labels or {}
        ready = next((c.status for c in (n.status.conditions or []) if c.type == "Ready"), "Unknown")
        inv["nodes"].append({
            "name": n.metadata.name,
            "pool": next((labels[k] for k in POOL_LABELS if k in labels), None),
            "kubelet": (n.status.node_info.kubelet_version if n.status.node_info else None),
            "ready": ready == "True",
        })
    return inv


# --------------------------------------------------------------------------- post-check
def verify_upgrade(cluster, nodepools, inventory, expected):
    """Did the upgrade actually finish? Returns a list of findings dicts."""
    f = Findings()
    ev = ver(expected)
    current = current_version(cluster)
    if ver(current) != ev:
        f.add("BLOCKER", "Upgrade verification", None, "Control plane",
              f"Control plane is on {current}, expected {expected}", "Check the AKS operation status / activity log")
    if cluster.get("provisioningState") != "Succeeded":
        f.add("BLOCKER", "Upgrade verification", None, "AKS cluster",
              f"Cluster provisioningState is '{cluster.get('provisioningState')}'",
              "Check the upgrade operation; retry or reconcile with `az aks update`")
    for np in nodepools or []:
        npv = np.get("currentOrchestratorVersion") or np.get("orchestratorVersion")
        name = f"NodePool/{np.get('name')}"
        if np.get("provisioningState") != "Succeeded":
            f.add("BLOCKER", "Upgrade verification", None, name,
                  f"Node pool provisioningState is '{np.get('provisioningState')}'", "Check the node pool upgrade")
        if ver(npv) != ev:
            f.add("BLOCKER", "Upgrade verification", None, name,
                  f"Node pool is on {npv}, expected {expected}", "Upgrade the node pool")
    for n in inventory["nodes"]:
        if n["kubelet"] and ver(n["kubelet"]) != ev:
            f.add("BLOCKER", "Upgrade verification", None, f"Node/{n['name']}",
                  f"Kubelet is {n['kubelet']}, expected v{expected}", "Node was not replaced; check its node pool")
    if not f.items:
        f.add("INFO", "Upgrade verification", None, "Cluster",
              f"Control plane, all node pools and all {len(inventory['nodes'])} nodes are on {expected}")
    return f.items


def inventory_regressions(base, now):
    """Things that worked before the upgrade and don't now."""
    f = Findings()
    for key, b in base["workloads"].items():
        ns, kind, name = key.split("/", 2)
        obj = f"{kind}/{name}"
        cur = now["workloads"].get(key)
        if cur is None:
            f.add("INFO", "Workload health", ns, obj, "Existed before the upgrade, now gone (deleted?)")
            continue
        was_ok = b["desired"] == 0 or b["ready"] >= b["desired"]
        is_ok = cur["desired"] == 0 or cur["ready"] >= cur["desired"]
        if was_ok and not is_ok:
            f.add("BLOCKER", "Workload health", ns, obj,
                  f"Was healthy before the upgrade ({b['ready']}/{b['desired']}), now {cur['ready']}/{cur['desired']}",
                  "Check pod events/logs: image, API, scheduling or probe failures after the node roll")
    for key, phase in base["pvcs"].items():
        ns, name = key.split("/", 1)
        cur = now["pvcs"].get(key)
        if phase == "Bound" and cur not in (None, "Bound"):
            f.add("BLOCKER", "Storage", ns, f"PVC/{name}", f"Was Bound before the upgrade, now {cur}",
                  "Check the CSI driver and volume attachment")
    bn, nn = len(base["nodes"]), len(now["nodes"])
    if nn < bn:
        f.add("WARNING", "Cluster health", None, "Nodes",
              f"{nn} nodes after the upgrade vs {bn} before", "Check the autoscaler and node pool counts")
    not_ready = [n["name"] for n in now["nodes"] if not n["ready"]]
    if not_ready:
        f.add("BLOCKER", "Cluster health", None, "Nodes", f"NotReady after upgrade: {', '.join(not_ready)}")
    return f.items


def compare(base_report, base_inv, post_report, post_inv, cluster, nodepools):
    expected = base_report["targetVersion"]
    verification = verify_upgrade(cluster, nodepools, post_inv, expected)
    regressions = inventory_regressions(base_inv, post_inv)
    covered = {(r["namespace"], r["object"]) for r in regressions}

    skip = {"Version"}  # version findings are expected to change; verification covers them
    pre = {i["key"]: i for i in base_report["findings"] if i["category"] not in skip}
    post = {i["key"]: i for i in post_report["findings"] if i["category"] not in skip}

    new = [post[k] for k in post.keys() - pre.keys()
           if (post[k]["namespace"], post[k]["object"]) not in covered]
    resolved = [pre[k] for k in pre.keys() - post.keys()]
    unchanged = [post[k] for k in post.keys() & pre.keys()]
    return {"expectedVersion": expected, "verification": verification, "regressions": regressions,
            "new": new, "resolved": resolved, "unchanged": unchanged}


def _rows(items, owners, with_ns=True):
    hdr = "| Severity | " + ("Namespace (owner) | " if with_ns else "") + "Category | Object | Finding | Action |"
    out = [hdr, "|---" * (5 + with_ns) + "|"]
    for r in sorted(items, key=lambda i: (SEV_RANK[i["severity"]], i["namespace"], i["category"], i["object"])):
        nscol = ""
        if with_ns:
            ns = r["namespace"]
            nscol = ("cluster | " if ns == CLUSTER_SCOPE else f"`{ns}` ({owners.get(ns, 'unknown')}) | ")
        out.append(f"| {ICON[r['severity']]} {r['severity']} | {nscol}{r['category']} | `{_esc(r['object'])}` | "
                   f"{_esc(r['message'])} | {_esc(r['action'])} |")
    return out


def render_post_md(meta, cmp, full=True):
    ver_fail = [v for v in cmp["verification"] if v["severity"] == "BLOCKER"]
    reg = cmp["regressions"] + [n for n in cmp["new"] if n["severity"] != "INFO"]
    reg_hard = [r for r in reg if r["severity"] == "BLOCKER"]
    new_info = [n for n in cmp["new"] if n["severity"] == "INFO"]
    status = "❌ UPGRADE INCOMPLETE" if ver_fail else ("❌ REGRESSIONS FOUND" if reg_hard else
                                                      ("⚠️ NEW WARNINGS" if reg else "✅ HEALTHY"))
    out = [f"## AKS upgrade post-check: `{meta['cluster']}` ({meta['env']})", "",
           f"**Expected version:** {cmp['expectedVersion']} · **Now on:** {meta['currentVersion']}  ",
           f"**Result:** {status}  ",
           f"🆕 {len(reg)} new problems · ✅ {len(cmp['resolved'])} resolved · "
           f"➖ {len(cmp['unchanged'])} unchanged (pre-existing)  ",
           f"_Baseline: pre-check from {meta['baselineGeneratedAt']} · post-check {meta['generatedAt']}_", ""]
    if meta.get("baselineStale"):
        out += [f"> ⚠️ The baseline is {meta['baselineAgeDays']} days old. Run the pre-check right before "
                "upgrading so the comparison is meaningful.", ""]
    out += ["### Upgrade verification", ""] + _rows(cmp["verification"], meta["owners"], with_ns=False) + [""]
    out += ["### 🆕 New since the pre-check (likely caused by the upgrade)", ""]
    out += (_rows(reg, meta["owners"]) if reg else ["None. 🎉"]) + [""]
    if cmp["resolved"]:
        out += ["### ✅ Resolved since the pre-check", ""] + _rows(cmp["resolved"], meta["owners"]) + [""]
    if full:
        if new_info:
            out += ["### 🔵 New info items", ""] + _rows(new_info, meta["owners"]) + [""]
        if cmp["unchanged"]:
            out += ["### ➖ Unchanged (existed before the upgrade)", ""] + _rows(cmp["unchanged"], meta["owners"]) + [""]
    elif cmp["unchanged"] or new_info:
        out += [f"_{len(cmp['unchanged'])} unchanged and {len(new_info)} new info items are in the full report artifact._", ""]
    return "\n".join(out), len(ver_fail), len(reg_hard), len(reg)


# --------------------------------------------------------------------------- reporting
def owner_map(namespaces, cfg):
    owners = {}
    for ns in namespaces:
        labels = ns.metadata.labels or {}
        name = ns.metadata.name
        owner = next((labels[k] for k in cfg["ownerLabels"] if labels.get(k)), None)
        owners[name] = owner or ("platform" if name in cfg["platformNamespaces"] else "unknown")
    owners[CLUSTER_SCOPE] = "platform"
    return owners


def _esc(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def render_md(meta, items, min_sev="INFO", title=True):
    keep = [i for i in items if SEV_RANK[i["severity"]] <= SEV_RANK[min_sev]]
    b = sum(i["severity"] == "BLOCKER" for i in items)
    w = sum(i["severity"] == "WARNING" for i in items)
    n = sum(i["severity"] == "INFO" for i in items)
    out = []
    if title:
        out += [f"## AKS upgrade pre-check: `{meta['cluster']}` ({meta['env']})", "",
                f"**Current:** {meta['currentVersion']} → **Target:** {meta['targetVersion']}  ",
                f"**Result:** {'❌ BLOCKED' if b else '✅ No blockers'}: "
                f"🔴 {b} blockers · 🟠 {w} warnings · 🔵 {n} info  ",
                f"_Generated {meta['generatedAt']}_", ""]
        if min_sev != "INFO" and n:
            out += [f"_{n} info items are in the full report artifact._", ""]

    groups = {}
    for i in keep:
        groups.setdefault(i["namespace"], []).append(i)
    order = sorted(groups, key=lambda ns: (ns != CLUSTER_SCOPE,
                                           min(SEV_RANK[i["severity"]] for i in groups[ns]), ns))
    for ns in order:
        rows = sorted(groups[ns], key=lambda i: (SEV_RANK[i["severity"]], i["category"], i["object"]))
        head = "### Cluster-level" if ns == CLUSTER_SCOPE else \
            f"### Namespace `{ns}`: owner `{meta['owners'].get(ns, 'unknown')}`"
        out += [head, "", "| Severity | Category | Object | Finding | Action |", "|---|---|---|---|---|"]
        out += [f"| {ICON[r['severity']]} {r['severity']} | {r['category']} | `{_esc(r['object'])}` | "
                f"{_esc(r['message'])} | {_esc(r['action'])} |" for r in rows]
        out.append("")
    if not keep:
        out.append("Nothing to report. 🎉")
    return "\n".join(out)


def write_outputs(meta, f, out_dir, inventory=None):
    out = Path(out_dir)
    (out / "namespaces").mkdir(parents=True, exist_ok=True)
    meta["counts"] = {s: f.count(s) for s in SEV_RANK}
    (out / "report.json").write_text(json.dumps({**meta, "findings": f.items}, indent=2))
    if inventory is not None:
        (out / "inventory.json").write_text(json.dumps(inventory, indent=2))
    (out / "report.md").write_text(render_md(meta, f.items))
    (out / "summary.md").write_text(render_md(meta, f.items, min_sev="WARNING"))
    for ns in {i["namespace"] for i in f.items} - {CLUSTER_SCOPE}:
        items = [i for i in f.items if i["namespace"] == ns]
        hdr = (f"# Upgrade pre-check for namespace `{ns}` on `{meta['cluster']}` ({meta['env']})\n\n"
               f"Owner: `{meta['owners'].get(ns, 'unknown')}` · "
               f"{meta['currentVersion']} → {meta['targetVersion']} · {meta['generatedAt']}\n\n")
        (out / "namespaces" / f"{ns}.md").write_text(hdr + render_md(meta, items, title=False))


# --------------------------------------------------------------------------- commands
def cmd_resolve(a):
    cluster = load_json(a.cluster_json, {})
    current = current_version(cluster)
    print(pick_target(current, available_upgrades(load_json(a.upgrades_json, {})), a.target))


def cmd_scan(a):
    cfg = {**DEFAULT_CONFIG, **(load_json(a.config, {}) or {})}
    cluster = load_json(a.cluster_json, {})
    f = Findings(cfg["ignoreNamespaces"])

    check_version(f, cluster, load_json(a.upgrades_json, {}), load_json(a.nodepools_json, []), a.target)
    check_kubent(f, load_json(a.kubent_json, []), a.target)
    metrics = Path(a.metrics_file).read_text() if a.metrics_file and Path(a.metrics_file).exists() else ""
    merr = Path(a.metrics_err).read_text() if a.metrics_err and Path(a.metrics_err).exists() else ""
    check_metric(f, metrics, merr, a.target)

    data = collect(a.kubeconfig)
    check_cluster_objects(f, data, cfg)

    meta = {
        "cluster": a.cluster_name, "env": a.env,
        "currentVersion": current_version(cluster), "targetVersion": a.target,
        "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "owners": owner_map(data["namespaces"], cfg),
    }
    write_outputs(meta, f, a.out_dir, build_inventory(data, cfg["ignoreNamespaces"]))

    counts = {s: f.count(s) for s in SEV_RANK}
    print(f"{a.cluster_name}: {counts['BLOCKER']} blockers, {counts['WARNING']} warnings, {counts['INFO']} info")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
            fh.write(f"blockers={counts['BLOCKER']}\nwarnings={counts['WARNING']}\n")


def _gh_output(**kv):
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
            fh.writelines(f"{k}={v}\n" for k, v in kv.items())


def cmd_wait_settle(a):
    """After an upgrade, wait until workloads that were healthy before are healthy again
    (or the timeout passes) so the post-check doesn't flag pods that are still starting."""
    import time
    cfg = {**DEFAULT_CONFIG, **(load_json(a.config, {}) or {})}
    base = load_json(Path(a.baseline_dir) / "inventory.json")
    deadline = time.time() + a.timeout_min * 60
    if not base:
        print("No baseline inventory; waiting a fixed 5 minutes instead")
        time.sleep(min(300, a.timeout_min * 60))
        return
    while True:
        inv = build_inventory(collect(a.kubeconfig), cfg["ignoreNamespaces"])
        pending = [f"{r['namespace']}/{r['object']}" for r in inventory_regressions(base, inv)
                   if r["severity"] == "BLOCKER"]
        if not pending:
            print("All workloads that were healthy before the upgrade are healthy again.")
            return
        left = int(deadline - time.time())
        if left <= 0:
            print(f"Timeout: {len(pending)} still not back: {', '.join(pending[:15])}"
                  + (" …" if len(pending) > 15 else ""))
            return
        print(f"{len(pending)} not back yet ({left // 60} min left): {', '.join(pending[:5])}"
              + (" …" if len(pending) > 5 else ""))
        time.sleep(min(a.interval, max(left, 1)))


def cmd_compare(a):
    bdir, pdir = Path(a.baseline_dir), Path(a.post_dir)
    base_report, post_report = load_json(bdir / "report.json"), load_json(pdir / "report.json")
    if not base_report:
        sys.exit(f"Baseline report not found in {bdir}")
    base_inv = load_json(bdir / "inventory.json") or {"workloads": {}, "pvcs": {}, "nodes": []}
    post_inv = load_json(pdir / "inventory.json")
    cluster, nodepools = load_json(a.cluster_json, {}), load_json(a.nodepools_json, [])

    cmp = compare(base_report, base_inv, post_report, post_inv, cluster, nodepools)

    try:
        base_ts = datetime.strptime(base_report["generatedAt"], "%Y-%m-%d %H:%M UTC").replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - base_ts).days
    except (KeyError, ValueError):
        age = None
    owners = {**base_report.get("owners", {}), **post_report.get("owners", {})}
    meta = {
        "cluster": a.cluster_name, "env": a.env,
        "currentVersion": current_version(cluster),
        "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "baselineGeneratedAt": base_report.get("generatedAt", "unknown"),
        "baselineAgeDays": age, "baselineStale": age is not None and age > a.stale_days,
        "owners": owners,
    }
    full, ver_fail, reg_hard, reg_all = render_post_md(meta, cmp, full=True)
    short, *_ = render_post_md(meta, cmp, full=False)
    (pdir / "postcheck.md").write_text(full)
    (pdir / "postcheck-summary.md").write_text(short)
    (pdir / "postcheck.json").write_text(json.dumps({**meta, **cmp, "counts": {
        "verificationFailures": ver_fail, "regressions": reg_hard, "newProblems": reg_all,
        "resolved": len(cmp["resolved"]), "unchanged": len(cmp["unchanged"])}}, indent=2))

    # one file per namespace with new problems, ready to send to the owning team
    nsdir = pdir / "namespaces-post"
    nsdir.mkdir(exist_ok=True)
    problems = cmp["regressions"] + [n for n in cmp["new"] if n["severity"] != "INFO"]
    for ns in {p["namespace"] for p in problems} - {CLUSTER_SCOPE}:
        rows = [p for p in problems if p["namespace"] == ns]
        (nsdir / f"{ns}.md").write_text(
            f"# Post-upgrade problems in `{ns}` on `{a.cluster_name}` ({a.env})\n\n"
            f"Owner: `{owners.get(ns, 'unknown')}` · upgraded to {cmp['expectedVersion']} · {meta['generatedAt']}\n\n"
            "These were not present in the pre-upgrade check.\n\n" + "\n".join(_rows(rows, owners, with_ns=False)) + "\n")

    print(f"{a.cluster_name}: verification failures={ver_fail}, regressions={reg_hard}, "
          f"new problems={reg_all}, resolved={len(cmp['resolved'])}, unchanged={len(cmp['unchanged'])}")
    _gh_output(verification_failures=ver_fail, regressions=reg_hard, new_problems=reg_all)


def cmd_summary(a):
    if a.kind == "post":
        return _post_summary(a)
    reports = sorted(Path(a.reports_dir).rglob("report.json"))
    lines = ["# AKS upgrade pre-check summary", "",
             "| Cluster | Env | Current → Target | 🔴 Blockers | 🟠 Warnings | 🔵 Info | Result |",
             "|---|---|---|---|---|---|---|"]
    env_order = {"dev": 0, "uat": 1, "prod": 2}
    rows = [load_json(r) for r in reports]
    for r in sorted(rows, key=lambda r: (env_order.get(r["env"], 9), r["cluster"])):
        c = r["counts"]
        lines.append(f"| `{r['cluster']}` | {r['env']} | {r['currentVersion']} → {r['targetVersion']} | "
                     f"{c['BLOCKER']} | {c['WARNING']} | {c['INFO']} | {'❌ Blocked' if c['BLOCKER'] else '✅ Ready'} |")
    if not rows:
        lines.append("| _no reports found_ | | | | | | |")
    print("\n".join(lines))


def _post_summary(a):
    rows = [load_json(r) for r in sorted(Path(a.reports_dir).rglob("postcheck.json"))]
    lines = ["# AKS upgrade post-check summary", "",
             "| Cluster | Env | Expected → Now | Upgrade complete | 🆕 New problems | ✅ Resolved | ➖ Unchanged | Result |",
             "|---|---|---|---|---|---|---|---|"]
    env_order = {"dev": 0, "uat": 1, "prod": 2}
    for r in sorted(rows, key=lambda r: (env_order.get(r["env"], 9), r["cluster"])):
        c = r["counts"]
        result = ("❌ Incomplete" if c["verificationFailures"] else "❌ Regressions" if c["regressions"]
                  else "⚠️ New warnings" if c["newProblems"] else "✅ Healthy")
        lines.append(f"| `{r['cluster']}` | {r['env']} | {r['expectedVersion']} → {r['currentVersion']} | "
                     f"{'no' if c['verificationFailures'] else 'yes'} | {c['newProblems']} | {c['resolved']} | "
                     f"{c['unchanged']} | {result} |")
    if not rows:
        lines.append("| _no reports found_ | | | | | | | |")
    print("\n".join(lines))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("resolve-target")
    r.add_argument("--cluster-json", required=True)
    r.add_argument("--upgrades-json", required=True)
    r.add_argument("--target", default="")
    r.set_defaults(func=cmd_resolve)

    s = sub.add_parser("scan")
    s.add_argument("--cluster-name", required=True)
    s.add_argument("--env", required=True)
    s.add_argument("--target", required=True)
    s.add_argument("--cluster-json", required=True)
    s.add_argument("--upgrades-json", required=True)
    s.add_argument("--nodepools-json", required=True)
    s.add_argument("--kubent-json", required=True)
    s.add_argument("--metrics-file")
    s.add_argument("--metrics-err")
    s.add_argument("--config")
    s.add_argument("--kubeconfig")
    s.add_argument("--out-dir", required=True)
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("wait-settle", help="Post-upgrade: wait until previously healthy workloads recover")
    w.add_argument("--baseline-dir", required=True)
    w.add_argument("--timeout-min", type=int, default=15)
    w.add_argument("--interval", type=int, default=30)
    w.add_argument("--config")
    w.add_argument("--kubeconfig")
    w.set_defaults(func=cmd_wait_settle)

    c = sub.add_parser("compare", help="Post-upgrade: verify the upgrade and diff against the pre-check")
    c.add_argument("--baseline-dir", required=True, help="Folder with the pre-check report.json + inventory.json")
    c.add_argument("--post-dir", required=True, help="Folder with the post-upgrade scan output")
    c.add_argument("--cluster-json", required=True)
    c.add_argument("--nodepools-json", required=True)
    c.add_argument("--cluster-name", required=True)
    c.add_argument("--env", required=True)
    c.add_argument("--stale-days", type=int, default=3)
    c.set_defaults(func=cmd_compare)

    m = sub.add_parser("summary")
    m.add_argument("--reports-dir", required=True)
    m.add_argument("--kind", choices=["pre", "post"], default="pre")
    m.set_defaults(func=cmd_summary)

    a = p.parse_args(argv)
    a.func(a)


if __name__ == "__main__":
    sys.exit(main())

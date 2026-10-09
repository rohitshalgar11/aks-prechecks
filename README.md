# AKS upgrade pre-check

Runs before every AKS upgrade and tells each team what will break in their namespace.

## What it checks

| Area | Checks | Severity |
|---|---|---|
| **Target version** | Target is offered by AKS for this cluster, no skipped minors, no downgrade, not preview, auto-upgrade channel, node-pool version skew | Blocker / Warning |
| **Removed APIs** (kubent) | Live objects and Helm releases using APIs removed in the target version | Blocker if removed ≤ target, else Warning |
| **Runtime API calls** (`apiserver_requested_deprecated_apis`) | Clients still *calling* removed APIs (CI jobs, scripts, old SDKs) | Blocker / Warning |
| **Cluster health** | Cluster / node pool provisioning state, NotReady nodes, node pressure, cordoned nodes, namespaces stuck Terminating | Blocker / Warning |
| **Workload health** | Pending pods, CrashLoopBackOff / ImagePullBackOff, high restarts, Running-but-not-Ready, failed pods, evicted pods, Deployments/StatefulSets/DaemonSets below desired, failed Jobs | Warning / Info |
| **Storage** | Pending and Lost PVCs (WaitForFirstConsumer PVCs with no pod are only Info), emptyDir in StatefulSets | Warning / Info |
| **Drain readiness** | PDBs allowing 0 disruptions, bare pods, single replicas, workloads pinned to one node, missing readiness probes | Blocker / Warning / Info |

Pre-existing health problems are reported so they are fixed (or at least known) **before**
the upgrade, so new failures afterwards can be told apart from old ones. `report.json`
doubles as the pre-upgrade baseline.

## Layout

```
.github/workflows/aks-upgrade-precheck.yml   pre-check workflow
.github/workflows/aks-upgrade-postcheck.yml  post-check workflow (verify + compare)
scripts/precheck.py                          all checks, inventory, compare, reports
scripts/install-tools.sh                     installs anything missing on the runner
scripts/requirements.txt                     python deps (kubernetes client)
config/clusters.json                         your clusters (name, env, RG, subscription)
config/precheck.json                         owner labels, platform namespaces, thresholds
manifests/precheck-rbac.yaml                 read-only ClusterRole for the identity
```

## Tools on the runner

az CLI, kubectl, kubelogin, kubent, Python 3. `install-tools.sh` installs kubectl,
kubelogin, kubent and the Python venv if missing; **az CLI must already be in the runner
image** (it needs root). Bake all of them into the self-hosted runner image for fast starts.

## One-time setup

1. **Self-hosted runner** in the cluster VNet (or a peered VNet), labelled
   `self-hosted, linux, aks-precheck`. Its VNet must be linked to each cluster's private
   DNS zone so it can resolve the private API server FQDN.
2. **Entra app registration / user-assigned identity** with federated credentials for
   subjects `repo:<org>/<repo>:environment:precheck-dev`, `…precheck-uat`, `…precheck-prod`.
3. **Azure roles** for that identity on each cluster:
   *Azure Kubernetes Service Cluster User Role* (fetch kubeconfig) and *Reader*
   (`az aks show`, `get-upgrades`, `nodepool list`).
4. **Kubernetes RBAC**: add the identity to an Entra group, put the group's object ID in
   `manifests/precheck-rbac.yaml`, and `kubectl apply` it on every cluster.
5. **GitHub environments** `precheck-dev`, `precheck-uat`, `precheck-prod` with variables
   `AZURE_CLIENT_ID` and `AZURE_TENANT_ID`. Leave them without required reviewers.
6. Fill in `config/clusters.json`, and label namespaces with `team=<name>` (or `owner=`) so
   reports are routed to the right owner.

## Running it

- **Manual / gate**: *Actions → AKS upgrade pre-check → Run workflow*, pick the environment
  and optionally a target version. Leave the target empty to use the latest GA patch of the
  next minor. With `fail_on_blockers` on, the run goes red if anything blocks.
- **Advance warning**: runs automatically on the 20th of every month across all clusters
  (never fails; it only reports).
- **From your upgrade workflow**: call it as a reusable workflow and make the upgrade job
  `needs:` it.

## Output

Each cluster gets an artifact `precheck-<cluster>` with:

- `report.md`: full report, grouped cluster-level first, then by namespace and owner
- `summary.md`: blockers and warnings only (also shown on the run summary page)
- `namespaces/<ns>.md`: one file per namespace, ready to send to that team
- `report.json`: machine-readable findings (the post-check's baseline)
- `inventory.json`: snapshot of every workload's ready/desired count, PVC phases and nodes
  (the post-check uses it to spot what stopped working)
- `raw/`: the AKS metadata, kubent output and metric data the report was built from

## Post-check (after the upgrade)

`aks-upgrade-postcheck.yml` runs after an upgrade and compares the cluster with its
pre-check baseline.

1. **Finds the baseline.** By default this is the latest `precheck-<cluster>` artifact; you
   can pin a specific pre-check run ID instead.
2. **Waits for things to settle.** It polls until every workload that was healthy before the
   upgrade is healthy again, or until `settle_minutes` runs out. This avoids flagging pods
   that are just restarting on new nodes.
3. **Verifies the upgrade finished.** The control plane, every node pool and every node's
   kubelet must be on the target version, and all provisioning states must be `Succeeded`.
4. **Re-runs every pre-check scan.** kubent runs against the new current version.
5. **Compares the results:**
   - **🆕 New**: problems that weren't there before (likely caused by the upgrade).
     Workloads that were fully ready and no longer are, and PVCs that were Bound and no
     longer are, are always blockers.
   - **✅ Resolved**: problems that disappeared.
   - **➖ Unchanged**: pre-existing problems. These are not blamed on the upgrade.

   Pod findings are matched by their owning workload, because pods get new names when
   they move nodes.

The run fails (when `fail_on_regressions` is on) if the upgrade is incomplete or a blocker
regression is found. New warnings are reported but don't fail the run.

The artifact `postcheck-<cluster>` contains `postcheck.md` (full),
`postcheck-summary.md`, `postcheck.json`, and `namespaces-post/<ns>.md` per team with
new problems.

**Run the pre-check right before each upgrade.** If the baseline is more than 3 days old,
the post-check report shows a warning, because the comparison is less meaningful.

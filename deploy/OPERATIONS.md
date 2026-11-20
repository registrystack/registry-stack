# Operate a Registry Stack installation

Use the installation's named Kubernetes context, Helm release and approved values for every operation. Keep a copy of the exact chart, image digests, artifact receipts, package, runtime inputs and binding names beside the backup. Keep credentials and private key material in your institution's controlled storage.

## Check health and diagnose failures

- Monitor the external HTTPS `/ready` of each Base Registry Engine (BReg) and Evidence instance and the App Kit `/health`. Check Casework's `/ready` endpoint. Alert on a TLS error, a non-200 response or approaching certificate expiry. Monitor from outside the node so ingress and DNS failures are visible.
- Run the operator's `status` command with the same arguments as `install` to check the ready database, active package and split-role activation ledger. Check Pod readiness, recent events and failed operation Job logs with `kubectl -n <namespace> get pods,jobs`, `kubectl -n <namespace> events` and `kubectl -n <namespace> logs job/<name> -c bregctl`. Keep diagnostics that name infrastructure or users within the operator environment.
- Monitor disk space and persistent-volume capacity, PostgreSQL replication and archive status if used, and app audit freshness. Use the installation's existing alerting channel and nominate a responder. The checks below can be called by the same scheduler.

## Back up a consistent installation

Choose a recovery point and backup cadence with the service owner. The reference uses a brief maintenance window and encrypted Restic storage on a separate host or account. Restic runs on the server that holds the bundle, not on the backup host. Install it on the server and initialise the repository once with `restic init`. Set `RESTIC_REPOSITORY` to the repository location and `RESTIC_PASSWORD_FILE` to an owner-only file holding the repository password. Export both in the environment of every `snapshot`, `check-snapshot` and `restic restore` command. For a larger or continuously written database, use an institution-operated PostgreSQL point-in-time recovery service. Rehearse a consistent restore of all participating state.

1. Drain callers, scheduled jobs, imports, outstanding notifications and partner endpoints that can write. Pause Casework, Evidence and other participants whose state you capture. Freeze identity administration if taking an identity backup. Write the BReg `status` JSON to a file while the release is ready, then run the operator's `stop`. Confirm serving Pods have terminated.

   `stop` applies the Helm release with serving turned off. The chart then renders no serving workloads, and Helm records the release as stopped, so a retried command leaves it stopped. `capture` refuses while any Pod of the release is still running, and again if one starts during the capture.

   ```bash
   sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml python3 deploy/stack_operator.py \
     --helm-bin /usr/local/lib/registry-stack/helm --kube-context default --namespace directory \
     --release directory --database-id directory-db \
     --values /srv/registry-directory/inputs/values.json status \
     | sudo tee /srv/registry-directory/backup-status.json >/dev/null
   sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml python3 deploy/stack_operator.py \
     --helm-bin /usr/local/lib/registry-stack/helm --kube-context default --namespace directory \
     --release directory --database-id directory-db \
     --values /srv/registry-directory/inputs/values.json stop
   ```
2. Assemble a private directory with the exact chart bindings, packaged code, runtime files, credential recovery material, and audit and authority stores. Copy the files from their owning storage, using its consistent snapshot or copy procedure. When you operate them, keep TLS material, the App Kit PostgreSQL state and encryption key, and the issuer's signing keys and database in the recovery set. For an external issuer, record who owns its recovery and verify it will preserve the issuer URL and subject mapping. Preserve the signer key versions through the signer's backup procedure. Back up the attachment bucket if used. BReg refuses a versioned bucket.
3. Dump each application database into the bundle. Include one `--database` per database. Record the role names and permissions to recreate before restore. The bundle manifest states what it leaves out: the persistent volumes behind the BReg audit and package claims, and any attachment or object storage. Copy their files into the `--files` directory to keep them with the bundle. In this example, run with a Kubeconfig that can administer the reference PostgreSQL Pod. The bundle is readable only by root, so run `snapshot` with the same privilege.

   ```bash
   sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml python3 deploy/state_bundle.py \
     capture --kube-context default --namespace directory \
     --release directory --database registry_breg \
     --status-file /srv/registry-directory/backup-status.json \
     --files /srv/registry-directory/recovery-inputs \
     --output /srv/registry-directory/backup-01
   ```

4. Archive the verified bundle to the Restic repository you initialised. Supply its credentials through protected files or the institution's secret manager. Keep the receipt off-host with the installation record.

   ```bash
   sudo env RESTIC_REPOSITORY=sftp:backup@backup.example.org:/srv/restic \
     RESTIC_PASSWORD_FILE=/root/restic-password \
     python3 deploy/state_bundle.py snapshot --bundle /srv/registry-directory/backup-01 \
     --receipt /srv/registry-directory/backup-01-receipt.json
   sudo env RESTIC_REPOSITORY=sftp:backup@backup.example.org:/srv/restic \
     RESTIC_PASSWORD_FILE=/root/restic-password \
     python3 deploy/state_bundle.py check-snapshot \
     --receipt /srv/registry-directory/backup-01-receipt.json --max-age-hours 26
   ```

5. When the backup is for routine operations, reopen the deployment by running `install` again with the same chart and values. `stop` does not undo itself, and `install` refuses values that differ from the installed ones. Reopening activates no package, so it needs no `--operator-reference`.

   ```bash
   sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml python3 deploy/stack_operator.py \
     --helm-bin /usr/local/lib/registry-stack/helm --kube-context default --namespace directory \
     --release directory --database-id directory-db \
     --values /srv/registry-directory/inputs/values.json install
   ```

   Configure the freshness check with your backup window. It reads the archived manifest, checks its digest and verifies when the database was captured. Re-archiving a bundle keeps its original capture time. A restore drill also reads and verifies the archived data.

For K3s control-plane recovery, take and export an embedded-etcd snapshot and protect the matching K3s server token. The application bundle separately protects the PostgreSQL data and mounted volumes. [K3s backup and restore](https://docs.k3s.io/datastore/backup-restore)

## Upgrade a release

Read the target [Registry Stack release notes](https://github.com/registrystack/registry-stack/releases) and rehearse on an isolated restored copy before the maintenance window. Rebuild product packages against the exact active baseline and rebuild App Kit with the matching client. For Casework or Scheduling versions that require a fresh database, follow the product's cutover procedure and preserve the source database for reconciliation.

1. Retain the previous chart, exact image digests, package claim, config and Secrets. Stage the successor package in a new read-only claim, with versioned runtime inputs that name the successor digest. On the reference single server, copy the private input directory, replace its package, set the successor digest in `runtime.yaml` and `values.json`, give the runtime ConfigMap and package claim new versioned names, and run `prepare_local.py` with the copy. It leaves existing objects whose inputs are unchanged and refuses a changed object under an existing name.
2. Pause callers and take a new backup. Check its receipt against the encrypted repository. The operator checks that it identifies the active installation and activation and that its capture is inside the backup window. If the operator refuses with a backup-age message, take a newer backup. If your recovery policy allows an older one, pass `--max-backup-age-hours` with that limit to `upgrade`. The default is 26 hours. Pass `--operator-reference` with the change or ticket reference for the upgrade. BReg records a keyed hash of it with the activation, so its runtime audit profile must be keyed. BReg refuses the activation otherwise, after the operator has stopped serving, so check the profile before the window. The reference also appears in the operation Job's arguments until the Job expires, so use a ticket ID, not personal data. An upgrade that keeps the active package, such as a configuration or image change, activates nothing and needs no reference. Supply the target chart values to the operator.

   ```bash
   python3 deploy/state_bundle.py check-snapshot \
     --receipt /srv/registry-directory/backup-01-receipt.json --max-age-hours 26
   sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml python3 deploy/stack_operator.py \
     --helm-bin /usr/local/lib/registry-stack/helm --kube-context default --namespace directory \
     --release directory --database-id directory-db \
     --values /srv/registry-directory/successor-values.json \
     upgrade --backup-receipt /srv/registry-directory/backup-01-receipt.json \
     --operator-reference CHANGE-1235
   ```

3. Verify the intended ledger transition, HTTPS readiness, and a previously known authorised record or transaction. Exercise an allowed and a denied request. Resume callers when each participating component is ready.

The operator supplies the active runtime config and package to BReg, mounts the candidate separately, and checks the exact successor plan before stopping old Pods. It runs apply with the candidate digest, then starts the target workloads after the ledger and doctor checks pass. It refuses migrations that require product-specific backup bindings. Use the [BReg reviewed migration procedure](https://docs.registrystack.org/operate/breg-changes/) for those changes.

### Resolve an interrupted upgrade

Before a BReg successor can change the database, the operator saves an immutable ConfigMap named `<release>-operator-upgrade` in the release namespace. It records the database, predecessor activation, candidate package and digests of the local chart with effective values and the backup receipt. Grant the operator ConfigMap get, create and delete permissions in the release namespace, in addition to the permissions listed under [Isolate customers](#isolate-customers). Helm readiness completes the operation and clears the record.

If the upgrade stops with a record still present, inspect the Job, the BReg ledger and Helm's status. If Helm reports a pending operation, resolve it with traffic closed before retrying. Run `upgrade` again with the original chart, values, predecessor backup receipt and `--operator-reference`, even if Helm already recorded the successor. The operator checks the recorded inputs. It does not recheck the receipt's age, because the record binds the retry to that receipt.

The operator keeps its Lease, `<release>-operator-lock`, when a Job's outcome is uncertain or the operator process ends without cleanup. The retry then reports `Cannot acquire Lease`. The `status` command takes the same Lease, so read the last Job's report with `kubectl logs job/<name> --container bregctl` instead. Confirm that no operator process or operation Job is running, delete only that Lease with `kubectl delete lease <release>-operator-lock`, and run `upgrade` again. After a completed BReg activation, it verifies the direct successor in the ledger and resumes Helm without repeating the migration. If the record is already gone and Helm reports the successor deployed, verify the completed release and ledger. Use a backup of the current activation for a separate configuration or image upgrade.

If BReg already committed before this operator recorded its inputs, keep traffic closed. Use your reviewed recovery procedure with the original verified chart and values, or the paired backup. Finish any interrupted upgrades before switching to this operator.

If BReg still holds a maintenance target, keep traffic closed. Run the product's read-only `bregctl migration reconcile` for the exact pinned target and inspect the result before taking the product's prescribed transition. A manual Job render uses `breg.operation.kind=reconcile` and the same `breg.operation.candidate` claim and digest as the failed apply. Verify that the Job finished and the activation ledger is ready before removing an abandoned operator Lease. Inspect its exact identity and Jobs before deleting it.

To abandon an upgrade before any database change, match the ready ledger activation to the predecessor in the upgrade record. Verify that Helm is still on the predecessor and no Job or Helm operation is running or uncertain. With other operator activity stopped, remove only that release's upgrade ConfigMap and use the previous verified package and values. A Helm revision only restores Kubernetes objects. For an incompatible committed database change, recover the paired application, database, authority and audit state from the chosen snapshot. Account for writes made after that point.

## Restore to a clean target

1. Fence the original installation and all writers. Keep its data available for reconciliation and remove its ability to serve or reconnect to the protected database. Record who confirmed fencing and how.
2. Restore the chosen snapshot into a private directory with `restic restore <snapshot-id> --target /srv/registry-directory/restored`, with `RESTIC_REPOSITORY` and `RESTIC_PASSWORD_FILE` set. Restic keeps the bundle's original absolute path under the target. A bundle captured at `/srv/registry-directory/backup-01` therefore restores to `/srv/registry-directory/restored/srv/registry-directory/backup-01`. Run `python3 deploy/state_bundle.py verify --bundle` with that path and `--receipt` with the receipt you kept off-host. The check refuses a bundle whose manifest differs from the receipt. Prepare storage and the same versioned chart inputs on the target, in the original namespace. The database URLs, the PostgreSQL server certificate's DNS names and the namespace selectors contain it. In another namespace, reissue that certificate and update those values. On the reference single server use `prepare_local.py --for-restore` to prepare an empty database and the roles. For an existing cluster, prepare a new empty database and recreate the exact roles there. Keep ingress traffic closed.
3. Restore each dump into its empty target. The tool refuses a database with existing application objects and restores each dump in one transaction.

   ```bash
   sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml python3 deploy/state_bundle.py \
     restore-database --kube-context default --namespace directory \
     --bundle /srv/registry-directory/restored/srv/registry-directory/backup-01 \
     --receipt /srv/registry-directory/backup-01-receipt.json \
     --database registry_breg --target registry_breg
   ```

4. Restore authority, TLS, identity and application state from the recovery set. Preserve the full surviving audit stream and shipped archive, including entries newer than the database backup. Continue the audit from that history and append the adoption and recovery entries. If the original host and unexported audit tail are lost, retain the available checkpoint audit and document the missing interval. Verify the issuer origin, signing-key continuity and OIDC client registration. Keep App Kit's state encryption key with its database. Use the same package digest and logical database and instance IDs. Restore filesystem ownership before starting a workload.
5. Run the operator's `claim-status` command with the restored values. A logical restore shows the prior claim. Adopt the copy after the original is permanently fenced. Adoption starts serving with the restored values' Ingress, so keep traffic closed at DNS or the firewall until acceptance. Record the change or ticket reference for the recovery in your own change log, because adoption takes none. On the isolated target, point DNS or a staging resolver at the new ingress for validation.

   ```bash
   sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml python3 deploy/stack_operator.py \
     --helm-bin /usr/local/lib/registry-stack/helm --kube-context default --namespace directory \
     --release directory --database-id directory-db \
     --values /srv/registry-directory/restored/values.json \
     adopt-restored --confirm-original-fenced
   ```

6. Verify HTTPS, sign-in, an authorised record and a denied request, previous audit entries, and one post-restore write and readback. Open ingress and callers after acceptance. Record measured recovery time and the recovered point in time.

## Renew certificates

Use a new versioned application TLS Secret and update the Helm values through the guarded upgrade path. For the reference PostgreSQL workload, put the renewed leaf and key in the input directory, then rerun preparation with `--postgres-tls-secret registry-postgres-tls-v2` and the original namespace and release. The StatefulSet starts a Pod with the new certificate. Keep the chosen Secret name in the preparation command for that installation. Allow for a short database interruption on one server. When changing the CA, first deploy client trust for both roots and renew the leaf. Remove the previous root after every client verifies the new chain.

## Isolate customers

Use a separate namespace and Helm release per deployment, with separate PostgreSQL roles and databases, audit claims, identity clients, signing keys, bucket credentials and backup permissions. Give operators access only to their scope. Besides the permissions Helm needs to apply the chart, the operator reads Pods, creates and reads Jobs and their logs, creates and deletes Leases, and creates, patches and deletes NetworkPolicies in the release namespace. Apply Restricted Pod Security and verify enforced NetworkPolicies. Use separate clusters for customers who need independent administration or stronger workload isolation.

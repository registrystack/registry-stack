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

   The subshell stops at the first failure. If `status` fails, `stop` does not run, and only the `.tmp` file is left, which the later steps do not read. The status file appears under its final name only after `status` succeeds.

   ```bash
   (
     set -euo pipefail
     sudo rm -f /srv/registry-directory/backup-status.json /srv/registry-directory/backup-status.json.tmp
     sudo install -m 600 /dev/null /srv/registry-directory/backup-status.json.tmp
     sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml python3 deploy/stack_operator.py \
       --helm-bin /usr/local/lib/registry-stack/helm --kube-context default --namespace directory \
       --release directory --database-id directory-db \
       --values /srv/registry-directory/inputs/values.json status \
       | sudo tee /srv/registry-directory/backup-status.json.tmp >/dev/null
     sudo mv /srv/registry-directory/backup-status.json.tmp /srv/registry-directory/backup-status.json
     sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml python3 deploy/stack_operator.py \
       --helm-bin /usr/local/lib/registry-stack/helm --kube-context default --namespace directory \
       --release directory --database-id directory-db \
       --values /srv/registry-directory/inputs/values.json stop
   )
   ```
2. Assemble a private directory. It holds the exact chart bindings, packaged code, runtime files, credential recovery material, and audit and authority stores. Copy the files from their owning storage, using its consistent snapshot or copy procedure. Keep TLS material, the App Kit PostgreSQL state and encryption key, and the issuer's signing keys and database in the recovery set. This applies to each one you operate. For an external issuer, record who owns its recovery. Verify that it preserves the issuer URL and subject mapping. Preserve the signer key versions through the signer's backup procedure. Back up the attachment bucket if used. BReg refuses a versioned bucket.

   On the reference single server, make a root-only directory for this backup, named like its bundle, and copy in the input directory and the BReg audit claim. `mkdir` refuses a name that already exists, so each backup starts from an empty directory. Copy the audit claim while serving is stopped.

   ```bash
   sudo mkdir -m 0700 /srv/registry-directory/backup-01-files
   sudo cp -a /srv/registry-directory/inputs /srv/registry-directory/backup-01-files/inputs
   sudo cp -a /var/lib/registry-stack/storage/directory/directory-audit /srv/registry-directory/backup-01-files/audit
   ```

   This copies the BReg inputs, including their TLS material, and the audit store. Add the other items above that you operate. The PostgreSQL CA key stays off the server with your other CA keys, and step 4 keeps the receipt off-host.
3. Dump each application database into the bundle. Include one `--database` per database. Record the role names and permissions to recreate before restore. The bundle manifest states what it leaves out: the persistent volumes behind the BReg audit and package claims, and any attachment or object storage. Copy their files into the `--files` directory to keep them with the bundle. In this example, run with a Kubeconfig that can administer the reference PostgreSQL Pod. The bundle is readable only by root, so run `snapshot` with the same privilege.

   ```bash
   sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml python3 deploy/state_bundle.py \
     capture --kube-context default --namespace directory \
     --release directory --database registry_breg \
     --status-file /srv/registry-directory/backup-status.json \
     --files /srv/registry-directory/backup-01-files \
     --output /srv/registry-directory/backup-01
   ```

   `capture` checks the status file against the BReg state in the database it dumps. It refuses a report from another activation or installation. If the BReg database is not `registry_breg`, name it with `--breg-database`. `capture` reads each dump back in full and refuses one it cannot read.

4. Archive the verified bundle to the Restic repository you initialised. Supply its credentials through protected files or the institution's secret manager. Keep the receipt off-host with the installation record. `snapshot` refuses an existing receipt path before it writes to the repository.

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

Read the target [Registry Stack release notes](https://github.com/registrystack/registry-stack/releases) and rehearse on an isolated restored copy before the maintenance window. Rebuild product packages against the exact active baseline and rebuild App Kit with the matching client. Build the BReg successor with `bregctl test --baseline-package <active package>` and `bregctl package --baseline-package <active package>`. Keep `project.version`, because BReg refuses a changed version for the life of the database. A change other than a compatible addition needs a reviewed migration. Follow the [BReg reviewed migration procedure](https://docs.registrystack.org/operate/breg-changes/). For Casework or Scheduling versions that require a fresh database, follow the product's cutover procedure and preserve the source database for reconciliation.

1. Retain the previous chart, exact image digests, package claim, config and Secrets. Stage the successor package in a new read-only claim, with versioned runtime inputs that name the successor digest. On the reference single server, copy the private input directory to `/srv/registry-directory/successor` and replace its package. Set the successor digest in `runtime.yaml` and `values.json`. Give the runtime ConfigMap and package claim new versioned names. Then run `prepare_local.py` with the copy. Run the block as root. `NEW_BUILD` holds the successor package, with its `package-digest` file, after you check it with `sha256sum -c`.

   ```bash
   IN=/srv/registry-directory/inputs
   NEW=/srv/registry-directory/successor
   NEW_BUILD=/srv/registry-directory/build-2
   umask 077
   install -d -m 0700 "$NEW"
   cp -a "$IN/." "$NEW/"
   OLD_DIGEST=$(cat "$IN/package-digest")
   NEW_DIGEST=$(cat "$NEW_BUILD/package-digest")
   rm -r "$NEW/package" "$NEW/package-digest"
   cp -a "$NEW_BUILD/package" "$NEW_BUILD/package-digest" "$NEW/"
   sed -i "s/$OLD_DIGEST/$NEW_DIGEST/" "$NEW/runtime.yaml" "$NEW/values.json"
   jq '.breg.runtimeConfig.configMapName = "directory-runtime-v2" | .breg.package.existingClaim = "directory-package-v2"' \
     "$NEW/values.json" > "$NEW/values.json.new"
   mv "$NEW/values.json.new" "$NEW/values.json"
   env KUBECONFIG=/etc/rancher/k3s/k3s.yaml python3 deploy/prepare_local.py \
     --kube-context default --namespace directory --release directory \
     --inputs "$NEW"
   ```

   Preparation leaves existing objects whose inputs are unchanged and refuses a changed object under an existing name. PostgreSQL keeps its previous `pg_hba.conf` rules until it restarts or reloads. Check whether the target release changes `deploy/postgres/postgres.yaml` with `git diff <active tag> <target tag> -- deploy/postgres/postgres.yaml`. If it prints a change, restart PostgreSQL after preparation with `kubectl --namespace directory rollout restart statefulset/registry-postgres`. Wait for `kubectl --namespace directory rollout status statefulset/registry-postgres`. Allow for a short database interruption.
2. Pause callers and take a new backup. Check its receipt against the encrypted repository. The operator checks that it identifies the active installation and activation and that its capture is inside the backup window. If the operator refuses with a backup-age message, take a newer backup. If your recovery policy allows an older one, pass `--max-backup-age-hours` with that limit to `upgrade`. The default is 26 hours. Pass `--operator-reference` with the change or ticket reference for the upgrade. BReg records a keyed hash of it with the activation, so its runtime audit profile must be keyed. BReg refuses the activation otherwise, after the operator has stopped serving, so check the profile before the window. The reference also appears in the operation Job's arguments until the Job expires, so use a ticket ID, not personal data. An upgrade that keeps the active package, such as a configuration or image change, activates nothing and needs no reference. Supply the target chart values to the operator.

   ```bash
   sudo env RESTIC_REPOSITORY=sftp:backup@backup.example.org:/srv/restic \
     RESTIC_PASSWORD_FILE=/root/restic-password \
     python3 deploy/state_bundle.py check-snapshot \
     --receipt /srv/registry-directory/backup-01-receipt.json --max-age-hours 26
   sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml python3 deploy/stack_operator.py \
     --helm-bin /usr/local/lib/registry-stack/helm --kube-context default --namespace directory \
     --release directory --database-id directory-db \
     --values /srv/registry-directory/successor/values.json \
     upgrade --backup-receipt /srv/registry-directory/backup-01-receipt.json \
     --operator-reference CHANGE-1235
   ```

3. Verify the intended ledger transition, HTTPS readiness, and a previously known authorised record or transaction. Exercise an allowed and a denied request. Resume callers when each participating component is ready.
4. Once you accept the upgrade, make the successor the input directory, so later backup, stop, install and upgrade commands read the active package and values. Keep the previous inputs under a versioned name with the other items step 1 retains. `mv -T` refuses to move a directory into an existing one.

   ```bash
   sudo mv -T /srv/registry-directory/inputs /srv/registry-directory/inputs-v1
   sudo mv -T /srv/registry-directory/successor /srv/registry-directory/inputs
   ```

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
2. Restore the chosen snapshot into a private directory with `restic restore <snapshot-id> --target /srv/registry-directory/restored`, with `RESTIC_REPOSITORY` and `RESTIC_PASSWORD_FILE` set. Restic keeps the bundle's original absolute path under the target. A bundle captured at `/srv/registry-directory/backup-01` therefore restores to `/srv/registry-directory/restored/srv/registry-directory/backup-01`. Verify it against the receipt you kept off-host. The bundle and receipt are readable only by root, so run `verify` with `sudo`. The check refuses a bundle whose manifest differs from the receipt.

   ```bash
   sudo python3 deploy/state_bundle.py verify \
     --bundle /srv/registry-directory/restored/srv/registry-directory/backup-01 \
     --receipt /srv/registry-directory/backup-01-receipt.json
   ```

   Prepare storage and the same versioned chart inputs on the target, in the original namespace. The database URLs, the PostgreSQL server certificate's DNS names and the namespace selectors contain it. On the reference single server, copy the recovered inputs into `/srv/registry-directory/restored`, next to the Restic tree. Step 5 reads `values.json` from there.

   ```bash
   sudo cp -a /srv/registry-directory/restored/srv/registry-directory/backup-01/payload/installation/inputs/. /srv/registry-directory/restored/
   ```

   In another namespace, make these edits in the copy. Reissue the PostgreSQL server certificate with the certificate commands in the [deployment guide](README.md#prepare-and-start-breg), the new namespace in its DNS name. Bring the PostgreSQL CA key from where you keep it, set `CA_KEY` to its path, and move it off the server again afterwards. Change the host in both database URLs. Change the `dependencyEgress` `namespaceSelector` in `values.json`. Run the block as root, with `NS` set to the new namespace, and use that namespace in every later command.

   ```bash
   IN=/srv/registry-directory/restored
   NS=directory-restore
   CA_KEY=/root/ca/pg-ca.key
   umask 077
   openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$IN/pg-server.key"
   openssl req -new -key "$IN/pg-server.key" -subj "/CN=registry-postgres" -out "$IN/pg-server.csr"
   printf 'subjectAltName=DNS:registry-postgres.%s.svc.cluster.local\n' "$NS" > "$IN/pg-server.ext"
   openssl x509 -req -in "$IN/pg-server.csr" -CA "$IN/breg-runtime/database-ca" -CAkey "$CA_KEY" \
     -CAserial "$IN/pg-ca.srl" -CAcreateserial -days 365 -sha256 -extfile "$IN/pg-server.ext" -out "$IN/pg-server.crt"
   sed -i "s/\.directory\.svc\./.$NS.svc./" "$IN/breg-runtime/runtime-database-url" "$IN/breg-migration/migration-database-url"
   jq --arg ns "$NS" \
     '.breg.networkPolicy.dependencyEgress[0].to.namespaceSelector.matchLabels["kubernetes.io/metadata.name"] = $ns' \
     "$IN/values.json" > "$IN/values.json.new"
   mv "$IN/values.json.new" "$IN/values.json"
   ```

   On the reference single server use `prepare_local.py --for-restore` to prepare an empty database and the roles. For an existing cluster, prepare a new empty database and recreate the exact roles there. Keep ingress traffic closed.
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
     adopt-restored --confirm-original-fenced \
     --backup-receipt /srv/registry-directory/backup-01-receipt.json
   ```

   Before it adopts anything, the operator reads the restored database's status. It refuses unless the status is ready and the database ID matches `--database-id` and the receipt. The activation must match the receipt. The package must match the receipt and the package in `values.json`. Two backups of the same activation look the same to this check, so pass the receipt you used in step 3.

6. Verify HTTPS, sign-in, an authorised record and a denied request, previous audit entries, and one post-restore write and readback. Open ingress and callers after acceptance. Record measured recovery time and the recovered point in time.

## Renew certificates

Use a new versioned application TLS Secret and update the Helm values through the guarded upgrade path. For the reference PostgreSQL workload, put the renewed leaf and key in the input directory, then rerun preparation with `--postgres-tls-secret registry-postgres-tls-v2` and the original namespace and release. The StatefulSet starts a Pod with the new certificate. Keep the chosen Secret name in the preparation command for that installation. Allow for a short database interruption on one server. When changing the CA, first deploy client trust for both roots and renew the leaf. Remove the previous root after every client verifies the new chain.

## Isolate customers

Use a separate namespace and Helm release per deployment. Give each one its own PostgreSQL roles and databases, audit claims, identity clients, signing keys, bucket credentials and backup permissions. Give operators access only to their scope. In the release namespace, the operator needs these permissions as well as those Helm needs to apply the chart. It reads Pods, creates and reads Jobs and their logs, creates and deletes Leases, and creates, patches and deletes NetworkPolicies. Apply Restricted Pod Security and verify enforced NetworkPolicies. Use separate clusters for customers who need independent administration or stronger workload isolation.

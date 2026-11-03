# SFTP source runtime example

This example supplies the operator-owned runtime binding for a pack endpoint
named `submissions`. Build the `adapter-job` host with `job-sftp`; the feature is
off by default.

Before using the example:

1. Create a dedicated read-only SFTP account.
2. Confine that account on the server to `/incoming/registry-adapter` with a
   chroot or equivalent authorization rule. The client path checks are not an
   atomic filesystem jail.
3. Replace `pinnedHostKey` with the server's complete OpenSSH Ed25519 or P-256
   public key.
4. Provide `SFTP_SOURCE_PASSWORD` through the process secret provider.
5. Make the producer follow the done-file lifecycle exactly: remove an old
   marker before changing a same-name file, write and close a temporary file,
   atomically rename it to the final `.csv` name, then create the `.done`
   marker. Never modify the final file while its marker exists.

The consumer lists, checks, opens, reads and closes. It never uploads, renames,
deletes, or removes a completion marker. A stale marker plus an in-place partial
overwrite is not detectable and is outside the supported producer protocol.

See [`job-runtime.example.yaml`](job-runtime.example.yaml) for the binding.

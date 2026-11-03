# Release templates

This directory holds deployment templates that ship inside each release
package. `scripts/setup-cass-fork.sh` copies it as `templates/` into the
package (release format `cass-fork-release/2`) and lists every file in
`SHA256SUMS`. The packaged `install.sh` verifies the files and publishes
them unchanged into the version directory.

Later tasks add the templates. Keep only regular files and directories here:
symbolic links, special files and names that contain a backslash or a newline
stop the release.

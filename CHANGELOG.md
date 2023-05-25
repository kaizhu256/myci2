# Changelog

# Todo
- none

# v2023.5.31
- jslint - Add grammar for "export async function ...".
- python - Migrate python-driver from pysqlite3 to cpython.
- jslint - Add grammar for regexp-named-capture-group and regexp-named-backreference.
- ci - Rename shell-function shRawLibFetch() to shRollupFetch().

# v2023.5.30
- ci - update .gitignore to exclude python build-files
- ci - add indent.exe dependencies
- ci - update cpplint.py to v1.6.1

# v2023.4.22
- ci - add shell-function shCiPreCustom2() to setup python in custom-ci
- ci - remove mandatory python ci
- ci - add python support
- sh - add cloudflared-tunnel support
- sh - add google-colab support

# v2023.3.21
- ci - update shell-function shRawLibFetch()

# v2023.2.26
- ci - update shell-function shGithubFileUpload() to be able to download file to specific destination
- ci - add shell-functions shBashrcWindowsInit(), shSecretPull()
- ci - remove little-used shell-function shCiBranchPromote()
- ci - replace shell-function shGithubPushBackupAndSquash() with simplified shGitCommitPushOrSquash()
- ci - revamp secret-handling so secrets can be manipulated while encrypted
- ci - add shell-functions shGithubBranchCopyAll(), shGithubBranchCopyAll()
- ci - remove/decouple cron-related code

# v2023.1.29
- ci - auto-create asset_image_logo_512.png from asset_image_logo_512.html
- replace branch shell with branch sh_lin, sh_mac, sh_win
- cron - add loopback to mycron2 stub
- jslint-ci - revamp auto-updating and add shell-function shGithubCheckoutRemote
- add branch-shell
- merge repo devenv into this one
- update jslint v2023.1.1

# v2022.5.21
- update jslint v2022.5.20

# v2022.4.29
- fix workflow_dispatch in ci.yml

# v2022.4.1
- fix ci failing in branch beta and master

# v2022.3.28
- initial release

# v2022.1.1
- none

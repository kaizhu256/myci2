# Changelog

# Todo
- none

# v2025.2.28
- jslint - Cleanup ci-shell-function shRollupFetch().
- jslint - Update ci-shell-function shDirHttplinkValidate() with pragma <\!!--novalidate--\>.
- ci - Upgrade nodejs used in ci to v22.

# v2024.12.25
- ci - Upgrade python used in ci to v3.12.
- ci - Auto-create asset_image_logo_256.png from asset_image_logo_256.html.
- ci - Fix shell-function shRollupFetch() from making excessive github-api-request.
- ci - Fix improperly-cropped jslint-logo, auto-generated by headless-chrome.
- ci - Fix failed-ci from missing graphicsmagick library in latest Ubuntu image.

# v2024.11.24
- jslint - Upgrade to jslint-v2024.11.24.

# v2024.10.23
- ci - Update shell-function shHttpFileServer() to auto-serve /index.html, when url-path is root /.

# v2024.9.30
- ci - Update function shMyciUpdate() to allow hard-link failure due to different drives.

# v2024.6.25
- jslint - Remove unnecessary shell-function shCurlExe().
- jslint - Upgrade to jslint-v2024.6.1-beta.

# v2024.4.24
- jslint - Remove unnecessary shell-function shCurlExe().
- ci - Add shell-function shRollupUpgrade().
- jslint - Update jslint to v2024.4.1-beta.

# v2024.3.25
- jslint-ci - Add shell-functions shGitPullrequestCleanup(), shGitPullrequest() to automatically cleanup or create-and-push github-pull-commit to origin/alpha.
- ci - Fix tmpdir in shell-function shBrowserScreenshot().
- vim - Allow installing vim-plugin to any directory, instead of hardcoded to ~/.vim/.

# v2024.2.20
- ci - Update github-ci for actions/cache, actions/setup-python from nodejs v16 to nodejs v20.
- ci - Update shell-function shRollupFetch() to fix blank date-committed.

# v2023.12.20
- jslint - bugfix - fix process.argv in shell-function shGithubFileDownloadUpload().

# v2023.11.22
- ci - bugfix - Fix google-chrome unable to create screenshot because user-data-dir is /dev/null.
- ci - Update mysh.

# v2023.10.24
- jslint - Update jslint to v2023.10.24.
- myci2 - Add file AppData.Local.Packages.Microsoft.WindowsTerminal_8wekyb3d8bbwe.LocalState.settings.json.

# v2023.8.20
- jslint - Update jslint to v2023.8.20.
- ci - Remove ci for nodejs-v19, and add ci for nodejs-v20.
- ci - Remove broken-links to unlicense.org, failing http-link-check.

# v2023.7.21
- jslint - Update jslint to v2023.6.21.

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

#!/bin/sh

shCiBuildVcpkg() {(set -e
# This function will build vcpkg binaries.
    if [ ! "$GITHUB_ACTION" ]
    then
        return
    fi
    (
    git clone https://github.com/microsoft/vcpkg.git \
        --branch=master \
        --single-branch \
        vcpkg
    cd vcpkg/
    ./bootstrap-vcpkg.sh
    #
    case "$(uname)" in
    Darwin*)
        vcpkg install zlib:arm64-osx || true
        ;;
    Linux*)
        vcpkg install zlib:x64-linux || true
        ;;
    MINGW*)
        vcpkg install zlib:x64-windows-static || true
        ;;
    esac
    )
    GITHUB_UPLOAD_RETRY=0
    while true
    do
        GITHUB_UPLOAD_RETRY="$((GITHUB_UPLOAD_RETRY + 1))"
        if [ "$GITHUB_UPLOAD_RETRY" -gt 4 ]
        then
            return 1
        fi
        if (node --input-type=module --eval '
import moduleChildProcess from "child_process";
(function () {
    moduleChildProcess.spawn(
        "sh",
        ["jslint_ci.sh", "shCiBuildVcpkgUpload"],
        {stdio: ["ignore", 1, 2]}
    ).on("exit", process.exit);
}());
') # '
        then
            break
        fi
        sleep 5
    done
)}

shCiBuildVcpkgUpload() {(set -e
# This function will build vcpkg binaries.
    rm -rf artifact/
    git clone https://github.com/kaizhu256/myci2 \
        --branch=artifact \
        --single-branch \
        artifact
    cd artifact
    mkdir -p vcpkg/
    cp -r ../vcpkg/installed vcpkg/
    git add .
    git pull origin artifact
    git status
    shGitCommitPushOrSquash "" 100
)}

shCiPreCustom() {(set -e
# this function will run pre-ci-custom
    # github-action-only
    if ! { [ "$GITHUB_ACTION" ] && [ "$MY_GITHUB_TOKEN" ]; }; then return 1; fi
    if (printf "%s" "$GITHUB_REF_NAME" | grep -q ".*/.*/.*")
    then
        shGithubCheckoutRemote "$GITHUB_REF_NAME"
        GITHUB_REF_NAME="$(printf "%s" "$GITHUB_REF_NAME" | cut -d'/' -f3)"
        sh jslint_ci.sh shCiPre
        return
    fi
    case "$GITHUB_REF_NAME" in
    mysh)
        shSshCloudflareServer
        ;;
    vcpkg)
        shCiBuildVcpkg
        ;;
    esac
    if (! shCiMatrixIsmainName)
    then
        return
    fi
    case "$GITHUB_REF_NAME" in
    alpha)
        # sync branch
        shGitCmdWithGithubToken push origin alpha:mysh -f
        shGitCmdWithGithubToken push origin alpha:vcpkg -f
        # test
        # (
        #     git push -f origin alpha:kaizhu256/betadog/alpha
        #     shGithubWorkflowDispatch kaizhu256/myci2 kaizhu256/betadog/alpha
        # ) &
        # shGithubWorkflowDispatch kaizhu256/myci2 mysh &
        ;;
    esac
)}

shCiPre() {(set -e
# this function will run pre-ci
    if (printf "$GITHUB_REF_NAME" | grep -qv ".*/.*/.*")
    then
        export GITHUB_REF_NAME="$GITHUB_REPOSITORY/$GITHUB_REF_NAME"
    fi
    export GITHUB_REPOSITORY="$(printf "$GITHUB_REF_NAME" | cut -d'/' -f1,2)"
    export GITHUB_REF_NAME="$(printf "$GITHUB_REF_NAME" | cut -d'/' -f3)"
    (set -e
    cd ..
    shGitCmdWithGithubToken clone \
        "https://github.com/$GITHUB_REPOSITORY" \
        "$GITHUB_WORKSPACE.tmp" \
        --branch="$GITHUB_REF_NAME" \
        --depth=1 \
        --single-branch
    rm -rf "$GITHUB_WORKSPACE/"* "$GITHUB_WORKSPACE/".* || true
    cp -rf "$GITHUB_WORKSPACE.tmp/"* "$GITHUB_WORKSPACE/"
    cp -rf "$GITHUB_WORKSPACE.tmp/".* "$GITHUB_WORKSPACE/" || true
    cd "$GITHUB_WORKSPACE"
    )
    cp .gitconfig .git/config
    git reset "origin/$GITHUB_REF_NAME" --hard
    shGitCmdWithGithubToken fetch origin alpha
    git checkout origin/alpha .ci.sh jslint_ci.sh
)}

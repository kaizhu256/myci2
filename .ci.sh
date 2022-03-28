shCiPre() {(set -e
# this function will run pre-ci
    local FILE
    if (printf "$GITHUB_REF_NAME" | grep -q ".*/.*/.*")
    then
        # branch - */*/*
        git fetch origin alpha
        # assert latest ci
        if [ "$(git rev-parse "$GITHUB_REF_NAME")" \
            != "$(git rev-parse origin/alpha)" ]
        then
            git push -f origin "origin/alpha:$GITHUB_REF_NAME"
            shGithubWorkflowDispatch "$GITHUB_REPOSITORY" "$GITHUB_REF_NAME"
            return 1
        fi
    else
        # branch - alpha, beta, master
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
    # fetch jslint_ci.sh from trusted source
    for FILE in .ci.sh jslint_ci.sh
    do
        shGithubFileDownload "$GITHUB_REPOSITORY/alpha/$FILE"
    done
)}

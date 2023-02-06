shCiPreCustom() {(set -e
# this function will run pre-ci-custom
    # github-action-only
    if ! ([ "$GITHUB_ACTION" ] && [ "$MY_GITHUB_TOKEN" ]) then return 1; fi
    if (printf "$GITHUB_REF_NAME" | grep -q ".*/.*/.*")
    then
        shGithubCheckoutRemote "$GITHUB_REF_NAME"
        return
    fi
    case "$GITHUB_REF_NAME" in
    mysh)
        shSshReverseTunnelServer
        ;;
    esac
    if (! shCiMatrixIsmainName)
    then
        return
    fi
    case "$GITHUB_REF_NAME" in
    alpha)
        #
        # sync branch
        shGitCmdWithGithubToken push origin alpha:mysh -f &
        #
        # test
        # (
        #     git push -f origin alpha:kaizhu256/betadog/alpha
        #     shGithubWorkflowDispatch kaizhu256/myci2 kaizhu256/betadog/alpha
        # ) &
        # shGithubWorkflowDispatch kaizhu256/myci2 mysh &
        ;;
    esac
)}

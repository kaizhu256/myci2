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
        case "$(uname)" in
        MINGW*)
            powershell \
                "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
            printf 'PubkeyAuthentication yes'> /c/programdata/ssh/sshd_config
            powershell "Start-Service sshd" &>/dev/null
            cat /c/programdata/ssh/sshd_config
            shSshReverseTunnelServer
            # powershell "taskkill /F /IM ssh.exe /T"
            ;;
        *)
            shSshReverseTunnelServer
            # killall ssh
            return
            ;;
        esac
        return
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
        node --input-type=module --eval '
import moduleChildProcess from "child_process";
import moduleAssert from "assert";
(async function () {
    await Promise.all([
        "shGitCmdWithGithubToken push origin alpha:mysh -f",
        ":"
    ].map(async function (script) {
        await new Promise(function (resolve) {
            moduleChildProcess.spawn(
                "sh",
                ["jslint_ci.sh", script.split(" ")].flat(),
                {stdio: ["ignore", 1, 2]}
            ).on("exit", function (exitCode) {
                moduleAssert.ok(exitCode === 0, exitCode);
                resolve();
            });
        });
    }));
}());
' "$@" # '
        #
        # test
        # git push -f origin alpha:kaizhu256/betadog/alpha
        # shGithubWorkflowDispatch kaizhu256/myci2 kaizhu256/betadog/alpha &
        # shGithubWorkflowDispatch kaizhu256/myci2 mysh &
        ;;
    esac
)}

shSshReverseTunnelServer() {(set -e
# this function will create ssh-reverse-tunnel on server
    # github-action-only
    if ! ([ "$GITHUB_ACTION" ] && [ "$MY_GITHUB_TOKEN" ]) then return 1; fi
    # init secret
    shSecretVarExport
    (
    cd "$HOME/.mysecret2"
    printf "$MY_GITHUB_TOKEN\n" > .my_github_token
    chmod 600 .my_github_token
    )
    # init dir .ssh/
    for FILE in authorized_keys id_ed25519 known_hosts
    do
        shSecretFileGet ".ssh/$FILE" "$HOME/.ssh/$FILE"
    done
    chmod 700 "$HOME/.ssh"
    # init ssh-reverse-tunnel
    local FILE
    local II
    local PROXY_HOST="$(printf $SSH_REVERSE_PROXY_HOST | sed "s/:.*//")"
    local PROXY_PORT="$(printf $SSH_REVERSE_PROXY_HOST | sed "s/.*://")"
    local REMOTE_PORT="$(printf $SSH_REVERSE_REMOTE_HOST | sed "s/:.*//")"
    if [ "$REMOTE_PORT" = random ]
    then
        REMOTE_PORT="$(bash -c 'echo $((32768 + $RANDOM))')"
        SSH_REVERSE_REMOTE_HOST=\
"$REMOTE_PORT:$(printf "$SSH_REVERSE_REMOTE_HOST" | sed "s/random://")"
    fi
    # copy ssh-files to proxy
    scp \
        -P "$PROXY_PORT" \
        "$HOME/.ssh/id_ed25519" "$PROXY_HOST:~/.ssh/" &>/dev/null
    ssh \
        -p "$PROXY_PORT" \
        "$PROXY_HOST" "chmod 600 ~/.ssh/id_ed25519" &>/dev/null
    # create ssh-reverse-tunnel from remote to proxy
    ssh \
        -N \
        -R"$SSH_REVERSE_REMOTE_HOST" \
        -T \
        -f \
        -p "$PROXY_PORT" \
        "$PROXY_HOST" &>/dev/null
    # add remote-fingerprint to proxy-known-hosts
    ssh -p "$PROXY_PORT" "$PROXY_HOST" \
        ssh -oStrictHostKeyChecking=no -p "$REMOTE_PORT" \
        "$(whoami)@localhost" : &>/dev/null
    # loop-print to keep ci awake
    II=-10
    while [ "$II" -lt 120 ] \
        && ([ "$II" -lt 0 ] \
            || (ps x | grep "$SSH_REVERSE_REMOTE_HOST\|/usr/bin/ssh$" \
                | grep -qv grep)) \
    do
        II=$((II + 1))
        printf "    $II -- $(date) -- $(whoami)@localhost:$REMOTE_PORT\n"
        if [ "$II" -lt 0 ]
        then
            sleep 5
        else
            sleep 60
        fi
    done
)}

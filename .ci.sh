shCiPreCustom() {(set -e
# this function will run pre-ci-custom
    [ "$GITHUB_ACTION" ] && [ "$MY_GITHUB_TOKEN" ] # github-action-only
    if (printf "$GITHUB_REF_NAME" | grep -q ".*/.*/.*")
    then
        shGithubCheckoutRemote "$GITHUB_REF_NAME"
        return
    fi
    case "$GITHUB_REF_NAME" in
    sh_lin)
        [ "$(uname)" = Linux ] || return 0
        shSshReverseTunnelServer
        # killall ssh
        return
        ;;
    sh_mac)
        [ "$(uname)" = Darwin ] || return 0
        shSshReverseTunnelServer
        # killall ssh
        return
        ;;
    sh_win)
        (printf "$(uname)" | grep -q MINGW64_NT) || return 0
        powershell \
            "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
        printf 'PubkeyAuthentication yes'> /c/programdata/ssh/sshd_config
        powershell "Start-Service sshd" &>/dev/null
        cat /c/programdata/ssh/sshd_config
        shSshReverseTunnelServer
        # powershell "taskkill /F /IM ssh.exe /T"
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
        shGitCmdWithGithubToken push origin alpha:cron -f &
        shGitCmdWithGithubToken push origin alpha:sh_lin -f &
        shGitCmdWithGithubToken push origin alpha:sh_mac -f &
        shGitCmdWithGithubToken push origin alpha:sh_win -f &
        #
        # test
        # git push -f origin alpha:kaizhu256/betadog/alpha
        # shGithubWorkflowDispatch kaizhu256/myci2 kaizhu256/betadog/alpha
        # shGithubWorkflowDispatch kaizhu256/myci2 sh_lin &
        # shGithubWorkflowDispatch kaizhu256/myci2 sh_mac &
        # shGithubWorkflowDispatch kaizhu256/myci2 sh_win &
        # shGithubWorkflowDispatch kaizhu256/mycron2 alpha
        #
        # update repo kaizhu256/mycron2
        (
        rm -rf __tmp1
        git clone https://github.com/kaizhu256/mycron2 __tmp1 \
            --branch=alpha --depth=1 --single-branch
        cd __tmp1
        echo '# this workflow will run cron-job
# https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#schedule
name: cron
on:
  schedule:
    # * is a special character in YAML so you have to quote this string
    # https://pubs.opengroup.org/onlinepubs/9699919799/utilities/crontab.htm
    # minute [0,59]
    # hour [0,23]
    # day of the month [1,31]
    # month of the year [1,12]
    # day of the week ([0,6] with 0=sunday)
    - cron:  '0 * * * *'
  workflow_dispatch:
jobs:
  job1:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl "https://api.github.com/repos/kaizhu256/myci2/actions/workflows/ci.yml/dispatches" \
            -H "accept: application/vnd.github.v3+json" \
            -H "authorization: token ${{ secrets.MY_GITHUB_TOKEN }}" \
            -X POST \
            -d '"'"'{"ref":"cron"}'"'"' \
            -s \
            &>/dev/null
' > .github/workflows/ci.yml
        if (git commit -am update)
        then
            shGithubPushBackupAndSquash origin alpha 100
        fi
        )
        ;;
    cron)
        shMycron2
        ;;
    esac
)}

shMycron2() {(set -e
# this function will run cron-task from mycron2
    [ "$GITHUB_ACTION" ] && [ "$MY_GITHUB_TOKEN" ] # github-action-only
    echo hello cron!
)}

shSshReverseTunnelServer() {(set -e
# this function will create ssh-reverse-tunnel on server
    [ "$GITHUB_ACTION" ] && [ "$MY_GITHUB_TOKEN" ] # github-action-only
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
    while [ "$II" -lt 60 ] \
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

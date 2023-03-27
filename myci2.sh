#!/bin/sh

# sh one-liner
# curl -o ~/myci2.sh -s https://raw.githubusercontent.com/kaizhu256/myci2/alpha/myci2.sh && . ~/myci2.sh && shMyciInit
# . ~/myci2.sh && shMyciUpdate
# shSecretGitPush

shGithubBranchCopyAll() {(set -e
# this function will copy-all branch from $GITHUB_REPO1 to $GITHUB_REPO2
    shGithubTokenExport
    GITHUB_REPO1="$1"
    GITHUB_REPO2="$2"
    MODE="$3"
    rm -rf __tmp1
    shGitCmdWithGithubToken clone "https://github.com/$GITHUB_REPO1" __tmp1
    (
    cd __tmp1
    for BRANCH in $(git branch -r | tail -n +2)
    do
        BRANCH="$(printf "$BRANCH" | sed -e "s|^origin/||")"
        git branch "$BRANCH" "origin/$BRANCH" || true
        if [ "$MODE" = force ]
        then
            shGitCmdWithGithubToken push \
                "https://github.com/$GITHUB_REPO2" "$BRANCH" -f &
        else
            shGitCmdWithGithubToken push \
                "https://github.com/$GITHUB_REPO2" "$BRANCH" &
        fi
        PID_LIST="$PID_LIST $!"
    done
    shPidListWait shGithubBranchCopyAll "$PID_LIST"
    )
)}

shGithubBranchDeleteAll() {(set -e
# this function will delete-all branch from $GITHUB_REPO
    shGithubTokenExport
    GITHUB_REPO="$1"
    for BRANCH in $(git ls-remote -q \
        "https://x-access-token:$MY_GITHUB_TOKEN@github.com/$GITHUB_REPO" \
        2>/dev/null \
        | grep -o "\<refs/heads/.*"
    )
    do
        BRANCH="$(printf "$BRANCH" | sed -e "s|^refs/heads/||")"
        shGitCmdWithGithubToken push \
            "https://github.com/$GITHUB_REPO" ":$BRANCH" &
        PID_LIST="$PID_LIST $!"
    done
    shPidListWait shGithubBranchDeleteAll "$PID_LIST"
)}

shMyciInit() {
# this function will init myci2 in current environment
    (
    set -e
    if [ "$1" = force ]
    then
        MODE_FORCE=1
        shift
    fi
    cd ~
    # init jslint_ci.sh
    for FILE in .screenrc .vimrc jslint_ci.sh
    do
        if [ ! -f "$FILE" ] || [ "$MODE_FORCE" ]
        then
            curl -s -o "$FILE" \
"https://raw.githubusercontent.com/kaizhu256/myci2/alpha/$FILE"
        fi
    done
    . ~/jslint_ci.sh :
    # init myci2
    if (git --version &>/dev/null)
    then
        if [ ! -d myci2 ] || [ "$MODE_FORCE" ]
        then
            rm -rf myci2
            git clone https://github.com/kaizhu256/myci2 \
                --branch=alpha --single-branch
            (cd myci2 && cp .gitconfig .git/config && shMyciUpdate)
        fi
    fi
    # init .bashrc
    if [ ! -f .bashrc ]
    then
        touch .bashrc
    fi
    for FILE in jslint_ci.sh
    do
        if [ -f "$FILE" ] && ! (grep -q "^. ~/$FILE :$" .bashrc)
        then
            printf "\n. ~/$FILE :\n" >> .bashrc
        fi
    done
    # google-colab-only
    if [ "$COLAB_RELEASE_TAG" ] || [ "$KAGGLE_CONTAINER_NAME" ]
    then
        GITHUB_ACTION=1
        if (! sudo /etc/init.d/ssh start &>/dev/null)
        then
            # https://github.com/nodesource/distributions
            curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
            sudo apt-get install -qq -y nodejs openssh-server sqlite3
            sudo /etc/init.d/ssh start
        fi
    fi
    # github-action-only
    if ! ([ "$GITHUB_ACTION" ] && [ "$MY_GITHUB_TOKEN" ]) then return; fi
    # init .git/config
    git config --global user.email "github-actions@users.noreply.github.com"
    git config --global user.name "github-actions"
    # init .mysecret2
    if [ ! -d .mysecret2 ]
    then
        shGitCmdWithGithubToken clone \
            https://github.com/kaizhu256/mysecret2 .mysecret2 \
            --branch=alpha --depth=1 --single-branch
        chmod 700 .mysecret2
    fi
    )
    . ~/jslint_ci.sh :
}

shMyciUpdate() {
# this function will update myci2 in current dir
    (
    set -e
    [ -d .git ] && [ -f jslint_ci.sh ] # git-repo-only
    # sync origin
    git fetch origin alpha beta master
    git pull origin alpha
    git branch beta origin/beta 2>/dev/null || git push . origin/beta:beta
    # ln file
    mkdir -p "$HOME/.vim"
    for FILE in \
        .vimrc \
        jslint.mjs \
        jslint_ci.sh \
        jslint_wrapper_vim.vim \
        myci2.sh
    do
        FILE_MYCI="$HOME/myci2/$FILE"
        FILE_HOME="$HOME/$FILE"
        case "$FILE" in
        jslint_wrapper_vim.vim)
            FILE_HOME="$HOME/.vim/$FILE"
            ;;
        esac
        if [ -f "$FILE_HOME" ]
        then
            ln -f "$FILE_HOME" "$FILE_MYCI"
        else
            ln -f "$FILE_MYCI" "$FILE_HOME"
        fi
        if [ -f "$FILE" ]
        then
            ln -f "$FILE_HOME" "$FILE"
        fi
    done
    ln -f "$HOME/jslint.mjs" "$HOME/.vim/jslint.mjs"
    # detect nodejs
    if ! (node --version &>/dev/null \
        || node.exe --version &>/dev/null)
    then
        git --no-pager diff
        return
    fi
    # sync .gitignore
    for FILE in \
        .gitconfig \
        .github/workflows/ci.yml \
        .github/workflows/publish.yml \
        .gitignore
    do
        if [ ! -f "$FILE" ]
        then
            cp "$HOME/myci2/$FILE" "$FILE"
        else
            node --input-type=module --eval '
import moduleAssert from "assert";
import moduleFs from "fs";
(async function () {
    let data1;
    let data2;
    let dataReplace;
    let file1 = process.argv[1];
    let file2 = process.argv[2];
    let rgx = new RegExp(
        `\\n# base - ${file2} - beg\\n[\\S\\s]*?\\n# base - ${file2} - end\\n`
    );
    data1 = `\n${await moduleFs.promises.readFile(file1, "utf8")}\n`;
    data2 = `\n${await moduleFs.promises.readFile(file2, "utf8")}\n`;
    dataReplace = rgx.exec(data1)[0];
    moduleAssert.ok(dataReplace);
    data2 = data2.replace(rgx, dataReplace.replace((
        /\$/g
    ), "$$"));
    await moduleFs.promises.writeFile(file2, data2.trim() + "\n");
}());
' "$HOME/myci2/$FILE" "$FILE" # '
        fi
    done
    git --no-pager diff
    )
    . ~/jslint_ci.sh :
}

shMyciUpdateReverse() {
# this function will reverse-update myci2 from current dir
    (
    set -e
    if [ ! -d .git ]
    then
        return
    fi
    git checkout HEAD .
    # ln file
    mkdir -p "$HOME/.vim"
    for FILE in \
        .vimrc \
        jslint.mjs \
        jslint_ci.sh \
        jslint_wrapper_vim.vim \
        myci2.sh
    do
        FILE_HOME="$HOME/$FILE"
        FILE_MYCI="$HOME/myci2/$FILE"
        case "$FILE" in
        jslint_wrapper_vim.vim)
            FILE_HOME="$HOME/.vim/$FILE"
            ;;
        esac
        if [ -f "$FILE" ]
        then
            ln -f "$FILE" "$FILE_HOME" || true
        fi
    done
    )
    . ~/jslint_ci.sh :
}

shSecretDecryptEncrypt() {(set -e
# this function will jwe-decrypt/jwe-encrypt mysecret2 using $MY_GITHUB_TOKEN
    shGithubTokenExport
    node --input-type=module --eval '
import moduleAssert from "assert";
import moduleFs from "fs";
import modulePath from "path";
import {
    webcrypto
} from "crypto";

function base64urlFromBuffer(buf) {
    return Buffer.from(buf).toString("base64").replace((
        /\+/g
    ), "-").replace((
        /\//g
    ), "_").replace((
        /\=/g
    ), "");
}

async function cryptoJweDecryptEncrypt({
    jweCompact,
    jwkKek,
    textPlain
}) {
    let cek;
    let header;
    let iv;
    let kek;
    let tag;
    let textCipher;


// Key-import to internal key-encryption-key kek,
// from external 256-bit jwk-formatted-key-encryption-key jwkKek.
// jwkKek = {"k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","kty":"oct"}

    kek = await webcrypto.subtle.importKey(
        "jwk",
        JSON.parse(jwkKek),
        {
            length: 256,
            name: "AES-KW"
        },
        true,
        ["unwrapKey", "wrapKey"]
    );

// Decrypt to textPlain, from encrypted-jweCompact.

    if (jweCompact) {
        [
            header,
            cek,
            iv,
            textCipher,
            tag
        ] = jweCompact.replace((
            /\s/g
        ), "").replace((
            /-/g
        ), "+").replace((
            /_/g
        ), "/").split(".").map(function (elem, ii) {
            if (ii === 0) {
                return elem;
            }
            return Buffer.from(elem, "base64");
        });
        moduleAssert.ok(

// {"alg":"A256KW","enc":"A256GCM"}

            "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0" === header,
            `cryptoJweDecrypt - invalid header - ${header}`
        );

// Key-unwrap to internal 256-bit content-encryption-key cek,
// from encrypted-jweCompact.

        cek = await webcrypto.subtle.unwrapKey(
            "raw",
            cek,
            kek,
            "AES-KW",
            "AES-GCM",
            true,
            [
                "decrypt", "encrypt"
            ]
        );

// Decrypt textPlain, from textCipher.

        textPlain = await webcrypto.subtle.decrypt(
            {
                additionalData: header,
                iv,
                name: "AES-GCM",
                tagLength: 128
            },
            cek,
            Buffer.concat([
                textCipher, tag
            ])
        );
        textPlain = new TextDecoder().decode(textPlain);
        return textPlain;
    }

// Encrypt to encrypted-jweCompact format, from textPlain.
// BASE64URL(UTF8(JWE Protected Header)) || . ||
// BASE64URL(JWE Encrypted Key) || . ||
// BASE64URL(JWE Initialization Vector) || . ||
// BASE64URL(JWE textCipher) || . ||
// BASE64URL(JWE Authentication Tag)

    if (!jweCompact) {
        jweCompact = [];

// BASE64URL(UTF8(JWE Protected Header)) || . ||

        header = base64urlFromBuffer(JSON.stringify({
            alg: "A256KW",
            enc: "A256GCM"
        }));
        jweCompact.push(header);

// BASE64URL(JWE Encrypted Key) || . ||

        cek = await webcrypto.subtle.generateKey(
            {
                length: 128,
                name: "AES-GCM"
            },
            true,
            ["decrypt", "encrypt"]
        );
        jweCompact.push(base64urlFromBuffer(
            await webcrypto.subtle.wrapKey("raw", cek, kek, "AES-KW")
        ));

// BASE64URL(JWE Initialization Vector) || . ||

        iv = webcrypto.getRandomValues(new Uint8Array(12));
        jweCompact.push(base64urlFromBuffer(iv));

// BASE64URL(JWE textCipher) || . ||

        textCipher = await webcrypto.subtle.encrypt(
            {
                additionalData: header,
                iv,
                name: "AES-GCM",
                tagLength: 128
            },
            cek,
            textPlain
        );
        textCipher = Buffer.from(textCipher);
        tag = textCipher.slice(-16);
        textCipher = textCipher.slice(0, -16);
        jweCompact.push(base64urlFromBuffer(textCipher).replace((
            /.{72}/g
        ), "$&\n"));

// BASE64URL(JWE Authentication Tag)

        jweCompact.push(base64urlFromBuffer(tag));
        jweCompact = jweCompact.join("\n.\n");
        return jweCompact;
    }
}

async function fsWriteFileWithParents(pathname, data) {

// This function will write <data> to <pathname> and lazy-mkdirp if necessary.

    // await moduleFsInit();

// Try writing to pathname.

    try {
        await moduleFs.promises.writeFile(pathname, data);
    } catch (ignore) {

// Lazy mkdirp.

        await moduleFs.promises.mkdir(modulePath.dirname(pathname), {
            recursive: true
        });

// Retry writing to pathname.

        await moduleFs.promises.writeFile(pathname, data);
    }
    // console.error("wrote file " + pathname);
}

function objectDeepCopyWithKeysSorted(obj) {

// This function will recursively deep-copy <obj> with keys sorted.

    let sorted;
    if (typeof obj !== "object" || !obj) {
        return obj;
    }

// Recursively deep-copy list with child-keys sorted.

    if (Array.isArray(obj)) {
        return obj.map(objectDeepCopyWithKeysSorted);
    }

// Recursively deep-copy obj with keys sorted.

    sorted = {};
    Object.keys(obj).sort().forEach(function (key) {
        sorted[key] = objectDeepCopyWithKeysSorted(obj[key]);
    });
    return sorted;
}

(async function () {
    let {
        HOME,
        MY_GITHUB_TOKEN
    } = process.env;
    let {
        argv
    } = process;
    let fileDecrypted = `${HOME}/.mysecret2/.mysecret2.json`;
    let fileEncrypted = `${HOME}/.mysecret2/.mysecret2.json.encrypted`;
    let fileGetDestination = argv[3];
    let itemKey = argv[2];
    let itemVal = argv[3];
    let jweCompact;
    let jwkKek;
    let modeDecryptEncrypt = argv[1];
    let mysecretJson;

    async function mysecretDecrypt() {
        mysecretJson = JSON.parse(
            await cryptoJweDecryptEncrypt({
                jweCompact,
                jwkKek
            })
        );
    }

    async function mysecretDecryptAndSave(mode) {
        await mysecretDecrypt();
        if (
            mode === "force"
            || moduleFs.existsSync(fileDecrypted) //jslint-ignore-line
        ) {
            await fsWriteFileWithParents(
                fileDecrypted,
                JSON.stringify((
                    objectDeepCopyWithKeysSorted(mysecretJson)
                ), undefined, 4) + "\n"
            );
        }
    }

    async function mysecretEncrypt() {
        if (!mysecretJson) {
            mysecretJson = JSON.parse(
                await moduleFs.promises.readFile(fileDecrypted, "utf8")
            );
        }
        jweCompact = await cryptoJweDecryptEncrypt({
            jwkKek,
            textPlain: JSON.stringify(mysecretJson)
        });
        await fsWriteFileWithParents(fileEncrypted, jweCompact + "\n");
        mysecretDecryptAndSave();
    }

// Get 256-bit jwk-formatted-key-encryption-key jwkKek,
// from sha256-hash of MY_GITHUB_TOKEN.

    moduleAssert.ok(
        MY_GITHUB_TOKEN.length >= 16,
        "cryptoJweDecryptEncrypt - MY_GITHUB_TOKEN length too short"
    );
    jwkKek = JSON.stringify({
        k: base64urlFromBuffer(
            await webcrypto.subtle.digest("SHA-256", MY_GITHUB_TOKEN)
        ),
        kty: "oct"
    });

    jweCompact = await moduleFs.promises.readFile(fileEncrypted, "utf8");
    switch (modeDecryptEncrypt) {
    case "shSecretDecryptFile":
        await mysecretDecryptAndSave("force");
        break;
    case "shSecretEncryptFile":
        await mysecretEncrypt();
        break;
    case "shSecretFileGet":
        await mysecretDecrypt();
        await fsWriteFileWithParents(
            fileGetDestination,
            mysecretJson[itemKey] || ""
        );
        await moduleFs.promises.chmod(fileGetDestination, "600");
        break;
    case "shSecretFileSet":
        await mysecretDecrypt();
        mysecretJson[itemKey] = (
            await moduleFs.promises.readFile(itemVal, "utf8")
        );
        await mysecretEncrypt();
        break;
    case "shSecretJsonGet":
        await mysecretDecrypt();
        itemVal = {};
        JSON.parse(itemKey).forEach(function (key) {
            itemVal[key] = mysecretJson[key] ?? undefined;
        });
        process.stdout.write(JSON.stringify(itemVal));
        break;
    case "shSecretJsonSet":
        await mysecretDecrypt();
        itemVal = "";
        process.stdin.setEncoding("utf8");
        process.stdin.on("data", function (chunk) {
            itemVal += chunk;
        });
        await new Promise(function (resolve) {
            process.stdin.on("end", resolve);
        });
        Object.assign(mysecretJson, JSON.parse(itemVal));
        await mysecretEncrypt();
        break;
    case "shSecretTextGet":
        await mysecretDecrypt();
        process.stdout.write(mysecretJson[itemKey] || "");
        break;
    case "shSecretTextSet":
        await mysecretDecrypt();
        mysecretJson[itemKey] = String(itemVal) || undefined;
        await mysecretEncrypt();
        break;
    default:
        moduleAssert.ok(
            undefined,
            `shSecretDecryptEncrypt - invalid mode - ${modeDecryptEncrypt}`
        );
    }
}());
' "$@" # '
)}

shSecretDecryptFile() {(set -e
# this function will decrypt myscret2 using jwe and $MY_GITHUB_TOKEN
    shSecretDecryptEncrypt shSecretDecryptFile
)}

shSecretEncryptFile() {(set -e
# this function will encrypt mysecret2 using jwe and $MY_GITHUB_TOKEN
    shSecretDecryptEncrypt shSecretEncryptFile
)}

shSecretFileGet() {(set -e
# this function will decrypt myscret2, and write from item-key $1 to file $2
    shSecretDecryptEncrypt shSecretFileGet "$1" "$2"
)}

shSecretFileSet() {(set -e
# this function will decrypt mysecret2, and write to item-key $1 from file $2
    shSecretDecryptEncrypt shSecretFileSet "$1" "$2"
)}

shSecretGitPush() {(set -e
# this function will git-commit and git-push .mysecret2
    cd ~/.mysecret2/
    if [ -f .mysecret2.json ]
    then
        shJsonNormalize .mysecret2.json
        shSecretEncryptFile
    fi
    shGitCommitPushOrSquash "" 100
)}

shSecretGitPull() {(set -e
# this function will pull mysecret2 from github
    cd ~/.mysecret2/
    git pull origin alpha
    shSecretDecryptFile
)}

shSecretJsonGet() {(set -e
# this function will decrypt mysecret2, and print items in $1 to stdout
    shSecretDecryptEncrypt shSecretJsonGet "$1"
)}

shSecretJsonSet() {(set -e
# this function will decrypt mysecret2, and Object.assign(mysecret2, stdin)
    shSecretDecryptEncrypt shSecretJsonSet
)}

shSecretTextGet() {(set -e
# this function will decrypt mysecret2, and print item-key $1 to stdout
    shSecretDecryptEncrypt shSecretTextGet "$1"
)}

shSecretTextSet() {(set -e
# this function will decrypt mysecret2, and set to item-key $1 from item-val $2
    shSecretDecryptEncrypt shSecretTextSet "$1" "$2"
)}

shSshCloudflareClient() {(set -e
# this function will client-login to ssh-server through cloudflare-tunnel
    shSshCloudflareInstall
    shSecretGitPull &>/dev/null || shSecretGitPull
    shSecretFileGet .ssh/known_hosts.proxy ~/.ssh/known_hosts.proxy
    ssh \
        -o ProxyCommand="cloudflared access ssh --hostname %h" \
        -o UserKnownHostsFile=~/.ssh/known_hosts.proxy \
        -t \
        "${SSH_CLOUDFLARE_HOST:-$(shSecretTextGet SSH_CLOUDFLARE_HOST)}" "$@"
)}

shSshCloudflareInstall() {(set -e
# this function will install cloudflared binary
    if (cloudflared --version)
    then
        return
    fi
    case "$(uname)" in
    Darwin*)
        curl -L -s \
https://github.com/cloudflare/cloudflared/\
releases/latest/download/cloudflared-darwin-amd64.tgz | tar -xz
        chmod 755 cloudflared
        mv cloudflared /usr/local/bin
        ;;
    Linux*)
        curl -L -s -o cloudflared \
https://github.com/cloudflare/cloudflared/\
releases/latest/download/cloudflared-linux-amd64
        chmod 755 cloudflared
        mv cloudflared /usr/local/bin
        ;;
    *)
        curl -L -s -o c:/windows/system32/cloudflared.exe \
https://github.com/cloudflare/cloudflared/\
releases/latest/download/cloudflared-windows-amd64.exe
        ;;
    esac
    cloudflared --version 1>&2
)}

shSshCloudflareServer() {(set -e
# this function will create cloudflare-tunnel on ssh-server
    # google-colab-only
    # !(export MY_GITHUB_TOKEN=xxxxxxxx && curl -o ~/myci2.sh -s https://raw.githubusercontent.com/kaizhu256/myci2/alpha/myci2.sh && . ~/myci2.sh && shMyciInit && shSshCloudflareServer)
    if [ "$COLAB_RELEASE_TAG" ] || [ "$KAGGLE_CONTAINER_NAME" ]
    then
        GITHUB_ACTION=1
    fi
    # github-action-only
    if ([ "$GITHUB_ACTION" ] && [ "$MY_GITHUB_TOKEN" ])
    then
        # init mysecret2
        if [ ! -d ~/.mysecret2 ]
        then
            shMyCiInit
        fi
        # init openssh
        case "$(uname)" in
        MINGW*)
            powershell \
                "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
            printf "PubkeyAuthentication yes\n"> /c/programdata/ssh/sshd_config
            powershell "Start-Service sshd" &>/dev/null
            ;;
        esac
        # init secret
        (
        cd "$HOME/.mysecret2"
        printf "$MY_GITHUB_TOKEN\n" > .my_github_token
        chmod 600 .my_github_token
        )
        # init dir .ssh/
        mkdir -p ~/.ssh/
        chmod 700 ~/.ssh/
        (
        cd ~/.ssh/
        shSecretFileGet .ssh/authorized_keys authorized_keys
        shSecretFileGet .ssh/id_ed25519 id_ed25519
        shSecretFileGet .ssh/known_hosts.proxy known_hosts.proxy
        )
    fi
    # create cloudflare-tunnel
    shSshCloudflareInstall
    node --input-type=module --eval '
import moduleChildProcess from "child_process";
(async function () {
    let hostname = "";
    let result = "";
    let whoami = process.argv[1];
    await new Promise(function (resolve) {
        moduleChildProcess.spawn(
            "cloudflared",
            ["tunnel", "--url", "ssh://localhost:22"],
            {encoding: "utf8", stdio: ["ignore", "ignore", "overlapped"]}
        ).on("exit", function (exitCode) {
            console.error(`cloudflared exitCode=${exitCode}`);
        }).stderr.on("data", function (chunk) {
            if (hostname) {
                return;
            }
            result += chunk;
            hostname = (
                /https:\/\/(.*?\.trycloudflare\.com)/
            ).exec(result);
            if (!hostname) {
                return;
            }
            hostname = `${whoami}@${hostname[1]}`;
            resolve();
        });
    });
    await new Promise(function (resolve) {
        moduleChildProcess.spawn(
            "sh",
            ["-c", (`
(set -e
    cd ~/myci2
    . ./jslint_ci.sh
    . ./myci2.sh
    cd ~/.ssh
    SSH_CLOUDFLARE_HOST="${hostname}"
    # bugfix - ssh might concat signature without adding newline
    touch known_hosts.proxy
    perl -pi -e "chomp if eof" known_hosts.proxy
    printf "\n" >> known_hosts.proxy
    # add ssh-proxy-fingerprint to ssh-proxy-known-hosts
    while (true)
    do
        sleep 5
        if (ssh \
            -o ProxyCommand="cloudflared access ssh --hostname %h" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=known_hosts.proxy \
            "$SSH_CLOUDFLARE_HOST" :) &>/dev/null
        then
            break
        fi
    done
    printf -- "$(tail -n 4 known_hosts.proxy)" > known_hosts.proxy
    shSecretFileSet .ssh/known_hosts.proxy known_hosts.proxy
    shSecretTextSet SSH_CLOUDFLARE_HOST "$SSH_CLOUDFLARE_HOST"
    shSecretGitPush || true
    II=-10
    while [ "$II" -lt 240 ]
    do
        II=$((II + 1))
        printf "    $II -- $(date) -- \\"$SSH_CLOUDFLARE_HOST\\"\n" \
            | sed -e "s|\.trycloudflare\.com||"
        if [ "$II" -lt 0 ]
        then
            sleep 10
        else
            sleep 60
        fi
    done
)
            `)],
            {stdio: ["ignore", 1, 2]}
        ).on("exit", resolve);
    });
}());
' "$(whoami)" || true # '
    # killall -9 node
    # taskkill //f //im node.exe
    # taskkill /f /im node.exe
)}

shSshKeygen() {(set -e
# this function will generate generic ssh key
    cd ~/.ssh/
    rm -f id_ed25519
    rm -f id_ed25519.pub
    ssh-keygen \
        -C "your_email@example.com" \
        -N "" \
        -f ~/.ssh/id_ed25519 \
        -t ed25519
    cp id_ed25519.pub authorized_keys
    cp id_ed25519 "id_ed25519.$(date +"%Y%m%d_%H%M%S")"
    cp id_ed25519.pub "id_ed25519.pub.$(date +"%Y%m%d_%H%M%S")"
    # save ssh-proxy-key
    shSecretFileSet .ssh/authorized_keys id_ed25519.pub
    shSecretFileSet .ssh/id_ed25519 id_ed25519
    # git push
    shSecretGitPush
)}

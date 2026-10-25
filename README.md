# goftp

A small resumable file server built on [Fiber v3](https://gofiber.io), with
[Viper](https://github.com/spf13/viper) configuration,
[Zap](https://github.com/uber-go/zap) logging, and users stored in
Postgres whose access is decided by [Casbin](https://casbin.org) policies.

- Users sign in with a password; roles decide what they may do, and each
  user has a private folder of their own (see [Personal folders](#personal-folders)).
- Range (single and multipart), `If-Range`, `If-None-Match` and
  `If-Modified-Since` are supported, so downloads can be resumed.
- Uploads never expose partial files (see [Uploads](#uploads)), and resume
  after a lost connection.
- Images, video, audio and PDFs can be viewed in the browser, and listings
  show thumbnails of images (see [Previews](#previews)).
- Deleted files and folders wait in a trash for 30 days (see
  [Deleting, moving and copying](#deleting-moving-and-copying)); entries
  can be moved, copied, and picked to act on several at once.
- Names can be searched across folders (see [Search](#search)), and links
  can share files and folders, or take uploads like a drop box (see
  [Share links](#share-links)).
- Sync apps and file managers reach the same files over WebDAV, signed in
  with app passwords (see [Syncing with WebDAV](#syncing-with-webdav)).
- Dotfiles are never listed or served. Paths are resolved with `os.Root`, so
  requests and symlinks cannot escape the served directory.

## Quick start with Docker Compose

```sh
cp .env.example .env && chmod 600 .env   # set POSTGRES_PASSWORD, e.g. $(openssl rand -hex 24)
docker compose up -d --build
docker compose exec goftp goftp user add alice --role superadmin
```

Instead of building it, you can use the image CI publishes for every commit
on `main`, for amd64 and arm64: `ghcr.io/ssenerg/goftp`, tagged `latest`
and `sha-COMMIT` (the first 7 characters of the commit). Pull it, name it
as Compose expects, then start without `--build`:

```sh
docker pull ghcr.io/ssenerg/goftp && docker tag ghcr.io/ssenerg/goftp goftp
docker compose up -d
```

`user add` prints a temporary password. Open http://localhost:8080, sign in
and choose a new password; more users can then be added in the browser
(see [Users and roles](#users-and-roles)). The database lives in the
`pgdata` volume, the files in the `files` volume, unless `.env` names a
directory to serve:

```sh
GOFTP_DATA=/mnt/storage/shared   # e.g. a disk, mounted before goftp starts
GOFTP_RUN_AS=1000:1000           # its owner (see `id`), so uploads can write
```

The port is only published on 127.0.0.1: put a TLS-terminating reverse
proxy in front and set `GOFTP_PROXY_HEADER=X-Forwarded-For` and
`GOFTP_TRUSTED_PROXIES` in `.env` (see [`.env.example`](.env.example)), or
let goftp serve HTTPS itself with `GOFTP_TLS_DIR`, `GOFTP_TLS_CERT` and
`GOFTP_TLS_KEY`, then set `GOFTP_BIND=0.0.0.0`.

## Users and roles

Superadmins manage users and access rules in the browser, under **Users and
rules** in their account menu (`/.admin/`). Adding a user or resetting a
password shows a temporary password once, for you to pass on. The page
leaves the signed-in superadmin's own account alone, so nobody locks
themselves out there; another superadmin or the command line can change it.

The command line does the same, and makes the first superadmin; it needs
access to the database:

```sh
goftp user add bob --role operator   # prints a temporary password
goftp user list
goftp user passwd bob                # new temporary password, ends bob's sessions
goftp user role bob admin
goftp user quota bob 10GiB           # how much his home may hold; none, or default
goftp user delete bob                # their home goes to the trash
```

New and reset passwords are temporary: after signing in, users can do
nothing but choose their own password (at least 12 characters), which ends
all their other sessions.

| Role         | May                                                                                     |
|--------------|-----------------------------------------------------------------------------------------|
| `user`       | list directories and download (`read`)                                                  |
| `operator`   | also upload new files and create folders (`write`)                                      |
| `admin`      | also replace, delete and rename files, and share links (`overwrite`, `delete`, `share`) |
| `superadmin` | every action (`*`)                                                                      |

These are Casbin rules on URL paths, kept in the `casbin_rule` table and
editable while the server runs, on the **Rules** tab or with `goftp policy`
(servers reload them within a moment):

```sh
goftp policy list
goftp policy add anonymous '/public/*' read   # public downloads, no sign-in
goftp policy add user:bob '/bob/*' write      # bob may upload into /bob/
goftp policy remove anonymous '/public/*' read
```

`"/docs/*"` covers `/docs/` and everything below it; `"/docs/"` alone is
just that listing. Listings only show what the visitor may open. Signed-in
users may always do what anonymous visitors may. A symlink never grants
more than the rules of where it leads: visitors need the rights for both
the path they use and the path the link points to.

A path starting with `!` denies, as in a `.gitignore`: it keeps its subject
out of a path that broader rules open (on the **Rules** tab, choose "may
not"). The rule for the longest path decides, whatever order the rules were
added in; for the same path, a user's own rules come before their roles'
rules, a role's before those it inherits, and a denial before the rest:

```sh
# Users may not open /hr/, but admins (and so superadmins) may, and users
# may read the handbook in it:
goftp policy add user '!/hr/*' '*'
goftp policy add admin '/hr/*' '*'
goftp policy add user '/hr/handbook/*' read

# bob may open /bob/ only, which he finds in the top folder:
goftp policy add user:bob '!/*' '*'
goftp policy add user:bob '/bob/*' '*'
goftp policy add user:bob '/' read
```

A denial for a role applies to the roles above it too. Rules for longer
paths still apply under a denial, also those of a user's roles: with both
examples, bob may read the handbook. A denial cannot take away what the
rules for `anonymous` allow, since anyone may sign out.

## Personal folders

Every user has a home, `/home/NAME/`, under **My files** in the top bar:
a private folder where they may do anything (upload, create folders,
delete, share links, also upload links) whatever their role, but delete
the home itself. Nobody else may open it, nor `/home/` itself: not even
admins and superadmins, and it is not listed under **Files**. A home is
made the first time its user shows up. What its user deletes there goes
to the trash, where only they see it.

These rules are built in; rules for those paths come first, so a
superadmin can still open homes up, e.g. `goftp policy add admin '/home/*' read`
to let admins read them, or `goftp policy add user:bob '!/home/bob/*' write`
to keep bob from adding files to his. `homes.path` (`GOFTP_HOMES_PATH`)
moves them to another folder, or with `off` turns them off. Turned off,
homes that are still there are ordinary folders, open to whoever the rules
let in (by default, every user may read `/home/`): goftp warns of that at
startup. The folder of homes may not be a symlink, and should be on the
same disk as the rest.

A home may hold up to a quota: `homes.quota` (`GOFTP_HOMES_QUOTA`, e.g.
`10GiB`; `0`, the default, for no limit), or what a superadmin set for
its user, under **Users** or with `goftp user quota NAME 10GiB` (`none` for
no limit, `default` for `homes.quota`). What its user deleted from it
counts too while it is in the trash, so deleting makes room once the trash
is emptied. Uploads, copies and moves that would go past it, also through
upload links into the home, get `507 Insufficient Storage`. **My files**
shows how much the home holds, with a bar when it has a quota.

Deleting a user moves their home to the trash, and removes the rules for
paths in it. Superadmins see it there, but not what is in it: they may
delete it for good, or restore it once a user of that name exists again,
for whom it then is (an empty home of theirs gives way), along with what
they had deleted from it. Until then, what they deleted is nobody's: a new
user of the same name does not see it. With the trash off, their home is
deleted for good. A hidden `.goftp-owner` file in each home notes whose it
is, so a home that a deleted user left behind goes to the trash before a
new user of the same name gets in.

## Running without Docker

```sh
export GOFTP_DATABASE_URL="postgres://goftp:secret@localhost:5432/goftp"
goftp user add alice --role superadmin
goftp --dir /srv/files --addr :8080       # same as: goftp serve ...
```

The schema is created or upgraded on startup (`goftp migrate` does just
that). Every setting can also come from a config file (`--config`, see
[`config.example.yaml`](config.example.yaml)) or a `GOFTP_*` environment
variable (`log.level` → `GOFTP_LOG_LEVEL`). Priority: flags > environment >
config file > defaults. The standard `PG*` variables (e.g. `PGPASSWORD`)
work as well.

## Clients

Browsers get a sign-in form. Other clients exchange credentials for a
session token and send it as a bearer token:

```sh
curl -s -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"..."}' https://host/.auth/login
# {"token":"...","expires_at":"...","must_change_password":false}
curl -C - -O -H "Authorization: Bearer $TOKEN" https://host/dir/file.iso
```

A temporary password is changed with `POST /.auth/password`
(`{"current_password":"...","new_password":"..."}`), which returns a new
token. `POST /.auth/logout` ends the session. Sessions last
`auth.session_ttl` (12h).

## Uploads

- Browser: users who may upload into a folder can drop files anywhere on its
  page, or choose them, and watch each upload's progress. Existing files
  are only replaced when "Replace files that already exist" is ticked.
  Folders can be dropped too, or picked with "Choose a folder": their
  folders are created first (or added to, if they exist), and dotfiles in
  them are left out.
  Uploads are resumable: after a lost connection they go on by themselves
  from what arrived, and after a reload or a closed tab once the same file
  is chosen again.
- curl: `curl -T file.iso -H "Authorization: Bearer $TOKEN" https://host/dir/`.
  PUT replaces existing files unless `-H "If-None-Match: *"` is given, and
  needs a Content-Length.

The target directory must exist, and `upload.max_size` caps each file.
Uploads stop short of the disk's last `upload.min_free` bytes
(`GOFTP_UPLOAD_MIN_FREE`; 1 GiB by default, `0` turns the check off), which stay for the database and
everything else on that disk: the upload gets `507 Insufficient Storage`.
Users who may upload new files into a folder (`write`) can also create
folders in it, with the "New folder" button or
`curl -d folder=photos -H "Authorization: Bearer $TOKEN" https://host/dir/`.

Partial uploads are never listed or served. While `<name>` is uploaded, the
lock file `.<name>.lock` keeps other uploads of it out, and the data goes to
a hidden `.goftp-*.part` file that is renamed into place only once complete;
until then the previous version, if any, stays available. Other tools can
hide files they write in place the same way: create `.<name>.lock` before
writing `<name>` and delete it afterwards (such locks are always honored;
a locked folder is hidden with everything in it).
A running upload refreshes its lock every 15 seconds; a lock left behind by
a goftp that stopped (crash, restart) is taken over by the next upload of
that name once it is a minute old, and removed with its temp file when
goftp starts again.

### Resumable uploads

goftp speaks [tus 1.0](https://tus.io/protocols/resumable-upload) (with
the creation, termination and expiration extensions), so tus clients such
as [tus-js-client](https://github.com/tus/tus-js-client) or
[tuspy](https://github.com/tus/tus-py-client) can upload to a folder
(`https://host/dir/` as the endpoint, the file's name as `filename` in its
metadata, and `replace` set to `1` to replace an existing file). With curl:

```sh
auth="Authorization: Bearer $TOKEN"
# Start: the answer's Location is where the data goes.
curl -i -X POST -H "$auth" -H "Tus-Resumable: 1.0.0" -H "Upload-Length: $(wc -c < big.iso)" \
  -H "Upload-Metadata: filename $(printf big.iso | base64 | tr -d '\n')" https://host/dir/
# Send the data; after an interruption, ask what arrived and go on from there.
off=$(curl -sI -H "$auth" -H "Tus-Resumable: 1.0.0" https://host/.uploads/ID | tr -d '\r' | awk -F': ' 'tolower($1) == "upload-offset" { print $2 }')
curl -X PATCH -H "$auth" -H "Tus-Resumable: 1.0.0" -H "Upload-Offset: $off" \
  -H "Content-Type: application/offset+octet-stream" -C "$off" -T big.iso https://host/.uploads/ID
```

What arrives is kept even when the connection drops, in a hidden
`.goftp-*.upload` file next to the file it becomes, which is checked like
any other upload when it starts and stored like one once complete. Only
whoever started an upload can continue it. An upload nothing arrives for
is removed after `upload.resume_window` (24 hours by default); `DELETE`
on its URL cancels it at once.

## Downloading folders

"Download zip" on a folder's page downloads everything in it that you may
read, as one zip (`curl -OJ -H "Authorization: Bearer $TOKEN"
"https://host/dir/?zip"`). Tick entries to zip only those (`?zip&pick=a.txt&pick=photos`).
The zip is streamed as it is made, and files are stored without
compression: most large files do not compress anyway.

## Previews

Clicking an image, a video, an audio file or a PDF opens it in a viewer,
with Download next to it and the previous and next ones of its folder a
click or an arrow key away (Escape goes back to the folder). Listings show
thumbnails of JPEG, PNG, GIF, WebP and BMP images, and a link to a single
file shows it on the link's page. The same works with a query: `?view` (the
viewer), `?inline` (the file, to be shown in a browser) and `?thumb` (a
thumbnail of at most 256×256 pixels).

Files are shown only if their content, whatever their name, is an image,
audio, video or PDF: never SVG, HTML or anything else that can hold a
script. PDFs, which can hold scripts and forms, are shown sandboxed like
downloads (see [Security notes](#security-notes)), and only goftp's own
pages may frame what is shown. Everything else is always downloaded.

Thumbnails are made of images up to 100 MB that take at most 256 MB of
memory to decode, at most two at a time; other images keep their icon.
They are kept in `cache.dir` (default: `goftp` in the user's cache
directory, such as `~/.cache/goftp`; in Docker, the `cache` volume), which
is trimmed back to three quarters of `cache.max_size` (512 MiB; `0` keeps
none) by removing the least recently used. It may not be a folder that
goftp serves.

## Deleting, moving and copying

The ⋯ menu of an entry offers what the visitor may do with it: Rename,
Move or copy (to a folder, typed as a path such as `/photos/2024`, with
folders suggested as you type), Share and Delete. Ticking entries brings
up a bar to download, move, copy or delete them together.

Deleting moves the entry to the **Trash**, in the top bar, where it waits
for `trash.keep` (30 days) and can be restored, or deleted for good; the
folder's page also offers to undo it. The trash is the hidden folder
`.goftp-trash` at the top of the served folder, so deleting and restoring
take no time and no space. Restoring needs the folder it was in, and no
entry of its name there. Entries on another disk than the trash can only
be deleted for good, and when `trash.keep` is `0`, everything is.

Deleting a folder deletes everything in it, and moving or renaming one
moves everything in it. Both are refused while something in it is being
uploaded, when the visitor may not delete (and, to move it, read) all of
it, and when another disk is mounted inside: what is in a folder gets new
paths, where other rules may apply. Copies hold what the visitor may read,
as a zip would, and are refused before they start if the visitor may not
create all of it where it goes. Nothing replaces an existing entry.
Scripts:

```sh
auth="Authorization: Bearer $TOKEN"
curl -X DELETE -H "$auth" https://host/dir/old.iso          # to the trash; ?permanent skips it
curl -d rename=draft.txt -d to=final.txt -H "$auth" https://host/dir/
curl -d move=a.txt -d move=b.txt -d into=/archive -H "$auth" https://host/dir/
curl -d copy=photos -d into=/backup -H "$auth" https://host/dir/
curl -d delete=a.txt -d delete=b.txt -d permanent=1 -H "$auth" https://host/dir/
curl -d action=restore -d id=ID -H "$auth" https://host/.trash/   # ID from the Goftp-Trash-Ids header
```

Deleting needs the `delete` action; renaming and moving need `read` and
`delete` on the entry and `write` where it goes; copying needs `read` on
it and `write` where it goes. The trash shows entries to those who may
read them where they were; restoring needs `write` there, and deleting
for good `delete`. Admins have `delete`; on upgrade, it is added only if
the admin rule is still the default one. To let others delete, e.g.
`goftp policy add operator '/*' delete`.

## Search

The search box of a folder filters it as you type; Enter searches the
folders in it too, by name, for what you may read. Every word has to be
part of a name, in any case. The search looks through the nearest folders
first, and stops at 200 matches or after 5 seconds. Scripts get JSON:

```sh
curl -H "Authorization: Bearer $TOKEN" -H "Accept: application/json" "https://host/.search/?q=tax+2024&in=/docs"
# {"results":[{"path":"/docs/Tax 2024.pdf","name":"Tax 2024.pdf","dir":false,...}],"more":false}
```

`folders=1` finds folders only, and without `q` lists the folders in `in`.

## Share links

A link lets people without an account open a file or a folder, until it
expires after an hour, a day, 7 days or 30 days. Create one from Share in
a folder, or from the ⋯ menu of a file or folder; a link can also need a
password (at least 8 characters). The link is shown once: only a hash of
it is stored. Visitors of a folder's link can browse it, download its
files and download it as a zip.

A link to a folder can instead let people upload into it, like a drop
box: its page takes files, resumably, and shows nothing of what is in the
folder. A name that is taken gets a number (`report (2).pdf`), so senders
learn nothing of what is there. It works while its creator may add files
there and share the folder. A link can also stop after a number of
downloads (anything that sends a file's first byte, or a zip; showing it
in the browser, its page or its thumbnail does not count, nor resuming a
download further on), or for upload links of files sent (one that fails
or is cancelled gives its use back). Upload links can also take a limited
size in all (`max_size`, e.g. `2GiB`); a resumable upload counts its whole
length when it starts, so one that does not fit is refused before it is
sent. **Shared** shows how much was sent through each.

A link never gives more than its creator may still read and share: it
stops working when they lose those rights, or when what it leads to is
moved or deleted. **Shared**, next to **Files** in the top bar, lists your
links, and for superadmins everyone's, with how often each was used and
when it was last opened, to revoke them. Deleting a user, or giving them a
new temporary password, ends their links too. Scripts:

```sh
curl -H "Authorization: Bearer $TOKEN" -d action=create -d path=/docs/report.pdf -d expires=7d https://host/.shares/
# {"id":1,"url":"https://host/.share/...","expires_at":"...","upload":false,"max_uses":0}
curl -H "Authorization: Bearer $TOKEN" -d action=create -d path=/inbox -d expires=30d -d kind=upload -d max_uses=20 -d max_size=2GiB https://host/.shares/
curl -H "Authorization: Bearer $TOKEN" -d action=revoke -d id=1 https://host/.shares/
```

Creating links needs the `share` action on what is shared, and for
upload links `write` too. Admins have it; on upgrade, it is added only if
the admin rule is still the default one. To let others share, e.g. `goftp policy add user:bob '/bob/*' share`.

## Syncing with WebDAV

goftp serves its files over WebDAV at `/.dav/`, so that sync apps can keep
a folder on a computer or phone in sync with it, and file managers can
open it: `https://host/.dav/PATH` is `PATH`, with the same rules, homes,
quotas and trash as the site. **Sync**, in the account menu, shows the
address (your home, if you have one) and makes app passwords.

Apps sign in with your username and an **app password**, never your own
password: make one for each app or device, so that you can revoke one
without the others. It is shown once (only a hash is stored), may be typed
without its dashes, and stops working when revoked, when you change your
password, or when you are given a new temporary one. Each user may have
20. Scripts:

```sh
curl -H "Authorization: Bearer $TOKEN" -d action=create -d name=laptop https://host/.sync/
# {"id":1,"name":"laptop","username":"bob","password":"abcd-efgh-...","url":"https://host/.dav/"}
curl -H "Authorization: Bearer $TOKEN" -d action=revoke -d id=1 https://host/.sync/
```

With [rclone](https://rclone.org), which keeps modification times with
`vendor=owncloud`, a folder syncs both ways like this; the first run needs
`--resync`, and the second line can then run from cron:

```sh
rclone config create goftp webdav url=https://host/.dav/home/bob/ vendor=owncloud user=bob pass=APP-PASSWORD --obscure
rclone bisync ~/goftp goftp: --exclude ".*" --exclude ".*/**" --resync
rclone bisync ~/goftp goftp: --exclude ".*" --exclude ".*/**"
```

FolderSync (Android), GoodSync, Mountain Duck and Cyberduck take the same
address, username and app password as a WebDAV account; Finder opens it
with Go → Connect to Server. goftp keeps the modification times that
apps send with uploads (`X-OC-Mtime`) or set afterwards (`PROPPATCH` of
`getlastmodified`, or Windows' `Win32LastModifiedTime`), and reports how
much room a home has left (RFC 4331). Limits:

- Names that start with a dot are not synced, as goftp hides them: exclude
  them in the app. macOS's `.DS_Store` and `._` files are taken and
  dropped.
- Other properties than modification times are refused. Locks are
  advisory: they keep other WebDAV clients that ask from taking the same
  lock, and nothing else.
- WebDAV sends each file in one request, where the browser sends large
  ones in pieces: behind a proxy that limits the size of requests
  (Cloudflare: 100 MB on its Free and Pro plans), larger files cannot be
  uploaded over WebDAV.

Wrong app passwords count against the client's sign-in budget
(`limiter.*`).

## Security notes

- Serve over HTTPS: passwords and session tokens travel with every sign-in
  and request. Over HTTPS (served by goftp, or by a trusted proxy that
  sends `X-Forwarded-Proto`) the session cookie is `Secure` and `__Host-`
  prefixed, and HSTS is sent.
- Passwords are hashed with Argon2id; only SHA-256 hashes of session tokens
  are stored.
- Failed sign-ins (and wrong current passwords) are rate limited per client
  (`limiter.*`), and each user can sign in at most 30 times a minute.
  Behind a reverse proxy, set `server.proxy_header` (`X-Forwarded-For`)
  and `server.trusted_proxies`, otherwise every client shares the proxy's
  budget and the server cannot tell that requests arrived over HTTPS;
  goftp logs a warning when it sees proxy headers it does not trust.
- Cross-site form posts and uploads are refused (`Sec-Fetch-Site`/`Origin`
  checks, `SameSite=Lax` cookies).
- Files are sent as attachments, with a `Content-Security-Policy` that runs
  no scripts and gives them an origin of their own, should a browser show
  one anyway. Previews are sent with the type the file's content proves,
  never one guessed from its name (`X-Content-Type-Options: nosniff`), and
  PDFs keep that policy. Other sites may not embed files
  (`Cross-Origin-Resource-Policy`).
- Concurrent connections are capped to fit the open file limit. When
  clients connect directly rather than through a proxy, also cap what one
  client may hold with `server.max_conns_per_ip` (`GOFTP_MAX_CONNS_PER_IP`).
- Symlinks are followed only when they use relative targets that stay inside
  the served directory, do not lead into a dotfile or dot-directory, and
  lead where the visitor may go anyway.
- App passwords carry 120 bits, and only their SHA-256 hashes are stored.
  They sign in to WebDAV alone, with HTTP Basic authentication, which
  sends them with every request: serve WebDAV over HTTPS only.
- Share links carry 256-bit tokens, which are kept out of the logs. Link
  passwords are hashed with Argon2id; wrong ones count against the
  client's sign-in budget, and each link takes at most 20 password checks
  a minute. The cookie that remembers a password lasts at most
  `auth.session_ttl`.
- Homes are private by built-in rules, which also hold against admins and
  superadmins until a rule opens them up. A superadmin can still change
  the rules, and whoever runs the server can read its files.
- Upload links let whoever has them fill a folder, with files of up to
  `upload.max_size` each, until the disk is down to `upload.min_free`:
  give them a short life, a password, a limit of files or of size. Into a
  home, they stop at its quota.
- Rules compare paths as spelled. On a file system that finds names in
  other spellings too (ignoring case or Unicode normalization), goftp
  compares them as that file system does where the kernel tells how names
  are stored, as on macOS, and otherwise refuses to serve the folder (FAT,
  NTFS on Windows, case-insensitive ZFS or ext4 folders): serve a folder
  on a case-sensitive file system there.
- Copies stop at 100,000 entries or 64 folders deep, as symlinks can make
  a folder hold far more than the disk does.

## Troubleshooting

"Wrong username or password" at sign-in: `docker compose logs goftp | grep
"login failed"` shows whether the name matched no user or the password was
wrong (names that match no user are not logged: they are sometimes
passwords typed into the wrong field). `goftp user list` shows the users, and
`goftp user passwd NAME` gives one a new temporary password (temporary
passwords ignore case and surrounding spaces).

## Deploying

Every push to `main` that passes CI is deployed to a Linux server with
Docker Compose: the `docker` job publishes the image to `ghcr.io` (see
[Quick start](#quick-start-with-docker-compose)), and the `deploy` job sends
its digest over SSH. The key GitHub signs in with runs nothing but
[`deploy/deploy.sh`](deploy/deploy.sh) there, which pulls exactly that
image and restarts goftp with it. If goftp does not keep running, the
script puts the image that ran before back and the job fails; goftp's last
logs go to the server's journal (`journalctl -t goftp-deploy`), not to the
public CI log. The server needs to reach `ghcr.io`, and the
`postgres:18-alpine` image once.

A leaked key can therefore only deploy images published to that
repository, in the setup the server has: the script, `docker-compose.yml`
and `.env` belong to root, and the key cannot change them. When
`deploy/deploy.sh` or `docker-compose.yml` change here, install them on the
server again, as below.

Once, on the server, as root, in a clone of this repository: a user to
deploy as (in the `docker` group, which is as good as root on that
server) and the directory goftp runs from, which it may read but not
change, with your `.env` (see [`.env.example`](.env.example)):

```sh
useradd --create-home --groups docker deploy
install -d -o root -g deploy -m 750 /opt/goftp
install -o root -g deploy -m 640 docker-compose.yml .env /opt/goftp/
install -o root -g deploy -m 750 deploy/deploy.sh /opt/goftp/
```

On your computer, a key for GitHub to sign in with, and the server's key
for GitHub to check it by. Check the key `ssh-keyscan` prints against
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server:

```sh
ssh-keygen -t ed25519 -N '' -C goftp-deploy -f goftp-deploy
ssh-keyscan -t ed25519 SERVER > known_hosts   # with -p PORT for another port
```

Add `goftp-deploy.pub` to `~deploy/.ssh/authorized_keys` on the server,
with the image it may deploy in front of it. `restrict` takes away shells,
terminals and forwarding; `command` runs whatever GitHub asks for, with
what it asked for as the digest:

```
restrict,command="/opt/goftp/deploy.sh ghcr.io/OWNER/goftp" ssh-ed25519 AAAA... goftp-deploy
```

On GitHub, under Settings → Environments, create the environment
`production`, let only `main` deploy to it (Deployment branches → Selected
branches), and give it these secrets:

```sh
gh secret set DEPLOY_HOST --env production --body SERVER
gh secret set DEPLOY_SSH_KEY --env production < goftp-deploy
gh secret set DEPLOY_KNOWN_HOSTS --env production < known_hosts
rm goftp-deploy   # GitHub has it now
```

Its variables, all optional: `DEPLOY_USER` (`deploy`), `DEPLOY_PORT`
(`22`) and `DEPLOY_URL`, the address shown with each deploy. Until the
secrets are set, the job skips deploying with a warning. If the package on
`ghcr.io` is private, sign the server in to it once with a token that may
read packages: `sudo -u deploy docker login ghcr.io`.

Compose names volumes after the directory: from `/opt/goftp` they are
`goftp_pgdata` and so on, as for a clone in a directory named `goftp`. If
goftp ran from a directory with another name before, set
`COMPOSE_PROJECT_NAME` to that name in `.env`, or the database starts out
empty. Manage goftp from the new directory from then on, as root or
`deploy`, who may read `.env`: e.g. `cd /opt/goftp && sudo -u deploy docker
compose exec goftp goftp user list`.

To deploy again, run the CI workflow on `main` (Actions → CI → Run
workflow). To go back to an earlier version, re-run the CI run of its
commit (which also points `latest` back to it), deploy its digest by hand
(`docker buildx imagetools inspect ghcr.io/OWNER/goftp:sha-COMMIT` shows it),
or go back one deploy:

```sh
sudo -u deploy /opt/goftp/deploy.sh ghcr.io/OWNER/goftp sha256:DIGEST
cd /opt/goftp && sudo -u deploy sh -c 'docker image tag goftp:previous goftp:latest && docker compose up -d --force-recreate goftp'
```

Older versions skip database migrations they do not know, so going back
works as long as migrations only add to the schema.

## Development

```sh
go test -race ./...
# Postgres-backed tests run when a database is given:
GOFTP_TEST_DATABASE_URL="postgres://postgres:secret@localhost/goftp_test" go test ./...
```

[CI](.github/workflows/ci.yml) runs these with Postgres on every pull request,
along with gofmt, `go vet`, builds for Windows, macOS and FreeBSD,
[govulncheck](https://go.dev/doc/security/vuln/) (also weekly) and a build
of the Docker image for amd64 and arm64. For `main`, it publishes the image
to `ghcr.io` and deploys it (see [Deploying](#deploying)).

# goftp

A small resumable file server built on [Fiber v3](https://gofiber.io), with
[Viper](https://github.com/spf13/viper) configuration,
[Zap](https://github.com/uber-go/zap) logging, and users stored in
Postgres whose access is decided by [Casbin](https://casbin.org) policies.

- Users sign in with a password; roles decide what they may do.
- Range (single and multipart), `If-Range`, `If-None-Match` and
  `If-Modified-Since` are supported, so downloads can be resumed.
- Uploads never expose partial files (see [Uploads](#uploads)), and resume
  after a lost connection.
- Images, video, audio and PDFs can be viewed in the browser, and listings
  show thumbnails of images (see [Previews](#previews)).
- Dotfiles are never listed or served. Paths are resolved with `os.Root`, so
  requests and symlinks cannot escape the served directory.

## Quick start with Docker Compose

```sh
cp .env.example .env && chmod 600 .env   # set POSTGRES_PASSWORD, e.g. $(openssl rand -hex 24)
docker compose up -d --build
docker compose exec goftp goftp user add alice --role superadmin
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
goftp user delete bob
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
  Uploads are resumable: after a lost connection they go on by themselves
  from what arrived, and after a reload or a closed tab once the same file
  is chosen again.
- curl: `curl -T file.iso -H "Authorization: Bearer $TOKEN" https://host/dir/`.
  PUT replaces existing files unless `-H "If-None-Match: *"` is given, and
  needs a Content-Length.

The target directory must exist, and `upload.max_size` caps each file.
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
"https://host/dir/?zip"`). The zip is streamed as it is made, and files are
stored without compression: most large files do not compress anyway.

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

## Deleting and renaming

Everyone who may delete an entry finds Rename and Delete in its ⋯ menu.
Deleting a folder deletes everything in it. That is refused while
something in it is being uploaded, when the visitor may not delete all of
it, and when another disk is mounted inside. Renaming never replaces an
existing entry. Scripts:

```sh
curl -X DELETE -H "Authorization: Bearer $TOKEN" https://host/dir/old.iso
curl -d rename=draft.txt -d to=final.txt -H "Authorization: Bearer $TOKEN" https://host/dir/
```

Deleting needs the `delete` action; renaming needs `read` and `delete` on
the entry and `write` for the new name. Admins have `delete`; on upgrade,
it is added only if the admin rule is still the default one. To let others
delete, e.g. `goftp policy add operator '/*' delete`.

## Share links

A link lets people without an account open a file or a folder, until it
expires after an hour, a day, 7 days or 30 days. Create one from Share in
a folder, or from the ⋯ menu of a file or folder; a link can also need a
password (at least 8 characters). The link is shown once: only a hash of
it is stored. Visitors of a folder's link can browse it, download its
files and download it as a zip.

A link never gives more than its creator may still read and share: it
stops working when they lose those rights, or when what it leads to is
moved or deleted. **Shared links** in the menu lists your links, and for
superadmins everyone's, to revoke them. Deleting a user, or giving them a
new temporary password, ends their links too. Scripts:

```sh
curl -H "Authorization: Bearer $TOKEN" -d action=create -d path=/docs/report.pdf -d expires=7d https://host/.shares/
# {"id":1,"url":"https://host/.share/...","expires_at":"..."}
curl -H "Authorization: Bearer $TOKEN" -d action=revoke -d id=1 https://host/.shares/
```

Creating links needs the `share` action on what is shared. Admins have
it; on upgrade, it is added only if the admin rule is still the default
one. To let others share, e.g. `goftp policy add user:bob '/bob/*' share`.

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
- Share links carry 256-bit tokens, which are kept out of the logs. Link
  passwords are hashed with Argon2id; wrong ones count against the
  client's sign-in budget, and each link takes at most 20 password checks
  a minute. The cookie that remembers a password lasts at most
  `auth.session_ttl`.

## Troubleshooting

"Wrong username or password" at sign-in: `docker compose logs goftp | grep
"login failed"` shows whether the name matched no user or the password was
wrong (names that match no user are not logged: they are sometimes
passwords typed into the wrong field). `goftp user list` shows the users, and
`goftp user passwd NAME` gives one a new temporary password (temporary
passwords ignore case and surrounding spaces).

## Development

```sh
go test -race ./...
# Postgres-backed tests run when a database is given:
GOFTP_TEST_DATABASE_URL="postgres://postgres:secret@localhost/goftp_test" go test ./...
```

[CI](.github/workflows/ci.yml) runs these with Postgres on every pull request,
along with gofmt, `go vet`, builds for Windows, macOS and FreeBSD,
[govulncheck](https://go.dev/doc/security/vuln/) (also weekly) and a build
of the Docker image.

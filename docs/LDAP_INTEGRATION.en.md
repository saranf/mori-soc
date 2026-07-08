# LDAP integration — one account for MORI · Grafana · Zabbix · Fleet

[🇰🇷 한국어](./LDAP_INTEGRATION.md) · **🇬🇧 English**

> LDAP is **optional**. The default install works without LDAP, using local accounts,
> and **only those who want it** turn it on with `MORI_LDAP_ENABLED=true`. Once enabled,
> ① MORI login goes through LDAP, and ② **an account is created in LDAP when a signup is
> approved**, so the same account also **logs in to Grafana/Zabbix/Fleet** that point at the
> same LDAP.

---

## 0. To enable or not? (30-second decision)

| Situation | Recommendation |
| --- | --- |
| Accounts are used only in MORI and the user count is small | **Leave LDAP off** and use local accounts (default) |
| You want **one account** for unified login across MORI + Grafana/Zabbix/Fleet | **Turn LDAP on** |
| You already have a corporate LDAP/AD | **Turn LDAP on** and point it at that directory |

LDAP can be turned on and off at any time (turning it off returns you to local accounts only).

---

## 1. Enabling LDAP (bundled OpenLDAP)

`docker compose up` also brings up the bundled **OpenLDAP + phpLDAPadmin**.
Just enable the settings below in `.env` and restart `mori-api` — that's it.

```dotenv
MORI_LDAP_ENABLED=true                                   # ← this one line is the switch (default false)
MORI_LDAP_URL=ldap://openldap:389
MORI_LDAP_BIND_DN=cn=admin,dc=mori,dc=local
MORI_LDAP_BIND_PASSWORD=change_this_ldap_admin_password  # = LDAP_ADMIN_PASSWORD (write access)
MORI_LDAP_BASE_DN=ou=users,dc=mori,dc=local              # user OU
MORI_LDAP_USER_ATTR=uid
```

```bash
docker compose up -d openldap mori-api
```

> phpLDAPadmin (web LDAP administration) is at `http://localhost:18089` (account `cn=admin,dc=mori,dc=local`).

**To use your existing (corporate) LDAP/AD**, replace the URL/DN/password above with that
directory's values. The bind account needs write access to the user OU in order to **create
accounts on signup approval** (read access is enough if you only want to validate logins).

---

## 2. Login & signup flow (approval-based)

**Login** — when LDAP is enabled, verification runs in the order `LDAP → local account`. That way
local accounts such as the administrator (`admin`) still log in as before.

**Signup (approval-based)** — to prevent just anyone from getting an account, it goes through
**admin approval**.

1. User: submits **login ID, name, and email** at `/signup-request`
2. Admin: admin console → **Signup Request Management** → on the request row, choose a **role** +
   enter an **initial password** (leave blank to auto-generate) → **Approve**
3. On approval, an **account is created in LDAP** + the initial password is **shown once** (pass it
   to the user)
4. The user logs in with that account to **MORI + Grafana/Zabbix/Fleet (the same LDAP)**

> The role persists in `ui_settings` (`ldaprole:<uid>`), so it is **retained across restarts**.
> The password is verified by LDAP, so MORI does not store it.

---

## 3. Managing users directly

### (A) MORI admin UI (recommended)

Log in as `admin` → **Admin console → Access Control → 🔑 LDAP User Management**.
When LDAP is on, the header shows `● Enabled · <url> · <base_dn>`, and below you can:

- **List users** — uid · name · email · MORI role
- **Add** — enter uid · name · email · initial password · role → **+ Add**
- **Reset password / change role / delete** — inline per row

An admin can create and manage accounts immediately without the signup form, and
accounts created here also log in to Grafana/Zabbix/Fleet pointed at the same LDAP.
(If LDAP is off, the panel just shows how to enable it.)

> API: `GET /admin/ldap/status` · `GET/POST /admin/ldap/users` ·
> `POST /admin/ldap/users/{uid}/password` · `.../role` · `DELETE /admin/ldap/users/{uid}` (all admin-only)

### (B) CLI helper script

You can also create accounts straight from a server terminal.

```bash
# Add to the bundled OpenLDAP
./scripts/mori-ldap-adduser.sh -u hong -n "홍길동" -p 'InitPassw0rd!' -m hong@corp.com

# Add to an existing (external) LDAP
./scripts/mori-ldap-adduser.sh -u hong -n "홍길동" -p 'pw' \
  --host ldap://ldap.corp.com:389 \
  --admin-dn 'cn=admin,dc=corp,dc=com' --admin-pw '***' \
  --base 'ou=users,dc=corp,dc=com'
```

The script creates the user OU if it doesn't exist and adds an `inetOrgPerson` account. The added
account can log in to every service that points at the same LDAP.

---

## 4. Attaching existing Zabbix/Grafana to the same LDAP

This stack **already exposes** each service's LDAP toggle **via `.env`**. Turn them on and all three
services look at the same directory, giving you **unified login with a single account**.

### Grafana
```dotenv
GRAFANA_LDAP_ENABLED=true
```
- Mapping is in `config/grafana/ldap.toml` (compose mounts it at `/etc/grafana/ldap.toml`).
- Auto-creating new users (`GF_AUTH_LDAP_ALLOW_SIGN_UP=true`) is on by default.

### Zabbix (bundled)
```dotenv
ZABBIX_LDAP_ENABLED=true
ZABBIX_LDAP_BASE_DN=ou=users,dc=mori,dc=local
ZABBIX_LDAP_SEARCH_ATTRIBUTE=uid
ZABBIX_LDAP_BIND_DN=cn=admin,dc=mori,dc=local
# The bind password uses LDAP_ADMIN_PASSWORD
```
> For an existing (external) Zabbix, enter the same values in the Zabbix web UI →
> **Administration → Authentication → LDAP** (base DN, search attribute, bind account).

### Apply
```bash
docker compose up -d grafana zabbix-web    # restart the bundled services
```

Now the accounts created via §2/§3 give you **the same login across MORI · Grafana · Zabbix**.

---

## 5. Turning off / reverting

Set `MORI_LDAP_ENABLED=false` in `.env` (plus `GRAFANA_LDAP_ENABLED`/`ZABBIX_LDAP_ENABLED=false`
if needed) and restart; each service goes back to using local accounts only. Accounts created in
LDAP remain in the directory.

---

## 6. Troubleshooting

| Symptom | What to check |
| --- | --- |
| LDAP login fails | Whether `MORI_LDAP_ENABLED=true`, the `MORI_LDAP_URL/BASE_DN/USER_ATTR` values, and the bind account password |
| "LDAP account creation failed" on signup approval | The bind account's **write access**, and whether the user OU (`MORI_LDAP_BASE_DN`) exists |
| Approved, but the role shows as user | After a restart the role is restored from `ui_settings` (`ldaprole:<uid>`) — check the DB connection (`MORI_DATABASE_URL`) |
| Password doesn't match | The initial password is **shown only once** at approval — if lost, reset it via phpLDAPadmin/the script |
| ldap3 not installed | Included in the image (`ldap3==2.9.1`). Install it if you use a custom environment |

---

## Next steps

- New install & operations → [GETTING_STARTED.en.md](GETTING_STARTED.en.md)
- Connecting existing Zabbix/Wazuh/Fleet data → [BROWNFIELD_CONNECT.en.md](BROWNFIELD_CONNECT.en.md)

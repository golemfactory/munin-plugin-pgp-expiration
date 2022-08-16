# Munin plugin that monitors pgp keys expiration date

Given a list of email addresses, downloads them from WKD and checks days to expiration.

If a key does not expire, it's omitted in output.

## Configuration

```
[pgp_expiration]
env.emails foo@example.com bar@example.org ...
```

## Cron

It should be run from cron daily using

```
@daily munin-run pgp_expiration cron
```

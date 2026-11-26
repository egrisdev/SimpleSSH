# Security policy

## Supported versions

Only the [latest release](https://github.com/egrisdev/SimpleSSH/releases/latest) gets security fixes. Please check that a problem still happens there before reporting it.

## Reporting a vulnerability

Please do **not** open a public issue for a security problem.

Report it privately instead: on this repository, open the **Security** tab and choose **Report a vulnerability** ([direct link](https://github.com/egrisdev/SimpleSSH/security/advisories/new)). Only the maintainers can see the report.

It helps to include:

- the SimpleSSH version and your Windows version,
- what kind of connection is involved (SSH, Remote Desktop, server console, web app),
- the steps to reproduce it, and what an attacker could gain.

Leave out real passwords, keys, host names and addresses.

## What to expect

SimpleSSH is a free project maintained in spare time, so there is no guaranteed response time. Reports are read, and confirmed problems are fixed in a new release and credited in its notes unless you ask not to be named.

## Scope

In scope: anything that lets someone read saved passwords or keys, get past host-key or certificate checks, run code on the PC, or reach a server the user did not choose.

Out of scope: malware or another person already running programs as the signed-in Windows user (see [Password security](README.md#password-security)), and vulnerabilities in the servers and devices SimpleSSH connects to.

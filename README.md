# Supabase Firebase Scanner

A Burp Suite extension for identifying exposed Supabase and Firebase configurations by observing client traffic and actively testing in-scope endpoints.

This extension passively detects:

- Supabase project URLs
- Supabase publishable/anonymous keys
- JWT tokens with anon role claims
- table names used in REST calls
- Firebase API keys and project identifiers
- Firebase Realtime Database URLs

It can then run targeted checks to confirm whether anonymous clients can read or write data.

## What it does

The extension adds a Burp tab named `BaaS Scanner` and tracks observed backend targets. Once a Supabase or Firebase target is detected, you can select it and run active checks against endpoints within Burp scope.

For Supabase, it can:

- test anonymous `SELECT` access to discovered tables
- optionally test anonymous `POST` writes to a table (with a warning because this may create a row)
- report issues in Burp as scan issues

For Firebase, it can:

- test whether the Realtime Database is publicly readable
- test whether Firebase Remote Config is readable using an observed API key

## Requirements

- Burp Suite
- Jython support enabled in Burp
- A target that is in scope for active checks
- Authorized testing only; this tool is intended for legitimate security assessment on systems you own or are authorized to test

## Installation

1. Open Burp Suite.
2. Go to `Extender`.
3. Choose the `Java` or `Jython` extension loader supported by your Burp version.
4. Load `supabase_firebase_scanner.py`.
5. The extension will register a new tab called `BaaS Scanner`.

## Usage

1. Browse or proxy traffic from the application under test.
2. The extension will passively collect Supabase/Firebase indicators from HTTP traffic.
3. In the `BaaS Scanner` tab, review the discovered targets.
4. Select a target row.
5. Click `Check selected`.
6. Optionally enable `Probe Supabase writes (may persist a row)` for write testing.
7. Review the results and issue details in the Burp UI.

## Important note

The active checks are limited to Burp scope. This is intentional to reduce accidental requests outside the target environment. However, some checks may create data or change state, especially the optional Supabase write probe. Use that option carefully and only on authorized targets.

## Example findings

The extension is designed to flag conditions such as:

- anonymous read access to a Supabase table
- anonymous write access to a Supabase table
- publicly readable Firebase Realtime Database
- publicly readable Firebase Remote Config template

## Disclaimer

This project is for authorized security testing and research only. Do not run it against systems you do not own or are not explicitly authorized to test.

## Repository layout

- `supabase_firebase_scanner.py` - Burp extension source
- `README.md` - project overview and usage notes

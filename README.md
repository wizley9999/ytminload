# ytminload

A minimal YouTube iOS tweak for personal sideloading. It turns on a few Premium features and fixes
sideload login by overriding getters at runtime. No new UI, no settings screen, no downloader.

## Features

|     | Feature             | How                                                                                                                                                       |
| --- | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A   | Ad removal          | Empties ad arrays and params in player and watch-next responses, removes ad items from home, search and Shorts lists, and hides any ad element left over. |
| B   | Background playback | Playability getters return YES.                                                                                                                           |
| C   | Picture in Picture  | PiP getters return YES.                                                                                                                                   |
| I   | Upsell and prompts  | No mealbar promo, app update dialog or "still watching" prompt.                                                                                           |
| L   | Sideload login      | Gives Google SSO a keychain access group the resigned app can use, so login survives an app restart.                                                      |

Out of scope: downloads, 1080p Premium and high-bitrate audio (the server decides those), cosmetic extras.

## Layout

| Path                          | Purpose                                                                                          |
| ----------------------------- | ------------------------------------------------------------------------------------------------ |
| `Tweak.mm`                    | The whole tweak: one install helper, a hook table grouped by feature, and the list filters.      |
| `Makefile`                    | Theos build. `make` builds the dylib. `make ipa` also checks the original and packs the IPA.     |
| `ytm.py`                      | `check`, `dump` and `pack` for the original IPA. Python 3.8+, no dependencies.                   |
| `.github/workflows/build.yml` | Builds the dylib on a GitHub macOS runner.                                                       |
| `.github/workflows/ipa.yml`   | Builds the dylib, then the IPA on a self-hosted runner.                                          |
| `ipa/`                        | Original `com.google.ios.youtube-<version>.ipa` files and built `ytminload-<version>.ipa` files. |

## Build locally

Requirements: a decrypted YouTube IPA in `ipa/`, Theos with an iOS toolchain and SDK, and Python 3.

```sh
make ipa
```

This builds `.theos/obj/ytminload.dylib`, runs `ytm.py check` (stops on any FAIL), then runs `ytm.py pack`,
which writes `ipa/ytminload-<version>.ipa`. If `ipa/` holds several originals, the highest version is used.
Pass `BASE=<file or folder>` to pick another one. `make` alone builds only the dylib.

With Theos in WSL, run this from the repository folder in PowerShell. WSL starts in the same folder, on any drive:

```powershell
wsl -d Ubuntu -- env THEOS=/home/<user>/theos make ipa
```

## CI

- `build.yml` runs on demand only and when `ipa.yml` calls it. It builds the dylib with the Xcode SDK,
  checks its install name and that no hooking framework is linked, and uploads the `ytminload-dylib` artifact.
- `ipa.yml` runs on demand only. After `build.yml`, a self-hosted runner reads the highest-version original
  from `ipa/` in its own checkout, runs `check` and `pack`, and writes the IPA to the same folder.
  IPAs never leave that machine.

## ytm.py

`<base>` is an IPA, or a folder whose highest-version `com.google.ios.youtube-<version>.ipa` is used.

| Command                     | What it does                                                                                                                                                                                                           |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `check <base>`              | Checks injection preconditions (decrypted binary, rpath, header space, audio background mode), every hook row (class, method, `+`/`-` kind, called by app code) and the getters the filters need. Exits 1 on any FAIL. |
| `dump <base> <dir>`         | Writes `classes.txt`, `selrefs.txt` and `cstrings.txt` to search when a hook breaks.                                                                                                                                   |
| `pack <base> <dylib> [out]` | Adds one `LC_LOAD_DYLIB`, copies the dylib into `Frameworks/`, drops app extensions. Default output: `ytminload-<version>.ipa` next to the original.                                                                   |

`pack` removes all app extensions to stay within the free account's app ID limit. It does not touch
Info.plist or signatures; Sideloadly signs the app.

## Notes

- For personal use. The repository holds no IPA or Google binary; keep built IPAs to yourself.
- Hooks are found by class name at runtime. A missing class or method is skipped silently, so a YouTube
  update can disable a feature without crashing. `ytm.py check` is how you find out.

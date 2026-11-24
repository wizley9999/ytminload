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
| L   | Sideload login      | Gives <Provider> SSO a keychain access group the resigned app can use, so login survives an app restart.                                                  |

Out of scope: downloads, 1080p Premium and high-bitrate audio (the server decides those), cosmetic extras.

## Layout

| Path                          | Purpose                                                                                              |
| ----------------------------- | ---------------------------------------------------------------------------------------------------- |
| `Tweak.mm`                    | The whole tweak: one install helper, a hook table grouped by feature, and the list filters.          |
| `Makefile`                    | Theos build. `make` builds the dylib. `make ipa` also checks the original and packs the IPA.         |
| `ytm.py`                      | `check`, `dump` and `pack` for the original IPA. Python 3.8+, no dependencies.                       |
| `.github/workflows/build.yml` | Builds the dylib on a GitHub macOS runner and uploads it as an artifact.                             |
| `.github/workflows/ipa.yml`   | Builds the IPA from an original IPA URL and publishes it as a `yt-<version>` release.                |
| `ipa/`                        | Original `com.<Provider>.ios.youtube-<version>.ipa` files and built `ytminload-<version>.ipa` files. |

## Build

Requirements: a decrypted YouTube IPA, Theos with an iOS toolchain and SDK, and Python 3.

Set up Theos with its [installation guide](https://theos.dev/docs/installation).

Create `ipa/` (it is not in the repository) and put the IPA there as `com.<Provider>.ios.youtube-<version>.ipa`.

Tags named `yt-<version>` mark the YouTube versions this code was built for.
Build from the one that matches your IPA with `git checkout yt-<version>`.

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

## GitHub Actions

Both workflows run only on demand from the Actions tab.

- `build.yml` builds the dylib on a macOS runner, checks its install name and that no hooking framework
  is linked, and uploads it as the `ytminload-dylib` artifact.
- `ipa.yml` asks for a direct download URL of a decrypted YouTube IPA. It runs `build.yml`, then `check` and
  `pack` on a Linux runner, and publishes `ytminload-<version>.ipa` as a release on the tag `yt-<version>`.

The URL must download the file directly, without a confirmation page. To rebuild a version that already
has a release, delete it first with `gh release delete yt-<version> --cleanup-tag`.

## ytm.py

`<base>` is an IPA, or a folder whose highest-version `com.<Provider>.ios.youtube-<version>.ipa` is used.

| Command                     | What it does                                                                                                                                                                                                           |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `check <base>`              | Checks injection preconditions (decrypted binary, rpath, header space, audio background mode), every hook row (class, method, `+`/`-` kind, called by app code) and the getters the filters need. Exits 1 on any FAIL. |
| `dump <base> <dir>`         | Writes `classes.txt`, `selrefs.txt` and `cstrings.txt` to search when a hook breaks.                                                                                                                                   |
| `pack <base> <dylib> [out]` | Adds one `LC_LOAD_DYLIB`, copies the dylib into `Frameworks/`, drops app extensions. Default output: `ytminload-<version>.ipa` next to the original.                                                                   |

`pack` removes all app extensions to stay within the free account's app ID limit. It does not touch
Info.plist or signatures; Sideloadly signs the app.

## Notes

- For personal use. Releases hold built IPAs.
- Hooks are found by class name at runtime. A missing class or method is skipped silently, so a YouTube
  update can disable a feature without crashing. `ytm.py check` is how you find out.

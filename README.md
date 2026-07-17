# AdBlocker

Android DNS-based ad blocker using VpnService. No root required.
Blocks ads and trackers by intercepting DNS queries and returning
NXDOMAIN for ~130,000 domains (StevenBlack list, cached daily).

---

## Option 1 — Open in Android Studio

1. **File → Open** → select this `AdBlocker/` folder
2. When prompted to download Gradle 8.6, click **OK**
3. Wait for project sync (~1-2 min on first run)
4. Connect your phone with USB debugging enabled
5. **Run → Run 'app'** → accept the VPN consent dialog on your phone

---

## Option 2 — Build with Claude Code (on your laptop)

Open a terminal in this folder and run:

```
claude
```

Then type:

```
Run ./gradlew assembleDebug. If gradlew is missing, run
`gradle wrapper` first or generate it. Tell me the APK path
when done.
```

Install the resulting APK:

```
adb install app/build/outputs/apk/debug/app-debug.apk
```

---

## Option 3 — Build via GitHub Actions (cloud, no laptop needed)

1. Push this folder to a new GitHub repo
2. Create `.github/workflows/build.yml` with:

```yaml
name: Build APK
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          java-version: '17'
          distribution: 'temurin'
      - uses: gradle/actions/setup-gradle@v3
      - run: ./gradlew assembleDebug
      - uses: actions/upload-artifact@v4
        with:
          name: app-debug
          path: app/build/outputs/apk/debug/app-debug.apk
```

3. Every push builds the APK — download it from the **Actions** tab on GitHub

---

## Notes

- First VPN start downloads the blocklist (~3 MB) — needs internet once.
- Apps using DNS-over-HTTPS (YouTube, Chromium) bypass DNS filtering.
- Not on Google Play by policy. Sideload the APK.

workflows:
  alvisia-android:
    name: ALVISIA PRO 5.5.0
    max_build_duration: 120
    instance_type: mac_mini_m2
    environment:
      java: 17
      vars:
        PACKAGE_NAME: "com.alvsia.pro"
      # Optional: set these in Codemagic UI → Environment variables (group "signing")
      # CM_KEYSTORE  (base64 of alvsia-release.keystore) OR use keystore in repo
      # CM_KEYSTORE_PASSWORD
      # CM_KEY_ALIAS: alvsia
      # CM_KEY_PASSWORD
    scripts:
      - name: Set gradlew permission
        script: |
          chmod +x ./gradlew
          java -version

      - name: Build release APK
        script: |
          set -o pipefail
          ./gradlew assembleRelease --stacktrace --no-daemon 2>&1 | tee build_full.log
          STATUS=${PIPESTATUS[0]}
          echo "===== ERRORS (if any) ====="
          grep -E "^e:|What went wrong|Caused by:|FAILED|error:" build_full.log | head -50 || true
          echo "===== APK outputs ====="
          find app/build/outputs -name "*.apk" -type f 2>/dev/null || true
          exit $STATUS

      - name: Sign APK if keystore present
        script: |
          set -e
          UNSIGNED=$(find app/build/outputs/apk -name "*.apk" -type f | head -1)
          if [ -z "$UNSIGNED" ]; then
            echo "No APK found — build step failed"
            exit 1
          fi
          echo "Found: $UNSIGNED"

          # Prefer Codemagic env keystore; fallback to repo keystore
          if [ -n "${CM_KEYSTORE:-}" ]; then
            echo "$CM_KEYSTORE" | base64 -d > /tmp/alvsia.keystore
            KS=/tmp/alvsia.keystore
            KSPASS="${CM_KEYSTORE_PASSWORD}"
            ALIAS="${CM_KEY_ALIAS:-alvsia}"
            KEYPASS="${CM_KEY_PASSWORD:-$KSPASS}"
          elif [ -f alvsia-release.keystore ]; then
            KS=alvsia-release.keystore
            # Password: set CM_KEYSTORE_PASSWORD in Codemagic UI (do not hardcode)
            KSPASS="${CM_KEYSTORE_PASSWORD:-}"
            ALIAS="${CM_KEY_ALIAS:-alvsia}"
            KEYPASS="${CM_KEY_PASSWORD:-$KSPASS}"
          else
            echo "No keystore — leaving unsigned APK"
            cp "$UNSIGNED" ALVSIA_PRO_5.5.0_unsigned.apk
            exit 0
          fi

          if [ -z "$KSPASS" ]; then
            echo "CM_KEYSTORE_PASSWORD not set — copying unsigned APK"
            cp "$UNSIGNED" ALVSIA_PRO_5.5.0_unsigned.apk
            exit 0
          fi

          # Align + sign
          BUILD_TOOLS=$(ls -d $ANDROID_SDK_ROOT/build-tools/* 2>/dev/null | sort -V | tail -1)
          ZIPALIGN="$BUILD_TOOLS/zipalign"
          APKSIGNER="$BUILD_TOOLS/apksigner"
          ALIGNED=/tmp/alvsia-aligned.apk
          SIGNED=ALVSIA_PRO_5.5.0_signed.apk

          "$ZIPALIGN" -f 4 "$UNSIGNED" "$ALIGNED"
          "$APKSIGNER" sign \
            --ks "$KS" \
            --ks-key-alias "$ALIAS" \
            --ks-pass "pass:$KSPASS" \
            --key-pass "pass:$KEYPASS" \
            --out "$SIGNED" \
            "$ALIGNED"
          "$APKSIGNER" verify "$SIGNED"
          echo "Signed OK: $SIGNED"
          ls -lh "$SIGNED"

    artifacts:
      - app/build/outputs/apk/**/*.apk
      - ALVSIA_PRO_5.5.0_signed.apk
      - ALVSIA_PRO_5.5.0_unsigned.apk
      - build_full.log

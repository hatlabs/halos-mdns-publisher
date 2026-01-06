#!/bin/bash
set -euo pipefail

echo "=== Building Debian Package ==="

# Run build in Docker container
docker run --rm \
    -v "$(pwd):/build" \
    -w /build \
    rust-debtools:latest \
    bash -c '
        set -euo pipefail

        echo "Building for aarch64 (arm64)..."

        # Build the release binary
        cargo build --release --target aarch64-unknown-linux-gnu

        # Get version from Cargo.toml
        VERSION=$(grep "^version" Cargo.toml | head -1 | sed "s/.*\"\(.*\)\"/\1/")
        PACKAGE_NAME="halos-mdns-publisher"

        echo "Package: ${PACKAGE_NAME}"
        echo "Version: ${VERSION}"

        # Create package directory structure
        PKG_DIR="${PACKAGE_NAME}_${VERSION}_arm64"
        rm -rf "$PKG_DIR"
        mkdir -p "$PKG_DIR/DEBIAN"
        mkdir -p "$PKG_DIR/usr/bin"
        mkdir -p "$PKG_DIR/usr/lib/systemd/system"
        mkdir -p "$PKG_DIR/usr/share/doc/${PACKAGE_NAME}"
        mkdir -p "$PKG_DIR/etc"

        # Copy and strip binary
        cp target/aarch64-unknown-linux-gnu/release/halos-mdns-publisher "$PKG_DIR/usr/bin/"
        aarch64-linux-gnu-strip "$PKG_DIR/usr/bin/halos-mdns-publisher"
        chmod 755 "$PKG_DIR/usr/bin/halos-mdns-publisher"

        # Copy systemd service (use /usr/lib not /lib for Debian Trixie)
        cp debian/halos-mdns-publisher.service "$PKG_DIR/usr/lib/systemd/system/"

        # Copy mdns.allow if it exists
        if [ -f debian/mdns.allow ]; then
            cp debian/mdns.allow "$PKG_DIR/etc/"
        fi

        # Generate debian/changelog if it does not exist (CI normally generates it,
        # but for local builds or PR checks we create a minimal one)
        if [ ! -f debian/changelog ]; then
            echo "Generating debian/changelog..."
            DEB_VERSION="${VERSION}-1"
            cat > debian/changelog <<CHANGELOG_EOF
${PACKAGE_NAME} (${DEB_VERSION}) unstable; urgency=medium

  * Build from source

 -- Hat Labs <info@hatlabs.fi>  $(date -R)
CHANGELOG_EOF
        fi

        # Read debian version from changelog
        DEB_VERSION=$(head -1 debian/changelog | sed "s/.*(\(.*\)).*/\1/")

        # Generate control file from debian/control template
        # Extract fields and format for binary package
        {
            echo "Package: ${PACKAGE_NAME}"
            echo "Version: ${DEB_VERSION}"
            echo "Architecture: arm64"
            grep "^Section:" debian/control || echo "Section: admin"
            grep "^Priority:" debian/control || echo "Priority: optional"
            grep "^Maintainer:" debian/control
            # Extract Depends, removing template variables, and add libc6
            DEPENDS=$(grep "^Depends:" debian/control | sed "s/\${[^}]*}, *//g" | sed "s/, *\${[^}]*}//g")
            echo "${DEPENDS}, libc6"
            grep "^Recommends:" debian/control || true
            grep "^Conflicts:" debian/control || true
            grep "^Replaces:" debian/control || true
            # Extract description (everything from Description: to end of file in Package stanza)
            sed -n "/^Description:/,/^$/p" debian/control | head -n -1
        } > "$PKG_DIR/DEBIAN/control"

        # Create conffiles for files in /etc
        echo "/etc/mdns.allow" > "$PKG_DIR/DEBIAN/conffiles"

        # Copy maintainer scripts from debian/ directory
        cp debian/postinst "$PKG_DIR/DEBIAN/postinst"
        chmod 755 "$PKG_DIR/DEBIAN/postinst"

        cp debian/postrm "$PKG_DIR/DEBIAN/postrm"
        chmod 755 "$PKG_DIR/DEBIAN/postrm"

        # Copy lintian overrides if they exist
        if [ -f "debian/${PACKAGE_NAME}.lintian-overrides" ]; then
            mkdir -p "$PKG_DIR/usr/share/lintian/overrides"
            cp "debian/${PACKAGE_NAME}.lintian-overrides" "$PKG_DIR/usr/share/lintian/overrides/${PACKAGE_NAME}"
            chmod 644 "$PKG_DIR/usr/share/lintian/overrides/${PACKAGE_NAME}"
        fi

        # Create changelog.Debian.gz (use -n for reproducible builds)
        # We always use non-native format (version with dash like "1.0-1")
        gzip -9 -n -c debian/changelog > "$PKG_DIR/usr/share/doc/${PACKAGE_NAME}/changelog.Debian.gz"

        # Copy copyright file
        if [ -f debian/copyright ]; then
            cp debian/copyright "$PKG_DIR/usr/share/doc/${PACKAGE_NAME}/copyright"
        fi

        # Build the package
        dpkg-deb --build "$PKG_DIR"

        # Rename to standard format (only if different)
        OUTPUT_NAME="${PACKAGE_NAME}_${DEB_VERSION}_arm64.deb"
        if [ "${PKG_DIR}.deb" != "$OUTPUT_NAME" ]; then
            mv "${PKG_DIR}.deb" "$OUTPUT_NAME"
        fi

        echo "=== Package built successfully ==="
        ls -la *.deb
    '

# Package is already in workspace root (Docker volume mount)
# Just verify it exists
echo "=== Build complete ==="
ls -la *.deb

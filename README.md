# sbomfetch

A Go program that parses SPDX-formatted SBOM (Software Bill of Materials) files to download and extract source code archives referenced in the `downloadLocation` fields. It supports both local SBOM files and direct container image references that retrieve SBOMs from Sigstore attestations.

## Features

- **SPDX SBOM Parsing**: Reads SPDX 2.3 formatted JSON files
- **Container Image Support**: Directly fetch SBOMs from container images via Sigstore attestations
- **Relationship Analysis**: Uses `GENERATED_FROM` relationships to map source packages to APK packages
- **Concurrent Downloads**: Configurable parallel downloading (default: 4 concurrent)
- **Multi-format Archive Support**: Handles `.tar.gz`, `.tar.xz`, `.tar.bz2`, and `.tgz` files
- **Automatic Extraction**: Extracts all downloaded archives after download completion
- **APK Traceability**: Shows which APK package each source archive belongs to
- **Security**: Includes path traversal protection during extraction
- **Organized Output**: Separates downloaded archives from extracted content
- **Default Directory Generation**: Automatically generates download directories for container images
- **SBOM Preservation**: Saves retrieved SBOMs to disk for reference

## Prerequisites

- Go 1.21 or later
- Internet connection for downloading archives

## Installation

Install using Go:
```bash
go install -v github.com/javacruft/sbomfetch@latest
```

## Usage

```bash
sbomfetch [options] <sbom-file.json|container-image> [download-directory]
```

### Options

- `-concurrency <n>`: Number of concurrent downloads (default: 4)
- `-platform <platform>`: Platform for container image (default: linux/amd64)
- `-h`: Show help

### Examples

```bash
# Basic usage with SBOM file and default 4 concurrent downloads
sbomfetch haproxy-sbom.json ./downloads

# Use 8 concurrent downloads with SBOM file
sbomfetch -concurrency 8 haproxy-sbom.json ./downloads

# Fetch SBOM from container image with auto-generated directory
sbomfetch cgr.dev/chainguard/unbound:latest

# Fetch SBOM from container image with specific directory
sbomfetch cgr.dev/chainguard/unbound:latest ./my-downloads

# Specify platform for multi-arch images
sbomfetch -platform linux/arm64 cgr.dev/chainguard/nginx:latest

# Show help
sbomfetch -h
```

## Output Structure

The program creates the following directory structure:

```
downloads/
├── sbom.json               # Copy of SBOM (when using container images)
├── archives/               # All downloaded tar files
│   ├── gcc-15.1.0.tar.xz
│   ├── glibc-2.41.tar.gz
│   ├── haproxy-3.2.1.tar.gz
│   └── ...
├── gcc-15.1.0/             # Extracted contents
├── glibc-2.41/             # Extracted contents  
├── haproxy-3.2.1/          # Extracted contents
└── ...
```

## Sample Output

### Container Image Example
```
🔍 Retrieving SBOM from container image: cgr.dev/chainguard/unbound:latest
💾 SBOM saved to: unbound/sbom.json
🔍 Found 8 populated downloadLocation URLs
🚀 Starting download (1/8): gcc-15.1.0.tar.xz [libgcc]
🚀 Starting download (2/8): glibc-2.41.tar.gz [glibc]
📦 Downloaded (1/8): gcc-15.1.0.tar.xz [libgcc]
📦 Downloaded (2/8): glibc-2.41.tar.gz [glibc]
...
🎁 Download complete. Files saved to: unbound
🗄️ Extracting 8 archives...
📤 Extracting (1/8): gcc-15.1.0.tar.xz [libgcc]
🎉 Extracted: gcc-15.1.0.tar.xz [libgcc]
...
🎆 Extraction complete. Archives extracted to: unbound

📊 === EXECUTION SUMMARY ===
🚀 Downloads: 8 successful, 0 failed (total: 8)
🎉 Extractions: 8 successful, 0 failed (total: 8)
```

## How It Works

1. **Input Processing**: Accepts either local SBOM files or container image references
2. **SBOM Retrieval**: For container images, fetches SBOM from Sigstore attestations
3. **SBOM Parsing**: Reads the SPDX JSON file and parses packages and relationships
4. **Relationship Mapping**: Uses `GENERATED_FROM` relationships to map source packages to APK packages
5. **URL Filtering**: Identifies packages with valid HTTP(S) download URLs pointing to tar archives
6. **Concurrent Download**: Downloads archives in parallel using configurable worker pools
7. **APK Association**: Shows which APK package each source archive belongs to via log output
8. **Archive Organization**: Stores downloaded files in an `archives/` subdirectory
9. **Automatic Extraction**: Extracts all archives to the main downloads directory
10. **Security**: Validates extraction paths to prevent directory traversal attacks
11. **Summary Reporting**: Provides detailed execution statistics

## Supported Archive Formats

- `.tar.gz` and `.tgz` (gzip compressed)
- `.tar.xz` (XZ compressed)  
- `.tar.bz2` (bzip2 compressed)

## Error Handling

- Continues downloading other files if individual downloads fail
- Continues extracting other archives if individual extractions fail
- Provides detailed error messages for troubleshooting
- Validates file paths during extraction for security

## Dependencies

- `github.com/ulikunitz/xz` - XZ decompression support
- `github.com/google/go-containerregistry` - Container registry operations
- `github.com/sigstore/cosign/v2` - Sigstore attestation verification

## License

Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

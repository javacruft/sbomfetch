# SBOM Downloader

A Go program that parses SPDX-formatted SBOM (Software Bill of Materials) files to download and extract source code archives referenced in the `downloadLocation` fields.

## Features

- **SPDX SBOM Parsing**: Reads SPDX 2.3 formatted JSON files
- **Relationship Analysis**: Uses `GENERATED_FROM` relationships to map source packages to APK packages
- **Concurrent Downloads**: Configurable parallel downloading (default: 4 concurrent)
- **Multi-format Archive Support**: Handles `.tar.gz`, `.tar.xz`, `.tar.bz2`, and `.tgz` files
- **Automatic Extraction**: Extracts all downloaded archives after download completion
- **APK Traceability**: Shows which APK package each source archive belongs to
- **Security**: Includes path traversal protection during extraction
- **Organized Output**: Separates downloaded archives from extracted content

## Prerequisites

- Go 1.21 or later
- Internet connection for downloading archives

## Installation

1. Clone or download the source code
2. Install dependencies:
   ```bash
   go mod tidy
   ```

## Usage

```bash
go run sbom-downloader.go [options] <sbom-file.json> <download-directory>
```

### Options

- `-concurrency <n>`: Number of concurrent downloads (default: 4)
- `-h`: Show help

### Examples

```bash
# Basic usage with default 4 concurrent downloads
go run sbom-downloader.go haproxy-sbom.json ./downloads

# Use 8 concurrent downloads
go run sbom-downloader.go -concurrency 8 haproxy-sbom.json ./downloads

# Show help
go run sbom-downloader.go -h
```

## Output Structure

The program creates the following directory structure:

```
downloads/
├── archives/                # All downloaded tar files
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

```
Found 8 populated downloadLocation URLs
→ Starting download (1/8): gcc-15.1.0.tar.xz [libgcc]
→ Starting download (2/8): glibc-2.41.tar.gz [glibc]
✓ Downloaded (1/8): gcc-15.1.0.tar.xz [libgcc]
✓ Downloaded (2/8): glibc-2.41.tar.gz [glibc]
...
Download complete. Files saved to: ./downloads
Extracting 8 archives...
Extracting (1/8): gcc-15.1.0.tar.xz
✓ Extracted: gcc-15.1.0.tar.xz
...
Extraction complete. Archives extracted to: ./downloads
```

## How It Works

1. **SBOM Parsing**: Reads the SPDX JSON file and parses packages and relationships
2. **Relationship Mapping**: Uses `GENERATED_FROM` relationships to map source packages to APK packages
3. **URL Filtering**: Identifies packages with valid HTTP(S) download URLs pointing to tar archives
4. **Concurrent Download**: Downloads archives in parallel using configurable worker pools
5. **APK Association**: Shows which APK package each source archive belongs to via log output
6. **Archive Organization**: Stores downloaded files in an `archives/` subdirectory
7. **Automatic Extraction**: Extracts all archives to the main downloads directory
8. **Security**: Validates extraction paths to prevent directory traversal attacks

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

## License

This project is provided as-is for educational and development purposes.

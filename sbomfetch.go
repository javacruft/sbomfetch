// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 Chainguard, Inc.

package main

import (
	"archive/tar"
	"compress/bzip2"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/ulikunitz/xz"
)

type SPDXSBOM struct {
	Packages      []Package      `json:"packages"`
	Relationships []Relationship `json:"relationships"`
}

type Package struct {
	SPDXID           string `json:"SPDXID"`
	Name             string `json:"name"`
	DownloadLocation string `json:"downloadLocation"`
}

type Relationship struct {
	SpdxElementId      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSpdxElement string `json:"relatedSpdxElement"`
}

type DownloadJob struct {
	URL         string
	Index       int
	Total       int
	APKPackages []string
}

type DownloadResult struct {
	URL         string
	APKPackages []string
	Error       error
}

type DownloadSummary struct {
	SuccessCount int
	FailureCount int
	Files        []string
	FilePackages map[string][]string
}

type ExtractionSummary struct {
	SuccessCount int
	FailureCount int
}

type PackageMapping struct {
	URL         string
	APKPackages []string
}

func main() {
	var concurrency = flag.Int("concurrency", 4, "Number of concurrent downloads")
	var platform = flag.String("platform", "linux/amd64", "Platform for container image")
	flag.Parse()

	if flag.NArg() < 1 || flag.NArg() > 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <sbom-file.json|container-image> [download-directory]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  %s sbom.json ./downloads\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s cgr.dev/chainguard/unbound:latest ./downloads\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s cgr.dev/chainguard/unbound:latest\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	sbomInput := flag.Arg(0)
	var downloadDir string

	if flag.NArg() == 2 {
		downloadDir = flag.Arg(1)
	} else if isContainerImage(sbomInput) {
		downloadDir = generateDefaultDownloadDir(sbomInput)
	} else {
		fmt.Fprintf(os.Stderr, "Error: download directory is required for SBOM files\n")
		os.Exit(1)
	}

	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating download directory: %v\n", err)
		os.Exit(1)
	}

	// Create archives subdirectory
	archivesDir := filepath.Join(downloadDir, "archives")
	if err := os.MkdirAll(archivesDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating archives directory: %v\n", err)
		os.Exit(1)
	}

	var sbomData []byte
	var err error

	if isContainerImage(sbomInput) {
		fmt.Printf("🔍 Retrieving SBOM from container image: %s\n", sbomInput)
		sbomData, err = retrieveSBOMFromSigstore(sbomInput, *platform)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error retrieving SBOM from sigstore: %v\n", err)
			os.Exit(1)
		}

		// Write SBOM to top level of download directory
		sbomPath := filepath.Join(downloadDir, "sbom.json")
		if err := os.WriteFile(sbomPath, sbomData, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing SBOM to %s: %v\n", sbomPath, err)
			os.Exit(1)
		}
		fmt.Printf("💾 SBOM saved to: %s\n", sbomPath)
	} else {
		fmt.Printf("🔍 Reading SBOM from file: %s\n", sbomInput)
		sbomData, err = os.ReadFile(sbomInput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading SBOM file: %v\n", err)
			os.Exit(1)
		}
	}

	packageMappings, err := extractPackageMappingsFromData(sbomData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error extracting package mappings: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🔍 Found %d populated downloadLocation URLs\n", len(packageMappings))

	if len(packageMappings) == 0 {
		fmt.Println("No tarball URLs found to download")
		return
	}

	downloadSummary := downloadConcurrently(packageMappings, archivesDir, *concurrency)

	fmt.Printf("🎁 Download complete. Files saved to: %s\n", downloadDir)
	fmt.Printf("🗄️ Extracting %d archives...\n", len(downloadSummary.Files))

	extractionSummary := extractArchives(downloadSummary.Files, downloadSummary.FilePackages, downloadDir)

	fmt.Printf("🎆 Extraction complete. Archives extracted to: %s\n", downloadDir)

	// Print execution summary
	fmt.Println("\n📊 === EXECUTION SUMMARY ===")
	fmt.Printf("🚀 Downloads: %d successful, %d failed (total: %d)\n",
		downloadSummary.SuccessCount, downloadSummary.FailureCount,
		downloadSummary.SuccessCount+downloadSummary.FailureCount)
	fmt.Printf("🎉 Extractions: %d successful, %d failed (total: %d)\n",
		extractionSummary.SuccessCount, extractionSummary.FailureCount,
		extractionSummary.SuccessCount+extractionSummary.FailureCount)
}

func extractPackageMappingsFromData(data []byte) ([]PackageMapping, error) {
	var sbom SPDXSBOM
	if err := json.Unmarshal(data, &sbom); err != nil {
		return nil, fmt.Errorf("failed to parse SBOM JSON: %w", err)
	}

	// Create maps for lookups
	packageMap := make(map[string]*Package)
	for i := range sbom.Packages {
		packageMap[sbom.Packages[i].SPDXID] = &sbom.Packages[i]
	}

	// Create mapping: source package SPDXID -> list of APK packages
	sourceToAPKs := make(map[string][]string)
	var validationErrors []string

	for _, rel := range sbom.Relationships {
		if rel.RelationshipType == "GENERATED_FROM" {
			// rel.SpdxElementId is the APK package
			// rel.RelatedSpdxElement is the source package with downloadLocation
			if apkPkg, exists := packageMap[rel.SpdxElementId]; exists {
				sourceToAPKs[rel.RelatedSpdxElement] = append(sourceToAPKs[rel.RelatedSpdxElement], apkPkg.Name)

				// Validate that the source package has a downloadLocation
				if sourcePkg, sourceExists := packageMap[rel.RelatedSpdxElement]; sourceExists {
					if sourcePkg.DownloadLocation == "" || sourcePkg.DownloadLocation == "NOASSERTION" {
						validationErrors = append(validationErrors, fmt.Sprintf("Package '%s' has GENERATED_FROM relation to '%s' but source package lacks downloadLocation", apkPkg.Name, sourcePkg.Name))
					}
				} else {
					validationErrors = append(validationErrors, fmt.Sprintf("Package '%s' has GENERATED_FROM relation to non-existent source package '%s'", apkPkg.Name, rel.RelatedSpdxElement))
				}
			}
		}
	}

	// Report validation errors if any
	if len(validationErrors) > 0 {
		fmt.Fprintf(os.Stderr, "⚠️  Validation warnings for GENERATED_FROM relations:\n")
		for _, err := range validationErrors {
			fmt.Fprintf(os.Stderr, "   - %s\n", err)
		}
		fmt.Fprintf(os.Stderr, "\n")
	}

	// Group by URL to collect all packages per download location
	urlToPackages := make(map[string][]string)
	for _, pkg := range sbom.Packages {
		if pkg.DownloadLocation != "" &&
			pkg.DownloadLocation != "NOASSERTION" &&
			strings.HasPrefix(pkg.DownloadLocation, "http") {

			if isTarball(pkg.DownloadLocation) {
				apkPackages := sourceToAPKs[pkg.SPDXID]
				if len(apkPackages) == 0 {
					apkPackages = []string{"unknown"}
				}
				// Append all packages for this source to the URL mapping
				urlToPackages[pkg.DownloadLocation] = append(urlToPackages[pkg.DownloadLocation], apkPackages...)
			}
		}
	}

	// Convert to final mappings format
	var mappings []PackageMapping
	for url, packages := range urlToPackages {
		// Remove duplicates
		uniquePackages := make(map[string]bool)
		var finalPackages []string
		for _, pkg := range packages {
			if !uniquePackages[pkg] {
				uniquePackages[pkg] = true
				finalPackages = append(finalPackages, pkg)
			}
		}
		mappings = append(mappings, PackageMapping{
			URL:         url,
			APKPackages: finalPackages,
		})
	}

	return mappings, nil
}

func downloadConcurrently(mappings []PackageMapping, archivesDir string, concurrency int) DownloadSummary {
	jobs := make(chan DownloadJob, len(mappings))
	results := make(chan DownloadResult, len(mappings))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker(jobs, results, archivesDir, &wg)
	}

	// Send jobs
	go func() {
		defer close(jobs)
		for i, mapping := range mappings {
			jobs <- DownloadJob{
				URL:         mapping.URL,
				APKPackages: mapping.APKPackages,
				Index:       i + 1,
				Total:       len(mappings),
			}
		}
	}()

	// Close results channel when all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	completed := 0
	var downloadedFiles []string
	filePackages := make(map[string][]string)
	successCount := 0
	failureCount := 0

	for result := range results {
		completed++
		if result.Error != nil {
			failureCount++
			fmt.Fprintf(os.Stderr, "❌ Error downloading %s: %v\n", result.URL, result.Error)
		} else {
			successCount++
			filename := getFilenameFromURL(result.URL)
			filePath := filepath.Join(archivesDir, filename)
			downloadedFiles = append(downloadedFiles, filePath)
			filePackages[filePath] = result.APKPackages
			fmt.Printf("📦 Downloaded (%d/%d): %s [%s]\n", completed, len(mappings), filename, strings.Join(result.APKPackages, ", "))
		}
	}

	return DownloadSummary{
		SuccessCount: successCount,
		FailureCount: failureCount,
		Files:        downloadedFiles,
		FilePackages: filePackages,
	}
}

func worker(jobs <-chan DownloadJob, results chan<- DownloadResult, archivesDir string, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {
		fmt.Printf("🚀 Starting download (%d/%d): %s [%s]\n", job.Index, job.Total, getFilenameFromURL(job.URL), strings.Join(job.APKPackages, ", "))

		err := downloadFileToDir(job.URL, archivesDir)
		results <- DownloadResult{
			URL:         job.URL,
			APKPackages: job.APKPackages,
			Error:       err,
		}
	}
}

func isTarball(url string) bool {
	lowerURL := strings.ToLower(url)
	return strings.Contains(lowerURL, ".tar.gz") ||
		strings.Contains(lowerURL, ".tar.xz") ||
		strings.Contains(lowerURL, ".tgz") ||
		strings.Contains(lowerURL, ".tar.bz2")
}

func downloadFileToDir(url, downloadDir string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	filename := getFilenameFromURL(url)
	filepath := filepath.Join(downloadDir, filename)

	out, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save file: %w", err)
	}

	return nil
}

func getFilenameFromURL(url string) string {
	filename := path.Base(url)

	if filename == "." || filename == "/" {
		parts := strings.Split(url, "/")
		for i := len(parts) - 1; i >= 0; i-- {
			if parts[i] != "" {
				filename = parts[i]
				break
			}
		}
	}

	if !isTarball(filename) {
		filename = filename + ".tar.gz"
	}

	return filename
}

func extractArchives(archiveFiles []string, filePackages map[string][]string, extractDir string) ExtractionSummary {
	successCount := 0
	failureCount := 0

	for i, archiveFile := range archiveFiles {
		packageNames := filePackages[archiveFile]
		if len(packageNames) == 0 {
			packageNames = []string{"unknown"}
		}
		packageList := strings.Join(packageNames, ", ")
		fmt.Printf("📤 Extracting (%d/%d): %s [%s]\n", i+1, len(archiveFiles), filepath.Base(archiveFile), packageList)
		if err := extractArchive(archiveFile, extractDir); err != nil {
			failureCount++
			fmt.Fprintf(os.Stderr, "😱 Error extracting %s: %v\n", archiveFile, err)
		} else {
			successCount++
			fmt.Printf("🎉 Extracted: %s [%s]\n", filepath.Base(archiveFile), packageList)
		}
	}

	return ExtractionSummary{
		SuccessCount: successCount,
		FailureCount: failureCount,
	}
}

func extractArchive(archiveFile, extractDir string) error {
	file, err := os.Open(archiveFile)
	if err != nil {
		return fmt.Errorf("failed to open archive: %w", err)
	}
	defer file.Close()

	var reader io.Reader
	filename := strings.ToLower(archiveFile)

	// Determine compression type and create appropriate reader
	if strings.HasSuffix(filename, ".tar.gz") || strings.HasSuffix(filename, ".tgz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	} else if strings.HasSuffix(filename, ".tar.xz") {
		xzReader, err := xz.NewReader(file)
		if err != nil {
			return fmt.Errorf("failed to create xz reader: %w", err)
		}
		reader = xzReader
	} else if strings.HasSuffix(filename, ".tar.bz2") {
		reader = bzip2.NewReader(file)
	} else {
		return fmt.Errorf("unsupported archive format: %s", archiveFile)
	}

	// Extract tar archive
	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Create the full path for extraction
		targetPath := filepath.Join(extractDir, header.Name)

		// Security check: prevent path traversal
		if !strings.HasPrefix(targetPath, filepath.Clean(extractDir)+string(os.PathSeparator)) {
			fmt.Fprintf(os.Stderr, "Warning: skipping potentially dangerous path: %s\n", header.Name)
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			// Create directory
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			// Create file
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory: %w", err)
			}

			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", targetPath, err)
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("failed to extract file %s: %w", targetPath, err)
			}
			outFile.Close()
		case tar.TypeSymlink:
			// Create symlink
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory: %w", err)
			}

			if err := os.Symlink(header.Linkname, targetPath); err != nil {
				fmt.Fprintf(os.Stderr, "failed to create symlink %s -> %s\n", header.Linkname, targetPath)
				continue
			}
		}
	}

	return nil
}

func isContainerImage(input string) bool {
	return strings.Contains(input, "/") && !strings.HasSuffix(input, ".json")
}

func generateDefaultDownloadDir(imageRef string) string {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "sbom-download"
	}

	repo := ref.Context().RepositoryStr()
	parts := strings.Split(repo, "/")
	imageName := parts[len(parts)-1]

	if digest, ok := ref.(name.Digest); ok {
		digestStr := strings.TrimPrefix(digest.DigestStr(), "sha256:")
		if len(digestStr) > 12 {
			digestStr = digestStr[:12]
		}
		return fmt.Sprintf("%s-%s", imageName, digestStr)
	}

	if tag, ok := ref.(name.Tag); ok {
		tagStr := tag.TagStr()
		if tagStr != "latest" {
			return fmt.Sprintf("%s-%s", imageName, tagStr)
		}
	}

	return imageName
}

func retrieveSBOMFromSigstore(imageRef, platform string) ([]byte, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("invalid image reference: %w", err)
	}

	signedImg, err := remote.SignedImage(ref)
	if err != nil {
		return nil, fmt.Errorf("failed to get signed image: %w", err)
	}

	attestations, err := signedImg.Attestations()
	if err != nil {
		return nil, fmt.Errorf("failed to get attestations: %w", err)
	}

	attestationList, err := attestations.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation list: %w", err)
	}

	if len(attestationList) == 0 {
		return nil, fmt.Errorf("no attestations found for image %s", imageRef)
	}

	for _, attestation := range attestationList {
		sbomData, err := extractSPDXFromAttestation(attestation)
		if err != nil {
			continue
		}
		if sbomData != nil {
			return sbomData, nil
		}
	}

	return nil, fmt.Errorf("no SPDX attestations found for image %s", imageRef)
}

func extractSPDXFromAttestation(attestation oci.Signature) ([]byte, error) {
	payload, err := attestation.Payload()
	if err != nil {
		return nil, fmt.Errorf("failed to get payload: %w", err)
	}

	var dsse map[string]interface{}
	if err := json.Unmarshal(payload, &dsse); err != nil {
		return nil, fmt.Errorf("failed to parse DSSE envelope: %w", err)
	}

	payloadField, exists := dsse["payload"]
	if !exists {
		return nil, fmt.Errorf("no payload field in DSSE envelope")
	}

	payloadStr, ok := payloadField.(string)
	if !ok {
		return nil, fmt.Errorf("payload field is not a string")
	}

	decodedPayload, err := base64.StdEncoding.DecodeString(payloadStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 payload: %w", err)
	}

	var statement map[string]interface{}
	if err := json.Unmarshal(decodedPayload, &statement); err != nil {
		return nil, fmt.Errorf("failed to parse statement: %w", err)
	}

	predicateType, exists := statement["predicateType"]
	if !exists {
		return nil, fmt.Errorf("no predicateType found")
	}

	predicateTypeStr, ok := predicateType.(string)
	if !ok {
		return nil, fmt.Errorf("predicateType is not a string")
	}

	if !strings.Contains(predicateTypeStr, "spdx.dev/Document") {
		return nil, fmt.Errorf("not an SPDX attestation")
	}

	predicate, exists := statement["predicate"]
	if !exists {
		return nil, fmt.Errorf("no predicate found in statement")
	}

	predicateBytes, err := json.Marshal(predicate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal predicate: %w", err)
	}

	return predicateBytes, nil
}

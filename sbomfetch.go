package main

import (
	"archive/tar"
	"compress/bzip2"
	"compress/gzip"
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
	URL        string
	Index      int
	Total      int
	APKPackage string
}

type DownloadResult struct {
	URL        string
	APKPackage string
	Error      error
}

type PackageMapping struct {
	URL        string
	APKPackage string
}

func main() {
	var concurrency = flag.Int("concurrency", 4, "Number of concurrent downloads")
	flag.Parse()

	if flag.NArg() != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <sbom-file.json> <download-directory>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	sbomFile := flag.Arg(0)
	downloadDir := flag.Arg(1)

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

	packageMappings, err := extractPackageMappings(sbomFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error extracting package mappings: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d populated downloadLocation URLs\n", len(packageMappings))

	if len(packageMappings) == 0 {
		fmt.Println("No tarball URLs found to download")
		return
	}

	downloadedFiles := downloadConcurrently(packageMappings, archivesDir, *concurrency)

	fmt.Printf("Download complete. Files saved to: %s\n", downloadDir)
	fmt.Printf("Extracting %d archives...\n", len(downloadedFiles))

	extractArchives(downloadedFiles, downloadDir)

	fmt.Printf("Extraction complete. Archives extracted to: %s\n", downloadDir)
}

func extractPackageMappings(sbomFile string) ([]PackageMapping, error) {
	data, err := os.ReadFile(sbomFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read SBOM file: %w", err)
	}

	var sbom SPDXSBOM
	if err := json.Unmarshal(data, &sbom); err != nil {
		return nil, fmt.Errorf("failed to parse SBOM JSON: %w", err)
	}

	// Create maps for lookups
	packageMap := make(map[string]*Package)
	for i := range sbom.Packages {
		packageMap[sbom.Packages[i].SPDXID] = &sbom.Packages[i]
	}

	// Create reverse mapping: source package SPDXID -> APK package
	sourceToAPK := make(map[string]string)
	for _, rel := range sbom.Relationships {
		if rel.RelationshipType == "GENERATED_FROM" {
			// rel.SpdxElementId is the APK package
			// rel.RelatedSpdxElement is the source package with downloadLocation
			if apkPkg, exists := packageMap[rel.SpdxElementId]; exists {
				sourceToAPK[rel.RelatedSpdxElement] = apkPkg.Name
			}
		}
	}

	var mappings []PackageMapping
	for _, pkg := range sbom.Packages {
		if pkg.DownloadLocation != "" && 
		   pkg.DownloadLocation != "NOASSERTION" && 
		   strings.HasPrefix(pkg.DownloadLocation, "http") {
			
			if isTarball(pkg.DownloadLocation) {
				apkPackage := sourceToAPK[pkg.SPDXID]
				if apkPackage == "" {
					apkPackage = "unknown"
				}
				mappings = append(mappings, PackageMapping{
					URL:        pkg.DownloadLocation,
					APKPackage: apkPackage,
				})
			}
		}
	}

	return mappings, nil
}

func downloadConcurrently(mappings []PackageMapping, archivesDir string, concurrency int) []string {
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
				URL:        mapping.URL,
				APKPackage: mapping.APKPackage,
				Index:      i + 1,
				Total:      len(mappings),
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
	for result := range results {
		completed++
		if result.Error != nil {
			fmt.Fprintf(os.Stderr, "Error downloading %s: %v\n", result.URL, result.Error)
		} else {
			filename := getFilenameFromURL(result.URL)
			downloadedFiles = append(downloadedFiles, filepath.Join(archivesDir, filename))
			fmt.Printf("✓ Downloaded (%d/%d): %s [%s]\n", completed, len(mappings), filename, result.APKPackage)
		}
	}
	
	return downloadedFiles
}

func worker(jobs <-chan DownloadJob, results chan<- DownloadResult, archivesDir string, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {
		fmt.Printf("→ Starting download (%d/%d): %s [%s]\n", job.Index, job.Total, getFilenameFromURL(job.URL), job.APKPackage)
		
		err := downloadFileToDir(job.URL, archivesDir)
		results <- DownloadResult{
			URL:        job.URL,
			APKPackage: job.APKPackage,
			Error:      err,
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

func extractArchives(archiveFiles []string, extractDir string) {
	for i, archiveFile := range archiveFiles {
		fmt.Printf("Extracting (%d/%d): %s\n", i+1, len(archiveFiles), filepath.Base(archiveFile))
		if err := extractArchive(archiveFile, extractDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error extracting %s: %v\n", archiveFile, err)
		} else {
			fmt.Printf("✓ Extracted: %s\n", filepath.Base(archiveFile))
		}
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
				return fmt.Errorf("failed to create symlink %s: %w", targetPath, err)
			}
		}
	}

	return nil
}
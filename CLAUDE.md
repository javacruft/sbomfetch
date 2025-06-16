# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Structure

- All of the code is contained in sbomfetch.go
- The tool parses an SPDX 2.3 JSON formatted SBOM and then downloads any files referenced in downloadLocation fields.
- Archives are then extracted into a specified directory and a summary of work displayed to the end used.



# BountyExtractor

A fast, multithreaded Python script designed for Web Bug Bounty hunters to extract hidden endpoints, API paths, and URIs from JavaScript files.

## Features
- **Fast:** Powered by Python's `ThreadPoolExecutor` for concurrent scanning.
- **Smart:** Utilizes optimized RegEx patterns tailored for bug hunting.
- **Flexible:** Supports scanning a single JS URL or a bulk list from a file.

## Installation
```bash
git clone https://github.com
cd BountyExtractor
pip install -r requirements.txt
```

## Usage
**Scan a single JavaScript file:**
```bash
python run.py -u https://example.com
```

**Scan multiple URLs from a file with 10 threads:**
```bash
python run.py -l js_urls.txt -t 10
```

## Documentation
For more detailed guides and advanced usage, visit our official documentation at: **https://ttooff.top**

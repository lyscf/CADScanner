# Example Samples

This directory contains the example CAD-related files used in our study.

## Directory Structure

- files directly under `examples/`: malicious samples used in the experiments.

## Why We Release Hashes Instead of Malicious Files

Releasing the original malicious files would directly enable redistribution of real attack artifacts. These files may be reused outside a controlled research setting, creating avoidable security, legal, and ethical concerns. For this reason, we only release cryptographic file hashes for the malicious samples.

In particular, we provide SHA-256 hashes that can be used as VirusTotal lookup identifiers. This allows other researchers to:

- verify the identity of the samples used in our evaluation;
- cross-check detections, labels, and metadata on VirusTotal;
- obtain the corresponding files through authorized channels if they have the legal right and an appropriate analysis environment.

This approach preserves transparency and reproducibility without openly redistributing malware.

## Benign Sample Availability

We also do not directly redistribute the benign samples in this repository. Many benign CAD scripts and compiled artifacts originate from third-party sources, and redistributing them may introduce copyright or other licensing concerns.

For this reason, the benign files are not included as an open dataset release here.

When benign samples are incorporated into our local evaluation workflow, they are prefixed with `white_` so that the evaluation software can easily identify and exclude them when needed.

## Reproducibility Notes

- Some samples may use misleading filename extensions. Therefore, extension alone should not be treated as the ground-truth file type.
- Our analysis may report both raw malicious file count and deduplicated malicious sample count. The deduplicated count is based on SHA-256.

## Provided Hash Files

- `malicious_hashes.txt`
  SHA-256 hashes for all malicious files, one hash per file.
